//! Tar header normalisation in front of the `tar` crate.
//!
//! The `tar` crate rejects numeric header fields that GNU tar and libarchive
//! accept: a field that starts with NUL (libarchive reads it as 0, e.g.
//! libarchive's `test_read_format_tar_empty_with_gnulabel` and
//! `test_read_format_tar_timestamp_overflow`), or one with trailing garbage
//! after the octal digits. [`TarFix`] follows the tar block structure (header,
//! PAX `size` override, GNU sparse extension blocks, padded data) and rewrites
//! only such fields, using libarchive's reading, then recomputes the header
//! checksum when the original one was valid. Data blocks pass straight
//! through into the caller's buffer without an extra copy.

use std::io::{self, Read};

const BLOCK: usize = 512;
/// size (the tar crate needs it to walk the archive) and mtime (we restore it).
/// Other numeric fields are left alone: ordinary writers leave uid/gid NUL.
const FIELDS: [(usize, usize); 2] = [(124, 12), (136, 12)];

pub(crate) struct TarFix<R> {
    inner: R,
    /// Data bytes (padded to blocks) still to pass through before the next header.
    data_left: u64,
    /// Following GNU sparse extension block(s) are expected; the entry's data
    /// (`after_ext` bytes) comes after them.
    sparse_ext: bool,
    after_ext: u64,
    /// `size` from a PAX extended header, applies to the next header.
    pax_size: Option<u64>,
    /// Header block being handed out: buffer and read position.
    hdr: [u8; BLOCK],
    hdr_pos: usize,
    /// Valid bytes in `hdr` (less than a block only at a truncated end).
    hdr_len: usize,
    /// Consecutive all-zero blocks; after the end marker (two) everything
    /// passes through untouched.
    zeros: u8,
    /// PAX data being collected to find `size=` (only for 'x' headers).
    pax: Option<Vec<u8>>,
    pax_left: u64,
    done: bool,
}

impl<R: Read> TarFix<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            data_left: 0,
            sparse_ext: false,
            after_ext: 0,
            pax_size: None,
            hdr: [0; BLOCK],
            hdr_pos: BLOCK,
            hdr_len: BLOCK,
            zeros: 0,
            pax: None,
            pax_left: 0,
            done: false,
        }
    }

    /// Read one block into `hdr` (`hdr_len` bytes); Ok(false) at the end.
    fn fill_block(&mut self) -> io::Result<bool> {
        let mut n = 0;
        while n < BLOCK {
            match self.inner.read(&mut self.hdr[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if n == 0 {
            return Ok(false);
        }
        self.hdr_len = n;
        if n < BLOCK {
            // Truncated archive: hand out what there is; the tar crate reports it.
            self.done = true;
        }
        Ok(true)
    }

    /// Process a freshly read header block.
    fn header(&mut self) {
        let h = &mut self.hdr;
        if self.sparse_ext {
            // GNU sparse extension block: 21 entries, continuation flag at 504.
            self.sparse_ext = h[504] != 0;
            if !self.sparse_ext {
                self.data_left = std::mem::take(&mut self.after_ext);
            }
            return;
        }
        if h.iter().all(|&b| b == 0) {
            self.zeros += 1;
            if self.zeros >= 2 {
                self.data_left = u64::MAX;
            }
            return;
        }
        self.zeros = 0;
        fix_header(h);
        let size = octal_libarchive(&h[124..136]).max(0) as u64;
        let kind = h[156];
        let size = match kind {
            b'x' | b'X' | b'g' => size,
            _ => self.pax_size.take().unwrap_or(size),
        };
        let padded = size.div_ceil(BLOCK as u64) * BLOCK as u64;
        if kind == b'S' && h[482] != 0 {
            self.sparse_ext = true;
            self.after_ext = padded;
            return;
        }
        if matches!(kind, b'x' | b'X') && size <= 1 << 20 {
            self.pax = Some(Vec::with_capacity(size as usize));
            self.pax_left = size;
        }
        self.data_left = padded;
    }

    fn take_pax(&mut self, data: &[u8]) {
        let Some(buf) = self.pax.as_mut() else {
            return;
        };
        let k = (data.len() as u64).min(self.pax_left) as usize;
        buf.extend_from_slice(&data[..k]);
        self.pax_left -= k as u64;
        if self.pax_left == 0 {
            let buf = self.pax.take().unwrap_or_default();
            self.pax_size = pax_size(&buf);
        }
    }
}

impl<R: Read> Read for TarFix<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.hdr_pos < self.hdr_len {
                let n = buf.len().min(self.hdr_len - self.hdr_pos);
                buf[..n].copy_from_slice(&self.hdr[self.hdr_pos..self.hdr_pos + n]);
                self.hdr_pos += n;
                return Ok(n);
            }
            if self.data_left > 0 {
                let want = (buf.len() as u64).min(self.data_left) as usize;
                let n = self.inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Ok(0);
                }
                self.data_left -= n as u64;
                if self.pax.is_some() {
                    let d = buf[..n].to_vec();
                    self.take_pax(&d);
                }
                return Ok(n);
            }
            if self.done || !self.fill_block()? {
                return Ok(0);
            }
            if self.hdr_len == BLOCK {
                self.header();
            }
            self.hdr_pos = 0;
        }
    }
}

/// `size` record of PAX extended header data ("<len> size=<n>\n").
fn pax_size(data: &[u8]) -> Option<u64> {
    let mut size = None;
    let mut rest = data;
    while !rest.is_empty() {
        let Some(sp) = rest.iter().position(|&b| b == b' ') else {
            break;
        };
        let Some(len) = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            break;
        };
        if len <= sp || len > rest.len() {
            break;
        }
        let rec = &rest[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(v) = rec.strip_prefix(b"size=") {
            size = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok());
        }
        rest = &rest[len..];
    }
    size
}

/// Value of a numeric field the way libarchive reads it: base-256 when the
/// high bit is set, else skip spaces/tabs, optional '-', then octal digits up
/// to the first other byte (so a leading NUL reads as 0).
fn octal_libarchive(f: &[u8]) -> i64 {
    if f[0] & 0x80 != 0 {
        // Base-256 big-endian; bit 6 of the first byte is the sign.
        if f[0] & 0x40 != 0 {
            return 0;
        }
        let mut v: i64 = i64::from(f[0] & 0x3f);
        for &b in &f[1..] {
            v = v.checked_mul(256).map_or(i64::MAX, |x| x | i64::from(b));
        }
        return v;
    }
    let mut i = 0;
    while i < f.len() && (f[i] == b' ' || f[i] == b'\t') {
        i += 1;
    }
    let neg = i < f.len() && f[i] == b'-';
    if neg {
        i += 1;
    }
    let mut v: i64 = 0;
    while i < f.len() && (b'0'..=b'7').contains(&f[i]) {
        v = v.saturating_mul(8).saturating_add(i64::from(f[i] - b'0'));
        i += 1;
    }
    if neg { -v } else { v }
}

/// Whether the `tar` crate parses this numeric field (its `octal_from`:
/// text up to the first NUL, trimmed, must be octal; or base-256).
fn crate_accepts(f: &[u8]) -> bool {
    if f[0] & 0x80 != 0 {
        return true;
    }
    let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    std::str::from_utf8(&f[..end])
        .ok()
        .is_some_and(|s| u64::from_str_radix(s.trim(), 8).is_ok())
}

fn checksum(h: &[u8; BLOCK]) -> u32 {
    h.iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u32::from(b)
            }
        })
        .sum()
}

/// Rewrite numeric fields the tar crate rejects; fix the checksum if it was valid.
fn fix_header(h: &mut [u8; BLOCK]) {
    if FIELDS.iter().all(|&(o, l)| crate_accepts(&h[o..o + l])) {
        return;
    }
    let stored = octal_libarchive(&h[148..156]);
    let was_valid = stored == i64::from(checksum(h));
    for (o, l) in FIELDS {
        let f = &mut h[o..o + l];
        if crate_accepts(f) {
            continue;
        }
        let v = octal_libarchive(f).max(0) as u64;
        let digits = format!("{v:0w$o}", w = l - 1);
        if digits.len() == l - 1 {
            f[..l - 1].copy_from_slice(digits.as_bytes());
            f[l - 1] = 0;
        } else {
            f.fill(b'0');
            f[l - 1] = 0;
        }
    }
    if was_valid {
        let c = format!("{:06o}\0 ", checksum(h));
        h[148..156].copy_from_slice(c.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, size: &[u8; 12], kind: u8) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(size);
        h[136..148].copy_from_slice(b"15155542402\0");
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let c = format!("{:06o}\0 ", checksum(&h));
        h[148..156].copy_from_slice(c.as_bytes());
        h
    }

    fn entries(data: Vec<u8>) -> Vec<(String, u64, Vec<u8>)> {
        let mut ar = tar::Archive::new(TarFix::new(io::Cursor::new(data)));
        let mut out = Vec::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
            let size = e.header().size().unwrap();
            let mut d = Vec::new();
            e.read_to_end(&mut d).unwrap();
            out.push((name, size, d));
        }
        out
    }

    #[test]
    fn nul_led_numeric_fields_read_as_zero() {
        // Like libarchive test_read_format_tar_timestamp_overflow: size field
        // is NULs followed by digits; libarchive reads 0.
        let mut t = header("tmp/f.txt", b"\0\0\0\0\0\0\0\x30016\0", b'0').to_vec();
        t.extend_from_slice(&[0; 1024]);
        let mut plain = tar::Archive::new(io::Cursor::new(t.clone()));
        let rejected = match plain.entries().unwrap().next().unwrap() {
            Err(_) => true,
            Ok(e) => e.header().size().is_err(),
        };
        assert!(rejected, "the tar crate alone rejects this header");
        let e = entries(t);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, "tmp/f.txt");
        assert_eq!(e[0].1, 0);
    }

    #[test]
    fn empty_gnu_label_is_an_empty_archive() {
        // Like libarchive test_read_format_tar_empty_with_gnulabel: one GNU
        // volume label ('V') with an all-NUL size, then the end blocks.
        let mut t = header("label", &[0; 12], b'V').to_vec();
        t.extend_from_slice(&[0; 1024]);
        let e = entries(t);
        assert!(e.iter().all(|(_, s, d)| *s == 0 && d.is_empty()));
    }

    #[test]
    fn data_and_pax_size_pass_through() {
        // A valid archive with a PAX size override and data that looks like a
        // broken header must come through byte for byte.
        let mut b = tar::Builder::new(Vec::new());
        let mut fake = header("x", b"\0\0\0\0\0\0\0\x30016\0", b'0').to_vec();
        fake.extend_from_slice(b"tail");
        let mut h = tar::Header::new_ustar();
        h.set_size(fake.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "a.bin", &fake[..]).unwrap();
        b.append_pax_extensions([("size", b"3".as_slice())])
            .unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(0);
        h.set_mode(0o644);
        h.set_cksum();
        let mut raw = Vec::new();
        b.append_data(&mut h, "b.txt", &b""[..]).unwrap();
        let mut t = b.into_inner().unwrap();
        // Give b.txt the 3 data bytes the PAX header announces.
        let end = t.len() - 1024;
        raw.extend_from_slice(&t[..end]);
        raw.extend_from_slice(b"xyz");
        raw.resize(raw.len().div_ceil(512) * 512, 0);
        raw.extend_from_slice(&[0; 1024]);
        t = raw;
        let mut direct = Vec::new();
        TarFix::new(io::Cursor::new(t.clone()))
            .read_to_end(&mut direct)
            .unwrap();
        assert_eq!(direct, t);
        let e = entries(t);
        assert_eq!(e[0].2, fake);
        assert_eq!(e[1].0, "b.txt");
        assert_eq!(e[1].2, b"xyz");
    }

    #[test]
    fn gnu_sparse_extension_blocks_come_before_data() {
        // Old GNU sparse ('S') with isextended set: extension blocks follow the
        // header, then the data. Data that looks like a broken header must not
        // be touched (it would be if the data were expected right after the header).
        let mut fake = header("x", b"\0\0\0\0\0\0\0\x30016\0", b'0').to_vec();
        fake.resize(1024, 7);
        let mut size = [0u8; 12];
        size.copy_from_slice(format!("{:011o}\0", fake.len()).as_bytes());
        let mut h = header("sparse", &size, b'S');
        h[482] = 1;
        h[148..156].copy_from_slice(b"        ");
        let c = format!("{:06o}\0 ", checksum(&h));
        h[148..156].copy_from_slice(c.as_bytes());
        let mut ext1 = [0u8; BLOCK];
        ext1[504] = 1;
        let ext2 = [0u8; BLOCK];
        let mut t = h.to_vec();
        t.extend_from_slice(&ext1);
        t.extend_from_slice(&ext2);
        t.extend_from_slice(&fake);
        t.extend_from_slice(&[0; 1024]);
        let mut out = Vec::new();
        TarFix::new(io::Cursor::new(t.clone()))
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, t);
    }

    #[test]
    fn corpus_passes_through_unchanged() {
        // Optional: NZ_TAR_CORPUS=<dir> checks every *.tar there comes out of
        // TarFix byte for byte unless one of its headers needed fixing.
        let Ok(dir) = std::env::var("NZ_TAR_CORPUS") else {
            return;
        };
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_none_or(|x| x != "tar") {
                continue;
            }
            let raw = std::fs::read(&p).unwrap();
            let mut out = Vec::new();
            TarFix::new(io::Cursor::new(raw.clone()))
                .read_to_end(&mut out)
                .unwrap();
            let diff: Vec<usize> = (0..raw.len().min(out.len()) / BLOCK)
                .filter(|&b| raw[b * BLOCK..][..BLOCK] != out[b * BLOCK..][..BLOCK])
                .collect();
            eprintln!(
                "{} len {} {} changed blocks {:?}",
                p.display(),
                raw.len(),
                out.len(),
                diff
            );
        }
    }

    #[test]
    fn libarchive_number_rules() {
        assert_eq!(octal_libarchive(b"  0755\0\0"), 0o755);
        assert_eq!(octal_libarchive(b"\0\0\0\x30016"), 0);
        assert_eq!(octal_libarchive(b"0016 junk\0\0\0"), 0o16);
        assert!(!crate_accepts(b"\0\0\0\x30016\0\0\0\0\0"));
        assert!(!crate_accepts(b"0016 junk\0\0\0"));
        assert!(crate_accepts(b"00000000016\0"));
        assert_eq!(pax_size(b"11 size=42\n13 path=a.txt\n"), Some(42));
    }
}
