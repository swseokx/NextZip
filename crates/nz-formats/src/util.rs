//! Small helpers shared by the readers.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use anyhow::{Result, bail};

/// Positional reads on a file of known length.
pub struct Src {
    pub f: File,
    pub len: u64,
}

impl Src {
    pub fn open(path: &std::path::Path) -> Result<Src> {
        let f = File::open(path)?;
        let len = f.metadata()?.len();
        Ok(Src { f, len })
    }

    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        if off
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.len)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past end",
            ));
        }
        read_exact_at(&self.f, buf, off)
    }

    /// `n` bytes at `off`, refusing sizes larger than the file.
    pub fn bytes(&self, off: u64, n: u64) -> Result<Vec<u8>> {
        if off.checked_add(n).is_none_or(|e| e > self.len) {
            bail!(
                "truncated archive (want {n} bytes at {off}, file is {})",
                self.len
            );
        }
        let mut v = vec![0u8; n as usize];
        self.read_at(off, &mut v)?;
        Ok(v)
    }

    /// A reader over `[off, off + n)`.
    pub fn section(&self, off: u64, n: u64) -> Result<Section<'_>> {
        if off.checked_add(n).is_none_or(|e| e > self.len) {
            bail!("section past end of file");
        }
        Ok(Section {
            src: self,
            pos: off,
            end: off + n,
        })
    }
}

#[cfg(windows)]
fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

/// A bounded reader over part of a [`Src`].
pub struct Section<'a> {
    src: &'a Src,
    pos: u64,
    end: u64,
}

impl Read for Section<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.end - self.pos).min(buf.len() as u64) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.src.read_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Copy `r` to the sink in chunks, refusing more than `limit` bytes.
pub fn pump(r: &mut dyn Read, sink: &mut dyn crate::Sink, limit: u64) -> Result<u64> {
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        total += n as u64;
        if total > limit {
            bail!("member larger than its limit");
        }
        sink.data(&buf[..n])?;
    }
}

/// Copy exactly `n` bytes of `r` to the sink.
pub fn pump_exact(r: &mut dyn Read, sink: &mut dyn crate::Sink, n: u64) -> Result<()> {
    let got = pump(&mut r.take(n), sink, n)?;
    if got != n {
        bail!("truncated member ({got} of {n} bytes)");
    }
    Ok(())
}

pub fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
pub fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
pub fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

/// Read the whole file into memory, refusing files above `max`.
pub fn read_all(path: &std::path::Path, max: u64) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let len = f.seek(SeekFrom::End(0))?;
    if len > max {
        bail!("file too large for this format ({len} bytes)");
    }
    f.seek(SeekFrom::Start(0))?;
    let mut v = Vec::with_capacity(len as usize);
    f.read_to_end(&mut v)?;
    Ok(v)
}

/// Lossy text of a NUL-padded byte field.
pub fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Parse an octal ASCII field (cpio odc, ar mode); spaces and NULs end it.
pub fn octal(b: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    let mut any = false;
    for &c in b {
        match c {
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add(u64::from(c - b'0'))?;
                any = true;
            }
            b' ' | 0 if any => break,
            b' ' | 0 => {}
            _ => return None,
        }
    }
    Some(v)
}

/// Parse a hex ASCII field (cpio newc).
pub fn hex(b: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(b).ok()?;
    u64::from_str_radix(s, 16).ok()
}

/// Parse a decimal ASCII field padded with spaces (ar).
pub fn decimal(b: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(b).ok()?.trim();
    if s.is_empty() {
        return Some(0);
    }
    s.parse().ok()
}

/// Several volume files read as one (split `.001`, `.002`, ... sets).
pub struct Concat {
    files: Vec<(File, u64)>,
    /// Start offset of each file in the joined stream.
    starts: Vec<u64>,
    len: u64,
    /// Bytes of the joined stream hidden before position 0 (an SFX stub).
    base: u64,
    pos: u64,
}

impl Concat {
    pub fn open(paths: &[std::path::PathBuf]) -> io::Result<Concat> {
        let mut files = Vec::with_capacity(paths.len());
        let mut starts = Vec::with_capacity(paths.len());
        let mut len = 0u64;
        for p in paths {
            let f = File::open(p)?;
            let n = f.metadata()?.len();
            starts.push(len);
            len += n;
            files.push((f, n));
        }
        Ok(Concat {
            files,
            starts,
            len,
            base: 0,
            pos: 0,
        })
    }

    /// Start the stream `off` bytes in (an archive after an SFX stub).
    pub fn skip_prefix(mut self, off: u64) -> Concat {
        self.base = off.min(self.len);
        self
    }
}

impl Read for Concat {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let at = self.base + self.pos;
        if at >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let i = self.starts.partition_point(|s| *s <= at) - 1;
        let (f, n) = &mut self.files[i];
        let off = at - self.starts[i];
        let k = ((*n - off).min(buf.len() as u64)) as usize;
        f.seek(SeekFrom::Start(off))?;
        let got = f.read(&mut buf[..k])?;
        if got == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.pos += got as u64;
        Ok(got)
    }
}

impl Seek for Concat {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => (self.len - self.base).checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = p.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad seek"))?;
        Ok(self.pos)
    }
}

/// The volumes of a split set when `path` is its first part (`x.001`
/// with at least `x.002` beside it), in order.
pub fn split_volumes(path: &std::path::Path) -> Option<Vec<std::path::PathBuf>> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".001")?;
    let mut v = vec![path.to_path_buf()];
    for i in 2..10_000u32 {
        let p = path.with_file_name(format!("{stem}.{i:03}"));
        if !p.is_file() {
            break;
        }
        v.push(p);
    }
    (v.len() > 1).then_some(v)
}

/// An archive embedded after a stub: a self-extractor (PE / ELF with a 7z,
/// RAR or ZIP payload) or a file with junk in front of a ZIP. Returns the
/// payload format and its offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Embedded {
    /// 7z at this offset (signature and start header CRC checked).
    SevenZ(u64),
    /// RAR 4 / 5 signature at this offset.
    Rar(u64),
    /// ZIP found by its end record; readers locate the members themselves.
    Zip,
}

/// How far into a stub to look for a 7z / RAR signature (SFX stubs are
/// well under this).
const SFX_SCAN: u64 = 16 << 20;

pub fn embedded(path: &std::path::Path) -> Option<Embedded> {
    let src = Src::open(path).ok()?;
    let n = src.len.min(SFX_SCAN) as usize;
    let mut head = vec![0u8; n];
    src.read_at(0, &mut head).ok()?;
    let mut i = 1;
    while i + 32 <= n {
        let w = &head[i..];
        if w.starts_with(b"7z\xBC\xAF\x27\x1C")
            && crc32fast::hash(&w[12..32]) == u32::from_le_bytes([w[8], w[9], w[10], w[11]])
        {
            return Some(Embedded::SevenZ(i as u64));
        }
        if w.starts_with(b"Rar!\x1A\x07\x00") || w.starts_with(b"Rar!\x1A\x07\x01\x00") {
            return Some(Embedded::Rar(i as u64));
        }
        i += 1;
    }
    // ZIP end of central directory record within the last 64 KiB + 22.
    let tail_len = src.len.min(65_557) as usize;
    let mut tail = vec![0u8; tail_len];
    src.read_at(src.len - tail_len as u64, &mut tail).ok()?;
    let eocd = tail.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    (tail_len - eocd >= 22).then_some(Embedded::Zip)
}
