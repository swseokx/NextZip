//! bzip2 decoder for standard streams and ALZ's stripped variant.
//!
//! ALZ (ALZip) stores bzip2 without the `BZh9` stream header, replaces the
//! 48-bit block magic plus block CRC plus randomised bit with the 32 bits
//! `"DLZ\x01"`, and replaces the end-of-stream magic plus combined CRC with
//! `"DLZ\x02"` (unalz 0.65, `UnAlzBz2decompress.c`). Everything between is
//! ordinary bzip2, so one decoder handles both. Integrity of ALZ data rests on
//! the member CRC-32, checked by the caller.

use anyhow::{Result, bail, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Standard,
    Alz,
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }
    #[inline]
    fn need(&mut self, n: u32) -> Result<()> {
        while self.cnt < n {
            let Some(&b) = self.data.get(self.pos) else {
                bail!("bzip2: unexpected end of data");
            };
            self.pos += 1;
            self.buf = (self.buf << 8) | u64::from(b);
            self.cnt += 8;
        }
        Ok(())
    }
    #[inline]
    fn bits(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.need(n)?;
        self.cnt -= n;
        Ok(((self.buf >> self.cnt) & ((1u64 << n) - 1)) as u32)
    }
    #[inline]
    fn bit(&mut self) -> Result<bool> {
        Ok(self.bits(1)? == 1)
    }
    /// Drop bits up to the next byte boundary.
    fn align(&mut self) {
        self.cnt -= self.cnt % 8;
    }
    fn at_end(&self) -> bool {
        self.pos >= self.data.len() && self.cnt < 8
    }
}

fn crc_table() -> &'static [u32; 256] {
    static T: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = (i as u32) << 24;
            for _ in 0..8 {
                c = if c & 0x8000_0000 != 0 {
                    (c << 1) ^ 0x04C1_1DB7
                } else {
                    c << 1
                };
            }
            *e = c;
        }
        t
    })
}

fn block_crc(data: &[u8]) -> u32 {
    let t = crc_table();
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = (c << 8) ^ t[((c >> 24) ^ u32::from(b)) as usize];
    }
    !c
}

const MAX_GROUPS: usize = 6;
const MAX_CODE_LEN: u32 = 20;
const MAX_SELECTORS: usize = 18_002;

struct Huff {
    min_len: u32,
    max_len: u32,
    /// First canonical code of each length.
    first: [u32; 21],
    count: [u32; 21],
    /// Offset of each length's symbols in `perm`.
    offset: [u32; 21],
    perm: Vec<u16>,
}

impl Huff {
    fn new(lens: &[u8]) -> Result<Huff> {
        let mut count = [0u32; 21];
        for &l in lens {
            count[usize::from(l)] += 1;
        }
        let min_len = lens.iter().copied().min().unwrap_or(1) as u32;
        let max_len = lens.iter().copied().max().unwrap_or(1) as u32;
        let mut first = [0u32; 21];
        let mut offset = [0u32; 21];
        let mut code = 0u32;
        let mut off = 0u32;
        for l in 1..=MAX_CODE_LEN as usize {
            first[l] = code;
            offset[l] = off;
            code = (code + count[l]) << 1;
            off += count[l];
        }
        let mut perm = Vec::with_capacity(lens.len());
        for l in min_len..=max_len {
            for (s, &sl) in lens.iter().enumerate() {
                if u32::from(sl) == l {
                    perm.push(s as u16);
                }
            }
        }
        Ok(Huff {
            min_len,
            max_len,
            first,
            count,
            offset,
            perm,
        })
    }
    #[inline]
    fn decode(&self, b: &mut Bits) -> Result<u16> {
        let mut code = b.bits(self.min_len)?;
        let mut l = self.min_len;
        loop {
            let li = l as usize;
            let d = code.wrapping_sub(self.first[li]);
            if d < self.count[li] {
                return Ok(self.perm[(self.offset[li] + d) as usize]);
            }
            l += 1;
            if l > self.max_len {
                bail!("bzip2: bad Huffman code");
            }
            code = (code << 1) | b.bits(1)?;
        }
    }
}

/// Decode one block after its header magic. Returns the block bytes.
fn decode_block(
    b: &mut Bits,
    variant: Variant,
    block_max: usize,
    out: &mut Vec<u8>,
) -> Result<u32> {
    let stored_crc = if variant == Variant::Standard {
        let crc = b.bits(32)?;
        ensure!(!b.bit()?, "bzip2: randomised blocks are not supported");
        Some(crc)
    } else {
        None
    };
    let orig_ptr = b.bits(24)? as usize;

    // Symbol map.
    let used16 = b.bits(16)?;
    let mut seq = Vec::with_capacity(256);
    for i in 0..16 {
        if used16 & (0x8000 >> i) != 0 {
            let w = b.bits(16)?;
            for j in 0..16 {
                if w & (0x8000 >> j) != 0 {
                    seq.push((i * 16 + j) as u8);
                }
            }
        }
    }
    ensure!(!seq.is_empty(), "bzip2: empty symbol map");
    let alpha = seq.len() + 2;

    let n_groups = b.bits(3)? as usize;
    ensure!(
        (2..=MAX_GROUPS).contains(&n_groups),
        "bzip2: bad group count"
    );
    let n_sel = b.bits(15)? as usize;
    ensure!(n_sel >= 1, "bzip2: no selectors");
    let mut mtf_g: Vec<u8> = (0..n_groups as u8).collect();
    let mut selectors = Vec::with_capacity(n_sel.min(MAX_SELECTORS));
    for _ in 0..n_sel {
        let mut j = 0usize;
        while b.bit()? {
            j += 1;
            ensure!(j < n_groups, "bzip2: bad selector");
        }
        let v = mtf_g.remove(j);
        mtf_g.insert(0, v);
        if selectors.len() < MAX_SELECTORS {
            selectors.push(v);
        }
    }

    let mut tables = Vec::with_capacity(n_groups);
    for _ in 0..n_groups {
        let mut lens = vec![0u8; alpha];
        let mut cur = b.bits(5)? as i32;
        for l in lens.iter_mut() {
            loop {
                ensure!((1..=20).contains(&cur), "bzip2: bad code length");
                if !b.bit()? {
                    break;
                }
                if b.bit()? {
                    cur -= 1;
                } else {
                    cur += 1;
                }
            }
            *l = cur as u8;
        }
        tables.push(Huff::new(&lens)?);
    }

    // Huffman + RUNA/RUNB + MTF.
    let eob = (alpha - 1) as u16;
    let mut mtf: Vec<u8> = (0..seq.len()).map(|i| i as u8).collect();
    let mut tt: Vec<u32> = Vec::with_capacity(block_max.min(1 << 20));
    let mut counts = [0u32; 256];
    let mut sel_i = 0usize;
    let mut left = 0usize;
    let mut table = &tables[0];
    let mut run: usize = 0;
    let mut run_w: usize = 1;
    loop {
        if left == 0 {
            ensure!(sel_i < selectors.len(), "bzip2: ran out of selectors");
            table = &tables[usize::from(selectors[sel_i])];
            sel_i += 1;
            left = 50;
        }
        left -= 1;
        let sym = table.decode(b)?;
        if sym <= 1 {
            ensure!(run_w <= block_max, "bzip2: run too long");
            run += run_w << sym; // RUNA adds w, RUNB adds 2w
            run_w <<= 1;
            continue;
        }
        if run > 0 {
            ensure!(tt.len() + run <= block_max, "bzip2: block too large");
            let byte = seq[usize::from(mtf[0])];
            counts[usize::from(byte)] += run as u32;
            tt.extend(std::iter::repeat_n(u32::from(byte), run));
            run = 0;
            run_w = 1;
        }
        if sym == eob {
            break;
        }
        let idx = usize::from(sym - 1);
        ensure!(idx < mtf.len(), "bzip2: bad MTF index");
        let v = mtf.remove(idx);
        mtf.insert(0, v);
        let byte = seq[usize::from(v)];
        ensure!(tt.len() < block_max, "bzip2: block too large");
        counts[usize::from(byte)] += 1;
        tt.push(u32::from(byte));
    }
    let n = tt.len();
    ensure!(orig_ptr < n.max(1), "bzip2: bad origin pointer");
    if n == 0 {
        return Ok(0);
    }

    // Inverse BWT.
    let mut cf = [0u32; 256];
    let mut sum = 0u32;
    for i in 0..256 {
        cf[i] = sum;
        sum += counts[i];
    }
    for i in 0..n {
        let byte = (tt[i] & 0xFF) as usize;
        let dst = cf[byte] as usize;
        tt[dst] |= (i as u32) << 8;
        cf[byte] += 1;
    }

    // Undo the initial run-length encoding while walking the BWT chain.
    let start = out.len();
    let mut pos = tt[orig_ptr] >> 8;
    let mut last: i32 = -1;
    let mut same = 0u32;
    let mut i = 0usize;
    while i < n {
        let e = tt[pos as usize];
        let ch = (e & 0xFF) as u8;
        pos = e >> 8;
        i += 1;
        if same == 4 {
            out.extend(std::iter::repeat_n(last as u8, usize::from(ch)));
            same = 0;
            last = -1;
            continue;
        }
        if i32::from(ch) == last {
            same += 1;
        } else {
            same = 1;
            last = i32::from(ch);
        }
        out.push(ch);
    }
    let crc = block_crc(&out[start..]);
    if let Some(s) = stored_crc {
        ensure!(s == crc, "bzip2: block CRC mismatch");
    }
    Ok(crc)
}

/// Decompress a whole bzip2 stream (or concatenated streams).
/// `size_hint` preallocates the output.
pub fn decompress(input: &[u8], variant: Variant, size_hint: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size_hint.min(crate::PREALLOC));
    let mut b = Bits::new(input);
    loop {
        let block_max = match variant {
            Variant::Standard => {
                ensure!(b.bits(24)? == 0x42_5A_68, "bzip2: bad stream header");
                let lvl = b.bits(8)?;
                ensure!((0x31..=0x39).contains(&lvl), "bzip2: bad block size");
                (lvl - 0x30) as usize * 100_000
            }
            Variant::Alz => 900_000,
        };
        let mut combined = 0u32;
        loop {
            match variant {
                Variant::Standard => {
                    let hi = b.bits(24)?;
                    let lo = b.bits(24)?;
                    match (hi, lo) {
                        (0x31_41_59, 0x26_53_59) => {
                            let crc = decode_block(&mut b, variant, block_max, &mut out)?;
                            combined = combined.rotate_left(1) ^ crc;
                        }
                        (0x17_72_45, 0x38_50_90) => {
                            let stored = b.bits(32)?;
                            ensure!(stored == combined, "bzip2: stream CRC mismatch");
                            break;
                        }
                        _ => bail!("bzip2: bad block magic"),
                    }
                }
                Variant::Alz => {
                    let magic = b.bits(24)?;
                    ensure!(magic == 0x44_4C_5A, "ALZ bzip2: bad block magic");
                    match b.bits(8)? {
                        1 => {
                            decode_block(&mut b, variant, block_max, &mut out)?;
                        }
                        2 => return Ok(out),
                        _ => bail!("ALZ bzip2: bad block magic"),
                    }
                }
            }
        }
        b.align();
        if b.at_end() {
            return Ok(out);
        }
    }
}

/// Convert a standard bzip2 stream into ALZ's variant (used by tests that
/// build ALZ samples). Blocks are found by scanning for the 48-bit magics,
/// like `bzip2recover`.
pub fn standard_to_alz(std: &[u8]) -> Result<Vec<u8>> {
    // Collect bit positions of every block / end magic.
    let total_bits = std.len() * 8;
    let get = |i: usize| -> u64 { u64::from((std[i / 8] >> (7 - i % 8)) & 1) };
    let mut marks = Vec::new();
    let mut acc = 0u64;
    for i in 0..total_bits {
        acc = ((acc << 1) | get(i)) & 0xFFFF_FFFF_FFFF;
        if i >= 47 && (acc == 0x3141_5926_5359 || acc == 0x1772_4538_5090) {
            marks.push((i + 1 - 48, acc == 0x1772_4538_5090));
        }
    }
    ensure!(marks.last().is_some_and(|m| m.1), "no end-of-stream marker");
    let mut w = BitWriter::default();
    for (k, &(start, is_end)) in marks.iter().enumerate() {
        if is_end {
            for &c in b"DLZ\x02" {
                w.put(u64::from(c), 8);
            }
            break;
        }
        for &c in b"DLZ\x01" {
            w.put(u64::from(c), 8);
        }
        // Skip magic (48), CRC (32) and the randomised bit (1).
        let body_start = start + 48 + 32 + 1;
        let body_end = marks[k + 1].0;
        for i in body_start..body_end {
            w.put(get(i), 1);
        }
    }
    Ok(w.finish())
}

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    fn put(&mut self, v: u64, bits: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((v >> i) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn bz(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = ::bzip2::write::BzEncoder::new(Vec::new(), ::bzip2::Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x = 12345u32;
        while v.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let word =
                ["alpha ", "beta ", "gamma ", "aaaaaaaaaa", "\n", "zz"][(x >> 16) as usize % 6];
            v.extend_from_slice(word.as_bytes());
            if x.is_multiple_of(7) {
                v.push((x >> 8) as u8);
            }
        }
        v.truncate(n);
        v
    }

    #[test]
    fn standard_streams() {
        for (n, lvl) in [(0, 9), (1, 9), (1000, 1), (250_000, 1), (2_000_000, 9)] {
            let d = sample(n);
            let c = bz(&d, lvl);
            assert_eq!(decompress(&c, Variant::Standard, n).unwrap(), d, "n={n}");
        }
    }

    #[test]
    fn concatenated_streams() {
        let mut c = bz(b"hello ", 9);
        c.extend(bz(b"world", 9));
        assert_eq!(
            decompress(&c, Variant::Standard, 0).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn alz_variant() {
        for n in [1, 5000, 1_900_000] {
            let d = sample(n);
            let alz = standard_to_alz(&bz(&d, 9)).unwrap();
            assert_eq!(&alz[..4], b"DLZ\x01");
            assert_eq!(decompress(&alz, Variant::Alz, n).unwrap(), d, "n={n}");
        }
    }

    #[test]
    fn corrupt_input_errors() {
        let d = sample(100_000);
        let mut c = bz(&d, 9);
        let mid = c.len() / 2;
        c[mid] ^= 0x55;
        assert!(decompress(&c, Variant::Standard, 0).is_err());
        c.truncate(mid);
        assert!(decompress(&c, Variant::Standard, 0).is_err());
    }
}
