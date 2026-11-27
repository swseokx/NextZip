//! Block-parallel raw Deflate (pigz-style) on top of libdeflate.
//!
//! libdeflate only offers one-shot compression, so every chunk comes out as a
//! complete Deflate stream whose last block has `BFINAL = 1` and ends at an
//! arbitrary bit position. To splice chunks into one standard stream we
//!
//! 1. scan the chunk's block structure ([`scan_blocks`]) to find the header of
//!    the final block and the exact bit where its end-of-block code ends,
//! 2. clear that `BFINAL` bit, and
//! 3. append an empty stored block (`000` + byte align + `00 00 FF FF`), the
//!    same marker zlib's `Z_SYNC_FLUSH` emits, so the next chunk starts on a
//!    byte boundary.
//!
//! The last chunk is left untouched. Any standard inflater (zlib, Windows
//! shell, 7-Zip) decodes the result as a single Deflate stream.
//!
//! libdeflate has no preset-dictionary API, so chunks do not share a 32 KiB
//! window with their predecessor. This costs a little ratio on large files
//! (see `bench/results`); the chunk size is configurable to trade parallelism
//! against ratio.

use std::cell::RefCell;

use anyhow::{Result, anyhow, bail};
use libdeflater::{CompressionLvl, Compressor, Decompressor};
use rayon::prelude::*;

/// Default chunk size for intra-file parallelism.
pub const DEFAULT_CHUNK: usize = 128 * 1024;

thread_local! {
    static COMPRESSOR: RefCell<Option<(i32, Compressor)>> = const { RefCell::new(None) };
}

fn with_compressor<T>(level: i32, f: impl FnOnce(&mut Compressor) -> T) -> T {
    COMPRESSOR.with(|cell| {
        let mut slot = cell.borrow_mut();
        let reuse = matches!(slot.as_ref(), Some((l, _)) if *l == level);
        if !reuse {
            let lvl = CompressionLvl::new(level).unwrap_or_default();
            *slot = Some((level, Compressor::new(lvl)));
        }
        f(&mut slot.as_mut().expect("compressor initialised").1)
    })
}

/// Compress one chunk. `last == false` makes the output a non-final,
/// byte-aligned fragment that can be followed by more Deflate data.
pub fn deflate_chunk(level: i32, data: &[u8], last: bool) -> Result<Vec<u8>> {
    let mut out = with_compressor(level, |c| -> Result<Vec<u8>> {
        let bound = c.deflate_compress_bound(data.len());
        let mut out = vec![0u8; bound];
        let n = c
            .deflate_compress(data, &mut out)
            .map_err(|e| anyhow!("libdeflate compress failed: {e:?}"))?;
        out.truncate(n);
        Ok(out)
    })?;
    if !last {
        make_nonfinal(&mut out)?;
    }
    Ok(out)
}

/// Result of compressing a whole buffer.
pub struct Deflated {
    pub data: Vec<u8>,
    pub crc32: u32,
}

/// Compress `data` as one raw Deflate stream, splitting it into `chunk`-sized
/// pieces that are compressed in parallel on the current Rayon pool.
/// The output depends only on `(data, level, chunk)`, never on thread count.
pub fn deflate_parallel(data: &[u8], level: i32, chunk: usize) -> Result<Deflated> {
    let chunk = chunk.max(4096);
    if data.len() <= chunk {
        return Ok(Deflated {
            data: deflate_chunk(level, data, true)?,
            crc32: crc32fast::hash(data),
        });
    }
    let n = data.len().div_ceil(chunk);
    let parts: Vec<Result<(Vec<u8>, u32, usize)>> = data
        .par_chunks(chunk)
        .enumerate()
        .map(|(i, piece)| {
            let comp = deflate_chunk(level, piece, i + 1 == n)?;
            Ok((comp, crc32fast::hash(piece), piece.len()))
        })
        .collect();
    let mut total = 0;
    let mut parts_ok = Vec::with_capacity(n);
    for p in parts {
        let p = p?;
        total += p.0.len();
        parts_ok.push(p);
    }
    let mut out = Vec::with_capacity(total);
    let mut crc = crc32fast::Hasher::new();
    for (comp, c, len) in parts_ok {
        out.extend_from_slice(&comp);
        crc.combine(&crc32fast::Hasher::new_with_initial_len(c, len as u64));
    }
    Ok(Deflated {
        data: out,
        crc32: crc.finalize(),
    })
}

/// Stored (method 0) members at least this large go through libdeflate;
/// smaller ones are LZ-coded by [`crate::hdeflate`] with the headers.
const CONTAINER_LZ_MIN: usize = 4 * 1024;
/// Compressed members smaller than this are LZ-coded too: on the M1 mixed
/// set this recovered ~90 KB over literal-only coding for ~10% more time.
const CONTAINER_LZ_SMALL: usize = 1024;

/// How a run of a ZIP/JAR image is coded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunKind {
    /// Headers and small members: own encoder, greedy LZ (names repeat).
    Header,
    /// Larger already-compressed member data: own encoder, literals only.
    Packed,
    /// Larger stored members and the central directory: libdeflate.
    Lib,
}

/// Split a ZIP/JAR image into coding runs (see [`RunKind`]). Anything from
/// the first local header that cannot be sized onward is [`RunKind::Lib`].
pub fn container_runs(data: &[u8]) -> Vec<(RunKind, std::ops::Range<usize>)> {
    let le16 = |o: usize| usize::from(u16::from_le_bytes([data[o], data[o + 1]]));
    let le32 = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let mut runs: Vec<(RunKind, std::ops::Range<usize>)> = Vec::new();
    let mut push = |k: RunKind, r: std::ops::Range<usize>| {
        if r.is_empty() {
            return;
        }
        match runs.last_mut() {
            Some((l, last)) if *l == k && last.end == r.start => last.end = r.end,
            _ => runs.push((k, r)),
        }
    };
    // Streamed archives (flag bit 3) leave sizes out of the local headers;
    // the central directory has them, keyed by local header offset.
    let cd_sizes = central_sizes(data);
    let mut p = 0usize;
    while p + 30 <= data.len() && data[p..p + 4] == *b"PK\x03\x04" {
        let flags = le16(p + 6);
        let method = le16(p + 8);
        let mut csize = le32(p + 18);
        if flags & 8 != 0 && csize == 0 {
            match cd_sizes.binary_search_by_key(&p, |&(o, _)| o) {
                Ok(k) => csize = cd_sizes[k].1,
                Err(_) => break,
            }
        }
        if csize == u32::MAX {
            break;
        }
        let start = p + 30 + le16(p + 26) + le16(p + 28);
        let Some(end) = start
            .checked_add(csize as usize)
            .filter(|&e| e <= data.len())
        else {
            break;
        };
        push(RunKind::Header, p..start);
        let kind = match method {
            0 if end - start >= CONTAINER_LZ_MIN => RunKind::Lib,
            0 => RunKind::Header,
            _ if end - start < CONTAINER_LZ_SMALL => RunKind::Header,
            _ => RunKind::Packed,
        };
        push(kind, start..end);
        p = end;
        if flags & 8 != 0 {
            let sig = p + 4 <= data.len() && data[p..p + 4] == *b"PK\x07\x08";
            let q = (p + if sig { 16 } else { 12 }).min(data.len());
            push(RunKind::Header, p..q);
            p = q;
        }
    }
    push(RunKind::Lib, p..data.len());
    runs
}

/// (local header offset, compressed size) of every central directory entry,
/// sorted by offset; empty when there is no usable (non-ZIP64) directory.
fn central_sizes(data: &[u8]) -> Vec<(usize, u32)> {
    let le16 = |o: usize| usize::from(u16::from_le_bytes([data[o], data[o + 1]]));
    let le32 = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    if data.len() < 22 {
        return Vec::new();
    }
    let lo = data.len().saturating_sub(22 + 0xFFFF);
    let Some(e) = (lo..=data.len() - 22)
        .rev()
        .find(|&i| data[i..i + 4] == *b"PK\x05\x06")
    else {
        return Vec::new();
    };
    let count = le16(e + 10);
    let (size, off) = (le32(e + 12) as usize, le32(e + 16) as usize);
    if off.checked_add(size).is_none_or(|end| end > e) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count);
    let mut q = off;
    for _ in 0..count {
        if q + 46 > e || data[q..q + 4] != *b"PK\x01\x02" {
            return Vec::new();
        }
        out.push((le32(q + 42) as usize, le32(q + 20)));
        q += 46 + le16(q + 28) + le16(q + 30) + le16(q + 32);
    }
    out.sort_unstable();
    out
}

/// One independently encoded piece of a container.
enum Piece {
    Lib(std::ops::Range<usize>),
    /// Range, plus the LZ sub-ranges relative to its start.
    Own(std::ops::Range<usize>, Vec<std::ops::Range<usize>>),
}

/// Deflate a ZIP-family container: headers and already-compressed member
/// data go through the own encoder ([`crate::hdeflate`]: LZ on headers,
/// literals on packed data), larger stored members and the central
/// directory through libdeflate at `level`. Pieces are at most `chunk`
/// bytes and `par` encodes them in parallel. One standard raw Deflate
/// stream comes out; it depends only on the arguments.
pub fn deflate_container(data: &[u8], level: i32, chunk: usize, par: bool) -> Result<Deflated> {
    let chunk = chunk.max(crate::hdeflate::BLOCK);
    let mut pieces: Vec<Piece> = Vec::new();
    let mut own: Option<(usize, Vec<std::ops::Range<usize>>)> = None;
    let flush = |own: &mut Option<(usize, Vec<std::ops::Range<usize>>)>,
                 end: usize,
                 pieces: &mut Vec<Piece>| {
        if let Some((s, lz)) = own.take() {
            pieces.push(Piece::Own(s..end, lz));
        }
    };
    for (k, r) in container_runs(data) {
        let mut a = r.start;
        while a < r.end {
            if k == RunKind::Lib {
                flush(&mut own, a, &mut pieces);
                let e = r.end.min(a + chunk);
                pieces.push(Piece::Lib(a..e));
                a = e;
                continue;
            }
            let s = own.get_or_insert_with(|| (a, Vec::new())).0;
            let e = r.end.min(s + chunk);
            if k == RunKind::Header {
                own.as_mut().expect("open piece").1.push(a - s..e - s);
            }
            a = e;
            if a == s + chunk {
                flush(&mut own, a, &mut pieces);
            }
        }
    }
    flush(&mut own, data.len(), &mut pieces);
    if pieces.is_empty() {
        pieces.push(Piece::Lib(0..0));
    }
    let n = pieces.len();
    let enc = |(i, p): (usize, &Piece)| -> Result<Vec<u8>> {
        let last = i + 1 == n;
        match p {
            Piece::Lib(r) => deflate_chunk(level, &data[r.clone()], last),
            Piece::Own(r, lz) => Ok(crate::hdeflate::encode(&data[r.clone()], lz, last)),
        }
    };
    let parts: Vec<Result<Vec<u8>>> = if par {
        pieces.par_iter().enumerate().map(enc).collect()
    } else {
        pieces.iter().enumerate().map(enc).collect()
    };
    let mut out = Vec::with_capacity(data.len() + 64);
    for p in parts {
        out.extend_from_slice(&p?);
    }
    Ok(Deflated {
        data: out,
        crc32: crc32fast::hash(data),
    })
}

/// Inflate a raw Deflate stream whose decompressed size is known.
pub fn inflate_exact(data: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    inflate_into(data, size, &mut out)?;
    out.truncate(size);
    Ok(out)
}

thread_local! {
    static DECOMPRESSOR: RefCell<Option<Decompressor>> = const { RefCell::new(None) };
}

/// [`inflate_exact`] into `out[..size]`, reusing `out`'s memory: `out` grows
/// to at least `size` bytes and only its first `size` bytes are meaningful
/// afterwards. Extraction threads keep one buffer each, so decoding a member
/// does not fault in fresh pages for every file.
pub fn inflate_into(data: &[u8], size: usize, out: &mut Vec<u8>) -> Result<()> {
    // Deflate expands at most ~1032:1 (258-byte matches in 2-bit codes), so
    // a larger claimed size is corrupt; refusing it here keeps a forged
    // header from allocating gigabytes.
    if size as u64 > data.len() as u64 * 1040 + 1024 {
        bail!(
            "inflate size {size} impossible for {} input bytes",
            data.len()
        );
    }
    if out.len() < size {
        out.resize(size, 0);
    }
    let n = DECOMPRESSOR.with(|cell| {
        cell.borrow_mut()
            .get_or_insert_with(Decompressor::new)
            .deflate_decompress(data, &mut out[..size])
            .map_err(|e| anyhow!("inflate failed: {e:?}"))
    })?;
    if n != size {
        bail!("inflate size mismatch: got {n}, expected {size}");
    }
    Ok(())
}

/// Turn a complete Deflate stream into a non-final, byte-aligned fragment.
fn make_nonfinal(buf: &mut Vec<u8>) -> Result<()> {
    let info = scan_blocks(buf)?;
    let hdr = info.final_header_bit;
    buf[hdr / 8] &= !(1u8 << (hdr % 8));
    let end = info.end_bit;
    buf.truncate(end.div_ceil(8));
    let used = end % 8;
    if used != 0 {
        // Zero any padding bits after the end-of-block code.
        let last = buf.len() - 1;
        buf[last] &= (1u8 << used) - 1;
    }
    // Empty stored block header: BFINAL=0, BTYPE=00 (3 zero bits), then align.
    if used == 0 || used > 5 {
        buf.push(0);
    }
    buf.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
    Ok(())
}

/// Block layout of a complete Deflate stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockScan {
    /// Bit offset of the header (BFINAL bit) of the final block.
    pub final_header_bit: usize,
    /// Bit offset just past the final block's end-of-block code.
    pub end_bit: usize,
    /// Number of blocks in the stream.
    pub blocks: usize,
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BitReader<'_> {
    #[inline]
    fn peek(&self, n: u32) -> u32 {
        let byte = self.pos >> 3;
        // Fast path: one unaligned 8-byte load (n <= 25 bits always fits).
        let v = match self.data.get(byte..byte + 8) {
            Some(b) => u64::from_le_bytes(b.try_into().expect("8 bytes")),
            None => {
                let mut v: u64 = 0;
                for i in 0..8 {
                    v |= u64::from(self.data.get(byte + i).copied().unwrap_or(0)) << (8 * i);
                }
                v
            }
        };
        ((v >> (self.pos & 7)) & ((1u64 << n) - 1)) as u32
    }
    #[inline]
    fn bits(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.pos += n as usize;
        v
    }
    fn check(&self) -> Result<()> {
        if self.pos > self.data.len() * 8 {
            bail!("deflate stream truncated");
        }
        Ok(())
    }
}

struct Huffman {
    table: Vec<u16>, // (symbol << 4) | length, indexed by bit-reversed code
    max_len: u32,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self> {
        let max_len = u32::from(lengths.iter().copied().max().unwrap_or(0));
        let mut count = [0u16; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..16 {
            code = (code + u32::from(count[bits - 1])) << 1;
            next[bits] = code;
        }
        let size = 1usize << max_len;
        let mut table = vec![0u16; size];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = u32::from(l);
            let c = next[l as usize];
            next[l as usize] += 1;
            if c >= (1 << l) {
                bail!("over-subscribed Huffman code");
            }
            let rev = (c.reverse_bits() >> (32 - l)) as usize;
            let entry = ((sym as u16) << 4) | l as u16;
            let mut i = rev;
            while i < size {
                table[i] = entry;
                i += 1 << l;
            }
        }
        Ok(Self { table, max_len })
    }

    #[inline]
    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16> {
        if self.max_len == 0 {
            bail!("symbol from empty Huffman code");
        }
        let e = self.table[br.peek(self.max_len) as usize];
        let l = u32::from(e & 15);
        if l == 0 {
            bail!("invalid Huffman code");
        }
        br.pos += l as usize;
        Ok(e >> 4)
    }
}

const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Walk the block structure of a raw Deflate stream without producing output.
pub fn scan_blocks(data: &[u8]) -> Result<BlockScan> {
    let mut br = BitReader { data, pos: 0 };
    let mut blocks = 0;
    let fixed = {
        let mut l = [0u8; 288];
        l[..144].fill(8);
        l[144..256].fill(9);
        l[256..280].fill(7);
        l[280..].fill(8);
        (Huffman::new(&l)?, Huffman::new(&[5u8; 30])?)
    };
    loop {
        let header = br.pos;
        let bfinal = br.bits(1);
        let btype = br.bits(2);
        blocks += 1;
        match btype {
            0 => {
                br.pos = br.pos.div_ceil(8) * 8;
                let len = br.bits(16);
                let nlen = br.bits(16);
                if len != (!nlen & 0xFFFF) {
                    bail!("stored block length mismatch");
                }
                br.pos += len as usize * 8;
            }
            1 => scan_codes(&mut br, &fixed.0, &fixed.1)?,
            2 => {
                let hlit = br.bits(5) as usize + 257;
                let hdist = br.bits(5) as usize + 1;
                let hclen = br.bits(4) as usize + 4;
                let mut cl = [0u8; 19];
                for &idx in &CLEN_ORDER[..hclen] {
                    cl[idx] = br.bits(3) as u8;
                }
                let clh = Huffman::new(&cl)?;
                let mut lens = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < lens.len() {
                    let sym = clh.decode(&mut br)?;
                    let (val, rep) = match sym {
                        0..=15 => (sym as u8, 1),
                        16 => {
                            if i == 0 {
                                bail!("repeat with no previous length");
                            }
                            (lens[i - 1], 3 + br.bits(2) as usize)
                        }
                        17 => (0, 3 + br.bits(3) as usize),
                        18 => (0, 11 + br.bits(7) as usize),
                        _ => bail!("bad code-length symbol"),
                    };
                    if i + rep > lens.len() {
                        bail!("code lengths overflow");
                    }
                    lens[i..i + rep].fill(val);
                    i += rep;
                }
                let lit = Huffman::new(&lens[..hlit])?;
                let dist = Huffman::new(&lens[hlit..])?;
                scan_codes(&mut br, &lit, &dist)?;
            }
            _ => bail!("reserved block type"),
        }
        br.check()?;
        if bfinal == 1 {
            return Ok(BlockScan {
                final_header_bit: header,
                end_bit: br.pos,
                blocks,
            });
        }
    }
}

fn scan_codes(br: &mut BitReader<'_>, lit: &Huffman, dist: &Huffman) -> Result<()> {
    loop {
        let sym = lit.decode(br)?;
        match sym {
            0..=255 => {}
            256 => return Ok(()),
            257..=285 => {
                br.pos += LEN_EXTRA[(sym - 257) as usize] as usize;
                let d = dist.decode(br)?;
                if d >= 30 {
                    bail!("bad distance symbol");
                }
                br.pos += DIST_EXTRA[d as usize] as usize;
            }
            _ => bail!("bad literal/length symbol"),
        }
        if br.pos > br.data.len() * 8 {
            bail!("deflate stream truncated");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A size no Deflate stream of this length can reach is refused before
    /// the output buffer is allocated (EGG fuzz OOM: 4 GiB claimed).
    #[test]
    fn inflate_exact_rejects_impossible_size() {
        let err = inflate_exact(&[3, 0], 4 << 30).unwrap_err();
        assert!(err.to_string().contains("impossible"), "{err}");
        // Highest-ratio real stream still decodes: 1 MiB of zeros.
        let zeros = vec![0u8; 1 << 20];
        let mut c = Compressor::new(CompressionLvl::best());
        let mut buf = vec![0u8; c.deflate_compress_bound(zeros.len())];
        let n = c.deflate_compress(&zeros, &mut buf).unwrap();
        assert_eq!(inflate_exact(&buf[..n], zeros.len()).unwrap(), zeros);
    }

    fn sample(len: usize, seed: u64) -> Vec<u8> {
        // Semi-compressible text-like data.
        let words = [
            "alpha ", "beta ", "gamma ", "delta\n", "<tag>", "</tag>", "0x1F ", "lorem ",
        ];
        let mut s = seed;
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            if s >> 60 == 0 {
                v.push((s >> 32) as u8);
            } else {
                v.extend_from_slice(words[(s >> 61) as usize].as_bytes());
            }
        }
        v.truncate(len);
        v
    }

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as u8
            })
            .collect()
    }

    #[test]
    fn scan_matches_libdeflate_output_length() {
        for level in [1, 6, 9, 12] {
            for data in [
                sample(300_000, 1),
                noise(200_000, 2),
                Vec::new(),
                b"a".to_vec(),
            ] {
                let out = deflate_chunk(level, &data, true).unwrap();
                let s = scan_blocks(&out).unwrap();
                assert_eq!(s.end_bit.div_ceil(8), out.len(), "level {level}");
                assert_eq!(
                    out[s.final_header_bit / 8] >> (s.final_header_bit % 8) & 1,
                    1
                );
            }
        }
    }

    #[test]
    fn parallel_stream_roundtrips() {
        let mut data = sample(1_000_003, 7);
        data.extend(noise(150_000, 3));
        data.extend(sample(77_777, 9));
        for chunk in [4096, 65536, DEFAULT_CHUNK, 1 << 20] {
            for level in [1, 6, 12] {
                let d = deflate_parallel(&data, level, chunk).unwrap();
                assert_eq!(d.crc32, crc32fast::hash(&data));
                let back = inflate_exact(&d.data, data.len()).unwrap();
                assert!(back == data, "chunk {chunk} level {level}");
            }
        }
    }

    #[test]
    fn nonfinal_fragment_is_byte_aligned_sync_marker() {
        let data = sample(50_000, 5);
        let frag = deflate_chunk(6, &data, false).unwrap();
        assert_eq!(&frag[frag.len() - 4..], &[0, 0, 0xFF, 0xFF]);
        // A fragment followed by an empty final stored block is a valid stream.
        let mut s = frag.clone();
        s.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
        assert_eq!(inflate_exact(&s, data.len()).unwrap(), data);
    }

    #[test]
    fn output_is_independent_of_thread_count() {
        let data = sample(2_000_000, 11);
        let run = |t| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(t)
                .build()
                .unwrap()
                .install(|| deflate_parallel(&data, 6, DEFAULT_CHUNK).unwrap().data)
        };
        let a = run(1);
        assert_eq!(a, run(3));
        assert_eq!(a, run(8));
    }

    #[test]
    fn scan_rejects_garbage() {
        assert!(scan_blocks(&[0xFF, 0xFF, 0xFF]).is_err());
        assert!(scan_blocks(&[]).is_err());
    }
}
