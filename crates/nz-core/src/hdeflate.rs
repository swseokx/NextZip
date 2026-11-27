//! Huffman-only raw Deflate encoder for already-compressed data.
//!
//! JAR and ZIP members are Deflate streams already: an LZ77 match finder finds
//! almost nothing in them, yet libdeflate still spends most of its time
//! searching. Re-coding the bytes with a per-block dynamic Huffman table
//! (no matches) keeps most of the small gain Deflate gets on such data at a
//! fraction of the cost. Blocks that would not shrink are emitted as stored
//! blocks.
//!
//! The output is a byte-aligned fragment in the same form as
//! [`crate::deflate`] chunks: when `last` is false it ends with an empty
//! stored block (the `Z_SYNC_FLUSH` marker) so more Deflate data can follow;
//! when `last` is true its final block carries `BFINAL`.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Input bytes per Deflate block (one Huffman table each).
pub const BLOCK: usize = 0xFFFF;
const MAX_BITS: usize = 15;
const MAX_CL_BITS: usize = 7;
/// Code-length alphabet order (RFC 1951, 3.2.7).
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    #[inline]
    fn put(&mut self, bits: u32, len: u32) {
        self.acc |= u64::from(bits) << self.n;
        self.n += len;
        if self.n >= 32 {
            self.out.extend_from_slice(&(self.acc as u32).to_le_bytes());
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    fn align(&mut self) {
        while self.n > 0 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n = self.n.saturating_sub(8);
        }
        self.acc = 0;
    }
}

/// Huffman code lengths for `freq`, limited to `max` bits. Symbols with zero
/// frequency get length 0; at least two symbols always get a code.
fn code_lengths(freq: &[u32], max: usize) -> Vec<u8> {
    let mut f: Vec<u32> = freq.to_vec();
    let used = f.iter().filter(|&&x| x > 0).count();
    if used < 2 {
        // Deflate decoders want a complete code; give two symbols a code.
        let mut have = used;
        for x in f.iter_mut() {
            if have >= 2 {
                break;
            }
            if *x == 0 {
                *x = 1;
                have += 1;
            }
        }
    }
    let syms: Vec<usize> = (0..f.len()).filter(|&i| f[i] > 0).collect();
    let n = syms.len();
    // Plain Huffman tree: nodes 0..n are leaves, the rest internal.
    let mut parent = vec![0usize; 2 * n];
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = syms
        .iter()
        .enumerate()
        .map(|(k, &s)| Reverse((u64::from(f[s]), k)))
        .collect();
    let mut next = n;
    while heap.len() > 1 {
        let Reverse((wa, a)) = heap.pop().expect("two nodes");
        let Reverse((wb, b)) = heap.pop().expect("two nodes");
        parent[a] = next;
        parent[b] = next;
        heap.push(Reverse((wa + wb, next)));
        next += 1;
    }
    let root = next - 1;
    let mut depth = vec![0usize; 2 * n];
    for k in (0..root).rev() {
        depth[k] = depth[parent[k]] + 1;
    }
    // Count codes per length, fold overflow into `max`, restore Kraft sum.
    let mut count = [0u32; 64];
    for k in 0..n {
        count[depth[k].min(63)] += 1;
    }
    for l in max + 1..64 {
        count[max] += count[l];
        count[l] = 0;
    }
    let mut total: u64 = (1..=max).map(|l| u64::from(count[l]) << (max - l)).sum();
    while total > 1 << max {
        count[max] -= 1;
        for l in (1..max).rev() {
            if count[l] != 0 {
                count[l] -= 1;
                count[l + 1] += 2;
                break;
            }
        }
        total -= 1;
    }
    // Shortest codes to the most frequent symbols.
    let mut order = syms.clone();
    order.sort_by_key(|&s| (Reverse(f[s]), s));
    let mut lens = vec![0u8; f.len()];
    let mut it = order.into_iter();
    for (l, &c) in count.iter().enumerate().take(max + 1).skip(1) {
        for _ in 0..c {
            let s = it.next().expect("as many codes as symbols");
            lens[s] = l as u8;
        }
    }
    lens
}

/// Canonical codes, bit-reversed for Deflate's LSB-first order.
fn codes(lens: &[u8]) -> Vec<u32> {
    let mut bl = [0u32; MAX_BITS + 2];
    for &l in lens {
        bl[l as usize] += 1;
    }
    bl[0] = 0;
    let mut next = [0u32; MAX_BITS + 2];
    let mut code = 0;
    for b in 1..=MAX_BITS + 1 {
        code = (code + bl[b - 1]) << 1;
        next[b] = code;
    }
    lens.iter()
        .map(|&l| {
            if l == 0 {
                return 0;
            }
            let c = next[l as usize];
            next[l as usize] += 1;
            c.reverse_bits() >> (32 - u32::from(l))
        })
        .collect()
}

/// Run-length encode code lengths with symbols 16/17/18: (symbol, extra).
fn rle(lens: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lens.len() {
        let l = lens[i];
        let mut run = 1;
        while i + run < lens.len() && lens[i + run] == l {
            run += 1;
        }
        let mut left = run;
        if l == 0 {
            while left >= 11 {
                let k = left.min(138);
                out.push((18, (k - 11) as u8));
                left -= k;
            }
            if left >= 3 {
                out.push((17, (left - 3) as u8));
                left = 0;
            }
        } else {
            out.push((l, 0));
            left -= 1;
            while left >= 3 {
                let k = left.min(6);
                out.push((16, (k - 3) as u8));
                left -= k;
            }
        }
        for _ in 0..left {
            out.push((l, 0));
        }
        i += run;
    }
    out
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const MIN_MATCH: usize = 4;
const MAX_MATCH: usize = 258;
const WINDOW: usize = 32 * 1024;
const HASH_BITS: u32 = 15;

/// A literal byte; a match ([`MATCH`] set, length - 3 in bits 16..24,
/// distance - 1 in bits 0..16); or a run of literals ([`RUN`] set, length
/// in bits 0..16) taken from the input in order.
type Token = u32;
const MATCH: u32 = 0x8000_0000;
const RUN: u32 = 0x4000_0000;

/// Add byte counts of `d` to `f` (four interleaved tables break the
/// store-to-load dependency on repeated bytes).
fn hist(d: &[u8], f: &mut [u32; 286]) {
    let mut t = [[0u32; 256]; 4];
    let (quads, rest) = d.as_chunks::<4>();
    for q in quads {
        t[0][q[0] as usize] += 1;
        t[1][q[1] as usize] += 1;
        t[2][q[2] as usize] += 1;
        t[3][q[3] as usize] += 1;
    }
    for &b in rest {
        t[0][b as usize] += 1;
    }
    for s in 0..256 {
        f[s] += t[0][s] + t[1][s] + t[2][s] + t[3][s];
    }
}

#[inline]
fn len_code(len: usize) -> usize {
    LEN_BASE.partition_point(|&b| usize::from(b) <= len) - 1
}

#[inline]
fn dist_code(dist: usize) -> usize {
    DIST_BASE.partition_point(|&b| usize::from(b) <= dist) - 1
}

/// One block covering `data` (or a stored block when that is smaller).
fn write_block(w: &mut BitWriter, data: &[u8], tokens: &[Token], last: bool) {
    let mut lf = [0u32; 286];
    let mut df = [0u32; 30];
    let mut p = 0usize;
    for &t in tokens {
        if t & RUN != 0 {
            let n = (t & 0xFFFF) as usize;
            hist(&data[p..p + n], &mut lf);
            p += n;
        } else if t & MATCH == 0 {
            lf[t as usize] += 1;
            p += 1;
        } else {
            p += ((t >> 16) & 0xFF) as usize + 3;
            lf[257 + len_code(((t >> 16) & 0xFF) as usize + 3)] += 1;
            df[dist_code((t & 0xFFFF) as usize + 1)] += 1;
        }
    }
    lf[256] = 1;
    let lit = code_lengths(&lf, MAX_BITS);
    let dist = code_lengths(&df, MAX_BITS);
    let hlit = (257..=286).rev().find(|&k| lit[k - 1] != 0).unwrap_or(257);
    let hdist = (1..=30).rev().find(|&k| dist[k - 1] != 0).unwrap_or(1);
    let mut all = lit[..hlit].to_vec();
    all.extend_from_slice(&dist[..hdist]);
    let r = rle(&all);
    let mut cf = [0u32; 19];
    for &(s, _) in &r {
        cf[s as usize] += 1;
    }
    let cl = code_lengths(&cf, MAX_CL_BITS);
    let hclen = (4..=19)
        .rev()
        .find(|&k| cl[CL_ORDER[k - 1]] != 0)
        .unwrap_or(4);
    let extra_bits = |s: u8| match s {
        16 => 2,
        17 => 3,
        18 => 7,
        _ => 0,
    };
    let header_bits: u64 = 3
        + 5
        + 5
        + 4
        + 3 * hclen as u64
        + r.iter()
            .map(|&(s, _)| u64::from(cl[s as usize]) + extra_bits(s))
            .sum::<u64>();
    let lit_bits: u64 = (0..286).map(|s| u64::from(lf[s]) * u64::from(lit[s])).sum();
    let len_extra: u64 = (0..29)
        .map(|c| u64::from(lf[257 + c]) * u64::from(LEN_EXTRA[c]))
        .sum();
    let dist_bits: u64 = (0..30)
        .map(|c| u64::from(df[c]) * (u64::from(dist[c]) + u64::from(DIST_EXTRA[c])))
        .sum();
    let dynamic = header_bits + lit_bits + len_extra + dist_bits;
    // Stored: 3 header bits, padding (up to 7), LEN/NLEN, the bytes.
    let stored = 3 + 7 + 32 + 8 * data.len() as u64;
    if dynamic >= stored {
        w.put(u32::from(last), 3);
        w.align();
        let len = data.len() as u16;
        w.out.extend_from_slice(&len.to_le_bytes());
        w.out.extend_from_slice(&(!len).to_le_bytes());
        w.out.extend_from_slice(data);
        return;
    }
    w.put(u32::from(last) | (2 << 1), 3);
    w.put((hlit - 257) as u32, 5);
    w.put((hdist - 1) as u32, 5);
    w.put(hclen as u32 - 4, 4);
    for &s in &CL_ORDER[..hclen] {
        w.put(u32::from(cl[s]), 3);
    }
    let cc = codes(&cl);
    for &(s, e) in &r {
        w.put(cc[s as usize], u32::from(cl[s as usize]));
        let eb = extra_bits(s) as u32;
        if eb > 0 {
            w.put(u32::from(e), eb);
        }
    }
    let lc = codes(&lit);
    let dc = codes(&dist);
    let table: Vec<(u32, u32)> = (0..286).map(|s| (lc[s], u32::from(lit[s]))).collect();
    let mut p = 0usize;
    for &t in tokens {
        if t & RUN != 0 {
            let n = (t & 0xFFFF) as usize;
            let run = &data[p..p + n];
            p += n;
            // Two codes (at most 15 bits each) per put.
            let (pairs, rest) = run.as_chunks::<2>();
            for q in pairs {
                let (c0, l0) = table[q[0] as usize];
                let (c1, l1) = table[q[1] as usize];
                w.put(c0 | (c1 << l0), l0 + l1);
            }
            for &b in rest {
                let (c, l) = table[b as usize];
                w.put(c, l);
            }
        } else if t & MATCH == 0 {
            let (c, l) = table[t as usize];
            w.put(c, l);
            p += 1;
        } else {
            let len = ((t >> 16) & 0xFF) as usize + 3;
            p += len;
            let lcode = len_code(len);
            let (c, l) = table[257 + lcode];
            w.put(c, l);
            if LEN_EXTRA[lcode] > 0 {
                w.put(
                    (len - usize::from(LEN_BASE[lcode])) as u32,
                    u32::from(LEN_EXTRA[lcode]),
                );
            }
            let d = (t & 0xFFFF) as usize + 1;
            let dcode = dist_code(d);
            w.put(dc[dcode], u32::from(dist[dcode]));
            if DIST_EXTRA[dcode] > 0 {
                w.put(
                    (d - usize::from(DIST_BASE[dcode])) as u32,
                    u32::from(DIST_EXTRA[dcode]),
                );
            }
        }
    }
    w.put(table[256].0, table[256].1);
}

#[inline]
fn hash4(d: &[u8], i: usize) -> usize {
    let v = u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// Deflate `data` as a byte-aligned fragment (see the module documentation
/// for `last`). Inside the sorted, disjoint `lz` ranges a greedy one-probe
/// hash match finder runs (file names in ZIP headers repeat a lot); all
/// other bytes are coded as literals without searching.
pub fn encode(data: &[u8], lz: &[std::ops::Range<usize>], last: bool) -> Vec<u8> {
    let mut w = BitWriter {
        out: Vec::with_capacity(data.len() + data.len() / 64 + 16),
        acc: 0,
        n: 0,
    };
    HEAD.with(|cell| {
        let (head, base) = &mut *cell.borrow_mut();
        // Entries below `base` belong to earlier calls: stale, never matched.
        if *base > u32::MAX as usize - data.len() - 2 * WINDOW {
            head.fill(0);
            *base = 0;
        }
        let b = *base + 1;
        *base += data.len() + 1;
        encode_with(&mut w, data, lz, last, head, b);
    });
    if !last {
        // Empty stored block: BFINAL=0, BTYPE=00, align, 00 00 FF FF.
        w.put(0, 3);
        w.align();
        w.out.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
    } else {
        w.align();
    }
    w.out
}

thread_local! {
    /// Reused hash heads (absolute position + 1) and the next call's base.
    static HEAD: std::cell::RefCell<(Vec<u32>, usize)> =
        std::cell::RefCell::new((vec![0; 1 << HASH_BITS], 0));
}

/// Length of the common prefix of `d[a..]` and `d[b..]`, at most `max`.
#[inline]
fn match_len(d: &[u8], a: usize, b: usize, max: usize) -> usize {
    let mut n = 0;
    while n + 8 <= max {
        let x = u64::from_le_bytes(d[a + n..a + n + 8].try_into().expect("8 bytes"))
            ^ u64::from_le_bytes(d[b + n..b + n + 8].try_into().expect("8 bytes"));
        if x != 0 {
            return n + (x.trailing_zeros() / 8) as usize;
        }
        n += 8;
    }
    while n < max && d[a + n] == d[b + n] {
        n += 1;
    }
    n
}

/// Body of [`encode`]: all blocks, without the closing marker. `head` holds
/// `base + position` for this call (values below `base` are stale).
fn encode_with(
    w: &mut BitWriter,
    data: &[u8],
    lz: &[std::ops::Range<usize>],
    last: bool,
    head: &mut [u32],
    base: usize,
) {
    let mut tokens: Vec<Token> = Vec::with_capacity(BLOCK.min(data.len()) / 4 + 16);
    let mut block_start = 0usize;
    let mut pos = 0usize;
    let mut ri = 0usize;
    // Blocks end at a token boundary once they span this much input, so a
    // stored fallback always fits in one stored block.
    let limit = BLOCK - MAX_MATCH;
    let hash_end = (data.len() + 1).saturating_sub(MIN_MATCH);
    while pos < data.len() {
        while ri < lz.len() && lz[ri].end <= pos {
            ri += 1;
        }
        let in_lz = ri < lz.len() && lz[ri].start <= pos;
        let block_end = (block_start + limit).min(data.len());
        if !in_lz {
            // Literal run up to the next LZ range or the block limit.
            let stop = lz.get(ri).map_or(data.len(), |r| r.start);
            let stop = stop.min(block_end).max(pos + 1);
            tokens.push(RUN | (stop - pos) as u32);
            pos = stop;
        } else {
            // Greedy matching to the end of this range or block; literals
            // between matches become one run token. Misses speed up the
            // scan (data without matches is passed over quickly).
            let stop = lz[ri].end.min(block_end).min(hash_end);
            let mut lit = pos;
            let mut miss = 0usize;
            while pos < stop {
                let h = hash4(data, pos);
                let cand = head[h] as usize;
                head[h] = (base + pos) as u32;
                let len = if cand >= base && pos - (cand - base) <= WINDOW {
                    let max = (data.len() - pos).min(MAX_MATCH);
                    match_len(data, cand - base, pos, max)
                } else {
                    0
                };
                if len >= MIN_MATCH {
                    if pos > lit {
                        tokens.push(RUN | (pos - lit) as u32);
                    }
                    let dist = pos - (cand - base);
                    tokens.push(MATCH | (((len - 3) as u32) << 16) | (dist - 1) as u32);
                    for i in pos + 1..(pos + len).min(hash_end) {
                        head[hash4(data, i)] = (base + i) as u32;
                    }
                    pos += len;
                    lit = pos;
                    miss = 0;
                } else {
                    miss += 1;
                    pos = (pos + 1 + (miss >> 6)).min(stop);
                }
            }
            // A match may run past the range; bytes too close to the end of
            // the data to hash are literals.
            let end = pos.max(lz[ri].end.min(block_end));
            if end > lit {
                tokens.push(RUN | (end - lit) as u32);
            }
            pos = end;
        }
        if pos - block_start >= limit && pos < data.len() {
            write_block(w, &data[block_start..pos], &tokens, false);
            tokens.clear();
            block_start = pos;
        }
    }
    write_block(w, &data[block_start..], &tokens, last);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::inflate_exact;

    fn noise(len: usize, mut s: u64) -> Vec<u8> {
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
    fn roundtrip_various() {
        let skewed: Vec<u8> = noise(300_000, 3).iter().map(|b| b & 0x1F).collect();
        let text = "hello huffman only deflate\n".repeat(9000).into_bytes();
        for data in [
            Vec::new(),
            vec![7u8],
            vec![0u8; 70_000],
            noise(200_000, 1),
            skewed,
            text,
        ] {
            let enc = encode(&data, &[], true);
            assert_eq!(inflate_exact(&enc, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn lz_roundtrip_and_shrinks() {
        let text = "com/example/pkg/SomeClass$Inner.class META-INF\n"
            .repeat(5000)
            .into_bytes();
        let all = [std::ops::Range {
            start: 0,
            end: text.len(),
        }];
        let enc = encode(&text, &all, true);
        assert!(enc.len() < text.len() / 20, "{}", enc.len());
        assert_eq!(inflate_exact(&enc, text.len()).unwrap(), text);
        // Long runs (max-length matches at distance 1) and partial ranges.
        let mut d = vec![0u8; 200_000];
        d.extend(noise(100_000, 4));
        d.extend_from_slice(&text);
        d.extend(vec![b'x'; 70_001]);
        let lz = [
            0..90_000,
            150_000..150_003,
            250_000..260_000,
            300_000..d.len(),
        ];
        for last in [true, false] {
            let mut enc = encode(&d, &lz, last);
            if !last {
                enc.extend_from_slice(&crate::deflate::deflate_chunk(1, b"tail", true).unwrap());
            }
            let mut want = d.clone();
            if !last {
                want.extend_from_slice(b"tail");
            }
            assert_eq!(inflate_exact(&enc, want.len()).unwrap(), want);
        }
    }

    #[test]
    fn container_roundtrip() {
        use crate::deflate::{RunKind, container_runs, deflate_container};
        // A small JAR-like image: deflated members, a stored one, a CD tail.
        let mut img = Vec::new();
        for i in 0..300u32 {
            let name = format!("com/example/pkg/Class{i}.class");
            let (method, body): (u16, Vec<u8>) = if i % 50 == 7 {
                (0, "stored text body\n".repeat(400).into_bytes())
            } else {
                (8, noise(300 + (i as usize * 37) % 2000, u64::from(i) + 1))
            };
            img.extend_from_slice(b"PK\x03\x04");
            img.extend_from_slice(&[20, 0, 0, 0]);
            img.extend_from_slice(&method.to_le_bytes());
            img.extend_from_slice(&[0; 8]);
            img.extend_from_slice(&(body.len() as u32).to_le_bytes());
            img.extend_from_slice(&(body.len() as u32).to_le_bytes());
            img.extend_from_slice(&(name.len() as u16).to_le_bytes());
            img.extend_from_slice(&[0, 0]);
            img.extend_from_slice(name.as_bytes());
            img.extend_from_slice(&body);
        }
        img.extend_from_slice(&"PK\x01\x02central directory".repeat(300).into_bytes());
        let runs = container_runs(&img);
        assert!(runs.iter().any(|(k, _)| *k == RunKind::Packed));
        assert!(runs.iter().any(|(k, _)| *k == RunKind::Lib));
        for (chunk, par) in [(BLOCK, true), (1 << 20, false)] {
            let d = deflate_container(&img, 6, chunk, par).unwrap();
            assert_eq!(inflate_exact(&d.data, img.len()).unwrap(), img);
            assert_eq!(d.crc32, crc32fast::hash(&img));
        }
    }

    #[test]
    fn fragment_splices_with_libdeflate() {
        let a: Vec<u8> = noise(150_000, 5).iter().map(|b| b % 40).collect();
        let b = "central directory entry name.class\n"
            .repeat(4000)
            .into_bytes();
        let mut s = encode(&a, &[], false);
        s.extend_from_slice(&crate::deflate::deflate_chunk(1, &b, true).unwrap());
        let mut want = a.clone();
        want.extend_from_slice(&b);
        assert_eq!(inflate_exact(&s, want.len()).unwrap(), want);
    }

    #[test]
    fn skewed_data_shrinks_and_noise_is_stored() {
        let skewed: Vec<u8> = noise(BLOCK, 9).iter().map(|b| b & 0x0F).collect();
        assert!(encode(&skewed, &[], true).len() < skewed.len() * 6 / 10);
        let n = noise(BLOCK, 11);
        assert!(encode(&n, &[], true).len() <= n.len() + 16);
    }

    #[test]
    fn lengths_are_limited_and_complete() {
        // Fibonacci-like frequencies force long codes.
        let mut f = vec![0u32; 257];
        let (mut a, mut b) = (1u32, 1u32);
        for x in f.iter_mut().take(30) {
            *x = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        let l = code_lengths(&f, MAX_BITS);
        assert!(l.iter().all(|&x| (x as usize) <= MAX_BITS));
        let kraft: f64 = l
            .iter()
            .filter(|&&x| x > 0)
            .map(|&x| 0.5f64.powi(i32::from(x)))
            .sum();
        assert!((kraft - 1.0).abs() < 1e-9);
    }
}
