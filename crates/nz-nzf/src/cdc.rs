//! FastCDC content-defined chunking (Xia et al. 2016, normalized chunking
//! level 2). Only the writer chunks; readers never need this, so chunk
//! boundaries are not part of the format. The gear table is derived from
//! BLAKE3 so the reference chunker is reproducible from the document.

use std::sync::OnceLock;

pub const MIN: usize = 16 * 1024;
pub const AVG: usize = 64 * 1024;
pub const MAX: usize = 256 * 1024;

/// `k` one-bits spread over the top of the word: bits 63, 60, 57, ...
const fn spread(k: u32) -> u64 {
    let mut m = 0u64;
    let mut i = 0;
    while i < k {
        m |= 1 << (63 - 3 * i);
        i += 1;
    }
    m
}

// Masks for AVG = 2^16 with normalization level 2: 18 and 14 one-bits.
const MASK_S: u64 = spread(18);
const MASK_L: u64 = spread(14);

/// `gear[i]` = first 8 bytes (LE) of BLAKE3("nz fastcdc gear" || i as u8).
pub fn gear() -> &'static [u64; 256] {
    static G: OnceLock<[u64; 256]> = OnceLock::new();
    G.get_or_init(|| {
        let mut g = [0u64; 256];
        for (i, v) in g.iter_mut().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(b"nz fastcdc gear");
            h.update(&[i as u8]);
            *v = u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().unwrap());
        }
        g
    })
}

/// Length of the next chunk at the start of `data` (`data.len()` when
/// `data` is shorter than MIN or no cut point is found before MAX).
pub fn cut(data: &[u8]) -> usize {
    let n = data.len();
    if n <= MIN {
        return n;
    }
    let g = gear();
    let end = n.min(MAX);
    let normal = AVG.min(end);
    let mut h: u64 = 0;
    let mut i = MIN;
    while i < normal {
        h = (h << 1).wrapping_add(g[data[i] as usize]);
        if h & MASK_S == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < end {
        h = (h << 1).wrapping_add(g[data[i] as usize]);
        if h & MASK_L == 0 {
            return i + 1;
        }
        i += 1;
    }
    end
}

/// Streaming chunker: feed bytes, take finished chunks.
#[derive(Default)]
pub struct Chunker {
    buf: Vec<u8>,
}

impl Chunker {
    /// Append `data` and return the chunks that are complete (at least MAX
    /// bytes of look-ahead, or a cut point found).
    pub fn push(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) {
        self.buf.extend_from_slice(data);
        let mut start = 0;
        while self.buf.len() - start >= MAX {
            let c = cut(&self.buf[start..]);
            out.push(self.buf[start..start + c].to_vec());
            start += c;
        }
        self.buf.drain(..start);
    }
    /// Flush the rest at end of input.
    pub fn finish(&mut self, out: &mut Vec<Vec<u8>>) {
        let mut start = 0;
        while start < self.buf.len() {
            let c = cut(&self.buf[start..]);
            out.push(self.buf[start..start + c].to_vec());
            start += c;
        }
        self.buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn masks_have_expected_bits() {
        assert_eq!(MASK_S.count_ones(), 18);
        assert_eq!(MASK_L.count_ones(), 14);
    }

    #[test]
    fn chunks_are_bounded_and_resync() {
        let data = lcg(4 << 20, 7);
        let mut c = Chunker::default();
        let mut a = Vec::new();
        for piece in data.chunks(100_000) {
            c.push(piece, &mut a);
        }
        c.finish(&mut a);
        assert_eq!(a.concat(), data);
        for ch in &a[..a.len() - 1] {
            assert!(ch.len() >= MIN && ch.len() <= MAX);
        }
        let avg = data.len() / a.len();
        assert!((32 * 1024..=128 * 1024).contains(&avg), "avg {avg}");
        // Insert bytes near the start: later boundaries re-synchronise.
        let mut d2 = data[..1000].to_vec();
        d2.extend_from_slice(b"inserted");
        d2.extend_from_slice(&data[1000..]);
        let mut b = Vec::new();
        let mut c2 = Chunker::default();
        c2.push(&d2, &mut b);
        c2.finish(&mut b);
        let set: std::collections::HashSet<_> = a.iter().collect();
        let shared = b.iter().filter(|x| set.contains(x)).count();
        assert!(shared + 3 >= a.len(), "shared {shared} of {}", a.len());
    }
}
