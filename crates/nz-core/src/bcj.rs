//! x86 BCJ filter (7-Zip method `03 03 01 03`, xz filter `0x04`).
//!
//! Converts the relative targets of `E8` (CALL) and `E9` (JMP) instructions
//! into absolute addresses so repeated calls to the same function become
//! identical byte strings, which LZMA then matches. This is the classic
//! public-domain algorithm used by 7-Zip and xz; the output is byte-identical
//! to liblzma's x86 filter with start offset 0 (checked in the tests against
//! liblzma itself).
//!
//! NextZip runs the filter over a whole 7z folder in one pass, so the folder
//! can still be LZMA2-compressed in independent parallel segments: in 7z the
//! BCJ coder sits after LZMA2 and sees one continuous stream.

/// `true` for 0x00 and 0xFF, the only plausible high bytes of a near call.
#[inline]
fn test_ms_byte(b: u8) -> bool {
    b.wrapping_add(1) & 0xFE == 0
}

const MASK_TO_ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
const MASK_TO_BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

/// Filter `buf` in place as one complete stream starting at position 0.
/// The last four bytes are never converted (same as the streaming filters).
pub fn x86_convert(buf: &mut [u8], encoding: bool) {
    let size = buf.len();
    if size < 5 {
        return;
    }
    let mut prev_mask: u32 = 0;
    let mut prev_pos: u32 = 0u32.wrapping_sub(5);
    let limit = size - 5;
    let mut pos = 0usize;
    while pos <= limit {
        let b = buf[pos];
        if b != 0xE8 && b != 0xE9 {
            pos += 1;
            continue;
        }
        let now = pos as u32;
        let offset = now.wrapping_sub(prev_pos);
        prev_pos = now;
        if offset > 5 {
            prev_mask = 0;
        } else {
            for _ in 0..offset {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }
        let b4 = buf[pos + 4];
        if test_ms_byte(b4)
            && MASK_TO_ALLOWED[((prev_mask >> 1) & 7) as usize]
            && (prev_mask >> 1) < 0x10
        {
            let mut src = u32::from_le_bytes([buf[pos + 1], buf[pos + 2], buf[pos + 3], b4]);
            let at = now.wrapping_add(5);
            let mut dest;
            loop {
                dest = if encoding {
                    src.wrapping_add(at)
                } else {
                    src.wrapping_sub(at)
                };
                if prev_mask == 0 {
                    break;
                }
                let i = MASK_TO_BIT_NUMBER[(prev_mask >> 1) as usize];
                let hb = (dest >> (24 - i * 8)) as u8;
                if !test_ms_byte(hb) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - i * 8)) - 1);
            }
            buf[pos + 4] = !(((dest >> 24) & 1).wrapping_sub(1)) as u8;
            buf[pos + 1] = dest as u8;
            buf[pos + 2] = (dest >> 8) as u8;
            buf[pos + 3] = (dest >> 16) as u8;
            pos += 5;
            prev_mask = 0;
        } else {
            pos += 1;
            prev_mask |= 1;
            if test_ms_byte(b4) {
                prev_mask |= 0x10;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};

    /// Run liblzma's raw x86+LZMA2 encoder, then decode only the LZMA2 layer:
    /// the result is liblzma's BCJ output for `data`.
    fn liblzma_bcj(data: &[u8]) -> Vec<u8> {
        let opts = LzmaOptions::new_preset(0).unwrap();
        let mut f = Filters::new();
        f.x86();
        f.lzma2(&opts);
        let mut enc = Stream::new_raw_encoder(&f).unwrap();
        let mut packed = Vec::with_capacity(data.len() * 2 + 4096);
        loop {
            let st = enc
                .process_vec(
                    &data[enc.total_in() as usize..],
                    &mut packed,
                    Action::Finish,
                )
                .unwrap();
            if st == Status::StreamEnd {
                break;
            }
            packed.reserve(packed.capacity());
        }
        let mut f2 = Filters::new();
        f2.lzma2(&opts);
        let mut dec = Stream::new_raw_decoder(&f2).unwrap();
        let mut out = Vec::with_capacity(data.len() + 16);
        dec.process_vec(&packed, &mut out, Action::Finish).unwrap();
        out
    }

    fn sample() -> Vec<u8> {
        // The test binary itself is real x86-64 machine code.
        let mut v = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        v.truncate(3 << 20);
        // Plus adversarial E8/E9 patterns near the end.
        v.extend_from_slice(&[0xE8, 0, 0, 0, 0, 0xE9, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8, 1, 2]);
        v
    }

    #[test]
    fn matches_liblzma_and_roundtrips() {
        let data = sample();
        let mut mine = data.clone();
        x86_convert(&mut mine, true);
        assert_ne!(mine, data, "filter changed nothing");
        let theirs = liblzma_bcj(&data);
        assert_eq!(mine.len(), theirs.len());
        assert!(mine == theirs, "BCJ output differs from liblzma");
        x86_convert(&mut mine, false);
        assert!(mine == data);
    }

    #[test]
    fn tiny_inputs() {
        for n in 0..12 {
            let data: Vec<u8> = (0..n).map(|i| if i % 3 == 0 { 0xE8 } else { 0 }).collect();
            let mut v = data.clone();
            x86_convert(&mut v, true);
            assert!(v == liblzma_bcj(&data), "n={n}");
            x86_convert(&mut v, false);
            assert_eq!(v, data);
        }
    }
}
