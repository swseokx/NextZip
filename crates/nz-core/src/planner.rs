//! Work planner (draft): decides per file whether compressing is worth it.
//!
//! A [`SAMPLE`]-byte budget is trial-compressed with LZ4 (fast mode). If the
//! sample does not shrink below [`STORE_THRESHOLD`] of its size, the file is
//! treated as already compressed (JPEG, MP4, zlib blobs, ...) and stored.
//!
//! M0 finding: sampling only the first 64 KiB misclassifies container files
//! such as JAR/ZIP, whose head is compressed entries but whose tail (central
//! directory, stored resources) still compresses: on the mixed benchmark set
//! this lost 2.7 percentage points of ZIP ratio. The planner therefore splits
//! the budget into three windows (head, middle, tail) and stores a file only
//! when *every* window is incompressible. When most (but not all) windows are
//! incompressible the file is [`Plan::Fast`]: still compressed, but with a
//! cheap setting, because high levels gain almost nothing on such data
//! (JARs: zstd 19 vs 9 = 0.3 pp for 7x the time).

use std::fs::File;
use std::path::Path;

use serde::Serialize;

/// Total bytes sampled per file.
pub const SAMPLE: usize = 64 * 1024;
/// Compressed/original ratio above which a window counts as incompressible.
pub const STORE_THRESHOLD: f64 = 0.97;
/// Files smaller than this are always compressed (sampling is not worth it).
pub const MIN_SAMPLE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Plan {
    /// Normal data: use the requested level.
    Compress,
    /// Mostly already-compressed data with some redundancy: use a fast level.
    Fast,
    /// Incompressible: store (ZIP) or put in the fastest frame (tar.zst).
    Store,
}

/// LZ4 (fast) compressed/original ratio of `data`.
pub fn lz4_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    match lz4::block::compress(data, Some(lz4::block::CompressionMode::FAST(1)), false) {
        Ok(c) => c.len() as f64 / data.len() as f64,
        Err(_) => 0.0,
    }
}

/// Byte ranges sampled from a file of `len` bytes.
pub fn windows(len: u64) -> Vec<(u64, usize)> {
    let budget = SAMPLE as u64;
    if len <= budget {
        return vec![(0, len as usize)];
    }
    let w = budget / 3;
    vec![
        (0, w as usize),
        (len / 2 - w / 2, w as usize),
        (len - w, w as usize),
    ]
}

fn decide(samples: &[&[u8]], total: u64) -> Plan {
    if total < MIN_SAMPLE as u64 {
        return Plan::Compress;
    }
    let hard = samples
        .iter()
        .filter(|s| lz4_ratio(s) > STORE_THRESHOLD)
        .count();
    if hard == samples.len() {
        Plan::Store
    } else if samples.len() >= 3 && hard >= 2 {
        Plan::Fast
    } else {
        Plan::Compress
    }
}

/// Plan a file whose full contents are in memory.
pub fn plan(data: &[u8]) -> Plan {
    let parts: Vec<&[u8]> = windows(data.len() as u64)
        .into_iter()
        .map(|(o, n)| &data[o as usize..o as usize + n])
        .collect();
    decide(&parts, data.len() as u64)
}

/// Plan a file on disk by reading only the sample windows.
pub fn plan_path(path: &Path, len: u64) -> Plan {
    classify_path(path, len).1
}

fn read_windows(path: &Path, len: u64) -> Option<Vec<Vec<u8>>> {
    let f = File::open(path).ok()?;
    let mut bufs = Vec::new();
    for (off, n) in windows(len) {
        let mut b = vec![0u8; n];
        crate::zip::read_at(&f, &mut b, off).ok()?;
        bufs.push(b);
    }
    Some(bufs)
}

/// Content class used to route files to codecs (M1, design fix A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Class {
    /// Text and source code: LZMA2.
    Text,
    /// x86 / x86-64 machine code (PE or ELF): BCJ x86 + LZMA2.
    Exec,
    /// Anything else that compresses: LZMA2.
    Other,
    /// ZIP-family containers (`PK\x03\x04`: ZIP, JAR, APK, OOXML, ...).
    /// Their Deflate streams barely compress further; zstd with a long window
    /// matches LZMA2 on them (M1: 88.67% vs 88.76% on 53 MB of JAR/ZIP) at
    /// 10x the speed, and finds content repeated across archives.
    Zip,
    /// Mostly compressed ([`Plan::Fast`]): a fast codec.
    Fast,
    /// Incompressible ([`Plan::Store`]): stored.
    Store,
}

impl Class {
    pub const ALL: [Class; 6] = [
        Class::Text,
        Class::Exec,
        Class::Other,
        Class::Zip,
        Class::Fast,
        Class::Store,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Class::Text => "text",
            Class::Exec => "exec",
            Class::Other => "other",
            Class::Zip => "zip",
            Class::Fast => "fast",
            Class::Store => "store",
        }
    }
}

/// PE (`MZ` .. `PE\0\0`, machine i386 / AMD64) or ELF (x86 / x86-64).
pub fn is_x86_exec(head: &[u8]) -> bool {
    let le16 = |o: usize| head.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    if head.starts_with(b"MZ") {
        let Some(lfanew) = head
            .get(0x3C..0x40)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        else {
            return false;
        };
        if head.get(lfanew..lfanew.saturating_add(4)) != Some(b"PE\0\0") {
            return false;
        }
        return matches!(le16(lfanew + 4), Some(0x014C | 0x8664));
    }
    if head.starts_with(b"\x7FELF") {
        // e_machine is little-endian for x86 targets (EI_DATA = 1).
        return head.get(5) == Some(&1) && matches!(le16(18), Some(3 | 62));
    }
    false
}

/// Text heuristic on a sample: no NUL bytes and almost no control characters
/// other than whitespace (UTF-8 and legacy 8-bit text both pass).
pub fn is_text(sample: &[u8]) -> bool {
    let mut ctrl = 0usize;
    for &b in sample {
        match b {
            0 => return false,
            b'\t' | b'\n' | b'\r' | 0x0C | 0x1B => {}
            1..=0x1F | 0x7F => ctrl += 1,
            _ => {}
        }
    }
    ctrl * 100 <= sample.len()
}

/// Bytes inspected by the text heuristic.
pub const TEXT_SAMPLE: usize = 8 * 1024;

/// Classify sampled windows (the first window is the file head).
pub fn classify(samples: &[&[u8]], total: u64) -> (Class, Plan) {
    let plan = decide(samples, total);
    let head = samples.first().copied().unwrap_or_default();
    if head.starts_with(b"PK\x03\x04") {
        return (Class::Zip, plan);
    }
    let class = match plan {
        Plan::Store => Class::Store,
        Plan::Fast => Class::Fast,
        Plan::Compress => {
            if is_x86_exec(head) {
                Class::Exec
            } else if is_text(&head[..head.len().min(TEXT_SAMPLE)]) {
                Class::Text
            } else {
                Class::Other
            }
        }
    };
    (class, plan)
}

/// Classify a file on disk (reads only the sample windows).
pub fn classify_path(path: &Path, len: u64) -> (Class, Plan) {
    match read_windows(path, len) {
        Some(bufs) => {
            let parts: Vec<&[u8]> = bufs.iter().map(Vec::as_slice).collect();
            classify(&parts, len)
        }
        None => (Class::Other, Plan::Compress),
    }
}

/// Classify a file whose contents are in memory.
pub fn classify_data(data: &[u8]) -> (Class, Plan) {
    let parts: Vec<&[u8]> = windows(data.len() as u64)
        .into_iter()
        .map(|(o, n)| &data[o as usize..o as usize + n])
        .collect();
    classify(&parts, data.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize) -> Vec<u8> {
        let mut s = 0x9E3779B97F4A7C15u64;
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
    fn text_is_compressed() {
        let text = "the quick brown fox jumps over the lazy dog\n".repeat(2000);
        assert_eq!(plan(text.as_bytes()), Plan::Compress);
    }

    #[test]
    fn random_is_stored() {
        let n = noise(300_000);
        assert!(lz4_ratio(&n) > 0.99);
        assert_eq!(plan(&n), Plan::Store);
    }

    #[test]
    fn compressible_tail_keeps_file_compressed() {
        // Like a JAR: incompressible body, compressible central directory.
        let mut v = noise(300_000);
        v.extend(
            "META-INF/MANIFEST.MF org/example/Foo.class\n"
                .repeat(1000)
                .as_bytes(),
        );
        assert_eq!(plan(&v), Plan::Fast);
    }

    #[test]
    fn windows_cover_budget() {
        assert_eq!(windows(100), vec![(0, 100)]);
        let w = windows(1 << 20);
        assert_eq!(w.len(), 3);
        assert_eq!(w[2].0 + w[2].1 as u64, 1 << 20);
        assert!(w.iter().map(|x| x.1).sum::<usize>() <= SAMPLE);
    }

    #[test]
    fn plan_path_matches_in_memory_plan() {
        let d = tempfile::tempdir().unwrap();
        let mut v = noise(200_000);
        v.extend(vec![b'a'; 50_000]);
        let p = d.path().join("f.bin");
        std::fs::write(&p, &v).unwrap();
        assert_eq!(plan_path(&p, v.len() as u64), plan(&v));
    }

    #[test]
    fn classes() {
        let text = "fn main() { println!(\"hi\"); }\n".repeat(3000);
        assert_eq!(classify_data(text.as_bytes()).0, Class::Text);
        assert_eq!(classify_data(&noise(300_000)).0, Class::Store);
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        if cfg!(any(target_arch = "x86_64", target_arch = "x86"))
            && cfg!(any(windows, target_os = "linux"))
        {
            assert!(is_x86_exec(&exe[..4096]));
            assert_eq!(classify_data(&exe).0, Class::Exec);
        }
        let mut bin = vec![0u8; 5000];
        bin.extend((0..5000u32).map(|i| (i % 251) as u8));
        assert_eq!(classify_data(&bin).0, Class::Other);
        assert!(!is_x86_exec(b"MZ"));
    }

    #[test]
    fn tiny_files_are_compressed() {
        assert_eq!(plan(&[1, 2, 3]), Plan::Compress);
        assert_eq!(plan(&[]), Plan::Compress);
    }
}
