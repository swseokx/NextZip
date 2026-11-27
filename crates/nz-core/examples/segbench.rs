//! Single-segment LZMA2 cost (1.0 perf follow-up): how long does one chained
//! segment of a class take with a given history, segment size and settings?
//!
//! `cargo run --release -p nz-core --example segbench -- <dir> <class> [seg KiB] [pre KiB]`
//!
//! The class's files are concatenated in the 7z writer's order (code gets
//! BCJ x86); the segment starting at 8 MiB is encoded single-threaded with
//! several settings, best of 3.

use std::time::Instant;

use nz_core::lzma::{Lzma2Params, Mf, lzma2_encode_with, segment_dict};
use nz_core::planner::{Class, classify_path};
use nz_core::walk::{Kind, collect};
use rayon::prelude::*;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&a[1]);
    let want = a[2].as_str();
    let seg: usize = a.get(3).map_or(4096, |s| s.parse().unwrap()) << 10;
    let pre: usize = a.get(4).map_or(4096, |s| s.parse().unwrap()) << 10;
    let entries = collect(&[dir])?;
    let mut files: Vec<_> = entries
        .par_iter()
        .filter(|e| e.kind == Kind::File && e.size > 0)
        .filter(|e| classify_path(&e.path, e.size).0.name() == want)
        .collect();
    files.sort_by_cached_key(|e| {
        let ext = e.name.rsplit_once('.').map(|x| x.1.to_ascii_lowercase());
        (ext, e.name.clone())
    });
    let mut data = Vec::new();
    for e in &files {
        data.extend_from_slice(&std::fs::read(&e.path)?);
    }
    if want == Class::Exec.name() {
        nz_core::bcj::x86_convert(&mut data, true);
    }
    let start = (8usize << 20).min(data.len().saturating_sub(seg));
    let h0 = start.saturating_sub(pre);
    println!(
        "{} files, {} bytes; segment {start}+{seg}, history {}",
        files.len(),
        data.len(),
        start - h0
    );
    let base = Lzma2Params {
        nice: Some(128),
        ..Lzma2Params::preset(6)
    };
    let with = |f: &dyn Fn(&mut Lzma2Params)| {
        let mut p = base;
        f(&mut p);
        p
    };
    let variants: Vec<(&str, Lzma2Params)> = vec![
        ("p6 nice128", base),
        ("p6 nice64", with(&|p| p.nice = Some(64))),
        ("p6 nice32", with(&|p| p.nice = Some(32))),
        ("p6 nice128 depth16", with(&|p| p.depth = Some(16))),
        ("bt3 nice128", with(&|p| p.mf = Some(Mf::Bt3))),
        ("hc4n nice128", with(&|p| p.mf = Some(Mf::Hc4Normal))),
        ("bt4f nice128", with(&|p| p.mf = Some(Mf::Bt4Fast))),
        ("hc4 fast", with(&|p| p.mf = Some(Mf::Hc4))),
    ];
    let segd = &data[start..start + seg.min(data.len() - start)];
    let hist = &data[h0..start];
    for (name, p) in variants {
        let dict = segment_dict(&p, seg + pre, data.len());
        let mut best = (f64::MAX, f64::MAX, 0usize);
        for _ in 0..3 {
            let t = Instant::now();
            let _ = lzma2_encode_with(&segd[..4096], hist, &p, dict)?;
            let skip = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let n = lzma2_encode_with(segd, hist, &p, dict)?.len();
            let all = t.elapsed().as_secs_f64();
            best = (best.0.min(skip), best.1.min(all), n);
        }
        println!(
            "{name:<22} history-only {:.3} s, segment {:.3} s, {} B",
            best.0, best.1, best.2
        );
    }
    Ok(())
}
