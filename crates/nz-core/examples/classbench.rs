//! Per-class codec experiment (M1 follow-up): how much ratio and time does
//! each codec cost on the files the planner puts in one class?
//!
//! `cargo run --release -p nz-core --example classbench -- <dir> <class> [threads]`
//!
//! `<class>` is text, exec, other, fast or store. The class's files are
//! concatenated in the 7z writer's order (extension, then name) and encoded
//! with LZMA2 (the current 7z path) and with zstd at several levels with a
//! long window (one multithreaded frame, output independent of threads).

use std::io::Write;
use std::time::Instant;

use nz_core::lzma::{Lzma2Params, lzma2_parallel};
use nz_core::planner::{Class, classify_path};
use nz_core::walk::{Kind, collect};
use rayon::prelude::*;

fn zstd_mt(data: &[u8], level: i32, wlog: u32, workers: u32) -> anyhow::Result<usize> {
    let mut e = zstd::stream::write::Encoder::new(Vec::new(), level)?;
    e.multithread(workers)?;
    e.set_parameter(zstd::stream::raw::CParameter::JobSize(2 << 20))?;
    e.set_parameter(zstd::stream::raw::CParameter::OverlapSizeLog(6))?;
    if wlog > 0 {
        e.long_distance_matching(true)?;
        e.window_log(wlog)?;
    }
    e.write_all(data)?;
    Ok(e.finish()?.len())
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&a[1]);
    let want = a[2].as_str();
    let threads: u32 = a.get(3).map_or(Ok(12), |s| s.parse())?;
    let entries = collect(&[dir])?;
    let mut files: Vec<_> = entries
        .par_iter()
        .filter(|e| e.kind == Kind::File && e.size > 0)
        .filter(|e| match want.strip_prefix("ext:") {
            Some(list) => {
                let base = e
                    .name
                    .rsplit('/')
                    .next()
                    .unwrap_or(&e.name)
                    .to_ascii_lowercase();
                list.split(',').any(|x| base.ends_with(&format!(".{x}")))
            }
            None => classify_path(&e.path, e.size).0.name() == want,
        })
        .collect();
    files.sort_by_cached_key(|e| {
        let base = e.name.rsplit('/').next().unwrap_or(&e.name);
        let ext = base
            .rsplit_once('.')
            .map(|(_, x)| x.to_ascii_lowercase())
            .unwrap_or_default();
        (ext, e.name.clone())
    });
    let mut data = Vec::new();
    for e in &files {
        data.extend_from_slice(&std::fs::read(&e.path)?);
    }
    let mb = data.len() as f64 / 1e6;
    println!("class {want}: {} files, {mb:.2} MB", files.len());
    let _ = Class::ALL;

    let report = |name: &str, size: usize, secs: f64| {
        println!(
            "{name:<28} {:>7.2}%  {secs:>6.3} s  {:>7.1} MB/s",
            size as f64 * 100.0 / data.len() as f64,
            mb / secs
        );
    };
    let mut lit0 = Lzma2Params::preset(6);
    lit0.lc = Some(0);
    lit0.pb = Some(0);
    let mut lit0p1 = Lzma2Params::preset(1);
    lit0p1.lc = Some(0);
    lit0p1.pb = Some(0);
    for (name, p) in [
        ("lzma2 p6 lc0 pb0 4M seg", lit0),
        ("lzma2 p1 lc0 pb0 4M seg", lit0p1),
    ] {
        let t0 = Instant::now();
        let o = lzma2_parallel(&data, &p, 4 << 20, 0)?;
        report(name, o.data.len(), t0.elapsed().as_secs_f64());
    }
    for (level, wlog) in [(3, 0), (3, 27), (9, 27), (15, 27), (19, 27), (19, 0)] {
        let t0 = Instant::now();
        let n = zstd_mt(&data, level, wlog, threads)?;
        report(
            &format!("zstd {level} long {wlog}"),
            n,
            t0.elapsed().as_secs_f64(),
        );
    }
    Ok(())
}
