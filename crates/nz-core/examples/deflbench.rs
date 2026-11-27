//! Parallel-Deflate cost breakdown: libdeflate time vs. block-scan time.
//!
//! `cargo run --release -p nz-core --example deflbench -- <dir> [level]`
//!
//! Concatenates the files under `<dir>`, cuts them into 128 KiB chunks and
//! times, on one thread, (a) libdeflate compression of every chunk and
//! (b) [`nz_core::deflate::scan_blocks`] over the compressed chunks, which the
//! splicer needs to clear BFINAL.

use std::time::Instant;

use nz_core::deflate::{DEFAULT_CHUNK, deflate_chunk, scan_blocks};

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let level: i32 = a.get(2).map_or(Ok(6), |s| s.parse())?;
    let mut paths: Vec<_> = walkdir::WalkDir::new(&a[1])
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    paths.sort();
    let mut data = Vec::new();
    for p in &paths {
        data.extend_from_slice(&std::fs::read(p)?);
    }
    let mb = data.len() as f64 / 1e6;
    let t0 = Instant::now();
    let chunks: Vec<Vec<u8>> = data
        .chunks(DEFAULT_CHUNK)
        .map(|c| deflate_chunk(level, c, true))
        .collect::<anyhow::Result<_>>()?;
    let tc = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    let mut blocks = 0;
    for c in &chunks {
        blocks += scan_blocks(c)?.blocks;
    }
    let ts = t1.elapsed().as_secs_f64();
    let out: usize = chunks.iter().map(Vec::len).sum();
    println!(
        "{mb:.1} MB, level {level}: {} chunks, {blocks} blocks, {:.2}%; compress {tc:.3} s ({:.0} MB/s), scan {ts:.3} s ({:.0} MB/s of input)",
        chunks.len(),
        out as f64 * 100.0 / data.len() as f64,
        mb / tc,
        mb / ts
    );
    Ok(())
}
