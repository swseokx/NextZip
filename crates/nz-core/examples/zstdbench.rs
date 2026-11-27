//! Decode-only throughput of a (multi-frame) zstd file: sequential decoder vs
//! `parzst::ParZstd`. Usage: `zstdbench <file.zst> [workers] [inflight]`.

use std::io::Read;
use std::time::Instant;

fn drain(mut r: impl Read) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 4 << 20];
    let mut n = 0u64;
    loop {
        let k = r.read(&mut buf)?;
        if k == 0 {
            return Ok(n);
        }
        n += k as u64;
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let path = a.get(1).expect("file");
    let workers: usize = a.get(2).map_or(12, |s| s.parse().unwrap());
    let inflight: usize = a.get(3).map_or(12, |s| s.parse().unwrap());
    scan_only(path)?;
    for round in 0..3 {
        let t = Instant::now();
        let f = std::fs::File::open(path)?;
        let n = drain(zstd::stream::read::Decoder::new(f)?)?;
        let s1 = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let f = std::fs::File::open(path)?;
        let m = drain(nz_core::parzst::ParZstd::new(f, workers, inflight))?;
        let s2 = t.elapsed().as_secs_f64();
        assert_eq!(n, m);
        println!(
            "round {round}: {n} bytes; sequential {:.2} GB/s, parallel {:.2} GB/s",
            n as f64 / s1 / 1e9,
            n as f64 / s2 / 1e9
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn scan_only(path: &str) -> anyhow::Result<()> {
    let t = Instant::now();
    let n = drain(std::fs::File::open(path)?)?;
    let s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let all = std::fs::read(path)?;
    let mut off = 0;
    let mut frames = 0;
    while off < all.len() {
        off += zstd::zstd_safe::find_frame_compressed_size(&all[off..])
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        frames += 1;
    }
    println!(
        "file read {:.2} GB/s; read+scan {frames} frames {:.2} GB/s (compressed)",
        n as f64 / s / 1e9,
        n as f64 / t.elapsed().as_secs_f64() / 1e9
    );
    Ok(())
}
