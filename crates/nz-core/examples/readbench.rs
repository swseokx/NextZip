//! Parallel whole-file read cost of a directory tree, by read method, and
//! the compute-only cost of ZIP level 5 on the same files (preloaded).
//!
//! `cargo run --release -p nz-core --example readbench -- <dir> [threads]`
//!
//! perf-4 (text set, 1,211 files, 12 threads): opening the files alone took
//! 13-15 ms, about as long as opening and reading them, and only ~1.7x faster
//! than on one thread: opens barely run in parallel. Grouping the opens by
//! folder did not change that.

use std::io::Read;
use std::time::Instant;

use nz_core::deflate::{DEFAULT_CHUNK, deflate_container, deflate_parallel};
use nz_core::planner::{self, Plan};
use nz_core::walk::{self, Kind};
use rayon::prelude::*;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let threads: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(12);
    let entries = walk::collect(&[a[1].clone().into()])?;
    let files: Vec<_> = entries.iter().filter(|e| e.kind == Kind::File).collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let mut runs: Vec<Vec<usize>> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        match runs.last_mut() {
            Some(r) if files[r[0]].path.parent() == f.path.parent() && r.len() < 32 => r.push(i),
            _ => runs.push(vec![i]),
        }
    }
    for round in 0..3 {
        for method in ["fs::read", "fs::read/dir", "open-only", "open-only/dir"] {
            let t = Instant::now();
            let one = |e: &&walk::Entry| -> u64 {
                match method.split('/').next().unwrap() {
                    "fs::read" => std::fs::read(&e.path).unwrap().len() as u64,
                    _ => {
                        drop(std::fs::File::open(&e.path).unwrap());
                        0
                    }
                }
            };
            let bytes: u64 = pool.install(|| {
                if method.ends_with("/dir") {
                    return runs
                        .par_iter()
                        .with_max_len(1)
                        .map(|r| r.iter().map(|&i| one(&files[i])).sum::<u64>())
                        .sum();
                }
                files
                    .par_iter()
                    .with_max_len(1)
                    .map(|e| -> u64 {
                        match method {
                            "fs::read" => std::fs::read(&e.path).unwrap().len() as u64,
                            "open+exact" => {
                                let mut f = std::fs::File::open(&e.path).unwrap();
                                let mut v = vec![0u8; e.size as usize];
                                f.read_exact(&mut v).unwrap();
                                v.len() as u64
                            }
                            _ => {
                                let f = std::fs::File::open(&e.path).unwrap();
                                drop(f);
                                0
                            }
                        }
                    })
                    .sum()
            });
            if round > 0 {
                println!(
                    "{method:<12} {:>7.2} ms  {} files {} bytes",
                    t.elapsed().as_secs_f64() * 1e3,
                    files.len(),
                    bytes
                );
            }
        }
    }
    // Compute only: data preloaded, same codec choice as ZIP level 5.
    let data: Vec<Vec<u8>> = files
        .iter()
        .map(|e| std::fs::read(&e.path).unwrap())
        .collect();
    let mut order: Vec<usize> = (0..data.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(data[i].len()));
    for round in 0..4 {
        let t = Instant::now();
        let out: usize = pool.install(|| {
            order
                .par_iter()
                .with_max_len(1)
                .map(|&i| {
                    let d = &data[i];
                    let plan = planner::plan(d);
                    let container = d.starts_with(b"PK");
                    let plan = if plan == Plan::Compress && container {
                        Plan::Fast
                    } else {
                        plan
                    };
                    match plan {
                        Plan::Store => d.len(),
                        Plan::Fast if container => deflate_container(d, 6, DEFAULT_CHUNK, false)
                            .unwrap()
                            .data
                            .len(),
                        Plan::Fast => deflate_parallel(d, 2, d.len().max(DEFAULT_CHUNK))
                            .unwrap()
                            .data
                            .len(),
                        Plan::Compress => deflate_parallel(d, 6, d.len().max(DEFAULT_CHUNK))
                            .unwrap()
                            .data
                            .len(),
                    }
                })
                .sum()
        });
        if round > 0 {
            println!(
                "compute-only {:>7.2} ms out {}",
                t.elapsed().as_secs_f64() * 1e3,
                out
            );
        }
    }
    Ok(())
}
