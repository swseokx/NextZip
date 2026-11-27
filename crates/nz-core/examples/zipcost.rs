//! ZIP level-5 cost breakdown per file extension, on one thread.
//!
//! `cargo run --release -p nz-core --example zipcost -- <dir>`
//!
//! For every file: read time, planner time and Deflate time (the same codec
//! choice as the ZIP writer at level 5), summed per extension. Shows where the
//! single-threaded CPU of a ZIP run goes.

use std::collections::BTreeMap;
use std::time::Instant;

use nz_core::deflate::{DEFAULT_CHUNK, deflate_container, deflate_parallel};
use nz_core::planner::{self, Plan};
use nz_core::walk::{self, Kind};

#[derive(Default)]
struct Acc {
    n: usize,
    bytes: u64,
    out: u64,
    read: f64,
    plan: f64,
    deflate: f64,
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let entries = walk::collect(&[a[1].clone().into()])?;
    let lc: i32 = std::env::var("ZC_LEVEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let lf: i32 = std::env::var("ZC_FAST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    pool.install(|| -> anyhow::Result<()> {
        for e in entries.iter().filter(|e| e.kind == Kind::File) {
            let ext = e
                .path
                .extension()
                .map_or("-".into(), |x| x.to_string_lossy().to_lowercase());
            let t0 = Instant::now();
            let data = std::fs::read(&e.path)?;
            let t1 = Instant::now();
            let plan = planner::plan(&data);
            let container = data.starts_with(b"PK\x03\x04");
            let plan = if plan == Plan::Compress && container {
                Plan::Fast
            } else {
                plan
            };
            let t2 = Instant::now();
            let out = match plan {
                Plan::Store => data.len(),
                Plan::Fast if container => deflate_container(&data, 6, DEFAULT_CHUNK, false)?
                    .data
                    .len(),
                Plan::Fast => deflate_parallel(&data, lf, data.len())?.data.len(),
                Plan::Compress => deflate_parallel(&data, lc, data.len())?.data.len(),
            };
            let t3 = Instant::now();
            let s = acc.entry(ext).or_default();
            s.n += 1;
            s.bytes += data.len() as u64;
            s.out += out as u64;
            s.read += (t1 - t0).as_secs_f64();
            s.plan += (t2 - t1).as_secs_f64();
            s.deflate += (t3 - t2).as_secs_f64();
        }
        Ok(())
    })?;
    let mut rows: Vec<_> = acc.into_iter().collect();
    rows.sort_by(|a, b| {
        (b.1.read + b.1.plan + b.1.deflate).total_cmp(&(a.1.read + a.1.plan + a.1.deflate))
    });
    let mut tot = Acc::default();
    println!("ext       files      bytes        out   read ms  plan ms  defl ms");
    for (k, s) in &rows {
        println!(
            "{k:<8} {:>6} {:>10} {:>10} {:>9.1} {:>8.1} {:>8.1}",
            s.n,
            s.bytes,
            s.out,
            s.read * 1e3,
            s.plan * 1e3,
            s.deflate * 1e3
        );
        tot.n += s.n;
        tot.bytes += s.bytes;
        tot.out += s.out;
        tot.read += s.read;
        tot.plan += s.plan;
        tot.deflate += s.deflate;
    }
    println!(
        "TOTAL    {:>6} {:>10} {:>10} {:>9.1} {:>8.1} {:>8.1}",
        tot.n,
        tot.bytes,
        tot.out,
        tot.read * 1e3,
        tot.plan * 1e3,
        tot.deflate * 1e3
    );
    Ok(())
}
