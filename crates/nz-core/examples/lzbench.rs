//! LZMA2 encoder microbenchmark (M1 encoder optimization trial).
//!
//! `cargo run --release -p nz-core --example lzbench -- <dir> [threads] [runs]`
//!
//! Concatenates the files under `<dir>` (sorted by path) and encodes them in
//! 2 MiB independent segments, like the text path of `nz c -fmt:7z -l:6`,
//! once on 1 thread and once on `threads` threads. Prints the median time.

use std::time::Instant;

use nz_core::lzma::{Lzma2Params, Mf, lzma2_parallel};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).expect("usage: lzbench <dir> [threads] [runs]");
    let threads: usize = args.get(2).map_or(Ok(12), |s| s.parse())?;
    let runs: usize = args.get(3).map_or(Ok(3), |s| s.parse())?;
    let mut paths: Vec<_> = walkdir::WalkDir::new(dir)
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
    println!("input: {} files, {:.2} MB", paths.len(), mb);

    let mut l6 = Lzma2Params::preset(6);
    l6.mf = Some(Mf::Bt4);
    l6.nice = Some(128);
    l6.pb = Some(0);
    let mut l9 = Lzma2Params::preset(9);
    l9.nice = Some(273);
    l9.pb = Some(0);
    let mut l3 = Lzma2Params::preset(3);
    l3.mf = Some(Mf::Hc4);
    let cases = [
        ("p6 bt4 nice128", l6),
        ("p9 bt4 nice273", l9),
        ("p3 hc4", l3),
    ];

    let ts: &[usize] = if threads == 1 { &[1] } else { &[1, threads] };
    for &t in ts {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(t).build()?;
        for (name, p) in &cases {
            let mut times = Vec::new();
            let mut size = 0;
            for _ in 0..runs {
                let t0 = Instant::now();
                let out = pool.install(|| lzma2_parallel(&data, p, 2 << 20, 0))?;
                times.push(t0.elapsed().as_secs_f64());
                size = out.data.len();
            }
            times.sort_by(f64::total_cmp);
            let med = times[times.len() / 2];
            println!(
                "t{t:<2} {name:<16} {size} B {:.3}%  {med:.3} s  {:.1} MB/s",
                size as f64 * 100.0 / data.len() as f64,
                mb / med
            );
        }
    }
    Ok(())
}
