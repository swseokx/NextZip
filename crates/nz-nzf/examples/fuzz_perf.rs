//! Throughput of the fuzz entry points over a corpus directory (no
//! sanitizers): `cargo run --release -p nz-nzf --example fuzz_perf -- <dir> [read|recovery]`.
//! Prints executions per second and the slowest inputs.

use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("usage: fuzz_perf <corpus dir> [read|recovery]");
    let target = args.next().unwrap_or_else(|| "read".into());
    let mut inputs: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .expect("corpus dir")
        .filter_map(|e| {
            let p = e.ok()?.path();
            Some((
                p.file_name()?.to_string_lossy().into_owned(),
                std::fs::read(&p).ok()?,
            ))
        })
        .collect();
    inputs.sort();
    // One thread, like a fuzzer worker.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut times: Vec<(f64, usize, String)> = Vec::with_capacity(inputs.len());
    let t0 = Instant::now();
    pool.install(|| {
        for (name, data) in &inputs {
            let t = Instant::now();
            if target == "recovery" {
                nz_nzf::fuzzing::recovery(data);
                nz_nzf::fuzzing::open_and_test(data, true);
            } else {
                nz_nzf::fuzzing::open_and_test(data, false);
            }
            times.push((t.elapsed().as_secs_f64(), data.len(), name.clone()));
        }
    });
    let total = t0.elapsed().as_secs_f64();
    let bytes: usize = inputs.iter().map(|(_, d)| d.len()).sum();
    println!(
        "{target}: {} inputs ({} bytes) in {total:.3}s = {:.0} exec/s",
        inputs.len(),
        bytes,
        inputs.len() as f64 / total
    );
    times.sort_by(|a, b| b.0.total_cmp(&a.0));
    for (t, n, name) in times.iter().take(8) {
        println!("  {:8.2} ms  {n:8} B  {name}", t * 1e3);
    }
}
