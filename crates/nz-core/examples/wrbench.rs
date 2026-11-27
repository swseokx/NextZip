//! Output write strategies for a buffer already in memory.
//!
//! `cargo run --release -p nz-core --example wrbench -- <out-dir> <MiB> [reps]`
//!
//! seq: one thread, 1 MiB `WriteFile` calls. map: [`nz_sys::FileMapping`]
//! filled by the Rayon pool in 1 MiB pieces. Each repetition deletes and
//! recreates the file; times include create, write and close.

use std::io::Write;
use std::time::Instant;

use rayon::prelude::*;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&a[1]);
    let mib: usize = a[2].parse()?;
    let reps: usize = a.get(3).map_or(Ok(5), |s| s.parse())?;
    let mut s = 0x1234_5678_9abc_def0u64;
    let data: Vec<u8> = (0..mib << 20)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect();
    std::fs::create_dir_all(&dir)?;
    let p = dir.join("wrbench.bin");
    for rep in 0..reps {
        let _ = std::fs::remove_file(&p);
        let t = Instant::now();
        let mut f = std::fs::File::create(&p)?;
        for c in data.chunks(1 << 20) {
            f.write_all(c)?;
        }
        drop(f);
        let seq = t.elapsed().as_secs_f64();
        let _ = std::fs::remove_file(&p);
        let t = Instant::now();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)?;
        let fm = nz_sys::FileMapping::new(&f, data.len() as u64)?;
        let mut m = fm.view(0, data.len())?;
        m.as_mut_slice()
            .par_chunks_mut(1 << 20)
            .zip(data.par_chunks(1 << 20))
            .for_each(|(d, s)| d.copy_from_slice(s));
        let t_fill = t.elapsed().as_secs_f64();
        m.finish()?;
        drop(fm);
        drop(f);
        let map = t.elapsed().as_secs_f64();
        println!(
            "rep {rep}: seq {:.1} ms ({:.2} GB/s)  map {:.1} ms (fill {:.1}) ({:.2} GB/s)",
            seq * 1e3,
            data.len() as f64 / seq / 1e9,
            map * 1e3,
            t_fill * 1e3,
            data.len() as f64 / map / 1e9
        );
    }
    let _ = std::fs::remove_file(&p);
    Ok(())
}
