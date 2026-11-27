//! Single-threaded LZMA2 cost of a whole 7z class at level-6 segmentation
//! (v1-release tuning): every segment of the class is encoded on one thread,
//! so the CPU time does not depend on machine load the way a parallel run does.
//!
//! `classcost <dir> <class> <seg KiB> <pre KiB> <variant>...`
//! class: text | exec | other6 (other + fast + store, as at -l:6)
//! variant: comma list of mf=<hc4|bt4|hc4n|bt4f|bt3|bt2>, nice=N, depth=N,
//! lc=N, pb=N, preset=N; "base" = the level-6 setting of the class.

use std::time::Instant;

use nz_core::lzma::{Mf, SegPlan};
use nz_core::planner::{Class, classify_path};
use nz_core::walk::{Kind, collect};
use rayon::prelude::*;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&a[1]);
    let want = a[2].as_str();
    let seg: usize = a[3].parse::<usize>()? << 10;
    let pre: usize = a[4].parse::<usize>()? << 10;
    let entries = collect(&[dir])?;
    let mut files: Vec<_> = entries
        .par_iter()
        .filter(|e| e.kind == Kind::File && e.size > 0)
        .filter(|e| {
            let c = classify_path(&e.path, e.size).0;
            match want {
                "other6" => matches!(c, Class::Other | Class::Fast | Class::Store),
                w => c.name() == w,
            }
        })
        .collect();
    files.sort_by_cached_key(|e| {
        let ext = e.name.rsplit_once('.').map(|x| x.1.to_ascii_lowercase());
        (ext, e.name.clone())
    });
    let mut data = Vec::new();
    for e in &files {
        data.extend_from_slice(&std::fs::read(&e.path)?);
    }
    if want == "exec" {
        nz_core::bcj::x86_convert(&mut data, true);
    }
    let o6 = nz_core::sevenz::SevenZOptions::for_level(6);
    let base = match want {
        "text" => o6.text,
        "exec" => o6.exec,
        _ => o6.other,
    };
    println!("{} files, {} bytes", files.len(), data.len());
    for v in &a[5..] {
        let mut p = base;
        for kv in v.split(',').filter(|s| *s != "base") {
            let (k, x) = kv.split_once('=').expect("key=value");
            match k {
                "mf" => {
                    p.mf = Some(match x {
                        "hc4" => Mf::Hc4,
                        "bt4" => Mf::Bt4,
                        "hc4n" => Mf::Hc4Normal,
                        "bt4f" => Mf::Bt4Fast,
                        "bt3" => Mf::Bt3,
                        _ => Mf::Bt2,
                    })
                }
                "nice" => p.nice = Some(x.parse()?),
                "depth" => p.depth = Some(x.parse()?),
                "lc" => p.lc = Some(x.parse()?),
                "pb" => p.pb = Some(x.parse()?),
                "preset" => p.preset = x.parse()?,
                "dict" => p.dict = Some(x.parse::<u32>()? << 10),
                _ => panic!("unknown key {k}"),
            }
        }
        let plan = SegPlan::new(data.len(), &p, seg, pre);
        let t = Instant::now();
        let mut size = 0;
        for i in 0..plan.n {
            size += plan.encode(&data, &p, i)?.len();
        }
        println!(
            "{v:<32} {size:>10} B  {:.3} s  ({} segs)",
            t.elapsed().as_secs_f64(),
            plan.n
        );
    }
    Ok(())
}
