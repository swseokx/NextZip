//! Native `.nz` commands: create, extract, list, test, repair, backup,
//! snapshots, restore.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use nz_nzf::read::{self, Archive, OpenOptions};
use nz_nzf::{Aead, FileSource, Method, WriteOptions};

use crate::Args;

/// `-fmt:nz`, or no `-fmt` and an `.nz` output name.
pub fn wants_nz(a: &Args, out: &str) -> bool {
    match a.get("fmt") {
        Some(f) => f.eq_ignore_ascii_case("nz"),
        None => out.to_ascii_lowercase().ends_with(".nz"),
    }
}

fn pool(a: &Args) -> Result<rayon::ThreadPool> {
    let t = a
        .num::<usize>("t")?
        .unwrap_or_else(nz_core::default_threads);
    nz_core::cpu::pool(t)
}

/// `-rr:<percent>` (decimals allowed, 0 = none, default 3).
fn recovery_bp(a: &Args) -> Result<u16> {
    match a.get("rr") {
        None => Ok(300),
        Some(v) => {
            let p: f64 = v
                .trim_end_matches('%')
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid -rr value '{v}'"))?;
            if !(0.0..=30.0).contains(&p) {
                bail!("-rr must be between 0 and 30 (percent)");
            }
            Ok((p * 100.0).round() as u16)
        }
    }
}

fn write_options(a: &Args) -> Result<WriteOptions> {
    let level: u8 = a.num("l")?.unwrap_or(5);
    if level > 9 {
        bail!("level must be 0..9");
    }
    let mut method = Method::for_level(level);
    if let Some(kib) = a.num::<usize>("block")? {
        if !(64..=262_144).contains(&kib) {
            bail!("-block must be 64..262144 KiB");
        }
        method.block = kib * 1024;
        if method.exec_block > 0 {
            method.exec_block = method.exec_block.max(method.block);
        }
    }
    let aead = match a.get("em").map(str::to_ascii_lowercase).as_deref() {
        None | Some("aes") | Some("aes256") | Some("aes-256-gcm") => Aead::Aes256Gcm,
        Some("chacha") | Some("chacha20") | Some("chacha20-poly1305") => Aead::ChaCha20Poly1305,
        Some(o) => bail!("unknown encryption method '{o}' (aes, chacha)"),
    };
    Ok(WriteOptions {
        method,
        recovery_bp: recovery_bp(a)?,
        password: a.get("p").map(str::to_owned),
        aead,
        label: a.get("label").unwrap_or("").to_owned(),
        sort_by_ext: !a.has("nosort"),
        keep_streams: !a.has("noads"),
        ..Default::default()
    })
}

fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

pub fn cmd_create(a: &Args, out: &str, sources: &[PathBuf]) -> Result<()> {
    let o = write_options(a)?;
    let t0 = Instant::now();
    let s = pool(a)?
        .install(|| nz_nzf::create(sources, out.as_ref(), &o))
        .with_context(|| format!("creating {out}"))?;
    let secs = t0.elapsed().as_secs_f64();
    for (p, e) in &s.skipped {
        eprintln!("nz: warning: skipped {p}: {e}");
    }
    if !a.has("q") {
        println!(
            "{out}: nz {} files, {} dirs, {} -> {} bytes ({:.2}%), recovery {} bytes, dedup {} chunks, {secs:.3}s, {:.1} MB/s",
            s.files,
            s.dirs,
            s.input_bytes,
            s.output_bytes,
            pct(s.output_bytes, s.input_bytes),
            s.recovery_bytes,
            s.dedup_chunks,
            s.input_bytes as f64 / 1048576.0 / secs.max(1e-9),
        );
    }
    Ok(())
}

fn open_opts(a: &Args) -> OpenOptions {
    OpenOptions {
        password: a.get("p").map(str::to_owned),
        verify: a.has("verify"),
    }
}

fn snap_arg(a: &Args) -> Result<Option<usize>> {
    Ok(match a.num::<usize>("snap")? {
        None | Some(0) => None,
        Some(n) => Some(n - 1),
    })
}

fn report_repair(rep: &Option<nz_nzf::rr::RepairReport>, notes: &[String]) {
    for n in notes {
        eprintln!("nz: note: {n}");
    }
    if let Some(r) = rep {
        if r.damaged_sectors > 0 || r.damaged_parity > 0 {
            eprintln!(
                "nz: recovery record: {} damaged sector(s) of {} B, {} repaired, {} damaged parity sector(s)",
                r.damaged_sectors, r.sector_size, r.repaired_sectors, r.damaged_parity
            );
        }
        for (g, d, p) in &r.failed_groups {
            eprintln!("nz: recovery group {g}: {d} damaged sectors exceed its {p} parity sectors");
        }
        for (s, e) in &r.unrecoverable {
            eprintln!("nz: unrecoverable bytes {s}..{e}");
        }
    }
}

/// `nz x` / `nz restore` on a .nz archive.
pub fn cmd_extract(a: &Args, archive: &Path, out: &Path) -> Result<()> {
    let src =
        FileSource::open(archive).with_context(|| format!("cannot open {}", archive.display()))?;
    let t0 = Instant::now();
    let pool = pool(a)?;
    let rep = pool.install(|| -> Result<_> {
        let mut ar = Archive::open(&src, &open_opts(a))?;
        read::extract(&mut ar, snap_arg(a)?, out)
    })?;
    report_repair(&rep.repair, &rep.notes);
    for (p, m) in &rep.failed {
        eprintln!("nz: FAILED {p}: {m}");
    }
    for (p, m) in &rep.stream_errors {
        eprintln!("nz: warning: stream {p} not restored: {m}");
    }
    if !a.has("q") {
        println!(
            "{} -> {}: {} files, {} dirs, {} bytes, {:.3}s",
            archive.display(),
            out.display(),
            rep.files,
            rep.dirs,
            rep.bytes,
            t0.elapsed().as_secs_f64()
        );
    }
    if !rep.failed.is_empty() {
        bail!("{} entries could not be restored", rep.failed.len());
    }
    Ok(())
}

fn time_str(ns: i64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_nanos(ns)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// `nz l` on a .nz archive.
pub fn cmd_list(a: &Args, archive: &Path) -> Result<()> {
    let src = FileSource::open(archive)?;
    let ar = Archive::open(&src, &open_opts(a))?;
    let si = ar.snapshot(snap_arg(a)?)?;
    let s = &ar.index.snapshots[si];
    if a.has("json") {
        #[derive(serde::Serialize)]
        struct E<'a> {
            name: &'a str,
            kind: nz_nzf::index::Kind,
            size: u64,
            mtime: String,
            chunks: usize,
        }
        let v: Vec<E> = s
            .entries
            .iter()
            .map(|e| E {
                name: &e.path,
                kind: e.kind,
                size: e.size,
                mtime: time_str(e.mtime_ns),
                chunks: e.chunks.len(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let h = &ar.header;
    println!(
        "{}: nz v1, snapshot {}/{}{}, {} blocks, {} chunks, {}{}",
        archive.display(),
        si + 1,
        ar.index.snapshots.len(),
        if s.label.is_empty() {
            String::new()
        } else {
            format!(" '{}'", s.label)
        },
        ar.index.blocks.len(),
        ar.index.chunks.len(),
        if h.encrypted() { "encrypted, " } else { "" },
        if h.has_recovery() {
            format!("recovery {:.2}%", f64::from(h.rr_basis_points) / 100.0)
        } else {
            "no recovery record".into()
        }
    );
    report_repair(&ar.repair, &ar.notes);
    println!("{:>14}  {:<19}  name", "size", "modified");
    let mut total = 0;
    for e in &s.entries {
        total += e.size;
        println!(
            "{:>14}  {:<19}  {}{}",
            e.size,
            time_str(e.mtime_ns),
            e.path,
            match e.kind {
                nz_nzf::index::Kind::Dir => "/".to_string(),
                nz_nzf::index::Kind::Symlink => format!(" -> {}", e.target),
                _ => String::new(),
            }
        );
    }
    println!(
        "{} entries, {} bytes, archive {} bytes",
        s.entries.len(),
        total,
        src.len
    );
    Ok(())
}

pub fn cmd_test(a: &Args) -> Result<()> {
    a.check_known(&["p", "t", "json"])?;
    let Some(archive) = a.pos.first() else {
        bail!("usage: nz t [-p:<password>] <archive.nz>");
    };
    let src = FileSource::open(Path::new(archive))?;
    let rep = pool(a)?.install(|| -> Result<_> {
        let mut ar = Archive::open(
            &src,
            &OpenOptions {
                password: a.get("p").map(str::to_owned),
                verify: false,
            },
        )?;
        read::test(&mut ar)
    })?;
    if a.has("json") {
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        report_repair(&rep.repair, &rep.notes);
        for (b, m) in &rep.bad_blocks {
            eprintln!("nz: block {b}: {m}");
        }
        println!(
            "{archive}: {} blocks, {} chunks checked: {}",
            rep.blocks,
            rep.chunks,
            if rep.ok() {
                if rep.repair.as_ref().is_some_and(|r| r.repaired_sectors > 0) {
                    "OK after repair (run `nz repair` to fix the file)"
                } else {
                    "OK"
                }
            } else {
                "DAMAGED"
            }
        );
    }
    if !rep.ok() {
        bail!("archive is damaged");
    }
    Ok(())
}

pub fn cmd_repair(a: &Args) -> Result<()> {
    a.check_known(&["p", "t", "rr"])?;
    let Some(archive) = a.pos.first() else {
        bail!("usage: nz repair [-p:<password>] [-rr:<percent>] <archive.nz> [<out.nz>]");
    };
    let out = match a.pos.get(1) {
        Some(o) => PathBuf::from(o),
        None => {
            let p = Path::new(archive);
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            p.with_file_name(format!("{stem}.repaired.nz"))
        }
    };
    let bp = if a.get("rr").is_some() {
        Some(recovery_bp(a)?)
    } else {
        None
    };
    let rep = pool(a)?.install(|| {
        nz_nzf::repair_to(Path::new(archive), &out, a.get("p").map(str::to_owned), bp)
    })?;
    println!(
        "{archive} -> {}: {} damaged sector(s), {} repaired",
        out.display(),
        rep.damaged_sectors,
        rep.repaired_sectors
    );
    Ok(())
}

pub fn cmd_backup(a: &Args) -> Result<()> {
    a.check_known(&["l", "t", "rr", "p", "em", "label", "q", "block", "noads"])?;
    if a.pos.len() < 2 {
        bail!("usage: nz backup [options] <archive.nz> <src>...");
    }
    let archive = Path::new(&a.pos[0]);
    let sources: Vec<PathBuf> = a.pos[1..].iter().map(PathBuf::from).collect();
    let o = write_options(a)?;
    let t0 = Instant::now();
    let s = pool(a)?.install(|| nz_nzf::backup(archive, &sources, &o))?;
    for (p, e) in &s.skipped {
        eprintln!("nz: warning: skipped {p}: {e}");
    }
    if !a.has("q") {
        println!(
            "{}: snapshot {}: {} files, {} dirs, {} bytes scanned, {} new chunks ({} bytes), {} reused, +{} bytes written, archive {} bytes, {:.3}s",
            archive.display(),
            s.snapshot,
            s.files,
            s.dirs,
            s.input_bytes,
            s.new_chunks,
            s.new_bytes,
            s.dedup_chunks,
            s.written_bytes,
            s.output_bytes,
            t0.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

pub fn cmd_snapshots(a: &Args) -> Result<()> {
    a.check_known(&["p", "json"])?;
    let Some(archive) = a.pos.first() else {
        bail!("usage: nz snapshots [-p:<password>] <archive.nz>");
    };
    let src = FileSource::open(Path::new(archive))?;
    let ar = Archive::open(&src, &open_opts(a))?;
    #[derive(serde::Serialize)]
    struct S<'a> {
        number: usize,
        time: String,
        label: &'a str,
        entries: usize,
        bytes: u64,
    }
    let v: Vec<S> = ar
        .index
        .snapshots
        .iter()
        .enumerate()
        .map(|(i, s)| S {
            number: i + 1,
            time: time_str(s.time_ns),
            label: &s.label,
            entries: s.entries.len(),
            bytes: s.entries.iter().map(|e| e.size).sum(),
        })
        .collect();
    if a.has("json") {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!(
            "{:>4}  {:<19}  {:>8}  {:>14}  label",
            "#", "time", "entries", "bytes"
        );
        for s in v {
            println!(
                "{:>4}  {:<19}  {:>8}  {:>14}  {}",
                s.number, s.time, s.entries, s.bytes, s.label
            );
        }
    }
    Ok(())
}

pub fn cmd_restore(a: &Args) -> Result<()> {
    a.check_known(&["o", "t", "p", "snap", "q", "verify"])?;
    let Some(archive) = a.pos.first() else {
        bail!("usage: nz restore [-snap:N] [-o:<dir>] [-p:<password>] <archive.nz>");
    };
    let archive = Path::new(archive);
    let out = a
        .get("o")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::archive_cmd::default_out(archive));
    cmd_extract(a, archive, &out)
}
