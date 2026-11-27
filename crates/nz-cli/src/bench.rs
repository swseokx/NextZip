//! `nz bench`: warm-cache compression / extraction benchmark.
//!
//! Every case runs as a child process (`nz c`, `nz x`, or an optional
//! reference console archiver given with `-ref`) so process start-up is
//! included the same way for all tools. One untimed
//! warm-up run is followed by `-runs` timed runs; the median is reported.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::Args;

#[derive(Debug, Clone)]
struct Case {
    label: String,
    tool: &'static str,
    format: String,
    level: u8,
    extra: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    case: String,
    tool: String,
    format: String,
    level: u8,
    options: Vec<String>,
    input_bytes: u64,
    input_files: usize,
    archive_bytes: u64,
    ratio_pct: f64,
    compress_s: f64,
    compress_mbps: f64,
    compress_runs_s: Vec<f64>,
    extract_s: f64,
    extract_runs_s: Vec<f64>,
    extract_verified: bool,
    /// Largest peak working set / private commit over the timed runs (MiB).
    compress_peak_ws_mib: f64,
    compress_peak_commit_mib: f64,
    extract_peak_ws_mib: f64,
    extract_peak_commit_mib: f64,
}

#[derive(Debug, Serialize)]
struct Report {
    tool: &'static str,
    version: &'static str,
    dataset: String,
    input_bytes: u64,
    input_files: usize,
    runs: usize,
    threads: usize,
    cpu: String,
    logical_cpus: usize,
    results: Vec<CaseResult>,
}

fn parse_cases(list: &str, tool: &'static str) -> Result<Vec<Case>> {
    let mut out = Vec::new();
    for spec in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let mut parts = spec.split(':');
        let format = parts.next().unwrap_or_default().to_ascii_lowercase();
        let level: u8 = parts
            .next()
            .context("case needs fmt:level")?
            .parse()
            .with_context(|| format!("bad level in case {spec}"))?;
        let mut extra = Vec::new();
        for kv in parts {
            match kv.split_once('=') {
                Some((k, v)) => extra.push(format!("-{k}:{v}")),
                None => extra.push(format!("-{kv}")),
            }
        }
        if tool == "nz" && format != "nz" {
            nz_core::Format::parse(&format)?;
        }
        out.push(Case {
            label: format!("{tool} {spec}"),
            tool,
            format,
            level,
            extra,
        });
    }
    Ok(out)
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let n = s.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

fn dir_summary(dir: &Path) -> Result<(usize, u64)> {
    let entries = nz_core::walk::collect(&[dir.to_path_buf()])?;
    let files = entries
        .iter()
        .filter(|e| e.kind == nz_core::walk::Kind::File)
        .count();
    Ok((files, nz_core::walk::total_bytes(&entries)))
}

/// Wall time and peak memory of one child process run.
struct Run {
    secs: f64,
    peak: nz_sys::PeakMemory,
}

/// [`run_once`], retried up to twice after a failure (some console
/// archivers occasionally exit with an error and no message; the retry is
/// logged).
fn run_cmd(cmd: &mut Command) -> Result<Run> {
    let mut last = None;
    for attempt in 0..3 {
        match run_once(cmd) {
            Ok(r) => return Ok(r),
            Err(e) => {
                eprint!(" [retry {}: {e:#}]", attempt + 1);
                last = Some(e);
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

fn run_once(cmd: &mut Command) -> Result<Run> {
    use std::io::Read;
    let t0 = Instant::now();
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run {cmd:?}"))?;
    let mut err = Vec::new();
    if let Some(mut e) = child.stderr.take() {
        e.read_to_end(&mut err)?;
    }
    let status = child.wait()?;
    let secs = t0.elapsed().as_secs_f64();
    if !status.success() {
        bail!("{cmd:?} failed: {}", String::from_utf8_lossy(&err));
    }
    Ok(Run {
        secs,
        peak: peak_memory(&child),
    })
}

#[cfg(windows)]
fn peak_memory(child: &std::process::Child) -> nz_sys::PeakMemory {
    use std::os::windows::io::AsRawHandle;
    nz_sys::process_peak_memory(child.as_raw_handle()).unwrap_or_default()
}

#[cfg(not(windows))]
fn peak_memory(_child: &std::process::Child) -> nz_sys::PeakMemory {
    nz_sys::PeakMemory::default()
}

fn mib(b: u64) -> f64 {
    b as f64 / 1048576.0
}

fn remove_path(p: &Path) {
    if p.is_dir() {
        let _ = std::fs::remove_dir_all(p);
    } else {
        let _ = std::fs::remove_file(p);
    }
}

pub fn run(a: &Args) -> Result<()> {
    a.check_known(&["runs", "t", "cases", "ref", "refcases", "json", "md", "tmp"])?;
    let Some(dir) = a.pos.first() else {
        bail!("usage: nz bench <dir> [options]");
    };
    let dir = std::fs::canonicalize(dir).with_context(|| format!("cannot open {dir}"))?;
    // Windows canonical paths carry a `\\?\` prefix that many console tools cannot parse.
    let dir = match dir.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(plain) if !plain.starts_with("UNC") => PathBuf::from(plain),
        _ => dir,
    };
    let runs: usize = a.num("runs")?.unwrap_or(5).max(1);
    let threads = a
        .num::<usize>("t")?
        .unwrap_or_else(nz_core::default_threads);
    let mut cases = parse_cases(a.get("cases").unwrap_or("zip:5,tar.zst:5"), "nz")?;
    let ref_path = match a.get("ref") {
        Some(p) => {
            let p = PathBuf::from(p);
            if !p.exists() {
                bail!("reference tool not found at {}", p.display());
            }
            cases.extend(parse_cases(
                a.get("refcases").unwrap_or("zip:5,7z:5"),
                "ref",
            )?);
            Some(p)
        }
        None => None,
    };
    let tmp_root = match a.get("tmp") {
        Some(t) => PathBuf::from(t),
        None => std::env::temp_dir(),
    };
    std::fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix("nzbench")
        .tempdir_in(&tmp_root)?;
    let exe = std::env::current_exe()?;
    let (input_files, input_bytes) = dir_summary(&dir)?;
    let mb = input_bytes as f64 / 1048576.0;
    eprintln!(
        "dataset {} : {input_files} files, {input_bytes} bytes; {runs} runs + 1 warm-up, {threads} threads",
        dir.display()
    );

    let mut results = Vec::new();
    for (ci, c) in cases.iter().enumerate() {
        let ext = if c.tool == "nz" && c.format == "nz" {
            "nz".to_string()
        } else if c.tool == "nz" {
            nz_core::Format::parse(&c.format)?.extension().to_string()
        } else {
            c.format.clone()
        };
        let archive = scratch.path().join(format!("case{ci}.{ext}"));
        let xdir = scratch.path().join(format!("case{ci}_x"));
        let compress_cmd = || -> Command {
            let mut cmd;
            if c.tool == "nz" {
                cmd = Command::new(&exe);
                cmd.arg("c")
                    .arg(format!("-fmt:{}", c.format))
                    .arg(format!("-l:{}", c.level))
                    .arg(format!("-t:{threads}"))
                    .arg("-q")
                    .args(&c.extra)
                    .arg(&archive)
                    .arg(&dir);
            } else {
                cmd = Command::new(ref_path.as_ref().expect("ref path"));
                cmd.arg("c")
                    .arg(format!("-fmt:{}", c.format))
                    .arg(format!("-l:{}", c.level))
                    .args(&c.extra)
                    .arg("-y")
                    .arg("-r")
                    .arg(&archive)
                    .arg(dir.join("*"));
            }
            cmd
        };
        let extract_cmd = || -> Command {
            let mut cmd;
            if c.tool == "nz" {
                cmd = Command::new(&exe);
                cmd.arg("x")
                    .arg(format!("-t:{threads}"))
                    .arg("-q")
                    .arg(format!("-o:{}", xdir.display()))
                    .arg(&archive);
            } else {
                cmd = Command::new(ref_path.as_ref().expect("ref path"));
                cmd.arg("x")
                    .arg("-y")
                    .arg(format!("-o:{}", xdir.display()))
                    .arg(&archive);
            }
            cmd
        };

        eprint!("{:<28} compress", c.label);
        let mut ctimes = Vec::new();
        let mut cpeak = nz_sys::PeakMemory::default();
        for r in 0..=runs {
            remove_path(&archive);
            let run = run_cmd(&mut compress_cmd())?;
            if r > 0 {
                ctimes.push(run.secs);
                cpeak.working_set = cpeak.working_set.max(run.peak.working_set);
                cpeak.commit = cpeak.commit.max(run.peak.commit);
            }
            eprint!(".");
        }
        let archive_bytes = std::fs::metadata(&archive)?.len();
        eprint!(" extract");
        let mut xtimes = Vec::new();
        let mut verified = false;
        let mut xpeak = nz_sys::PeakMemory::default();
        for r in 0..=runs {
            remove_path(&xdir);
            let run = run_cmd(&mut extract_cmd())?;
            let t = run.secs;
            if r == 0 {
                let (f, b) = dir_summary(&xdir)?;
                verified = f == input_files && b == input_bytes;
                if !verified {
                    eprint!(" [MISMATCH files {f}/{input_files} bytes {b}/{input_bytes}]");
                }
            } else {
                xtimes.push(t);
                xpeak.working_set = xpeak.working_set.max(run.peak.working_set);
                xpeak.commit = xpeak.commit.max(run.peak.commit);
            }
            eprint!(".");
        }
        remove_path(&xdir);
        remove_path(&archive);
        eprintln!();
        let cs = median(&ctimes);
        let mut options = vec![format!("-t:{threads}")];
        options.extend(c.extra.iter().cloned());
        if c.tool != "nz" {
            options = c.extra.clone();
        }
        results.push(CaseResult {
            case: c.label.clone(),
            tool: c.tool.to_string(),
            format: c.format.clone(),
            level: c.level,
            options,
            input_bytes,
            input_files,
            archive_bytes,
            ratio_pct: 100.0 * archive_bytes as f64 / input_bytes.max(1) as f64,
            compress_s: cs,
            compress_mbps: mb / cs.max(1e-9),
            compress_runs_s: ctimes,
            extract_s: median(&xtimes),
            extract_runs_s: xtimes,
            extract_verified: verified,
            compress_peak_ws_mib: mib(cpeak.working_set),
            compress_peak_commit_mib: mib(cpeak.commit),
            extract_peak_ws_mib: mib(xpeak.working_set),
            extract_peak_commit_mib: mib(xpeak.commit),
        });
    }

    let report = Report {
        tool: "nz",
        version: env!("CARGO_PKG_VERSION"),
        dataset: dir.display().to_string(),
        input_bytes,
        input_files,
        runs,
        threads,
        cpu: std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default(),
        logical_cpus: nz_core::default_threads(),
        results,
    };
    let table = markdown_table(&report);
    println!("{table}");
    let json = serde_json::to_string_pretty(&report)?;
    match a.get("json") {
        Some(p) => std::fs::write(p, &json).with_context(|| format!("cannot write {p}"))?,
        None => println!("{json}"),
    }
    if let Some(p) = a.get("md") {
        std::fs::write(p, &table).with_context(|| format!("cannot write {p}"))?;
    }
    Ok(())
}

fn markdown_table(r: &Report) -> String {
    let mut s = format!(
        "dataset: {} ({} files, {:.2} MiB), median of {} runs, {} threads\n\n",
        r.dataset,
        r.input_files,
        r.input_bytes as f64 / 1048576.0,
        r.runs,
        r.threads
    );
    s.push_str(
        "| case | size (bytes) | ratio | compress s | MB/s | extract s | verified | peak WS c/x MiB |\n",
    );
    s.push_str("|---|---:|---:|---:|---:|---:|:---:|---:|\n");
    for c in &r.results {
        s.push_str(&format!(
            "| {} | {} | {:.2}% | {:.3} | {:.1} | {:.3} | {} | {:.0} / {:.0} |\n",
            c.case,
            c.archive_bytes,
            c.ratio_pct,
            c.compress_s,
            c.compress_mbps,
            c.extract_s,
            if c.extract_verified { "yes" } else { "NO" },
            c.compress_peak_ws_mib,
            c.extract_peak_ws_mib
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_works() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), 2.5);
    }

    #[test]
    fn cases_parse() {
        let c = parse_cases("zip:5,tar.zst:7:zl=12:noplan", "nz").unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].extra, ["-zl:12", "-noplan"]);
        assert!(parse_cases("rar:5", "nz").is_err());
    }
}
