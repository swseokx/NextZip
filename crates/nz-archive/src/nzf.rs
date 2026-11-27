//! NextZip's own `.nz` container (crate `nz-nzf`): list and extract the
//! newest snapshot. Snapshots, repair and backup stay in the `nz` CLI.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use nz_nzf::FileSource;
use nz_nzf::index::Kind as NzKind;
use nz_nzf::read::{self, Archive, OpenOptions};

use crate::{ArchiveError, Entry, ExtractStats, Options, Progress, scan};

fn open_opts(opt: &Options) -> OpenOptions {
    OpenOptions {
        password: opt.password.clone(),
        verify: false,
    }
}

/// Password errors from `nz-nzf` as [`ArchiveError`]s.
fn map_err(e: anyhow::Error) -> anyhow::Error {
    match read::password_error(&e) {
        Some(true) => ArchiveError::PasswordRequired.into(),
        Some(false) => ArchiveError::WrongPassword.into(),
        None => e,
    }
}

fn mtime(ns: i64) -> Option<SystemTime> {
    let d = Duration::from_nanos(ns.unsigned_abs());
    if ns >= 0 {
        UNIX_EPOCH.checked_add(d)
    } else {
        UNIX_EPOCH.checked_sub(d)
    }
}

pub(crate) fn list(path: &Path, opt: &Options) -> Result<(Vec<Entry>, bool)> {
    let src = FileSource::open(path)?;
    let ar = Archive::open(&src, &open_opts(opt)).map_err(map_err)?;
    let si = ar.snapshot(None)?;
    let entries = ar.index.snapshots[si]
        .entries
        .iter()
        .map(|e| Entry {
            name: e.path.clone(),
            is_dir: e.kind == NzKind::Dir,
            size: e.size,
            csize: 0,
            mtime: mtime(e.mtime_ns),
            method: "NZ".into(),
            crc: None,
            encrypted: ar.header.encrypted(),
        })
        .collect();
    Ok((entries, true))
}

pub(crate) fn extract(
    archive: &Path,
    out_dir: &Path,
    opt: &Options,
    prog: &Progress,
    guard: &scan::Guard,
) -> Result<ExtractStats> {
    let src = FileSource::open(archive)?;
    let mut ar = Archive::open(&src, &open_opts(opt)).map_err(map_err)?;
    let si = ar.snapshot(None)?;
    let entries = &ar.index.snapshots[si].entries;
    crate::check_total(entries.iter().map(|e| e.size), archive)?;
    crate::check_entries(entries.len(), archive)?;
    let before = guard.snapshot(out_dir);
    let threads = if opt.threads == 0 {
        nz_core::default_threads()
    } else {
        opt.threads
    };
    let rep = nz_core::cpu::pool(threads)?
        .install(|| read::extract(&mut ar, None, out_dir))
        .map_err(map_err)?;
    guard.scan_written(out_dir, before)?;
    for n in &rep.notes {
        prog.note(n.clone());
    }
    prog.done.fetch_add(rep.bytes, Ordering::Relaxed);
    prog.files.fetch_add(rep.files as u64, Ordering::Relaxed);
    if let Some((p, m)) = rep.failed.first() {
        anyhow::bail!(nz_front::trf(
            "{}개 항목을 복원하지 못했습니다 (첫 항목 {}: {})",
            &[&rep.failed.len(), p, m]
        ));
    }
    Ok(ExtractStats {
        files: rep.files,
        dirs: rep.dirs,
        bytes: rep.bytes,
    })
}
