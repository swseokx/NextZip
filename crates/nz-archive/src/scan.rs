//! Malware scanning of extracted content (spec 9: "AMSI 연동(별도
//! 프로세스), 해제 전 검사 옵션").
//!
//! Content is scanned through AMSI in a separate process (`nz-decode
//! --scan`, see `nz_scan`) before it gets its final name:
//!
//! * ZIP, ALZ, EGG members are decoded in memory and scanned before
//!   anything is written.
//! * Members streamed from the isolated decoder are written under a
//!   temporary name, scanned as they arrive, and renamed only when clean.
//! * The `nz-core` extractors (native 7z, the tar family) write files
//!   themselves; everything new or changed under the output folder is
//!   scanned afterwards and a detected file is deleted.
//!
//! A detected member is not written (or is deleted); the other members are
//! still extracted and the whole extraction ends with
//! [`ArchiveError::MalwareFound`]. When AMSI cannot be started (no
//! antimalware provider, policy, missing scanner) extraction goes on
//! unscanned and a notice is added to [`Progress::notes`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::{ArchiveError, Progress};

pub(crate) struct Guard {
    scanner: Option<nz_scan::Scanner>,
    found: Mutex<Vec<String>>,
}

fn failed(name: &str) -> String {
    nz_front::trf("악성코드 검사 실패: {}", &[&name])
}

impl Guard {
    /// A guard that scans when `on`; scanner start failures become notes.
    pub(crate) fn new(on: bool, prog: &Progress) -> Guard {
        let scanner = if on {
            let s = crate::isolated::worker_path()
                .and_then(|exe| nz_scan::Scanner::start_with(exe, vec!["--scan".to_string()]));
            match s {
                Ok(s) => Some(s),
                Err(e) => {
                    prog.note(nz_front::trf(
                        "악성코드 검사 없이 풉니다: {}",
                        &[&format!("{e:#}")],
                    ));
                    None
                }
            }
        } else {
            None
        };
        Guard {
            scanner,
            found: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, name: &str) {
        if let Ok(mut f) = self.found.lock() {
            f.push(name.to_string());
        }
    }

    /// May `data` (member `name`) be written? A threat is recorded.
    pub(crate) fn clean(&self, name: &str, data: &[u8]) -> Result<bool> {
        let Some(s) = &self.scanner else {
            return Ok(true);
        };
        let v = s.scan(name, data).with_context(|| failed(name))?;
        if v.is_threat() {
            self.record(name);
            return Ok(false);
        }
        Ok(true)
    }

    /// Start a streamed scan of member `name` (None when not scanning).
    pub(crate) fn begin(&self, name: &str) -> Result<Option<nz_scan::Scan<'_>>> {
        match &self.scanner {
            Some(s) => Ok(Some(s.begin(name).with_context(|| failed(name))?)),
            None => Ok(None),
        }
    }

    /// Finish a streamed scan; false (and recorded) for a threat.
    pub(crate) fn end(&self, name: &str, scan: Option<nz_scan::Scan<'_>>) -> Result<bool> {
        let Some(scan) = scan else {
            return Ok(true);
        };
        let v = scan.end().with_context(|| failed(name))?;
        if v.is_threat() {
            self.record(name);
            return Ok(false);
        }
        Ok(true)
    }

    /// Files under `dir` before an extractor that writes by itself runs
    /// (None when not scanning).
    pub(crate) fn snapshot(&self, dir: &Path) -> Option<Snapshot> {
        self.scanner.as_ref()?;
        Some(Snapshot::take(dir))
    }

    /// Scan every file under `dir` that is new or changed since `before`;
    /// delete the detected ones.
    pub(crate) fn scan_written(&self, dir: &Path, before: Option<Snapshot>) -> Result<()> {
        let (Some(s), Some(before)) = (&self.scanner, before) else {
            return Ok(());
        };
        let todo = before.changed(dir);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;
        pool.install(|| {
            todo.par_iter().try_for_each(|p| -> Result<()> {
                let name = p
                    .strip_prefix(dir)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/");
                let v = match std::fs::File::open(p) {
                    Ok(f) => s
                        .scan_reader(&name, std::io::BufReader::new(f))
                        .with_context(|| failed(&name))?,
                    // The real-time scanner may already have removed it.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        self.record(&name);
                        return Ok(());
                    }
                    Err(e) => return Err(anyhow::Error::from(e).context(failed(&name))),
                };
                if v.is_threat() {
                    let _ = std::fs::remove_file(p);
                    self.record(&name);
                }
                Ok(())
            })
        })
    }

    /// Ok when nothing was detected, else [`ArchiveError::MalwareFound`].
    pub(crate) fn finish(self) -> Result<()> {
        let mut found = self.found.into_inner().unwrap_or_default();
        if found.is_empty() {
            return Ok(());
        }
        found.sort();
        Err(ArchiveError::MalwareFound(found).into())
    }
}

/// Size and modification time of every file below a folder, to find what
/// an extractor that writes by itself created or replaced. (A file
/// replaced by one of the same size and time is not seen as changed.)
pub(crate) struct Snapshot(HashMap<PathBuf, (u64, Option<SystemTime>)>);

impl Snapshot {
    pub(crate) fn take(dir: &Path) -> Snapshot {
        let mut m = HashMap::new();
        walk(dir, &mut |p, len, t| {
            m.insert(p.to_path_buf(), (len, t));
        });
        Snapshot(m)
    }

    /// Files below `dir` that are new or changed since the snapshot.
    pub(crate) fn changed(&self, dir: &Path) -> Vec<PathBuf> {
        let mut v = Vec::new();
        walk(dir, &mut |p, len, t| {
            if self.0.get(p) != Some(&(len, t)) {
                v.push(p.to_path_buf());
            }
        });
        v
    }
}

/// Every regular file below `dir` (links are not followed).
fn walk(dir: &Path, f: &mut dyn FnMut(&Path, u64, Option<SystemTime>)) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file()
                && let Ok(m) = e.metadata()
            {
                f(&p, m.len(), m.modified().ok());
            }
        }
    }
}

/// Temporary name a streamed member is written under until it is scanned.
pub(crate) fn pending_name(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".nzpart");
    PathBuf::from(s)
}

/// Message for [`ArchiveError::MalwareFound`].
pub(crate) fn found_message(names: &[String]) -> String {
    const SHOW: usize = 5;
    let mut list = names
        .iter()
        .take(SHOW)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOW {
        list.push_str(&nz_front::trf(" 외 {}개", &[&(names.len() - SHOW)]));
    }
    nz_front::trf(
        "악성코드가 발견되어 {}개 파일을 풀지 않았습니다: {}. 이 압축 파일은 열지 않는 것이 좋습니다.",
        &[&names.len(), &list],
    )
}
