//! NextZip archive facade: one API to list and extract every format the
//! front ends (CLI, GUI, shell extension) open.
//!
//! * ZIP: `nz-core`'s reader plus legacy-name code page detection
//!   ([`codepage`]) and ZipCrypto decryption
//! * 7z, tar.zst: `nz-core`
//! * ALZ, EGG: [`alz`], [`egg`] (own readers, split and encrypted archives)
//! * RAR: `nz-rar` (UnRAR, extraction only; feature `rar`)
//!
//! Every member name goes through [`safepath::sanitize`] before anything is
//! written, so crafted names cannot escape the output folder.

pub mod alz;
pub mod bzip2;
pub mod codepage;
pub mod crypto;
pub mod egg;
#[doc(hidden)]
pub mod fuzzing;
pub mod isolated;
mod motw;
pub mod multivol;
mod nzf;
pub mod safepath;
mod scan;

use nz_front::tr;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;

pub use codepage::{Codepage, Detection};

/// Largest member decoded in memory (legacy formats decode whole members).
pub const MAX_MEMBER: u64 = 4 << 30;

/// Most that is allocated up front from a size read from an archive header;
/// buffers grow beyond it only as data is actually decoded.
pub(crate) const PREALLOC: usize = 64 << 20;

/// Errors front ends react to (ask for a password, show "unsupported").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    PasswordRequired,
    WrongPassword,
    Unsupported(String),
    Cancelled,
    /// The malware scan (AMSI) flagged these members; they were not
    /// written. Everything else was extracted.
    MalwareFound(Vec<String>),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::PasswordRequired => f.write_str(tr("암호가 필요합니다")),
            ArchiveError::WrongPassword => f.write_str(tr("암호가 틀렸습니다")),
            ArchiveError::Unsupported(what) => {
                f.write_str(&nz_front::trf("지원하지 않는 기능: {}", &[what]))
            }
            ArchiveError::Cancelled => f.write_str(tr("취소했습니다")),
            ArchiveError::MalwareFound(names) => f.write_str(&scan::found_message(names)),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// The `ArchiveError` inside an `anyhow` chain, if any.
pub fn archive_error(e: &anyhow::Error) -> Option<&ArchiveError> {
    e.chain().find_map(|c| c.downcast_ref::<ArchiveError>())
}

/// Archive kinds recognised by content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Kind {
    Zip,
    SevenZ,
    TarZst,
    Alz,
    Egg,
    Rar,
    /// NextZip's own `.nz` container (newest snapshot).
    Nz,
    /// A format read by `nz-formats` in the isolated decoder process.
    Fmt(nz_formats::Format),
    /// Something `nz-core` recognises that this facade has no lister for.
    Other,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Zip => "ZIP",
            Kind::SevenZ => "7Z",
            Kind::TarZst => "TAR.ZST",
            Kind::Alz => "ALZ",
            Kind::Egg => "EGG",
            Kind::Rar => "RAR",
            Kind::Nz => "NZ",
            Kind::Fmt(f) => f.label(),
            Kind::Other => tr("기타"),
        }
    }

    pub fn sniff(path: &Path) -> Result<Kind> {
        let mut head = [0u8; 8];
        let n = File::open(path)
            .with_context(|| format!("cannot open {}", path.display()))?
            .read(&mut head)?;
        let h = &head[..n];
        if nz_nzf::sniff(path) {
            return Ok(Kind::Nz);
        }
        // Split `x.zip.001` / `x.7z.001` sets: read joined in the isolated
        // full-coder readers.
        let split = nz_formats::util::split_volumes(path).is_some();
        Ok(if split && h.starts_with(b"PK") {
            Kind::Fmt(nz_formats::Format::ZipFull)
        } else if split && h.starts_with(b"7z\xBC\xAF\x27\x1C") {
            Kind::Fmt(nz_formats::Format::SevenZ)
        } else if h.starts_with(b"PK\x03\x04") || h.starts_with(b"PK\x05\x06") {
            Kind::Zip
        } else if h.starts_with(b"7z\xBC\xAF\x27\x1C") {
            Kind::SevenZ
        } else if h.len() >= 4 && h[0] & 0xF0 == 0x50 && h[1..4] == [0x2A, 0x4D, 0x18] {
            // zstd starting with a skippable frame (0x184D2A50..5F), which
            // the in-process tar.zst path does not take.
            Kind::Fmt(nz_formats::Format::Zst)
        } else if h.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            tar_or_stream(path, Kind::TarZst, nz_formats::Format::Zst)
        } else if h.starts_with(b"ALZ\x01") {
            Kind::Alz
        } else if h.starts_with(b"EGGA") {
            Kind::Egg
        } else if h.starts_with(b"Rar!\x1A\x07") {
            Kind::Rar
        } else if let Ok(f) = nz_core::Format::sniff(path) {
            use nz_core::Format as C;
            use nz_formats::Format as F;
            match f {
                C::TarGz => tar_or_stream(path, Kind::Other, F::Gz),
                C::TarXz => tar_or_stream(path, Kind::Other, F::Xz),
                C::TarBz2 => tar_or_stream(path, Kind::Other, F::Bz2),
                C::TarLz4 => tar_or_stream(path, Kind::Other, F::Lz4),
                C::TarZst => tar_or_stream(path, Kind::Other, F::Zst),
                _ => Kind::Other,
            }
        } else if let Some(f) = nz_formats::detect(path) {
            Kind::Fmt(f)
        } else if let Some(e) = nz_formats::util::embedded(path) {
            // Self-extractors and archives behind a stub.
            use nz_formats::util::Embedded;
            match e {
                Embedded::SevenZ(_) => Kind::Fmt(nz_formats::Format::SevenZ),
                Embedded::Rar(_) => Kind::Rar,
                Embedded::Zip => Kind::Fmt(nz_formats::Format::ZipFull),
            }
        } else {
            bail!(nz_front::trf(
                "{}: 알 수 없는 압축 형식",
                &[&path.display()]
            ))
        })
    }
}

/// A compressed stream holding tar goes to `nz-core` (in process, parallel
/// codecs); any other payload is a single-file stream read by `nz-formats`.
fn tar_or_stream(path: &Path, tar: Kind, stream: nz_formats::Format) -> Kind {
    if nz_formats::stream::inner_is_tar(stream, path) {
        tar
    } else {
        Kind::Fmt(stream)
    }
}

/// One member as shown in a file list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Entry {
    /// `/`-separated path inside the archive.
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Compressed size (0 when unknown, e.g. inside a solid block).
    pub csize: u64,
    #[serde(skip)]
    pub mtime: Option<SystemTime>,
    pub method: String,
    pub crc: Option<u32>,
    pub encrypted: bool,
}

/// Result of [`list`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct Listing {
    pub kind: Kind,
    pub entries: Vec<Entry>,
    /// Code page detection for legacy (non-UTF-8) names, if any were present.
    pub detection: Option<Detection>,
    /// Code page actually used for legacy names.
    pub codepage: Option<Codepage>,
    pub solid: bool,
    pub volumes: Vec<PathBuf>,
}

impl Listing {
    pub fn total_size(&self) -> u64 {
        self.entries
            .iter()
            .fold(0u64, |a, e| a.saturating_add(e.size))
    }
    pub fn total_csize(&self) -> u64 {
        self.entries
            .iter()
            .fold(0u64, |a, e| a.saturating_add(e.csize))
    }
    pub fn files(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_dir).count()
    }
    pub fn any_encrypted(&self) -> bool {
        self.entries.iter().any(|e| e.encrypted)
    }
}

/// Options for [`list`] and [`extract`].
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Force a code page for legacy names instead of detecting it.
    pub codepage: Option<Codepage>,
    /// System code page used as a tie-break hint by the detector.
    pub hint: Option<Codepage>,
    pub password: Option<String>,
    /// Worker threads (0: all logical processors).
    pub threads: usize,
    /// Scan extracted content with Windows AMSI before it is written
    /// (spec 9). Off in `Default`; front ends take it from the
    /// `malware_scan` setting, which is on unless the user turns it off.
    pub malware_scan: bool,
    /// Recreate symbolic links (tar family) as real links. Off (spec 9
    /// default): every link becomes a small text file holding its target.
    /// A link pointing outside the output folder is never extracted.
    pub symlinks: bool,
}

/// Most bytes of members decoded in memory at the same time (ZIP, ALZ and
/// EGG decode whole members; without a cap a small archive with a few big
/// members could hold several GiB at once). A member larger than this
/// still runs, alone.
pub const MEMORY_BUDGET: u64 = 2 << 30;

/// Counts the bytes of members being decoded in memory; [`MemBudget::take`]
/// waits while taking more would pass [`MEMORY_BUDGET`].
struct MemBudget {
    used: Mutex<u64>,
    freed: std::sync::Condvar,
}

struct MemTicket<'a> {
    budget: &'a MemBudget,
    n: u64,
}

impl MemBudget {
    fn new() -> MemBudget {
        MemBudget {
            used: Mutex::new(0),
            freed: std::sync::Condvar::new(),
        }
    }

    /// Reserve `n` bytes (a declared member size) until the ticket drops.
    fn take(&self, n: u64) -> MemTicket<'_> {
        let n = n.min(MEMORY_BUDGET);
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        while *used > 0 && *used + n > MEMORY_BUDGET {
            used = self.freed.wait(used).unwrap_or_else(|e| e.into_inner());
        }
        *used += n;
        MemTicket { budget: self, n }
    }

    #[cfg(test)]
    fn used(&self) -> u64 {
        *self.used.lock().unwrap()
    }
}

impl Drop for MemTicket<'_> {
    fn drop(&mut self) {
        let mut used = self.budget.used.lock().unwrap_or_else(|e| e.into_inner());
        *used -= self.n;
        self.budget.freed.notify_all();
    }
}

impl Options {
    /// Wipe the password from memory (front ends call this when they are
    /// done with it; spec 9 "암호는 메모리에서 사용 후 제로화").
    pub fn forget_password(&mut self) {
        if let Some(mut p) = self.password.take() {
            zeroize::Zeroize::zeroize(&mut p);
        }
    }
}

/// Shared progress and cancellation state (poll it from a UI thread).
#[derive(Debug, Default)]
pub struct Progress {
    /// Bytes to write in total (uncompressed), once known.
    pub total: AtomicU64,
    /// Uncompressed bytes written so far.
    pub done: AtomicU64,
    pub files: AtomicU64,
    pub cancel: AtomicBool,
    pub current: Mutex<String>,
    /// Notices for the user that do not stop the operation (for example
    /// "extracting without a malware scan").
    pub notes: Mutex<Vec<String>>,
}

impl Progress {
    fn check(&self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(ArchiveError::Cancelled.into());
        }
        Ok(())
    }
    fn note(&self, msg: String) {
        if let Ok(mut n) = self.notes.lock() {
            n.push(msg);
        }
    }
    fn file_done(&self, name: &str, bytes: u64) {
        self.done.fetch_add(bytes, Ordering::Relaxed);
        self.files.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut c) = self.current.lock() {
            c.clear();
            c.push_str(name);
        }
    }
}

pub use nz_core::ExtractStats;

/// List the members of `path`.
pub fn list(path: &Path, opt: &Options) -> Result<Listing> {
    let kind = Kind::sniff(path)?;
    let mut l = Listing {
        kind,
        entries: Vec::new(),
        detection: None,
        codepage: None,
        solid: false,
        volumes: vec![path.to_path_buf()],
    };
    match kind {
        Kind::Zip => {
            let f = File::open(path)?;
            let entries = nz_core::zip::read_central(&f)?;
            let (names, det, cp) = zip_names(&entries, opt);
            l.detection = det;
            l.codepage = cp;
            l.entries = entries
                .iter()
                .zip(names)
                .map(|(e, name)| Entry {
                    name,
                    is_dir: e.is_dir,
                    size: e.usize,
                    csize: e.csize,
                    mtime: e.mtime,
                    method: match e.method {
                        0 => "Store".into(),
                        8 => "Deflate".into(),
                        9 => "Deflate64".into(),
                        12 => "BZip2".into(),
                        14 => "LZMA".into(),
                        93 => "Zstd".into(),
                        99 => "AES".into(),
                        m => format!("Method {m}"),
                    },
                    crc: Some(e.crc),
                    encrypted: e.flags & 1 != 0,
                })
                .collect();
        }
        Kind::SevenZ => {
            let f = File::open(path)?;
            let a = match nz_core::sevenz::open(&f) {
                Ok(a) => a,
                Err(_) => {
                    let b = isolated::Backend::Formats(nz_formats::Format::SevenZ);
                    let r = isolated::list(b, path, opt.password.as_deref())?;
                    l.solid = r.solid;
                    l.entries = r.members.iter().map(entry_from_member).collect();
                    return Ok(l);
                }
            };
            l.solid = a.folders().iter().any(|(_, _, _, n)| *n > 1);
            l.entries = a
                .items
                .iter()
                .map(|i| Entry {
                    name: i.name.replace('\\', "/"),
                    is_dir: i.is_dir,
                    size: i.size,
                    csize: 0,
                    mtime: i.mtime,
                    method: "7z".into(),
                    crc: i.crc,
                    encrypted: false,
                })
                .collect();
        }
        Kind::TarZst => {
            l.solid = true;
            let dec = zstd::stream::read::Decoder::new(File::open(path)?)?;
            let mut ar = tar::Archive::new(dec);
            for item in ar.entries()? {
                let item = item?;
                let h = item.header();
                l.entries.push(Entry {
                    name: item.path()?.to_string_lossy().replace('\\', "/"),
                    is_dir: h.entry_type().is_dir(),
                    size: h.size().unwrap_or(0),
                    csize: 0,
                    mtime: h.mtime().ok().and_then(|t| {
                        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(t))
                    }),
                    method: "zstd".into(),
                    crc: None,
                    encrypted: false,
                });
            }
        }
        Kind::Alz => {
            let a = alz::open(path)?;
            let (names, det, cp) = legacy_names(
                a.members.iter().map(|m| m.raw_name.as_slice()),
                opt,
                Some(Codepage::Cp949),
            );
            l.detection = det;
            l.codepage = cp;
            l.volumes = a.reader.paths();
            l.entries = a
                .members
                .iter()
                .zip(names)
                .map(|(m, name)| Entry {
                    name,
                    is_dir: m.is_dir(),
                    size: m.usize,
                    csize: m.csize,
                    mtime: m.mtime(),
                    method: m.method_name(),
                    crc: Some(m.crc),
                    encrypted: m.encrypted(),
                })
                .collect();
        }
        Kind::Egg => {
            let e = egg::open(path)?;
            l.solid = e.solid;
            l.volumes = e.reader.paths();
            l.entries = e
                .members
                .iter()
                .map(|m| Entry {
                    name: m.name.clone(),
                    is_dir: m.is_dir,
                    size: m.size,
                    csize: m.csize(),
                    mtime: m.mtime,
                    method: m.method_name(),
                    crc: (m.blocks.len() == 1).then(|| m.blocks[0].crc),
                    encrypted: m.encryption.is_some(),
                })
                .collect();
        }
        Kind::Rar | Kind::Fmt(_) => {
            let r = isolated::list(backend(kind), path, opt.password.as_deref())?;
            l.solid = r.solid;
            if !r.volumes.is_empty() {
                l.volumes = r.volumes;
            }
            l.entries = r.members.iter().map(entry_from_member).collect();
            if let Some((names, det, cp)) = member_names(&r.members, opt) {
                for (e, n) in l.entries.iter_mut().zip(names) {
                    e.name = n;
                }
                l.detection = det;
                l.codepage = cp;
            }
        }
        Kind::Nz => {
            (l.entries, l.solid) = nzf::list(path, opt)?;
        }
        Kind::Other => {
            return Err(ArchiveError::Unsupported(tr("이 형식의 목록 보기").into()).into());
        }
    }
    Ok(l)
}

/// Isolated backend for a kind read in `nz-decode.exe`.
fn backend(kind: Kind) -> isolated::Backend {
    match kind {
        Kind::Fmt(f) => isolated::Backend::Formats(f),
        _ => isolated::Backend::Rar,
    }
}

fn unix_to_system(t: i64) -> Option<SystemTime> {
    if t >= 0 {
        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(t as u64))
    } else {
        std::time::UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(t.unsigned_abs()))
    }
}

fn entry_from_member(m: &nz_formats::Member) -> Entry {
    Entry {
        name: m.name.replace('\\', "/"),
        is_dir: m.is_dir,
        size: m.size,
        csize: m.csize,
        mtime: m.mtime.and_then(unix_to_system),
        method: m.method.clone(),
        crc: m.crc,
        encrypted: m.encrypted,
    }
}

#[cfg(feature = "rar")]
pub(crate) fn map_rar_err(e: nz_rar::RarError) -> anyhow::Error {
    match e {
        nz_rar::RarError::PasswordRequired => ArchiveError::PasswordRequired.into(),
        nz_rar::RarError::WrongPassword => ArchiveError::WrongPassword.into(),
        nz_rar::RarError::Cancelled => ArchiveError::Cancelled.into(),
        nz_rar::RarError::Other(m) => anyhow::anyhow!(m),
    }
}

/// Decode legacy names: forced code page, else detection with `default_hint`.
fn legacy_names<'a>(
    raw: impl Iterator<Item = &'a [u8]> + Clone,
    opt: &Options,
    default_hint: Option<Codepage>,
) -> (Vec<String>, Option<Detection>, Option<Codepage>) {
    let det = codepage::detect(raw.clone(), opt.hint.or(default_hint));
    let cp = opt.codepage.unwrap_or(det.codepage);
    let names = raw.map(|r| cp.decode_lossy(r).replace('\\', "/")).collect();
    let det = (det.names_checked > 0).then_some(det);
    (names, det, Some(cp))
}

/// Names of `nz-formats` members when some are in a legacy code page:
/// detection runs over those raw names (UTF-8 ones pass through as bytes).
fn member_names(
    members: &[nz_formats::Member],
    opt: &Options,
) -> Option<(Vec<String>, Option<Detection>, Option<Codepage>)> {
    if opt.codepage.is_none() && members.iter().all(|m| m.raw_name.is_none()) {
        return None;
    }
    let raw: Vec<&[u8]> = members
        .iter()
        .map(|m| m.raw_name.as_deref().unwrap_or(m.name.as_bytes()))
        .collect();
    Some(legacy_names(raw.iter().copied(), opt, None))
}

fn zip_names(
    entries: &[nz_core::zip::ZipEntry],
    opt: &Options,
) -> (Vec<String>, Option<Detection>, Option<Codepage>) {
    let legacy: Vec<&[u8]> = entries
        .iter()
        .filter(|e| e.legacy_name)
        .map(|e| e.raw_name.as_slice())
        .collect();
    let det = codepage::detect(legacy.iter().copied(), opt.hint);
    if det.names_checked == 0 && opt.codepage.is_none() {
        return (
            entries.iter().map(|e| e.name.replace('\\', "/")).collect(),
            None,
            None,
        );
    }
    let cp = opt.codepage.unwrap_or(det.codepage);
    let names = entries
        .iter()
        .map(|e| {
            if e.legacy_name {
                cp.decode_lossy(&e.raw_name).replace('\\', "/")
            } else {
                e.name.replace('\\', "/")
            }
        })
        .collect();
    (names, (det.names_checked > 0).then_some(det), Some(cp))
}

pub(crate) fn inflate(data: &[u8], size: usize) -> Result<Vec<u8>> {
    nz_core::deflate::inflate_exact(data, size)
}

pub(crate) fn dos_to_system(time: u16, date: u16) -> Option<SystemTime> {
    use chrono::{Local, TimeZone};
    let y = 1980 + i32::from(date >> 9);
    let mo = u32::from((date >> 5) & 15);
    let d = u32::from(date & 31);
    let h = u32::from(time >> 11);
    let mi = u32::from((time >> 5) & 63);
    let s = u32::from(time & 31) * 2;
    let dt = Local.with_ymd_and_hms(y, mo, d, h, mi, s).earliest()?;
    Some(dt.into())
}

/// Write one member below the output folder (name already sanitised by the
/// caller), creating its parent folder first if no member did yet. A parent
/// missing anyway (removed meanwhile) is created again.
fn write_member(dirs: &Dirs, rel: &Path, data: &[u8], mtime: Option<SystemTime>) -> Result<()> {
    dirs.ensure_parent(rel)?;
    let dest = dirs.out_dir.join(rel);
    let mut f = match File::create(&dest) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            File::create(&dest)
        }
        r => r,
    }
    .with_context(|| format!("cannot create {}", dest.display()))?;
    f.write_all(data)?;
    if let Some(t) = mtime {
        let _ = f.set_modified(t);
    }
    Ok(())
}

fn sanitized(name: &str) -> Result<PathBuf> {
    safepath::sanitize(name).with_context(|| format!("unsafe member name rejected: {name:?}"))
}

fn pool(threads: usize) -> Result<rayon::ThreadPool> {
    let n = if threads == 0 {
        nz_core::default_threads()
    } else {
        threads
    };
    Ok(rayon::ThreadPoolBuilder::new().num_threads(n).build()?)
}

/// Extract everything in `archive` into `out_dir`.
pub fn extract(
    archive: &Path,
    out_dir: &Path,
    opt: &Options,
    progress: Option<&Progress>,
) -> Result<ExtractStats> {
    let fallback = Progress::default();
    let prog = progress.unwrap_or(&fallback);
    let kind = Kind::sniff(archive)?;
    let guard = scan::Guard::new(opt.malware_scan, prog);
    // Mark-of-the-Web: files written by this extraction inherit the
    // archive's Internet zone mark (spec 9), even when it fails halfway.
    let mark = motw::mark_for(archive);
    let before = mark.as_ref().map(|_| scan::Snapshot::take(out_dir));
    let stats = extract_kind(kind, archive, out_dir, opt, prog, &guard);
    if let (Some(m), Some(b)) = (&mark, &before) {
        for p in b.changed(out_dir) {
            motw::apply(&p, m);
        }
    }
    let stats = stats?;
    guard.finish()?;
    Ok(stats)
}

fn extract_kind(
    kind: Kind,
    archive: &Path,
    out_dir: &Path,
    opt: &Options,
    prog: &Progress,
    guard: &scan::Guard,
) -> Result<ExtractStats> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;
    let pw = opt.password.as_deref().map(str::as_bytes);
    let budget = MemBudget::new();
    let mut stats = ExtractStats::default();
    match kind {
        Kind::Zip => {
            let f = File::open(archive)?;
            let entries = nz_core::zip::read_central(&f)?;
            check_zip_layout(&entries, f.metadata()?.len())?;
            check_entries(entries.len(), archive)?;
            let (names, _, _) = zip_names(&entries, opt);
            if entries.iter().any(zip_needs_full_reader) {
                return extract_isolated(
                    isolated::Backend::Formats(nz_formats::Format::ZipFull),
                    archive,
                    out_dir,
                    opt,
                    prog,
                    Some(names),
                    guard,
                );
            }
            prog.total.store(
                entries.iter().fold(0u64, |a, e| a.saturating_add(e.usize)),
                Ordering::Relaxed,
            );
            let (jobs, dirs) = plan(
                &names,
                entries.iter().map(|e| e.is_dir),
                &mut stats,
                out_dir,
                prog,
            )?;
            let bytes: Vec<Option<u64>> = pool(opt.threads)?.install(|| {
                jobs.par_iter()
                    .map(|(i, rel)| -> Result<Option<u64>> {
                        prog.check()?;
                        let e = &entries[*i];
                        let _mem = budget.take(e.usize);
                        let data = read_zip_member(&f, e, pw).with_context(|| names[*i].clone())?;
                        if !guard.clean(&names[*i], &data)? {
                            return Ok(None);
                        }
                        write_member(&dirs, rel, &data, e.mtime)?;
                        prog.file_done(&names[*i], data.len() as u64);
                        Ok(Some(data.len() as u64))
                    })
                    .collect::<Result<_>>()
            })?;
            dirs.finish()?;
            stats.files = bytes.iter().flatten().count();
            stats.bytes = bytes.iter().flatten().sum();
        }
        Kind::Alz => {
            let a = alz::open(archive)?;
            check_total(a.members.iter().map(|m| m.usize), archive)?;
            check_entries(a.members.len(), archive)?;
            let (names, _, _) = legacy_names(
                a.members.iter().map(|m| m.raw_name.as_slice()),
                opt,
                Some(Codepage::Cp949),
            );
            prog.total
                .store(a.members.iter().map(|m| m.usize).sum(), Ordering::Relaxed);
            let (jobs, dirs) = plan(
                &names,
                a.members.iter().map(|m| m.is_dir()),
                &mut stats,
                out_dir,
                prog,
            )?;
            let bytes: Vec<Option<u64>> = pool(opt.threads)?.install(|| {
                jobs.par_iter()
                    .map(|(i, rel)| -> Result<Option<u64>> {
                        prog.check()?;
                        let m = &a.members[*i];
                        let _mem = budget.take(m.usize);
                        let data = a.read(m, pw).with_context(|| names[*i].clone())?;
                        if !guard.clean(&names[*i], &data)? {
                            return Ok(None);
                        }
                        write_member(&dirs, rel, &data, m.mtime())?;
                        prog.file_done(&names[*i], data.len() as u64);
                        Ok(Some(data.len() as u64))
                    })
                    .collect::<Result<_>>()
            })?;
            dirs.finish()?;
            stats.files = bytes.iter().flatten().count();
            stats.bytes = bytes.iter().flatten().sum();
        }
        Kind::Egg => {
            let e = egg::open(archive)?;
            check_total(e.members.iter().map(|m| m.size), archive)?;
            check_entries(e.members.len(), archive)?;
            let names: Vec<String> = e.members.iter().map(|m| m.name.clone()).collect();
            prog.total
                .store(e.members.iter().map(|m| m.size).sum(), Ordering::Relaxed);
            let (jobs, dirs) = plan(
                &names,
                e.members.iter().map(|m| m.is_dir),
                &mut stats,
                out_dir,
                prog,
            )?;
            if e.solid {
                let want: std::collections::HashMap<usize, &PathBuf> =
                    jobs.iter().map(|(i, p)| (*i, p)).collect();
                e.read_solid(pw, |i, data| {
                    prog.check()?;
                    if let Some(rel) = want.get(&i)
                        && guard.clean(&names[i], &data)?
                    {
                        write_member(&dirs, rel, &data, e.members[i].mtime)?;
                        prog.file_done(&names[i], data.len() as u64);
                        stats.files += 1;
                        stats.bytes += data.len() as u64;
                    }
                    Ok(())
                })?;
            } else {
                let bytes: Vec<Option<u64>> = pool(opt.threads)?.install(|| {
                    jobs.par_iter()
                        .map(|(i, rel)| -> Result<Option<u64>> {
                            prog.check()?;
                            let m = &e.members[*i];
                            let _mem = budget.take(m.size);
                            let data = e.read(m, pw).with_context(|| names[*i].clone())?;
                            if !guard.clean(&names[*i], &data)? {
                                return Ok(None);
                            }
                            write_member(&dirs, rel, &data, m.mtime)?;
                            prog.file_done(&names[*i], data.len() as u64);
                            Ok(Some(data.len() as u64))
                        })
                        .collect::<Result<_>>()
                })?;
                stats.files = bytes.iter().flatten().count();
                stats.bytes = bytes.iter().flatten().sum();
            }
            dirs.finish()?;
        }
        Kind::Nz => {
            stats = nzf::extract(archive, out_dir, opt, prog, guard)?;
        }
        Kind::Rar | Kind::Fmt(_) => {
            stats = extract_isolated(backend(kind), archive, out_dir, opt, prog, None, guard)?;
        }
        Kind::SevenZ => {
            let mut notice = None;
            if let Ok(a) = nz_core::sevenz::open(&File::open(archive)?) {
                check_total(a.items.iter().map(|i| i.size), archive)?;
                check_entries(a.items.len(), archive)?;
                notice = safepath::rename_notice(a.items.iter().map(|i| i.name.as_str()));
            }
            let threads = if opt.threads == 0 {
                nz_core::default_threads()
            } else {
                opt.threads
            };
            let before = guard.snapshot(out_dir);
            match nz_core::extract(archive, out_dir, threads) {
                Ok(s) => {
                    guard.scan_written(out_dir, before)?;
                    // (The isolated fallback reports names itself.)
                    if let Some(n) = notice {
                        prog.note(n);
                    }
                    stats = s;
                    prog.done.fetch_add(stats.bytes, Ordering::Relaxed);
                    prog.files.fetch_add(stats.files as u64, Ordering::Relaxed);
                }
                // Coders nz-core does not implement (PPMd, BZip2, BCJ2,
                // ARM64, Delta, AES, ...): the isolated full 7z reader.
                Err(_) => {
                    stats = extract_isolated(
                        isolated::Backend::Formats(nz_formats::Format::SevenZ),
                        archive,
                        out_dir,
                        opt,
                        prog,
                        None,
                        guard,
                    )?;
                }
            }
        }
        Kind::TarZst | Kind::Other => {
            // nz-core extractors sanitise names themselves
            // (walk::safe_relative); the stream's real size is only known
            // while decoding, so the bomb limit is applied there.
            let before = guard.snapshot(out_dir);
            let renamed: Mutex<(usize, Option<(String, String)>)> = Mutex::new((0, None));
            let on_name = |name: &str, rel: &Path| {
                if let Some(new) = safepath::changed(name, rel)
                    && let Ok(mut r) = renamed.lock()
                {
                    r.0 += 1;
                    r.1.get_or_insert_with(|| (name.to_string(), new));
                }
            };
            let len = std::fs::metadata(archive)?.len();
            let xo = nz_core::ExtractOptions {
                max_total: Some(isolated::Limits::for_archive(len).total),
                max_entries: Some(max_entries(len)),
                on_name: Some(&on_name),
                symlinks: opt.symlinks,
            };
            let threads = if opt.threads == 0 {
                nz_core::default_threads()
            } else {
                opt.threads
            };
            let r = nz_core::extract_with(archive, out_dir, threads, &xo);
            if let Ok((n, Some((old, new)))) = renamed.into_inner() {
                prog.note(safepath::notice(n, &old, &new));
            }
            stats = r.map_err(|e| limit_error(e, len))?;
            guard.scan_written(out_dir, before)?;
            prog.done.fetch_add(stats.bytes, Ordering::Relaxed);
            prog.files.fetch_add(stats.files as u64, Ordering::Relaxed);
        }
    }
    Ok(stats)
}

/// Most members an archive of `archive_len` bytes may have (spec 9 "파일
/// 수 상한"): one per byte of the archive plus 10,000. Every real member
/// costs more than a byte (headers, names), even in a compressed tar or a
/// 7z with a compressed header; see `bench/results/M5-2026-11-22.md` for
/// the measurements behind the formula.
pub fn max_entries(archive_len: u64) -> u64 {
    archive_len.saturating_add(10_000)
}

fn too_many(limit: u64) -> anyhow::Error {
    anyhow::anyhow!(nz_front::trf(
        "압축 폭탄 의심: 항목 수가 한도({}개)를 넘습니다",
        &[&limit]
    ))
}

/// Stop before extracting when the archive lists more members than
/// [`max_entries`] allows.
fn check_entries(count: usize, archive: &Path) -> Result<()> {
    let limit = max_entries(std::fs::metadata(archive)?.len());
    if count as u64 > limit {
        return Err(too_many(limit));
    }
    Ok(())
}

/// nz-core's limit errors in the user's language.
fn limit_error(e: anyhow::Error, archive_len: u64) -> anyhow::Error {
    match e.downcast_ref::<nz_core::LimitExceeded>() {
        Some(nz_core::LimitExceeded::Total) => {
            anyhow::anyhow!(tr("압축 폭탄 의심: 출력이 한도를 넘었습니다"))
        }
        Some(nz_core::LimitExceeded::Entries) => too_many(max_entries(archive_len)),
        None => e,
    }
}

/// Zip-bomb guard on declared sizes (spec 9): the members of an archive
/// may not add up to more than [`isolated::Limits::for_archive`] allows
/// (4096 times the archive plus 1 GiB, at most 64 GiB).
fn check_total(sizes: impl Iterator<Item = u64>, archive: &Path) -> Result<()> {
    let len = std::fs::metadata(archive)?.len();
    let total = sizes.fold(0u64, u64::saturating_add);
    if total > isolated::Limits::for_archive(len).total {
        bail!(tr("압축 폭탄 의심: 풀린 크기 합계가 한도를 넘습니다"));
    }
    Ok(())
}

/// ZIP layout checks before anything is extracted (spec 9 "겹치는 로컬
/// 헤더 감지"): every member's local header and data lie inside the file,
/// no two members share or overlap their data (the overlapping-file zip
/// bomb reuses one deflate stream for many members), and the declared
/// sizes pass [`check_total`].
pub fn check_zip_layout(entries: &[nz_core::zip::ZipEntry], file_len: u64) -> Result<()> {
    let mut spans = Vec::with_capacity(entries.len());
    let mut total = 0u64;
    for e in entries {
        // A local header is at least 30 bytes, then the data.
        let end = e
            .local_offset
            .checked_add(30)
            .and_then(|x| x.checked_add(e.csize));
        match end {
            Some(end) if end <= file_len => spans.push((e.local_offset, end)),
            _ => bail!(tr("손상된 ZIP: 항목 데이터가 파일 밖을 가리킵니다")),
        }
        total = total.saturating_add(e.usize);
    }
    if total > isolated::Limits::for_archive(file_len).total {
        bail!(tr("압축 폭탄 의심: 풀린 크기 합계가 한도를 넘습니다"));
    }
    spans.sort_unstable();
    if spans.windows(2).any(|w| w[1].0 < w[0].1) {
        bail!(tr("압축 폭탄 의심: ZIP 항목의 데이터가 서로 겹칩니다"));
    }
    Ok(())
}

/// ZIP members `nz-core` and the ZipCrypto path cannot read: methods other
/// than Store/Deflate, WinZip AES, PKWARE strong encryption.
fn zip_needs_full_reader(e: &nz_core::zip::ZipEntry) -> bool {
    !e.is_dir && (!matches!(e.method, 0 | 8) || e.flags & 0x40 != 0)
}

/// List and extract through the isolated decoder process. `names`
/// replaces the decoder's member names when it lists the same number of
/// members (ZIP legacy names decoded with our code page detection).
fn extract_isolated(
    b: isolated::Backend,
    archive: &Path,
    out_dir: &Path,
    opt: &Options,
    prog: &Progress,
    names: Option<Vec<String>>,
    guard: &scan::Guard,
) -> Result<ExtractStats> {
    let mut stats = ExtractStats::default();
    let l = isolated::list(b, archive, opt.password.as_deref())?;
    check_entries(l.members.len(), archive)?;
    let names: Vec<String> = match names {
        Some(n) if n.len() == l.members.len() => n,
        _ => match member_names(&l.members, opt) {
            Some((n, _, _)) => n,
            None => l
                .members
                .iter()
                .map(|m| m.name.replace('\\', "/"))
                .collect(),
        },
    };
    prog.total.store(
        l.members.iter().fold(0u64, |a, m| a.saturating_add(m.size)),
        Ordering::Relaxed,
    );
    let (mut jobs, dirs) = plan(
        &names,
        l.members.iter().map(|m| m.is_dir),
        &mut stats,
        out_dir,
        prog,
    )?;
    // The isolated decoder writes the files itself: every folder first.
    dirs.create_all()?;
    // Links (spec 9): written as small text files holding the target, and
    // only when the target stays inside the output folder. The decoder is
    // not asked for them.
    let mut link_files = 0usize;
    jobs.retain(|(i, rel)| {
        let Some(target) = &l.members[*i].link else {
            return true;
        };
        // (An unknown target, as RAR listings give, writes nothing.)
        if !target.is_empty() && safepath::link_inside(rel, target) {
            let dest = out_dir.join(rel);
            if let Some(p) = dest.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            if std::fs::write(&dest, target.as_bytes()).is_ok() {
                link_files += 1;
            }
        }
        false
    });
    let size = std::fs::metadata(archive).map(|m| m.len()).unwrap_or(0);
    let (files, bytes) = isolated::extract(
        b,
        archive,
        opt.password.as_deref(),
        out_dir,
        &jobs,
        &|i| l.members[i].mtime.and_then(unix_to_system),
        &|i| names[i].clone(),
        prog,
        isolated::Limits::for_archive(size),
        guard,
    )?;
    stats.files = files + link_files;
    stats.bytes = bytes;
    Ok(stats)
}

/// Output folders of one extraction. Each file's parent folder is created
/// by the first member that needs it, while other members are already being
/// written (creating the 249 folders of the benchmark set up front took
/// 20-35 ms of a ~200 ms extraction); explicit folder entries are created by
/// [`Dirs::finish`].
struct Dirs {
    out_dir: PathBuf,
    parents: std::collections::HashMap<PathBuf, std::sync::OnceLock<Result<(), String>>>,
    explicit: Vec<PathBuf>,
}

impl Dirs {
    /// Make sure the parent folder of `rel` exists.
    fn ensure_parent(&self, rel: &Path) -> Result<()> {
        let Some(cell) = rel.parent().and_then(|p| self.parents.get(p)) else {
            return Ok(());
        };
        cell.get_or_init(|| {
            let p = self.out_dir.join(rel.parent().unwrap_or(rel));
            std::fs::create_dir_all(&p).map_err(|e| format!("cannot create {}: {e}", p.display()))
        })
        .clone()
        .map_err(|e| anyhow::anyhow!(e))
    }

    /// Create every folder now (explicit entries and file parents).
    fn create_all(&self) -> Result<()> {
        self.parents
            .keys()
            .collect::<Vec<_>>()
            .par_iter()
            .try_for_each(|d| -> Result<()> {
                let p = self.out_dir.join(d);
                std::fs::create_dir_all(&p)
                    .with_context(|| format!("cannot create {}", p.display()))
            })?;
        self.finish()
    }

    /// Create the folders that the archive lists as entries.
    fn finish(&self) -> Result<()> {
        self.explicit.par_iter().try_for_each(|d| -> Result<()> {
            let p = self.out_dir.join(d);
            std::fs::create_dir_all(&p).with_context(|| format!("cannot create {}", p.display()))
        })
    }
}

/// Sanitise every name and return the file jobs and the folders to create.
/// Names changed to fit Windows are reported in `prog.notes`.
fn plan(
    names: &[String],
    is_dir: impl Iterator<Item = bool>,
    stats: &mut ExtractStats,
    out_dir: &Path,
    prog: &Progress,
) -> Result<(Vec<(usize, PathBuf)>, Dirs)> {
    if let Some(n) = safepath::rename_notice(names.iter().map(String::as_str)) {
        prog.note(n);
    }
    let mut jobs = Vec::new();
    let mut dirs = Dirs {
        out_dir: out_dir.to_path_buf(),
        parents: std::collections::HashMap::new(),
        explicit: Vec::new(),
    };
    for (i, d) in is_dir.enumerate() {
        let rel = sanitized(&names[i])?;
        if d {
            dirs.explicit.push(rel);
            stats.dirs += 1;
        } else {
            if let Some(p) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
                dirs.parents.entry(p.to_path_buf()).or_default();
            }
            jobs.push((i, rel));
        }
    }
    Ok((jobs, dirs))
}

/// Read a ZIP member, decrypting traditional PKWARE encryption if needed.
fn read_zip_member(
    f: &File,
    e: &nz_core::zip::ZipEntry,
    password: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if e.flags & 1 == 0 {
        return nz_core::zip::read_entry(f, e);
    }
    if e.method == 99 || e.flags & 0x40 != 0 {
        return Err(ArchiveError::Unsupported(tr("ZIP AES/강력 암호화").into()).into());
    }
    let pw = password.ok_or(ArchiveError::PasswordRequired)?;
    let mut lh = [0u8; 30];
    nz_core::zip::read_at(f, &mut lh, e.local_offset)?;
    ensure!(lh[..4] == *b"PK\x03\x04", "bad local header");
    let nlen = u64::from(u16::from_le_bytes([lh[26], lh[27]]));
    let xlen = u64::from(u16::from_le_bytes([lh[28], lh[29]]));
    let mod_time = u16::from_le_bytes([lh[10], lh[11]]);
    ensure!(
        e.csize >= 12 && e.usize <= MAX_MEMBER,
        "bad encrypted member"
    );
    let mut data = vec![0u8; e.csize as usize];
    nz_core::zip::read_at(f, &mut data, e.local_offset + 30 + nlen + xlen)?;
    let mut zc = crypto::ZipCrypto::new(pw);
    let mut head = [0u8; 12];
    head.copy_from_slice(&data[..12]);
    let check = zc.check_header(&head);
    let expect = if e.flags & 8 != 0 {
        (mod_time >> 8) as u8
    } else {
        (e.crc >> 24) as u8
    };
    if check != expect {
        return Err(ArchiveError::WrongPassword.into());
    }
    let body = &mut data[12..];
    zc.decrypt(body);
    let out = match e.method {
        0 => body.to_vec(),
        8 => inflate(body, e.usize as usize).map_err(|_| ArchiveError::WrongPassword)?,
        m => bail!("unsupported compression method {m}"),
    };
    if crc32fast::hash(&out) != e.crc {
        return Err(ArchiveError::WrongPassword.into());
    }
    Ok(out)
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn memory_budget_waits_and_lets_one_big_member_run() {
        let b = MemBudget::new();
        let t1 = b.take(MEMORY_BUDGET - 10);
        assert_eq!(b.used(), MEMORY_BUDGET - 10);
        // A second member that does not fit waits until the first ends.
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                let _t = b.take(100);
                b.used()
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(!h.is_finished());
            drop(t1);
            assert_eq!(h.join().unwrap(), 100);
        });
        assert_eq!(b.used(), 0);
        // Bigger than the budget: runs alone, counted as the whole budget.
        let t = b.take(10 * MEMORY_BUDGET);
        assert_eq!(b.used(), MEMORY_BUDGET);
        drop(t);
        assert_eq!(b.used(), 0);
    }
}
