//! RAR listing and extraction for NextZip through the UnRAR library
//! (RAR 1.5 to RAR 7, solid, multi-volume, encrypted), via `unrar`/`unrar_sys`.
//!
//! Licence note (required by the UnRAR licence, LICENSE-UNRAR.txt):
//!
//! UnRAR source code may be used in any software to handle RAR archives
//! without limitations free of charge, but cannot be used to develop RAR
//! (WinRAR) compatible archiver and to re-create RAR compression algorithm,
//! which is proprietary. Distribution of modified UnRAR source code in
//! separate form or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code" words, is
//! included in license, or in documentation if license is not available, and
//! in source code comments of resulting package.
//!
//! NextZip only extracts RAR archives; it never creates them.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use nz_front::{tr, trf};
use unrar::error::{Code, UnrarError};

/// Errors the facade maps to its own types.
#[derive(Debug)]
pub enum RarError {
    PasswordRequired,
    WrongPassword,
    Cancelled,
    Other(String),
}

impl std::fmt::Display for RarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RarError::PasswordRequired => f.write_str(tr("암호가 필요합니다")),
            RarError::WrongPassword => f.write_str(tr("암호가 틀렸습니다")),
            RarError::Cancelled => f.write_str(tr("취소했습니다")),
            RarError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for RarError {}

fn map(e: UnrarError, what: &str) -> RarError {
    match e.code {
        Code::MissingPassword => RarError::PasswordRequired,
        Code::BadPassword => RarError::WrongPassword,
        // Encrypted data with a wrong key shows up as a CRC error.
        Code::BadData => {
            RarError::Other(trf("{}: 데이터 손상 또는 잘못된 암호 ({})", &[&what, &e]))
        }
        _ => RarError::Other(format!("{what}: {e}")),
    }
}

#[derive(Debug, Clone)]
pub struct RarEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub csize: u64,
    pub mtime: Option<SystemTime>,
    pub method: String,
    pub crc: Option<u32>,
    pub encrypted: bool,
    /// Symbolic link, junction or other redirection (carries no data).
    pub link: bool,
}

/// Unix `S_IFLNK` in the attribute word, or a Windows reparse point.
fn attr_is_link(attr: u32) -> bool {
    attr & 0xF000 == 0xA000 || attr & 0x400 != 0
}

#[derive(Debug, Clone)]
pub struct RarListing {
    pub entries: Vec<RarEntry>,
    pub solid: bool,
    pub volumes: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct RarStats {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}

fn dos_time(t: u32) -> Option<SystemTime> {
    // Local DOS date/time -> SystemTime, without a time zone crate: treat as
    // UTC for display ordering only (UnRAR restores real mtimes itself).
    let date = t >> 16;
    let time = t & 0xFFFF;
    let y = 1980 + (date >> 9) as i64;
    let mo = ((date >> 5) & 15) as i64;
    let d = (date & 31) as i64;
    if !(1..=12).contains(&mo) || d == 0 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let (y2, m2) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400
        + ((time >> 11) as i64) * 3600
        + (((time >> 5) & 63) as i64) * 60
        + ((time & 31) as i64) * 2;
    u64::try_from(secs)
        .ok()
        .map(|s| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s))
}

fn method_name(m: u32) -> String {
    match m {
        0x30 => "Store".into(),
        0x31..=0x35 => format!("RAR m{}", m - 0x30),
        x => format!("RAR {x:#x}"),
    }
}

fn archive<'a>(path: &'a Path, password: Option<&'a str>) -> unrar::Archive<'a> {
    match password {
        Some(pw) => unrar::Archive::with_password(path, pw),
        None => unrar::Archive::new(path),
    }
}

/// List a RAR archive (pass the first volume of a multi-volume set).
pub fn list(path: &Path, password: Option<&str>) -> Result<RarListing, RarError> {
    let a = archive(path, password);
    let volumes = if a.is_multipart() {
        let mut v: Vec<PathBuf> = (1..1000)
            .map_while(|n| a.nth_part(n).filter(|p| p.is_file()))
            .collect();
        if v.is_empty() {
            v.push(path.to_path_buf());
        }
        v
    } else {
        vec![path.to_path_buf()]
    };
    let mut entries = Vec::new();
    let mut ignore = |_: Event| true;
    let solid = walk(
        path,
        password,
        unrar_sys::RAR_OM_LIST,
        &mut ignore,
        &mut |hd, _st| {
            let len = hd
                .filename_w
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(hd.filename_w.len());
            if hd.flags & 0x01 == 0 {
                entries.push(RarEntry {
                    name: from_wide(&hd.filename_w[..len]).replace('\\', "/"),
                    is_dir: hd.flags & 0x20 != 0,
                    size: u64::from(hd.unp_size) | (u64::from(hd.unp_size_high) << 32),
                    csize: u64::from(hd.pack_size) | (u64::from(hd.pack_size_high) << 32),
                    mtime: dos_time(hd.file_time),
                    method: method_name(hd.method),
                    crc: Some(hd.file_crc),
                    encrypted: hd.flags & 0x04 != 0,
                    link: hd.redir_type != 0 || attr_is_link(hd.file_attr),
                });
            }
            Ok(unrar_sys::RAR_SKIP)
        },
    )?;
    Ok(RarListing {
        entries,
        solid,
        volumes,
    })
}

/// Extract every member below `out_dir`.
///
/// `sanitize` maps a member name to a safe relative path (or `None` to
/// reject it); NextZip passes its zip-slip guard. `on_file(name, bytes,
/// total)` is called after each file and returns `false` to cancel.
pub fn extract(
    path: &Path,
    out_dir: &Path,
    password: Option<&str>,
    on_file: &mut dyn FnMut(&str, u64, u64) -> bool,
    sanitize: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<RarStats, RarError> {
    // Total size first, for progress.
    let total: u64 = list(path, password)
        .map(|l| l.entries.iter().map(|e| e.size).sum())
        .unwrap_or(0);
    let mut stats = RarStats::default();
    let mut cur = archive(path, password)
        .open_for_processing()
        .map_err(|e| map(e, &path.display().to_string()))?;
    loop {
        let Some(item) = cur
            .read_header()
            .map_err(|e| map(e, &path.display().to_string()))?
        else {
            break;
        };
        let h = item.entry();
        let name = h.filename.to_string_lossy().replace('\\', "/");
        let Some(rel) = sanitize(&name) else {
            return Err(RarError::Other(format!(
                "unsafe member name rejected: {name:?}"
            )));
        };
        let dest = out_dir.join(rel);
        if h.is_directory() {
            std::fs::create_dir_all(&dest).map_err(|e| RarError::Other(e.to_string()))?;
            stats.dirs += 1;
            cur = item.skip().map_err(|e| map(e, &name))?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RarError::Other(e.to_string()))?;
        }
        let size = h.unpacked_size;
        let encrypted = h.is_encrypted();
        cur = item.extract_to(&dest).map_err(|e| {
            // RAR4 reports a wrong key only as a CRC error on the data.
            if encrypted && e.code == Code::BadData {
                let _ = std::fs::remove_file(&dest);
                RarError::WrongPassword
            } else {
                map(e, &name)
            }
        })?;
        stats.files += 1;
        stats.bytes += size;
        if !on_file(&name, size, total) {
            return Err(RarError::Cancelled);
        }
    }
    Ok(stats)
}

/// Events delivered by [`stream`].
pub enum Event<'a> {
    /// A file member starts: its index in [`list`] order and its name.
    Start(usize, &'a str),
    /// Decoded data of the current member.
    Data(&'a [u8]),
    /// The current member is complete and its checksum verified.
    Finish,
}

struct StreamState<'a> {
    on: &'a mut dyn FnMut(Event) -> bool,
    /// Set when `on` asked to stop or a volume is missing.
    stop: Option<RarError>,
}

extern "C" fn stream_callback(
    msg: unrar_sys::UINT,
    user: unrar_sys::LPARAM,
    p1: unrar_sys::LPARAM,
    p2: unrar_sys::LPARAM,
) -> std::os::raw::c_int {
    if user == 0 {
        return -1;
    }
    // SAFETY: `user` is the `StreamState` passed to RARSetCallback, alive
    // for the whole RARProcessFileW call that invokes this callback.
    let st = unsafe { &mut *(user as *mut StreamState) };
    match msg {
        unrar_sys::UCM_PROCESSDATA => {
            if p2 <= 0 || p1 == 0 {
                return 1;
            }
            // SAFETY: UnRAR passes a buffer of `p2` bytes at `p1`.
            let data = unsafe { std::slice::from_raw_parts(p1 as *const u8, p2 as usize) };
            if (st.on)(Event::Data(data)) {
                1
            } else {
                st.stop = Some(RarError::Cancelled);
                -1
            }
        }
        unrar_sys::UCM_CHANGEVOLUMEW | unrar_sys::UCM_CHANGEVOLUME => {
            if p2 == unrar_sys::RAR_VOL_ASK {
                st.stop = Some(RarError::Other(tr("다음 볼륨을 찾을 수 없습니다").into()));
                -1
            } else {
                1
            }
        }
        // Passwords are set up front; never prompt.
        unrar_sys::UCM_NEEDPASSWORD | unrar_sys::UCM_NEEDPASSWORDW => -1,
        _ => 0,
    }
}

/// NUL-terminated `wchar_t` string for UnRAR (UTF-16 on Windows).
#[cfg(windows)]
fn wide(s: &std::ffi::OsStr) -> Vec<unrar_sys::WCHAR> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// NUL-terminated `wchar_t` string for UnRAR (UTF-32 elsewhere). Only the
/// Linux fuzz build (OSS-Fuzz) uses this; the shipped app is Windows-only.
#[cfg(not(windows))]
fn wide(s: &std::ffi::OsStr) -> Vec<unrar_sys::WCHAR> {
    s.to_string_lossy()
        .chars()
        .map(|c| c as unrar_sys::WCHAR)
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn from_wide(w: &[unrar_sys::WCHAR]) -> String {
    String::from_utf16_lossy(w)
}

#[cfg(not(windows))]
fn from_wide(w: &[unrar_sys::WCHAR]) -> String {
    w.iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn code_err(code: std::os::raw::c_int, what: &str, encrypted: bool) -> RarError {
    match code {
        unrar_sys::ERAR_MISSING_PASSWORD => RarError::PasswordRequired,
        unrar_sys::ERAR_BAD_PASSWORD => RarError::WrongPassword,
        // RAR4 reports a wrong key only as a CRC error on the data.
        unrar_sys::ERAR_BAD_DATA if encrypted => RarError::WrongPassword,
        unrar_sys::ERAR_BAD_DATA => RarError::Other(trf("{}: 데이터 손상 (CRC 오류)", &[&what])),
        c => RarError::Other(trf("{}: UnRAR 오류 {}", &[&what, &c])),
    }
}

struct RarHandle(*const unrar_sys::Handle);

impl Drop for RarHandle {
    fn drop(&mut self) {
        // SAFETY: handle from a successful RAROpenArchiveEx, closed once.
        unsafe { unrar_sys::RARCloseArchive(self.0) };
    }
}

/// Open `path` and call `each` for every header; `each` returns the
/// operation (RAR_SKIP / RAR_TEST). Returns whether the archive is solid.
fn walk(
    path: &Path,
    password: Option<&str>,
    mode: std::os::raw::c_uint,
    on: &mut dyn FnMut(Event) -> bool,
    each: &mut dyn FnMut(
        &unrar_sys::HeaderDataEx,
        &mut StreamState,
    ) -> Result<std::os::raw::c_int, RarError>,
) -> Result<bool, RarError> {
    let name_w = wide(path.as_os_str());
    let mut st = StreamState { on, stop: None };
    // SAFETY: zeroed OpenArchiveDataEx is a valid "no comment, no callback"
    // request; the name buffer outlives the call.
    let mut od: unrar_sys::OpenArchiveDataEx = unsafe { std::mem::zeroed() };
    od.archive_name_w = name_w.as_ptr() as *const _;
    od.open_mode = mode;
    // SAFETY: valid request struct.
    let h = unsafe { unrar_sys::RAROpenArchiveEx(&od) };
    if h.is_null() || od.open_result != 0 {
        if !h.is_null() {
            drop(RarHandle(h));
        }
        return Err(code_err(
            od.open_result as i32,
            &path.display().to_string(),
            false,
        ));
    }
    let solid = od.flags & 0x0008 != 0;
    let h = RarHandle(h);
    let pw_c;
    if let Some(pw) = password {
        pw_c = std::ffi::CString::new(pw).map_err(|_| RarError::WrongPassword)?;
        // SAFETY: NUL-terminated password; UnRAR copies it.
        unsafe { unrar_sys::RARSetPassword(h.0, pw_c.as_ptr()) };
    }
    // SAFETY: `st` lives until the end of this function, longer than any
    // UnRAR call that can invoke the callback.
    unsafe {
        unrar_sys::RARSetCallback(
            h.0,
            Some(stream_callback),
            &mut st as *mut StreamState as unrar_sys::LPARAM,
        )
    };
    loop {
        // SAFETY: zeroed header is a valid output buffer.
        let mut hd: Box<unrar_sys::HeaderDataEx> = Box::new(unsafe { std::mem::zeroed() });
        // SAFETY: valid handle and header buffer.
        let r = unsafe { unrar_sys::RARReadHeaderEx(h.0, std::ptr::addr_of_mut!(*hd)) };
        if r == unrar_sys::ERAR_END_ARCHIVE {
            break;
        }
        if r != unrar_sys::ERAR_SUCCESS {
            return Err(st
                .stop
                .take()
                .unwrap_or_else(|| code_err(r, "header", false)));
        }
        let op = each(&hd, &mut st)?;
        let encrypted = hd.flags & 0x04 != 0;
        // SAFETY: valid handle; no destination for TEST/SKIP.
        let r = unsafe { unrar_sys::RARProcessFileW(h.0, op, std::ptr::null(), std::ptr::null()) };
        if r != unrar_sys::ERAR_SUCCESS {
            let len = hd
                .filename_w
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(hd.filename_w.len());
            let name = from_wide(&hd.filename_w[..len]);
            return Err(st
                .stop
                .take()
                .unwrap_or_else(|| code_err(r, &name, encrypted)));
        }
        if op == unrar_sys::RAR_TEST && !(st.on)(Event::Finish) {
            return Err(RarError::Cancelled);
        }
    }
    Ok(solid)
}

/// Decode every file member and hand its data to `on` without writing any
/// file (used by the isolated decoder process). Member indices match
/// [`list`]. `on` returns `false` to stop; `want(index)` selects members.
pub fn stream(
    path: &Path,
    password: Option<&str>,
    want: &dyn Fn(usize) -> bool,
    on: &mut dyn FnMut(Event) -> bool,
) -> Result<(), RarError> {
    let mut index = 0usize;
    walk(
        path,
        password,
        unrar_sys::RAR_OM_EXTRACT,
        on,
        &mut |hd, st| {
            let len = hd
                .filename_w
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(hd.filename_w.len());
            let name = from_wide(&hd.filename_w[..len]).replace('\\', "/");
            let flags = hd.flags;
            let is_dir = flags & 0x20 != 0;
            let is_link = hd.redir_type != 0 || attr_is_link(hd.file_attr);
            let split_before = flags & 0x01 != 0;
            let this = index;
            if !split_before {
                index += 1;
            }
            if !is_dir && !is_link && !split_before && want(this) {
                if !(st.on)(Event::Start(this, &name)) {
                    return Err(RarError::Cancelled);
                }
                Ok(unrar_sys::RAR_TEST)
            } else {
                Ok(unrar_sys::RAR_SKIP)
            }
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_time_epoch() {
        // 2026-11-20 12:34:56 -> date bits
        let date = ((2026 - 1980) << 9) | (11 << 5) | 20;
        let time = (12 << 11) | (34 << 5) | 28;
        let t = dos_time((date << 16) | time).unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_795_178_096);
    }
}
