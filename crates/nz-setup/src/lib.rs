//! Per-user install and uninstall of NextZip.
//!
//! Everything lives under the current user: files in
//! `%LOCALAPPDATA%\Programs\NextZip`, registry under `HKCU` only, no
//! elevation. Installed keys:
//!
//! - `Software\Classes\CLSID\{5870dc66-…}` (the `IExplorerCommand` server),
//!   `Software\Classes\*\shell\NextZip` and `Software\Classes\Directory\shell\NextZip`
//!   — the same keys as `crates/nz-shell/packaging/register-hkcu.ps1`;
//! - `Software\Microsoft\Windows\CurrentVersion\Uninstall\NextZip` (Apps &
//!   features entry);
//! - a Start menu shortcut.
//!
//! File associations (ProgIDs, `OpenWithProgids`, default apps) are never
//! touched. Uninstall removes exactly these keys and files and nothing else.
//! [`Layout`] carries every location so tests can install into a temporary
//! folder and a scratch registry key.

use nz_front::{tr, trf};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, IPersistFile,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
    RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW,
};
use windows::Win32::UI::Shell::{
    IShellLinkW, SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify, ShellLink,
};
use windows::core::{HSTRING, Interface, PCWSTR};

/// CLSID of the context menu server in `nextzip_shell.dll`.
pub const CLSID: &str = "{5870dc66-afb5-4e9c-ab2a-31f1bd5321d9}";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Files the payload must contain, in install order.
pub const FILES: [&str; 6] = [
    "nextzip.exe",
    "nz.exe",
    "nz-decode.exe",
    "nextzip_shell.dll",
    "nz-sfx-x64.exe",
    "nz-sfx-arm64.exe",
];
pub const UNINSTALLER: &str = "uninstall.exe";

/// Where an installation lives.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Install folder.
    pub dir: PathBuf,
    /// Key under `HKCU` that plays the role of `Software\Classes`.
    pub classes: String,
    /// Full key under `HKCU` of the uninstall entry.
    pub uninstall: String,
    /// Start menu shortcut, if any.
    pub shortcut: Option<PathBuf>,
}

impl Layout {
    /// The real per-user locations.
    pub fn user() -> Result<Layout> {
        let local = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?;
        let roaming = std::env::var_os("APPDATA").context("APPDATA is not set")?;
        Ok(Layout {
            dir: Path::new(&local).join("Programs").join("NextZip"),
            classes: r"Software\Classes".into(),
            uninstall: r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NextZip".into(),
            shortcut: Some(
                Path::new(&roaming)
                    .join(r"Microsoft\Windows\Start Menu\Programs")
                    .join("NextZip.lnk"),
            ),
        })
    }

    fn shell_keys(&self) -> [String; 3] {
        [
            format!(r"{}\CLSID\{CLSID}", self.classes),
            format!(r"{}\*\shell\NextZip", self.classes),
            format!(r"{}\Directory\shell\NextZip", self.classes),
        ]
    }
}

/// One file of the payload.
pub struct Item {
    pub name: String,
    pub data: Vec<u8>,
}

/// Decode a payload made by `build.rs`.
pub fn unpack(bytes: &[u8]) -> Result<Vec<Item>> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
        if b.len() < n {
            bail!("payload is truncated");
        }
        let (h, t) = b.split_at(n);
        *b = t;
        Ok(h)
    }
    let mut b = bytes;
    let count = u32::from_le_bytes(take(&mut b, 4)?.try_into()?);
    let mut out = Vec::new();
    for _ in 0..count {
        let nlen = u16::from_le_bytes(take(&mut b, 2)?.try_into()?) as usize;
        let name = String::from_utf8(take(&mut b, nlen)?.to_vec())?;
        let size = u64::from_le_bytes(take(&mut b, 8)?.try_into()?) as usize;
        let clen = u64::from_le_bytes(take(&mut b, 8)?.try_into()?) as usize;
        let data = zstd::bulk::decompress(take(&mut b, clen)?, size)
            .with_context(|| format!("payload file {name} is corrupt"))?;
        if data.len() != size {
            bail!("payload file {name} has the wrong size");
        }
        out.push(Item { name, data });
    }
    Ok(out)
}

/// The payload embedded in this binary (empty in a development build).
pub fn embedded() -> Result<Vec<Item>> {
    unpack(include_bytes!(concat!(env!("OUT_DIR"), "/payload.bin")))
}

// ------------------------------------------------------------- registry

fn check(e: WIN32_ERROR, what: &str) -> Result<()> {
    if e == ERROR_SUCCESS {
        Ok(())
    } else {
        bail!("{what}: {}", windows::core::Error::from(e.to_hresult()))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn create_key(path: &str) -> Result<HKEY> {
    let mut key = HKEY::default();
    let e = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            &HSTRING::from(path),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
    };
    check(e, &format!(r"cannot create HKCU\{path}"))?;
    Ok(key)
}

fn set(key: HKEY, name: &str, ty: REG_VALUE_TYPE, data: &[u8]) -> Result<()> {
    let e = unsafe { RegSetValueExW(key, &HSTRING::from(name), None, ty, Some(data)) };
    check(e, &format!("cannot set value {name:?}"))
}

/// Set string values (`""` = default value) on `HKCU\path`.
fn set_strings(path: &str, values: &[(&str, &str)]) -> Result<()> {
    let key = create_key(path)?;
    let r = values.iter().try_for_each(|(n, v)| {
        let w = wide(v);
        let bytes: Vec<u8> = w.iter().flat_map(|c| c.to_le_bytes()).collect();
        set(key, n, REG_SZ, &bytes)
    });
    unsafe {
        let _ = RegCloseKey(key);
    }
    r
}

fn set_dwords(path: &str, values: &[(&str, u32)]) -> Result<()> {
    let key = create_key(path)?;
    let r = values
        .iter()
        .try_for_each(|(n, v)| set(key, n, REG_DWORD, &v.to_le_bytes()));
    unsafe {
        let _ = RegCloseKey(key);
    }
    r
}

/// Delete `HKCU\path` with everything below it; a missing key is fine.
fn delete_tree(path: &str) -> Result<bool> {
    let e = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, &HSTRING::from(path)) };
    if e == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    check(e, &format!(r"cannot delete HKCU\{path}"))?;
    Ok(true)
}

/// Read a string value of `HKCU\path` (`""` = default value).
pub fn read_string(path: &str, name: &str) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = (buf.len() * 2) as u32;
    let name = HSTRING::from(name);
    let e = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            &HSTRING::from(path),
            if name.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(name.as_ptr())
            },
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut len),
        )
    };
    if e != ERROR_SUCCESS {
        return None;
    }
    buf.truncate((len as usize / 2).saturating_sub(1));
    Some(String::from_utf16_lossy(&buf))
}

// ---------------------------------------------------------------- files

/// Write `data` to `dst`, replacing a file that may be in use: Explorer
/// keeps `nextzip_shell.dll` loaded and a running GUI locks `nextzip.exe`.
/// A locked file can still be renamed, so it is moved aside as
/// `<name>.old-<n>` and removed on a later install or uninstall.
fn put(dst: &Path, data: &[u8]) -> Result<()> {
    let tmp = dst.with_file_name(format!(
        "{}.new",
        dst.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp, data).with_context(|| format!("cannot write {}", tmp.display()))?;
    if dst.exists() && std::fs::remove_file(dst).is_err() {
        let aside = aside_name(dst);
        std::fs::rename(dst, &aside)
            .with_context(|| format!("{} is in use and cannot be replaced", dst.display()))?;
    }
    std::fs::rename(&tmp, dst).with_context(|| format!("cannot write {}", dst.display()))?;
    Ok(())
}

fn aside_name(p: &Path) -> PathBuf {
    let base = p.file_name().unwrap_or_default().to_string_lossy();
    (0u32..)
        .map(|n| p.with_file_name(format!("{base}.old-{n}")))
        .find(|c| !c.exists())
        .expect("free name")
}

/// Remove files moved aside by [`put`]; returns those still locked.
fn sweep_aside(dir: &Path) -> Vec<PathBuf> {
    let mut left = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let ours = FILES.iter().chain([&UNINSTALLER]).any(|f| {
                n.strip_prefix(f)
                    .is_some_and(|rest| rest.starts_with(".old-") || rest == ".new")
            });
            if ours && std::fs::remove_file(e.path()).is_err() {
                left.push(e.path());
            }
        }
    }
    left
}

fn create_shortcut(lnk: &Path, target: &Path) -> Result<()> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(&HSTRING::from(target.as_os_str()))?;
        if let Some(d) = target.parent() {
            link.SetWorkingDirectory(&HSTRING::from(d.as_os_str()))?;
        }
        link.SetDescription(&HSTRING::from("NextZip"))?;
        let file: IPersistFile = link.cast()?;
        if let Some(d) = lnk.parent() {
            std::fs::create_dir_all(d)?;
        }
        file.Save(&HSTRING::from(lnk.as_os_str()), true)?;
    }
    Ok(())
}

fn notify_shell() {
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
}

// -------------------------------------------------------------- install

/// Install `payload` (and `uninstaller`, normally this setup binary) into
/// `layout`. Returns notes for the user.
pub fn install(layout: &Layout, payload: &[Item], uninstaller: &[u8]) -> Result<Vec<String>> {
    for f in FILES {
        if !payload.iter().any(|i| i.name == f) {
            bail!("this setup was built without {f} (set NZ_SETUP_PAYLOAD when building)");
        }
    }
    let mut notes = Vec::new();
    std::fs::create_dir_all(&layout.dir)
        .with_context(|| format!("cannot create {}", layout.dir.display()))?;
    sweep_aside(&layout.dir);
    for i in payload {
        put(&layout.dir.join(&i.name), &i.data)?;
    }
    put(&layout.dir.join(UNINSTALLER), uninstaller)?;

    let dll = layout.dir.join("nextzip_shell.dll");
    let exe = layout.dir.join("nextzip.exe");
    let [clsid, star, dir] = layout.shell_keys();
    set_strings(&clsid, &[("", "NextZip context menu")])?;
    set_strings(
        &format!(r"{clsid}\InprocServer32"),
        &[
            ("", &dll.to_string_lossy()),
            ("ThreadingModel", "Apartment"),
        ],
    )?;
    for k in [&star, &dir] {
        set_strings(
            k,
            &[("ExplorerCommandHandler", CLSID), ("MUIVerb", "NextZip")],
        )?;
    }

    let un = layout.dir.join(UNINSTALLER);
    let size_kb: u64 = payload.iter().map(|i| i.data.len() as u64).sum::<u64>() / 1024
        + uninstaller.len() as u64 / 1024;
    set_strings(
        &layout.uninstall,
        &[
            ("DisplayName", "NextZip"),
            ("DisplayVersion", VERSION),
            ("Publisher", "NextZip project"),
            ("InstallLocation", &layout.dir.to_string_lossy()),
            ("DisplayIcon", &format!("{},0", exe.display())),
            (
                "UninstallString",
                &format!("\"{}\" /uninstall", un.display()),
            ),
            (
                "QuietUninstallString",
                &format!("\"{}\" /uninstall /quiet", un.display()),
            ),
        ],
    )?;
    set_dwords(
        &layout.uninstall,
        &[
            ("NoModify", 1),
            ("NoRepair", 1),
            ("EstimatedSize", size_kb.min(u32::MAX as u64) as u32),
        ],
    )?;
    if let Some(lnk) = &layout.shortcut {
        match create_shortcut(lnk, &exe) {
            Ok(()) => {}
            Err(e) => notes.push(trf("시작 메뉴 바로 가기를 만들지 못했습니다: {}", &[&e])),
        }
    }
    notify_shell();
    if layout
        .dir
        .read_dir()?
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains(".old-"))
    {
        notes.push(
            tr("이전 버전 파일 일부가 사용 중이라 옆으로 옮겨 두었습니다. 탐색기를 다시 시작하거나 \
             로그아웃하면 다음 설치·제거 때 지워집니다.")
            .into(),
        );
    }
    Ok(notes)
}

/// Remove everything [`install`] created under `layout`. Returns notes.
pub fn uninstall(layout: &Layout) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    for k in layout.shell_keys() {
        delete_tree(&k)?;
    }
    delete_tree(&layout.uninstall)?;
    if let Some(lnk) = &layout.shortcut {
        let _ = std::fs::remove_file(lnk);
    }
    notify_shell();
    let mut locked = Vec::new();
    for f in FILES.iter().chain([&UNINSTALLER]) {
        let p = layout.dir.join(f);
        if p.exists() && std::fs::remove_file(&p).is_err() {
            // In use (the shell DLL inside Explorer, or this very
            // uninstaller): move aside so the name is free, retry later.
            let aside = aside_name(&p);
            if std::fs::rename(&p, &aside).is_err() {
                locked.push(p);
            }
        }
    }
    locked.extend(sweep_aside(&layout.dir));
    // Only an empty folder is removed: user files are never deleted.
    let _ = std::fs::remove_dir(&layout.dir);
    if !locked.is_empty() {
        notes.push(trf(
            "사용 중인 파일 {}개는 지우지 못했습니다(탐색기가 셸 DLL을 사용 중일 수 있음). \
             탐색기를 다시 시작한 뒤 {} 폴더를 지우면 됩니다.",
            &[&locked.len(), &layout.dir.display()],
        ));
    }
    Ok(notes)
}

/// Locked leftovers of a previous uninstall (for tests and the UI).
pub fn leftovers(layout: &Layout) -> Vec<PathBuf> {
    std::fs::read_dir(&layout.dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Delete `HKCU\path` (tests clean their scratch keys with this).
pub fn delete_key(path: &str) -> Result<bool> {
    delete_tree(path)
}
