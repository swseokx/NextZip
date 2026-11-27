//! NextZip Explorer context menu: an in-process COM server exposing one
//! `IExplorerCommand` ("NextZip") with three sub-commands:
//!
//! * 여기에 풀기   — `nextzip.exe --extract-here <archives>`
//! * 폴더로 풀기   — `nextzip.exe --extract-folder <archives>`
//! * 압축…         — `nextzip.exe --compress <items>`
//!
//! The DLL never writes the registry and never touches file associations.
//! Registration is done by the scripts in `packaging/` (sparse package for
//! the Windows 11 top-level menu, or per-user HKCU keys for the classic
//! menu), which are run only after the user agrees.
//!
//! `nextzip.exe` is looked up next to this DLL.

use nz_front::tr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicIsize, Ordering};

use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_NOTIMPL, E_POINTER, HMODULE,
    S_FALSE, S_OK,
};
use windows::Win32::System::Com::{CoTaskMemFree, IBindCtx, IClassFactory, IClassFactory_Impl};
use windows::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows::Win32::UI::Shell::{
    ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECS_ENABLED, ECS_HIDDEN, IEnumExplorerCommand,
    IEnumExplorerCommand_Impl, IExplorerCommand, IExplorerCommand_Impl, IShellItemArray, SHStrDupW,
    SIGDN_FILESYSPATH,
};
use windows_core::{
    BOOL, GUID, HRESULT, IUnknown, Interface, PCWSTR, PWSTR, Ref, Result, implement,
};

/// CLSID of the NextZip context menu command.
pub const CLSID_NEXTZIP_MENU: GUID = GUID::from_u128(0x5870dc66_afb5_4e9c_ab2a_31f1bd5321d9);

static LOCKS: AtomicIsize = AtomicIsize::new(0);
static OBJECTS: AtomicIsize = AtomicIsize::new(0);

/// File name suffixes NextZip can extract.
const ARCHIVES: &[&str] = &[
    ".zip", ".7z", ".nz", ".rar", ".alz", ".egg", ".tar.zst", ".tzst", ".zst",
];

pub fn is_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    ARCHIVES.iter().any(|s| name.ends_with(s))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Root,
    ExtractHere,
    ExtractFolder,
    Compress,
}

impl Kind {
    pub fn title(self) -> &'static str {
        nz_front::i18n::init_once();
        match self {
            Kind::Root => "NextZip",
            Kind::ExtractHere => tr("여기에 풀기"),
            Kind::ExtractFolder => tr("폴더로 풀기"),
            Kind::Compress => tr("압축…"),
        }
    }

    fn tooltip(self) -> &'static str {
        nz_front::i18n::init_once();
        match self {
            Kind::Root => tr("NextZip으로 풀거나 압축합니다"),
            Kind::ExtractHere => tr("압축 파일과 같은 폴더에 풉니다"),
            Kind::ExtractFolder => tr("압축 파일 이름으로 폴더를 만들어 풉니다"),
            Kind::Compress => tr("선택한 항목을 압축합니다"),
        }
    }

    fn canonical(self) -> GUID {
        match self {
            Kind::Root => CLSID_NEXTZIP_MENU,
            Kind::ExtractHere => GUID::from_u128(0x5870dc66_afb5_4e9c_ab2a_31f1bd5321da),
            Kind::ExtractFolder => GUID::from_u128(0x5870dc66_afb5_4e9c_ab2a_31f1bd5321db),
            Kind::Compress => GUID::from_u128(0x5870dc66_afb5_4e9c_ab2a_31f1bd5321dc),
        }
    }

    /// Whether the command is shown for `paths` (the selection).
    pub fn visible(self, paths: &[PathBuf]) -> bool {
        match self {
            Kind::Root | Kind::Compress => !paths.is_empty(),
            Kind::ExtractHere | Kind::ExtractFolder => {
                !paths.is_empty() && paths.iter().all(|p| is_archive(p))
            }
        }
    }

    /// `nextzip.exe` arguments for `paths`.
    pub fn arguments(self, paths: &[PathBuf]) -> Vec<String> {
        let flag = match self {
            Kind::Root => return Vec::new(),
            Kind::ExtractHere => "--extract-here",
            Kind::ExtractFolder => "--extract-folder",
            Kind::Compress => "--compress",
        };
        std::iter::once(flag.to_string())
            .chain(paths.iter().map(|p| p.to_string_lossy().into_owned()))
            .collect()
    }
}

/// Directory of this DLL (`nextzip.exe` lives next to it).
fn module_dir() -> Option<PathBuf> {
    let mut h = HMODULE::default();
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(module_dir as *const u16),
            &mut h,
        )
        .ok()?;
        let mut buf = vec![0u16; 32768];
        let n = GetModuleFileNameW(Some(h), &mut buf) as usize;
        if n == 0 {
            return None;
        }
        PathBuf::from(String::from_utf16_lossy(&buf[..n]))
            .parent()
            .map(Path::to_path_buf)
    }
}

fn selection(items: Ref<IShellItemArray>) -> Vec<PathBuf> {
    let Some(items) = items.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    unsafe {
        let n = items.GetCount().unwrap_or(0);
        for i in 0..n {
            let Ok(it) = items.GetItemAt(i) else { continue };
            if let Ok(p) = it.GetDisplayName(SIGDN_FILESYSPATH) {
                if let Ok(s) = p.to_string() {
                    out.push(PathBuf::from(s));
                }
                CoTaskMemFree(Some(p.0 as *const _));
            }
        }
    }
    out
}

fn dup(s: &str) -> Result<PWSTR> {
    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { SHStrDupW(PCWSTR(w.as_ptr())) }
}

#[implement(IExplorerCommand)]
pub struct Command {
    kind: Kind,
}

impl Command {
    pub fn create(kind: Kind) -> IExplorerCommand {
        OBJECTS.fetch_add(1, Ordering::SeqCst);
        Command { kind }.into()
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        OBJECTS.fetch_sub(1, Ordering::SeqCst);
    }
}

impl IExplorerCommand_Impl for Command_Impl {
    fn GetTitle(&self, _items: Ref<IShellItemArray>) -> Result<PWSTR> {
        dup(self.kind.title())
    }

    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> Result<PWSTR> {
        match module_dir() {
            Some(d) => dup(&format!("{},0", d.join("nextzip.exe").display())),
            None => Err(E_NOTIMPL.into()),
        }
    }

    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> Result<PWSTR> {
        dup(self.kind.tooltip())
    }

    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(self.kind.canonical())
    }

    fn GetState(&self, items: Ref<IShellItemArray>, _slow_ok: BOOL) -> Result<u32> {
        let paths = selection(items);
        Ok(if self.kind.visible(&paths) {
            ECS_ENABLED.0 as u32
        } else {
            ECS_HIDDEN.0 as u32
        })
    }

    fn Invoke(&self, items: Ref<IShellItemArray>, _bc: Ref<IBindCtx>) -> Result<()> {
        let paths = selection(items);
        if self.kind == Kind::Root || !self.kind.visible(&paths) {
            return Ok(());
        }
        let exe = module_dir()
            .map(|d| d.join("nextzip.exe"))
            .ok_or_else(|| windows_core::Error::from(E_FAIL))?;
        std::process::Command::new(exe)
            .args(self.kind.arguments(&paths))
            .spawn()
            .map(|_| ())
            .map_err(|_| E_FAIL.into())
    }

    fn GetFlags(&self) -> Result<u32> {
        Ok(if self.kind == Kind::Root {
            ECF_HASSUBCOMMANDS.0 as u32
        } else {
            ECF_DEFAULT.0 as u32
        })
    }

    fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
        if self.kind != Kind::Root {
            return Err(E_NOTIMPL.into());
        }
        Ok(SubCommands {
            items: vec![
                Command::create(Kind::ExtractHere),
                Command::create(Kind::ExtractFolder),
                Command::create(Kind::Compress),
            ],
            pos: std::sync::atomic::AtomicUsize::new(0),
        }
        .into())
    }
}

#[implement(IEnumExplorerCommand)]
struct SubCommands {
    items: Vec<IExplorerCommand>,
    pos: std::sync::atomic::AtomicUsize,
}

impl IEnumExplorerCommand_Impl for SubCommands_Impl {
    fn Next(&self, celt: u32, out: *mut Option<IExplorerCommand>, fetched: *mut u32) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        let mut n = 0u32;
        while n < celt {
            let i = self.pos.load(Ordering::SeqCst);
            let Some(c) = self.items.get(i) else { break };
            unsafe { out.add(n as usize).write(Some(c.clone())) };
            self.pos.store(i + 1, Ordering::SeqCst);
            n += 1;
        }
        if !fetched.is_null() {
            unsafe { *fetched = n };
        }
        if n == celt { S_OK } else { S_FALSE }
    }

    fn Skip(&self, celt: u32) -> Result<()> {
        self.pos.fetch_add(celt as usize, Ordering::SeqCst);
        Ok(())
    }

    fn Reset(&self) -> Result<()> {
        self.pos.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn Clone(&self) -> Result<IEnumExplorerCommand> {
        Ok(SubCommands {
            items: self.items.clone(),
            pos: std::sync::atomic::AtomicUsize::new(self.pos.load(Ordering::SeqCst)),
        }
        .into())
    }
}

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        iid: *const GUID,
        object: *mut *mut core::ffi::c_void,
    ) -> Result<()> {
        if object.is_null() || iid.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *object = std::ptr::null_mut() };
        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let cmd = Command::create(Kind::Root);
        unsafe { cmd.query(iid, object).ok() }
    }

    fn LockServer(&self, lock: BOOL) -> Result<()> {
        if lock.as_bool() {
            LOCKS.fetch_add(1, Ordering::SeqCst);
        } else {
            LOCKS.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// COM entry point.
///
/// # Safety
/// Called by COM with valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const GUID,
    iid: *const GUID,
    out: *mut *mut core::ffi::c_void,
) -> HRESULT {
    if clsid.is_null() || iid.is_null() || out.is_null() {
        return E_POINTER;
    }
    unsafe {
        *out = std::ptr::null_mut();
        if *clsid != CLSID_NEXTZIP_MENU {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let f: IClassFactory = Factory.into();
        f.query(iid, out)
    }
}

/// COM entry point.
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if LOCKS.load(Ordering::SeqCst) == 0 && OBJECTS.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_suffixes() {
        assert!(is_archive(Path::new("C:\\a\\b.ZIP")));
        assert!(is_archive(Path::new("x.tar.zst")));
        assert!(is_archive(Path::new("movie.part1.rar")));
        assert!(!is_archive(Path::new("notes.txt")));
        assert!(!is_archive(Path::new("folder")));
    }

    #[test]
    fn visibility_and_arguments() {
        let arcs = vec![PathBuf::from("a.zip"), PathBuf::from("b.egg")];
        let mixed = vec![PathBuf::from("a.zip"), PathBuf::from("c.txt")];
        assert!(Kind::ExtractHere.visible(&arcs));
        assert!(!Kind::ExtractFolder.visible(&mixed));
        assert!(Kind::Compress.visible(&mixed));
        assert!(!Kind::Compress.visible(&[]));
        assert_eq!(
            Kind::ExtractFolder.arguments(&arcs),
            vec!["--extract-folder", "a.zip", "b.egg"]
        );
        assert_eq!(Kind::Compress.arguments(&mixed)[0], "--compress");
    }

    #[test]
    fn command_objects() {
        nz_front::i18n::set(nz_front::Lang::Korean);
        let root = Command::create(Kind::Root);
        unsafe {
            let t = root.GetTitle(None).unwrap();
            assert_eq!(t.to_string().unwrap(), "NextZip");
            CoTaskMemFree(Some(t.0 as *const _));
            assert_eq!(root.GetFlags().unwrap(), ECF_HASSUBCOMMANDS.0 as u32);
            let e = root.EnumSubCommands().unwrap();
            let mut titles = Vec::new();
            loop {
                let mut c = [None];
                let mut got = 0;
                let _ = e.Next(&mut c, Some(&mut got));
                if got == 0 {
                    break;
                }
                let t = c[0].as_ref().unwrap().GetTitle(None).unwrap();
                titles.push(t.to_string().unwrap());
                CoTaskMemFree(Some(t.0 as *const _));
            }
            assert_eq!(titles, ["여기에 풀기", "폴더로 풀기", "압축…"]);
            // No selection: hidden.
            assert_eq!(root.GetState(None, true).unwrap(), ECS_HIDDEN.0 as u32);
        }
    }
}
