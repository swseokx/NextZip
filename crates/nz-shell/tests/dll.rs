//! Load the built `nextzip_shell.dll` the way Explorer does (no registry):
//! DllGetClassObject -> IClassFactory -> IExplorerCommand, then query the
//! menu for a real selection of files.

use std::path::PathBuf;

use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, IClassFactory,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Shell::{
    ECS_ENABLED, ECS_HIDDEN, IExplorerCommand, IShellItem, IShellItemArray,
    SHCreateItemFromParsingName, SHCreateShellItemArrayFromShellItem,
};
use windows_core::{GUID, HRESULT, HSTRING, Interface, s};

type GetClassObject =
    unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut core::ffi::c_void) -> HRESULT;

fn dll_path() -> PathBuf {
    // The test exe lives somewhere under target/ (deps/ or build/<pkg>/...);
    // the cdylib is at target/<profile>/nextzip_shell.dll.
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let exe = std::env::current_exe().unwrap();
    for dir in exe.ancestors() {
        let p = dir.join(profile).join("nextzip_shell.dll");
        if p.exists() {
            return p;
        }
        let p = dir.join("nextzip_shell.dll");
        if dir.file_name().is_some_and(|n| n == profile) && p.exists() {
            return p;
        }
    }
    exe.with_file_name("nextzip_shell.dll")
}

fn selection(path: &std::path::Path) -> IShellItemArray {
    unsafe {
        let it: IShellItem =
            SHCreateItemFromParsingName(&HSTRING::from(path.as_os_str()), None).unwrap();
        SHCreateShellItemArrayFromShellItem(&it).unwrap()
    }
}

#[test]
fn explorer_style_activation() {
    let dll = dll_path();
    if !dll.exists() {
        eprintln!("skipped: {} not built", dll.display());
        return;
    }
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let h = LoadLibraryW(&HSTRING::from(dll.as_os_str())).unwrap();
        let f = GetProcAddress(h, s!("DllGetClassObject")).expect("export");
        let get: GetClassObject = std::mem::transmute(f);
        let clsid = nextzip_shell::CLSID_NEXTZIP_MENU;
        let mut p = std::ptr::null_mut();
        get(&clsid, &IClassFactory::IID, &mut p).ok().unwrap();
        let factory = IClassFactory::from_raw(p);
        let cmd: IExplorerCommand = factory.CreateInstance(None).unwrap();

        let t = cmd.GetTitle(None).unwrap();
        assert_eq!(t.to_string().unwrap(), "NextZip");
        CoTaskMemFree(Some(t.0 as *const _));

        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("photos.zip");
        let txt = dir.path().join("notes.txt");
        std::fs::write(&zip, b"PK\x05\x06").unwrap();
        std::fs::write(&txt, b"x").unwrap();

        // Archive selected: every sub-command is shown.
        let subs = cmd.EnumSubCommands().unwrap();
        let mut states = Vec::new();
        loop {
            let mut c = [None];
            let mut got = 0;
            let _ = subs.Next(&mut c, Some(&mut got));
            if got == 0 {
                break;
            }
            let c = c[0].take().unwrap();
            states.push((
                c.GetState(&selection(&zip), true).unwrap(),
                c.GetState(&selection(&txt), true).unwrap(),
            ));
        }
        let on = ECS_ENABLED.0 as u32;
        let off = ECS_HIDDEN.0 as u32;
        // (zip, txt) for 여기에 풀기 / 폴더로 풀기 / 압축…
        assert_eq!(states, vec![(on, off), (on, off), (on, on)]);

        // Unknown class is refused.
        let other = GUID::from_u128(1);
        let mut q = std::ptr::null_mut();
        assert!(get(&other, &IClassFactory::IID, &mut q).is_err());
    }
}
