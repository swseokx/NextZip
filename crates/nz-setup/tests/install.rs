//! Install / uninstall into a temporary folder and a scratch registry key
//! (`HKCU\Software\NextZipSetupTest-<pid>`), never the real locations.

use nz_setup::{CLSID, FILES, Item, Layout, read_string};

struct Scratch {
    root: String,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = nz_setup::delete_key(&self.root);
    }
}

fn layout(dir: &std::path::Path, tag: &str) -> (Layout, Scratch) {
    let root = format!(r"Software\NextZipSetupTest-{}-{tag}", std::process::id());
    let l = Layout {
        dir: dir.join("Programs").join("NextZip"),
        classes: format!(r"{root}\Classes"),
        uninstall: format!(r"{root}\Uninstall\NextZip"),
        shortcut: Some(dir.join("Start Menu").join("NextZip.lnk")),
    };
    (l, Scratch { root })
}

fn payload(tag: u8) -> Vec<Item> {
    FILES
        .iter()
        .map(|n| Item {
            name: (*n).into(),
            data: vec![tag; 1000 + n.len()],
        })
        .collect()
}

#[test]
fn install_then_uninstall_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (l, _s) = layout(tmp.path(), "a");
    let notes = nz_setup::install(&l, &payload(1), b"uninstaller").unwrap();
    assert!(notes.is_empty(), "{notes:?}");

    for f in FILES {
        assert_eq!(std::fs::read(l.dir.join(f)).unwrap()[0], 1);
    }
    assert_eq!(
        std::fs::read(l.dir.join("uninstall.exe")).unwrap(),
        b"uninstaller"
    );
    assert!(l.shortcut.as_ref().unwrap().exists());

    let clsid = format!(r"{}\CLSID\{CLSID}", l.classes);
    let dll = l.dir.join("nextzip_shell.dll");
    assert_eq!(
        read_string(&format!(r"{clsid}\InprocServer32"), "").unwrap(),
        dll.to_string_lossy()
    );
    assert_eq!(
        read_string(&format!(r"{clsid}\InprocServer32"), "ThreadingModel").unwrap(),
        "Apartment"
    );
    for k in [r"*\shell\NextZip", r"Directory\shell\NextZip"] {
        let k = format!(r"{}\{k}", l.classes);
        assert_eq!(read_string(&k, "ExplorerCommandHandler").unwrap(), CLSID);
        assert_eq!(read_string(&k, "MUIVerb").unwrap(), "NextZip");
    }
    assert_eq!(read_string(&l.uninstall, "DisplayName").unwrap(), "NextZip");
    assert!(
        read_string(&l.uninstall, "UninstallString")
            .unwrap()
            .ends_with(r#"uninstall.exe" /uninstall"#)
    );
    // No association keys: nothing but CLSID, * and Directory under Classes.
    assert!(read_string(&format!(r"{}\.zip", l.classes), "").is_none());

    // A user file in the install folder survives uninstall.
    std::fs::write(l.dir.join("notes.txt"), b"mine").unwrap();
    let notes = nz_setup::uninstall(&l).unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(nz_setup::leftovers(&l), [l.dir.join("notes.txt")]);
    std::fs::remove_file(l.dir.join("notes.txt")).unwrap();
    assert!(read_string(&format!(r"{clsid}\InprocServer32"), "").is_none());
    assert!(read_string(&l.uninstall, "DisplayName").is_none());
    assert!(read_string(&format!(r"{}\*\shell\NextZip", l.classes), "MUIVerb").is_none());
    assert!(!l.shortcut.as_ref().unwrap().exists());

    // Uninstalling twice is fine.
    nz_setup::uninstall(&l).unwrap();
    assert!(!l.dir.exists());
}

#[test]
fn reinstall_replaces_files_in_use() {
    let tmp = tempfile::tempdir().unwrap();
    let (l, _s) = layout(tmp.path(), "b");
    nz_setup::install(&l, &payload(1), b"u1").unwrap();
    // Hold the DLL open without delete sharing, like a loaded module.
    let dll = l.dir.join("nextzip_shell.dll");
    let held = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1 | 4) // FILE_SHARE_READ | FILE_SHARE_DELETE (rename allowed)
            .open(&dll)
            .unwrap()
    };
    nz_setup::install(&l, &payload(2), b"u2").unwrap();
    assert_eq!(std::fs::read(&dll).unwrap()[0], 2);
    drop(held);
    // The moved-aside copy is swept by the next uninstall.
    nz_setup::uninstall(&l).unwrap();
    assert!(!l.dir.exists(), "{:?}", nz_setup::leftovers(&l));
}

#[test]
fn refuses_empty_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let (l, _s) = layout(tmp.path(), "c");
    let err = nz_setup::install(&l, &[], b"u").unwrap_err();
    assert!(err.to_string().contains("NZ_SETUP_PAYLOAD"), "{err}");
    assert!(!l.dir.exists());
}

#[test]
fn payload_roundtrip() {
    // The development build embeds an empty payload.
    assert!(nz_setup::embedded().unwrap().is_empty());
    assert!(nz_setup::unpack(&[1, 0, 0, 0]).is_err());
}
