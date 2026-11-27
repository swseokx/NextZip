//! `.nz` archives through the facade (GUI and shell path).

use nz_archive::{ArchiveError, Kind, Options, archive_error};

fn make(dir: &std::path::Path, password: Option<&str>) -> std::path::PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello nz\n".repeat(1000)).unwrap();
    std::fs::write(src.join("sub").join("b.bin"), vec![7u8; 50_000]).unwrap();
    let out = dir.join("t.nz");
    let opt = nz_nzf::WriteOptions {
        password: password.map(str::to_owned),
        kdf: nz_nzf::KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        ..Default::default()
    };
    nz_nzf::create(&[src], &out, &opt).unwrap();
    out
}

#[test]
fn list_and_extract_nz() {
    let t = tempfile::tempdir().unwrap();
    let nz = make(t.path(), None);
    let l = nz_archive::list(&nz, &Options::default()).unwrap();
    assert_eq!(l.kind, Kind::Nz);
    let names: Vec<_> = l.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a.txt"), "{names:?}");
    assert!(names.contains(&"sub/b.bin"), "{names:?}");

    let out = t.path().join("out");
    let s = nz_archive::extract(&nz, &out, &Options::default(), None).unwrap();
    assert_eq!(s.files, 2);
    assert_eq!(
        std::fs::read(out.join("a.txt")).unwrap(),
        b"hello nz\n".repeat(1000)
    );
    assert_eq!(
        std::fs::read(out.join("sub/b.bin")).unwrap(),
        vec![7u8; 50_000]
    );
}

#[test]
fn nz_password_errors() {
    let t = tempfile::tempdir().unwrap();
    let nz = make(t.path(), Some("pw"));
    let e = nz_archive::list(&nz, &Options::default()).unwrap_err();
    assert!(matches!(
        archive_error(&e),
        Some(ArchiveError::PasswordRequired)
    ));
    let bad = Options {
        password: Some("nope".into()),
        ..Default::default()
    };
    let e = nz_archive::extract(&nz, &t.path().join("o"), &bad, None).unwrap_err();
    assert!(matches!(
        archive_error(&e),
        Some(ArchiveError::WrongPassword)
    ));
    let good = Options {
        password: Some("pw".into()),
        ..Default::default()
    };
    let s = nz_archive::extract(&nz, &t.path().join("o2"), &good, None).unwrap();
    assert_eq!(s.files, 2);
}
