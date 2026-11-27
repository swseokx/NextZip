//! Self-extracting .exe made by `nz-create` with this crate's stub:
//! run it (`-y -o:`), extract it with the library, read it with NextZip's
//! archive reader, and (when available, `NZ_SEVENZIP` or `7z.exe` on PATH)
//! with 7-Zip. An ARM64 SFX is built when `NZ_SFX_ARM64_STUB` names an
//! ARM64 stub; it cannot run on x64, so it is checked through the readers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nz_create::{Kind, Options, sfx::Arch};

fn source(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert("readme.txt".to_string(), b"hello sfx\n".repeat(100));
    files.insert(
        "문서/데이터.bin".to_string(),
        (0..300_000u32).map(|i| (i * 31 % 253) as u8).collect(),
    );
    files.insert("문서/빈 파일.txt".to_string(), Vec::new());
    // PE-looking bytes so nz-core picks its BCJ x86 code path.
    let mut code = b"MZ".to_vec();
    code.extend((0..50_000u32).flat_map(|i| [0xE8, (i % 256) as u8, 0, 0, 0]));
    files.insert("bin/tool.exe".to_string(), code);
    for (n, d) in &files {
        let p = root.join(n);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, d).unwrap();
    }
    files
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

fn make(arch: Arch, stub: PathBuf, src: &Path, out: &Path) {
    let opt = Options {
        sfx_stub: Some(stub),
        ..Default::default()
    };
    let s = nz_create::create(Kind::Sfx(arch), &[src.to_path_buf()], out, &opt).unwrap();
    assert_eq!(s.files, 4);
}

fn sevenzip() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NZ_SEVENZIP") {
        return Some(p.into());
    }
    let ok = std::process::Command::new("7z.exe")
        .arg("i")
        .output()
        .is_ok_and(|o| o.status.success());
    ok.then(|| "7z.exe".into())
}

/// The archive inside `exe` through NextZip's reader and 7-Zip.
fn check_readers(exe: &Path, want: &BTreeMap<String, Vec<u8>>) {
    let out = tempfile::tempdir().unwrap();
    nz_archive::extract(exe, out.path(), &nz_archive::Options::default(), None).unwrap();
    assert_eq!(&tree(out.path()), want, "NextZip reader");
    let Some(z) = sevenzip() else {
        eprintln!("7-Zip not found; skipping cross-check");
        return;
    };
    let o = tempfile::tempdir().unwrap();
    let r = std::process::Command::new(&z)
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", o.path().display()))
        .arg(exe)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stdout));
    assert_eq!(&tree(o.path()), want, "7-Zip");
}

#[test]
fn trailer_magic_matches_writer() {
    assert_eq!(nz_sfx::TRAILER_MAGIC, nz_create::sfx::TRAILER_MAGIC);
}

#[test]
fn native_sfx_runs_and_extracts() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    let want = source(&src);
    let exe = t.path().join("bundle.exe");
    make(
        Arch::native(),
        env!("CARGO_BIN_EXE_nz-sfx").into(),
        &src,
        &exe,
    );

    // The stub itself, unattended.
    let dest = t.path().join("out-run");
    let r = std::process::Command::new(&exe)
        .arg("-y")
        .arg(format!("-o:{}", dest.display()))
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert_eq!(tree(&dest), want);

    // Without -y in the library: existing files are not replaced.
    assert!(nz_sfx::extract_sfx(&exe, &dest, false).is_err());
    let s = nz_sfx::extract_sfx(&exe, &dest, true).unwrap();
    assert_eq!(s.files, 4);

    check_readers(&exe, &want);
}

#[test]
fn wrong_architecture_stub_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    source(&src);
    let other = match Arch::native() {
        Arch::X64 => Arch::Arm64,
        Arch::Arm64 => Arch::X64,
    };
    let opt = Options {
        sfx_stub: Some(env!("CARGO_BIN_EXE_nz-sfx").into()),
        ..Default::default()
    };
    let out = t.path().join("x.exe");
    let e = nz_create::create(Kind::Sfx(other), &[src], &out, &opt).unwrap_err();
    assert!(format!("{e:#}").contains("not a"), "{e:#}");
    assert!(!out.exists());
}

#[test]
fn arm64_sfx_reads_back() {
    let Some(stub) = std::env::var_os("NZ_SFX_ARM64_STUB") else {
        eprintln!("NZ_SFX_ARM64_STUB not set; skipping");
        return;
    };
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    let want = source(&src);
    let exe = t.path().join("bundle-arm64.exe");
    make(Arch::Arm64, stub.into(), &src, &exe);
    let dest = t.path().join("lib");
    nz_sfx::extract_sfx(&exe, &dest, false).unwrap();
    assert_eq!(tree(&dest), want);
    check_readers(&exe, &want);
}

#[test]
fn damaged_payload_fails_cleanly() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    source(&src);
    let exe = t.path().join("bundle.exe");
    make(
        Arch::native(),
        env!("CARGO_BIN_EXE_nz-sfx").into(),
        &src,
        &exe,
    );
    let mut b = std::fs::read(&exe).unwrap();
    let n = b.len();
    for i in (n - 4000..n - 100).step_by(37) {
        b[i] ^= 0x55;
    }
    let bad = t.path().join("bad.exe");
    std::fs::write(&bad, b).unwrap();
    assert!(nz_sfx::extract_sfx(&bad, &t.path().join("o"), true).is_err());
    // No trailer at all.
    assert!(
        nz_sfx::extract_sfx(
            Path::new(env!("CARGO_BIN_EXE_nz-sfx")),
            &t.path().join("o2"),
            true
        )
        .is_err()
    );
}
