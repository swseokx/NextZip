//! Every writer -> our readers (nz-formats), and -> 7-Zip (`7z t`, `7z x`)
//! when it is available (`NZ_SEVENZIP` or a `7z.exe` on PATH), so the
//! layout is confirmed by an independent implementation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nz_create::{Kind, Options, stream::Codec, zipx::Method};
use nz_formats::{Format, VecSink};

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let long = format!("{}.txt", "긴이름".repeat(40)); // 123 UTF-16 units
    let mut files = BTreeMap::new();
    files.insert("hello.txt".to_string(), b"hello nextzip\n".repeat(50));
    files.insert(
        "문서/보고서 2026.txt".to_string(),
        (0..70_000u32).map(|i| (i * 7 % 251) as u8).collect(),
    );
    files.insert("문서/빈 파일.txt".to_string(), Vec::new());
    files.insert("a/x.y.txt".to_string(), b"one".to_vec());
    files.insert("a/x_y.txt".to_string(), b"two".to_vec());
    files.insert(format!("a/{long}"), b"long".to_vec());
    for (n, d) in &files {
        let p = root.join(n);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, d).unwrap();
    }
    std::fs::create_dir_all(root.join("빈 폴더")).unwrap();
    files
}

fn read(f: Format, p: &Path) -> BTreeMap<String, Vec<u8>> {
    let opt = nz_formats::Options::default();
    let mut s = VecSink::default();
    nz_formats::extract(f, p, &opt, &mut s).unwrap();
    s.files.into_iter().collect()
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

fn check_7z(p: &Path, want: &BTreeMap<String, Vec<u8>>, exact_names: bool) {
    let Some(z) = sevenzip() else {
        eprintln!("7-Zip not found; skipping cross-check of {}", p.display());
        return;
    };
    let t = std::process::Command::new(&z)
        .arg("t")
        .arg(p)
        .output()
        .unwrap();
    assert!(
        t.status.success(),
        "7z t {}: {}",
        p.display(),
        String::from_utf8_lossy(&t.stdout)
    );
    let out = tempfile::tempdir().unwrap();
    let x = std::process::Command::new(&z)
        .arg("x")
        .arg(format!("-o{}", out.path().display()))
        .arg(p)
        .output()
        .unwrap();
    assert!(x.status.success());
    if exact_names {
        for (n, d) in want {
            let got = std::fs::read(out.path().join(n)).unwrap_or_else(|e| panic!("7z {n}: {e}"));
            assert_eq!(&got, d, "7z content of {n}");
        }
    }
}

#[test]
fn zipx_all_methods() {
    let src = tempfile::tempdir().unwrap();
    let want = tree(src.path());
    let out = tempfile::tempdir().unwrap();
    for m in [
        Method::Zstd,
        Method::Lzma,
        Method::Ppmd,
        Method::Xz,
        Method::Bzip2,
    ] {
        let p = out.path().join(format!("{m:?}.zipx"));
        let s = nz_create::create(
            Kind::Zipx(m),
            &[src.path().to_path_buf()],
            &p,
            &Options::default(),
        )
        .unwrap();
        assert_eq!(s.files, want.len());
        assert_eq!(read(Format::ZipFull, &p), want, "{m:?}");
        check_7z(&p, &want, true);
    }
}

#[test]
fn iso_joliet() {
    let src = tempfile::tempdir().unwrap();
    let want = tree(src.path());
    let out = tempfile::tempdir().unwrap();
    let p = out.path().join("disc.iso");
    nz_create::create(
        Kind::Iso,
        &[src.path().to_path_buf()],
        &p,
        &Options::default(),
    )
    .unwrap();
    let got = read(Format::Iso, &p);
    // Joliet keeps names up to 103 UTF-16 units; the long one is shortened.
    let mut w = want.clone();
    let long = w.keys().find(|k| k.len() > 200).unwrap().clone();
    let data = w.remove(&long).unwrap();
    let short: Vec<_> = got.keys().filter(|k| k.starts_with("a/긴이름")).collect();
    assert_eq!(short.len(), 1, "{:?}", got.keys());
    assert!(short[0].ends_with(".txt") && short[0].encode_utf16().count() <= 105);
    assert_eq!(got[short[0]], data);
    for (n, d) in &w {
        assert_eq!(got.get(n), Some(d), "{n}");
    }
    check_7z(&p, &w, true);
}

#[test]
fn single_file_streams() {
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("data.bin");
    let data: Vec<u8> = (0..300_000u32)
        .map(|i| (i % 97) as u8 ^ (i >> 9) as u8)
        .collect();
    std::fs::write(&f, &data).unwrap();
    let out = tempfile::tempdir().unwrap();
    for (c, fmt) in [
        (Codec::Gzip, Format::Gz),
        (Codec::Xz, Format::Xz),
        (Codec::Bzip2, Format::Bz2),
        (Codec::Zstd, Format::Zst),
        (Codec::Lz4, Format::Lz4),
    ] {
        let p = out.path().join(format!("data.bin.{}", c.extension()));
        nz_create::create(
            Kind::Stream(c),
            std::slice::from_ref(&f),
            &p,
            &Options::default(),
        )
        .unwrap();
        assert_eq!(nz_formats::detect(&p), Some(fmt));
        let got = read(fmt, &p);
        assert_eq!(got.into_values().next().unwrap(), data, "{c:?}");
        if !matches!(c, Codec::Lz4 | Codec::Zstd) {
            let mut w = BTreeMap::new();
            w.insert("data.bin".to_string(), data.clone());
            check_7z(&p, &w, true);
        }
    }
    // A folder is refused (tar.* is the format for that).
    let p = out.path().join("x.gz");
    assert!(
        nz_create::create(
            Kind::Stream(Codec::Gzip),
            &[src.path().to_path_buf()],
            &p,
            &Options::default()
        )
        .is_err()
    );
    assert!(!p.exists());
}

#[test]
fn names_and_kinds() {
    assert_eq!(Kind::from_name(Path::new("a.tar.gz")), None);
    assert_eq!(
        Kind::from_name(Path::new("a.txt.gz")),
        Some(Kind::Stream(Codec::Gzip))
    );
    assert_eq!(Kind::from_name(Path::new("a.ISO")), Some(Kind::Iso));
    assert_eq!(
        Kind::from_name(Path::new("a.zipx")),
        Some(Kind::Zipx(Method::Zstd))
    );
    assert_eq!(Kind::from_name(Path::new("a.zip")), None);
}
