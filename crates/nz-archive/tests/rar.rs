//! RAR extraction through UnRAR, compared file by file with an
//! external extractor (`NZ_REF_ARCHIVER`) when one is set.
//! Samples: libarchive's test suite (BSD-2-Clause, see tests/data/rar/NOTICE.md).

#![cfg(feature = "rar")]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nz_archive::{ArchiveError, Kind, Options, archive_error};

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("rar")
        .join(name)
}

/// Regular files below `root` (relative path -> bytes).
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut m = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let ft = e.file_type().unwrap();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else {
                let rel = e
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                m.insert(rel, std::fs::read(e.path()).unwrap());
            }
        }
    }
    m
}

/// Extract with us and with the reference tool and compare. `links` names
/// the archive's symbolic links: other tools may write them as plain files, UnRAR
/// creates links (skipped by `tree`) or nothing without the privilege.
fn compare(name: &str, links: &[&str]) -> usize {
    let p = data(name);
    let opt = Options::default();
    let l = nz_archive::list(&p, &opt).unwrap();
    assert_eq!(l.kind, Kind::Rar);
    let ours = tempfile::tempdir().unwrap();
    nz_archive::extract(&p, ours.path(), &opt, None).unwrap_or_else(|e| panic!("{name}: {e:#}"));
    let got = tree(ours.path());
    assert!(!got.is_empty(), "{name}: nothing extracted");
    if common::ref_tool().is_some() {
        let rt = tempfile::tempdir().unwrap();
        common::ref_extract(&p, rt.path(), None).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = tree(rt.path());
        for (k, v) in &got {
            let w = want
                .get(k)
                .unwrap_or_else(|| panic!("{name}: {k} not produced by the reference tool"));
            assert!(v == w, "{name}: {k} differs from the reference tool");
        }
        for k in want.keys().filter(|k| !got.contains_key(*k)) {
            assert!(links.iter().any(|l| k.ends_with(l)), "{name}: missing {k}");
        }
    }
    got.len()
}

/// The libarchive samples do not publish their passwords, so check the
/// password errors: none given, and a wrong one.
fn password_errors(name: &str) {
    let p = data(name);
    let out = tempfile::tempdir().unwrap();
    let e = nz_archive::extract(&p, out.path(), &Options::default(), None).unwrap_err();
    assert_eq!(
        archive_error(&e),
        Some(&ArchiveError::PasswordRequired),
        "{name}: {e:#}"
    );
    let bad = Options {
        password: Some("definitely-wrong".into()),
        ..Default::default()
    };
    let e = nz_archive::extract(&p, out.path(), &bad, None).unwrap_err();
    assert_eq!(
        archive_error(&e),
        Some(&ArchiveError::WrongPassword),
        "{name}: {e:#}"
    );
}

#[test]
fn rar4_basic() {
    assert!(compare("test_read_format_rar.rar", &["testlink"]) >= 2);
}

#[test]
fn rar4_unicode_names() {
    compare("test_read_format_rar_unicode.rar", &["ファイル"]);
}

#[test]
fn rar4_encrypted() {
    password_errors("test_read_format_rar_encryption_data.rar");
}

#[test]
fn rar5_variants() {
    for n in [
        "test_read_format_rar5_stored.rar",
        "test_read_format_rar5_compressed.rar",
        "test_read_format_rar5_solid.rar",
    ] {
        compare(n, &[]);
    }
}

#[test]
fn rar5_unicode_names() {
    // Only our side is checked: not every extractor handles these emoji names.
    let p = data("test_read_format_rar5_unicode.rar");
    let out = tempfile::tempdir().unwrap();
    nz_archive::extract(&p, out.path(), &Options::default(), None).unwrap();
    assert!(tree(out.path()).keys().any(|k| k.contains('\u{1F44B}')));
}

#[test]
fn rar5_encrypted() {
    password_errors("test_read_format_rar5_encrypted.rar");
}

#[test]
fn rar5_multivolume() {
    let p = data("test_read_format_rar5_multiarchive.part01.rar");
    let l = nz_archive::list(&p, &Options::default()).unwrap();
    assert_eq!(l.volumes.len(), 8);
    compare("test_read_format_rar5_multiarchive.part01.rar", &[]);
}

#[test]
fn rar5_symlinks_stay_inside() {
    let p = data("test_read_format_rar5_symlink.rar");
    let out = tempfile::tempdir().unwrap();
    let inner = out.path().join("x");
    // Whatever UnRAR does with links, nothing may appear outside the folder.
    let _ = nz_archive::extract(&p, &inner, &Options::default(), None);
    let names: Vec<_> = std::fs::read_dir(out.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("x")]);
}

#[test]
#[ignore = "extracts a 241 MB member; run with --ignored"]
fn rar4_multivolume_ppmd() {
    compare(
        "test_read_format_rar_multivolume.part0001.rar",
        &["testlink"],
    );
}
