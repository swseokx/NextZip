//! The isolated decoder process (`nz-decode.exe`): its confinement, and the
//! whole parent pipeline (sniff → worker → sanitised writes) over the
//! nz-formats fixtures, checked against their manifest.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nz_archive::Options;

#[cfg(windows)]
#[test]
fn worker_runs_at_low_integrity_and_cannot_write_or_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let r = nz_archive::isolated::probe(dir.path()).unwrap();
    assert_eq!(r.integrity, Some(0x1000), "{r:?}");
    assert!(
        !r.wrote_file,
        "worker could write a medium-integrity folder"
    );
    assert!(!r.spawned_process, "worker could start a process");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../nz-formats/tests/data")
}

fn manifest() -> BTreeMap<String, Vec<(String, u64, String)>> {
    let text = std::fs::read_to_string(fixtures().join("manifest.tsv")).unwrap();
    let mut m: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = l.split('\t').collect();
        m.entry(f[0].to_string()).or_default().push((
            f[1].to_string(),
            f[2].parse().unwrap(),
            f[3].to_string(),
        ));
    }
    m
}

fn tree(root: &Path) -> Vec<(String, u64, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let data = std::fs::read(&p).unwrap();
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((
                    rel,
                    data.len() as u64,
                    format!("{:08x}", crc32fast::hash(&data)),
                ));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn fixtures_extract_through_the_worker() {
    let want = manifest();
    let mut failures = Vec::new();
    for (name, files) in &want {
        let p = fixtures().join(name);
        let opt = Options {
            password: name.contains("_aes.").then(|| "pass".to_string()),
            ..Default::default()
        };
        let out = tempfile::tempdir().unwrap();
        if let Err(e) = nz_archive::extract(&p, out.path(), &opt, None) {
            failures.push(format!("{name}: {e:#}"));
            continue;
        }
        // Links are extracted as small text files holding the target
        // (spec 9); the manifest lists regular files only.
        let links: Vec<String> = nz_formats::detect(&p)
            .and_then(|f| nz_formats::list(f, &p, &Default::default()).ok())
            .map(|l| {
                l.members
                    .iter()
                    .filter(|m| m.link.is_some())
                    .map(|m| m.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut got = tree(out.path());
        got.retain(|g| !links.contains(&g.0));
        let mut w = files.clone();
        w.sort();
        // Legacy code page names are re-decoded by the parent; compare the
        // data only for those.
        let same = if w.iter().any(|f| f.0.contains('%')) {
            got.iter().map(|g| (g.1, &g.2)).collect::<Vec<_>>()
                == w.iter().map(|g| (g.1, &g.2)).collect::<Vec<_>>()
        } else {
            got == w
        };
        if !same {
            failures.push(format!("{name}: got {got:?}, want {w:?}"));
        }
    }
    assert!(want.len() >= 60);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// LHA names in a legacy code page reach the parent as raw bytes and go
/// through the same code page handling as ZIP.
#[test]
fn lha_shift_jis_names() {
    let p = fixtures().join("la_lha_filename_cp932.lzh");
    let opt = Options {
        codepage: Some(nz_archive::Codepage::ShiftJis),
        ..Default::default()
    };
    let l = nz_archive::list(&p, &opt).unwrap();
    let mut names: Vec<_> = l.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["漢字.txt", "表.txt"]);
    let out = tempfile::tempdir().unwrap();
    nz_archive::extract(&p, out.path(), &opt, None).unwrap();
    assert!(out.path().join("漢字.txt").is_file());
}

/// Split sets (`x.zip.001`, `x.7z.001`, ... as 7-Zip `-v` writes them: the
/// archive cut into pieces) list and extract as one archive.
#[test]
fn split_001_sets() {
    let want = manifest();
    for name in ["zip_LZMA.zip", "7z_PPMd.7z", "zip_Deflate64.zip"] {
        let data = std::fs::read(fixtures().join(name)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let part = data.len().div_ceil(3);
        for (i, chunk) in data.chunks(part).enumerate() {
            std::fs::write(dir.path().join(format!("{name}.{:03}", i + 1)), chunk).unwrap();
        }
        let first = dir.path().join(format!("{name}.001"));
        let l = nz_archive::list(&first, &Options::default()).unwrap();
        assert_eq!(l.files(), want[name].len(), "{name}");
        assert_eq!(l.volumes.len(), 3, "{name}");
        let out = tempfile::tempdir().unwrap();
        nz_archive::extract(&first, out.path(), &Options::default(), None).unwrap();
        let mut w = want[name].clone();
        w.sort();
        assert_eq!(tree(out.path()), w, "{name}");
    }
}

/// Self-extractors (an executable stub with the archive appended) and
/// archives with junk in front open like the bare archive.
#[test]
fn sfx_and_prefixed_archives() {
    let want = manifest();
    let stub: Vec<u8> = b"MZ"
        .iter()
        .copied()
        .chain((0..70_000u32).map(|i| (i * 7 % 251) as u8))
        .collect();
    let dir = tempfile::tempdir().unwrap();
    for name in ["7z_PPMd.7z", "zip_LZMA.zip"] {
        let mut exe = stub.clone();
        exe.extend(std::fs::read(fixtures().join(name)).unwrap());
        let p = dir.path().join(format!("{name}.exe"));
        std::fs::write(&p, exe).unwrap();
        let out = tempfile::tempdir().unwrap();
        nz_archive::extract(&p, out.path(), &Options::default(), None)
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        let mut w = want[name].clone();
        w.sort();
        assert_eq!(tree(out.path()), w, "{name}");
    }
    // RAR: the same members as the bare archive.
    let rar = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/rar/test_read_format_rar5_compressed.rar");
    let mut exe = stub.clone();
    exe.extend(std::fs::read(&rar).unwrap());
    let p = dir.path().join("rar5.exe");
    std::fs::write(&p, exe).unwrap();
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    nz_archive::extract(&rar, a.path(), &Options::default(), None).unwrap();
    nz_archive::extract(&p, b.path(), &Options::default(), None).unwrap();
    assert!(!tree(a.path()).is_empty());
    assert_eq!(tree(a.path()), tree(b.path()));
    // libarchive samples: zeros before a ZIP; zstd with skippable frames.
    for (name, files) in [
        ("la_zip_junk_prefix.zip", 3),
        ("la_zstd_skippable.tar.zst", 6),
    ] {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name);
        let out = tempfile::tempdir().unwrap();
        nz_archive::extract(&p, out.path(), &Options::default(), None)
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        assert_eq!(tree(out.path()).len(), files, "{name}");
    }
}
