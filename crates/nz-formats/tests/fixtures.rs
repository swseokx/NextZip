//! Every fixture in `tests/data` is detected, listed and extracted, and the
//! extracted files must match `tests/data/manifest.tsv` (name, size, CRC-32;
//! cross-checked against 7-Zip where 7-Zip reads the format).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nz_formats::{Format, Options, VecSink};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

type Files = Vec<(String, u64, String)>;

fn manifest() -> BTreeMap<String, Files> {
    let text = std::fs::read_to_string(data().join("manifest.tsv")).unwrap();
    let mut m: BTreeMap<String, Files> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 4, "bad manifest line {line:?}");
        m.entry(f[0].to_string()).or_default().push((
            f[1].to_string(),
            f[2].parse().unwrap(),
            f[3].to_string(),
        ));
    }
    m
}

/// ZIP and 7z are routed by nz-archive; here the full-coder readers are
/// picked by extension like the `nzf` tool does.
fn format_of(p: &Path) -> Format {
    match p.extension().and_then(|e| e.to_str()) {
        Some("zip") => Format::ZipFull,
        Some("7z") => Format::SevenZ,
        _ => nz_formats::detect(p).unwrap_or_else(|| panic!("{} not detected", p.display())),
    }
}

fn run(p: &Path) -> anyhow::Result<Files> {
    let name = p.file_name().unwrap().to_string_lossy();
    let opt = Options {
        password: name.contains("_aes.").then(|| "pass".to_string()),
    };
    let f = format_of(p);
    let l = nz_formats::list(f, p, &opt)?;
    let mut s = VecSink::default();
    nz_formats::extract(f, p, &opt, &mut s)?;
    let files = l.members.iter().filter(|m| !m.is_dir && m.link.is_none());
    assert_eq!(files.count(), s.files.len(), "{name}: list/extract count");
    let mut out: Files = s
        .files
        .iter()
        .map(|(n, d)| {
            (
                n.clone(),
                d.len() as u64,
                format!("{:08x}", crc32fast::hash(d)),
            )
        })
        .collect();
    out.sort();
    Ok(out)
}

#[test]
fn fixtures_match_manifest() {
    let want = manifest();
    let mut failures = Vec::new();
    let mut seen = 0;
    for e in std::fs::read_dir(data()).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name == "manifest.tsv" || name == "README.md" || name.starts_with('.') {
            continue;
        }
        seen += 1;
        let Some(w) = want.get(&name) else {
            failures.push(format!("{name}: not in manifest"));
            continue;
        };
        let mut w = w.clone();
        w.sort();
        match run(&p) {
            Ok(got) if got == w => {}
            Ok(got) => failures.push(format!("{name}: got {got:?}, want {w:?}")),
            Err(e) => failures.push(format!("{name}: {e:#}")),
        }
    }
    assert!(seen >= 60, "only {seen} fixtures found");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn wrong_password_is_reported() {
    for f in ["zip_aes.zip", "7z_aes.7z"] {
        let p = data().join(f);
        let opt = Options {
            password: Some("nope".into()),
        };
        let fmt = format_of(&p);
        let mut s = VecSink::default();
        let r = nz_formats::list(fmt, &p, &opt)
            .and_then(|_| nz_formats::extract(fmt, &p, &opt, &mut s));
        let e = r.expect_err(f);
        assert!(
            matches!(
                e.downcast_ref::<nz_formats::FormatError>(),
                Some(nz_formats::FormatError::WrongPassword)
            ),
            "{f}: {e:#}"
        );
    }
}

/// Damaged input must fail cleanly (no panic): truncate every fixture at a
/// few points and flip bytes; any outcome but a panic is fine.
#[test]
fn truncated_and_flipped_fixtures_do_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    for e in std::fs::read_dir(data()).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name == "manifest.tsv" || name == "README.md" || name.starts_with('.') {
            continue;
        }
        let bytes = std::fs::read(&p).unwrap();
        let mut variants = Vec::new();
        for cut in [
            bytes.len() / 3,
            bytes.len() / 2,
            bytes.len().saturating_sub(7),
        ] {
            variants.push(bytes[..cut].to_vec());
        }
        let mut flip = bytes.clone();
        for i in (16..flip.len()).step_by(97) {
            flip[i] ^= 0x5A;
        }
        variants.push(flip);
        for (k, v) in variants.into_iter().enumerate() {
            let q = dir.path().join(format!("{k}_{name}"));
            std::fs::write(&q, v).unwrap();
            let f = match p.extension().and_then(|e| e.to_str()) {
                Some("zip") => Some(Format::ZipFull),
                Some("7z") => Some(Format::SevenZ),
                _ => nz_formats::detect(&q),
            };
            let Some(f) = f else { continue };
            let opt = Options::default();
            if nz_formats::list(f, &q, &opt).is_ok() {
                let _ = nz_formats::extract(f, &q, &opt, &mut VecSink::default());
            }
        }
    }
}

/// Every reader, forced onto tiny or blank input (as a renamed file would
/// be), fails with an error rather than a decoder fault (a panic the guard
/// caught). Regression for the `fmt_image` fuzz finding: a VHD shorter
/// than its 512-byte footer.
#[test]
fn every_format_rejects_tiny_input_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let mut faults = Vec::new();
    for &f in Format::ALL {
        let ext = f.extensions().first().copied().unwrap_or("bin");
        for n in [0usize, 1, 7, 100, 511, 513, 4096] {
            for fill in [0u8, 0xFF] {
                let q = dir.path().join(format!("t{n}_{fill}.{ext}"));
                std::fs::write(&q, vec![fill; n]).unwrap();
                let opt = Options::default();
                let r = nz_formats::list(f, &q, &opt)
                    .and_then(|_| nz_formats::extract(f, &q, &opt, &mut VecSink::default()));
                if let Err(e) = r {
                    let msg = format!("{e:#}");
                    if msg.contains("decoder fault") {
                        faults.push(format!("{f:?} n={n} fill={fill:#x}: {msg}"));
                    }
                }
            }
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// An ARC "squeezed" member whose node table is cut short makes the
/// unarc-rs decoder index past its buffer (found by `fmt_legacy` fuzzing,
/// `arc/unsqueeze.rs:24`, also in release builds). The guard turns the
/// panic into an error.
#[test]
fn arc_squeeze_short_node_table_is_an_error() {
    let data = [0x02u8, 0x00, 0x01]; // 2 nodes, then 1 byte
    let mut a = vec![0x1A, 4];
    let mut name = b"X.TXT".to_vec();
    name.resize(13, 0);
    a.extend(name);
    a.extend((data.len() as u32).to_le_bytes());
    a.extend([0, 0, 0, 0, 0, 0]); // date, time, crc
    a.extend(100u32.to_le_bytes());
    a.extend(data);
    a.extend([0x1A, 0]);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.arc");
    std::fs::write(&p, &a).unwrap();
    let opt = Options::default();
    let r = nz_formats::list(Format::Arc, &p, &opt)
        .and_then(|_| nz_formats::extract(Format::Arc, &p, &opt, &mut VecSink::default()));
    let e = r.expect_err("damaged member must fail");
    assert!(format!("{e:#}").contains("decoder fault"), "{e:#}");
}
