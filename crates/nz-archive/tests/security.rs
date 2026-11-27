//! Spec 9 threats, attacked end to end through `nz_archive::extract`
//! (M5 security review, docs/security/self-review.md). Archives are built
//! byte by byte so the hostile fields are exactly what a crafted file
//! would carry.

use std::path::{Path, PathBuf};

// ------------------------------------------------------------- builders --

/// A ustar header block.
fn tar_header(name: &str, size: u64, kind: u8, link: &str) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"14000000000\0");
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// A tar of (name, type, data or link target) entries.
fn tar(entries: &[(&str, u8, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, kind, body) in entries {
        let (data, link) = if kind == b'0' {
            (body.as_bytes(), "")
        } else {
            (&b""[..], body)
        };
        out.extend_from_slice(&tar_header(name, data.len() as u64, kind, link));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// One ZIP member as the central directory will describe it.
struct ZipMember<'a> {
    name: &'a str,
    data: &'a [u8],
    /// Override the declared uncompressed size.
    usize: Option<u32>,
    /// Reuse the local header of member `n` (overlapping members).
    share_with: Option<usize>,
    /// Override the declared compressed size.
    csize: Option<u32>,
}

impl<'a> ZipMember<'a> {
    fn new(name: &'a str, data: &'a [u8]) -> Self {
        ZipMember {
            name,
            data,
            usize: None,
            share_with: None,
            csize: None,
        }
    }
}

/// A stored (method 0) ZIP.
fn zip(members: &[ZipMember<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for m in members {
        if let Some(n) = m.share_with {
            offsets.push(offsets[n]);
            continue;
        }
        offsets.push(out.len() as u32);
        let crc = crc32fast::hash(m.data);
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(m.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(m.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(m.name.as_bytes());
        out.extend_from_slice(m.data);
    }
    let cd = out.len() as u32;
    for (m, off) in members.iter().zip(&offsets) {
        let crc = crc32fast::hash(m.data);
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&[20, 0, 20, 0, 0, 8, 0, 0, 0, 0, 0x21, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&m.csize.unwrap_or(m.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&m.usize.unwrap_or(m.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(m.name.as_bytes());
    }
    let cd_len = out.len() as u32 - cd;
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// `base/archive.<ext>` holding `bytes`, extracted into `base/sub/out`
/// (two levels below `base`, so an escape of one or two levels lands in
/// `base/sub` or `base` where the test looks for it).
fn extract(bytes: &[u8], ext: &str) -> (tempfile::TempDir, PathBuf, anyhow::Result<()>) {
    extract_opt(bytes, ext, &nz_archive::Options::default())
}

fn extract_opt(
    bytes: &[u8],
    ext: &str,
    opt: &nz_archive::Options,
) -> (tempfile::TempDir, PathBuf, anyhow::Result<()>) {
    let base = tempfile::tempdir().unwrap();
    let arc = base.path().join(format!("archive.{ext}"));
    std::fs::write(&arc, bytes).unwrap();
    let out = base.path().join("sub").join("out");
    let r = nz_archive::extract(&arc, &out, opt, None).map(|_| ());
    (base, out, r)
}

/// Every file or link anywhere under `base` other than the archive.
fn files_outside(base: &Path, out: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![base.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.starts_with(out) {
                continue;
            }
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(p);
            } else if !p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("archive.")
            {
                found.push(p);
            }
        }
    }
    found
}

// ---------------------------------------------------------------- tests --

/// Windows trims trailing dots and spaces, so `.. ` and `...` name the
/// parent folder. Found in the M5 review: nz-core (7z, tar family)
/// accepted them.
#[test]
fn dot_dot_with_trailing_space_or_dot_is_rejected() {
    for name in [
        ".. /evil.txt",
        "a/.. /.. /evil.txt",
        "... /evil.txt",
        "a/... /evil.txt",
    ] {
        let (base, out, r) = extract(&tar(&[(name, b'0', "pwned")]), "tar");
        assert!(r.is_err(), "tar {name:?} accepted");
        assert!(
            files_outside(base.path(), &out).is_empty(),
            "tar {name:?} escaped"
        );

        let z = zip(&[ZipMember::new(name, b"pwned")]);
        let (base, out, r) = extract(&z, "zip");
        assert!(r.is_err(), "zip {name:?} accepted");
        assert!(
            files_outside(base.path(), &out).is_empty(),
            "zip {name:?} escaped"
        );
    }
}

#[test]
fn traversal_absolute_drive_and_stream_names_are_rejected() {
    for name in [
        "../evil.txt",
        "a/../../evil.txt",
        "..\\evil.txt",
        "/evil.txt",
        "\\evil.txt",
        "C:evil.txt",
        "C:/evil.txt",
        "a.txt:stream",
    ] {
        let (base, out, r) = extract(&tar(&[(name, b'0', "pwned")]), "tar");
        assert!(r.is_err(), "tar {name:?} accepted");
        assert!(files_outside(base.path(), &out).is_empty(), "tar {name:?}");
        let (base, out, r) = extract(&zip(&[ZipMember::new(name, b"pwned")]), "zip");
        assert!(r.is_err(), "zip {name:?} accepted");
        assert!(files_outside(base.path(), &out).is_empty(), "zip {name:?}");
    }
}

/// Reserved device names are renamed instead of opening a device (spec 9).
#[test]
fn reserved_names_are_renamed() {
    let z = zip(&[
        ZipMember::new("CON", b"a"),
        ZipMember::new("dir/nul.txt", b"b"),
        ZipMember::new("trailing. ", b"c"),
    ]);
    let (_b, out, r) = extract(&z, "zip");
    r.unwrap();
    assert_eq!(std::fs::read(out.join("_CON")).unwrap(), b"a");
    assert_eq!(
        std::fs::read(out.join("dir").join("_nul.txt")).unwrap(),
        b"b"
    );
    assert_eq!(std::fs::read(out.join("trailing")).unwrap(), b"c");

    let t = tar(&[("CON", b'0', "a"), ("dir/com1.log", b'0', "b")]);
    let (_b, out, r) = extract(&t, "tar");
    r.unwrap();
    assert_eq!(std::fs::read(out.join("_CON")).unwrap(), b"a");
    assert_eq!(
        std::fs::read(out.join("dir").join("_com1.log")).unwrap(),
        b"b"
    );
}

/// The overlapping-file zip bomb: many central entries share one local
/// header and data stream (spec 9 "겹치는 로컬 헤더 감지").
#[test]
fn overlapping_zip_members_are_rejected() {
    let data = vec![b'x'; 4096];
    let mut m = vec![ZipMember::new("a.bin", &data)];
    for name in ["b.bin", "c.bin", "d.bin"] {
        let mut x = ZipMember::new(name, &data);
        x.share_with = Some(0);
        m.push(x);
    }
    let (_b, out, r) = extract(&zip(&m), "zip");
    let e = r.expect_err("overlapping members must be rejected");
    assert!(format!("{e:#}").contains("겹칩니다"), "{e:#}");
    assert!(!out.join("a.bin").exists(), "nothing is written");
}

/// Declared sizes far beyond the ratio limit stop extraction before
/// anything is written.
#[test]
fn declared_total_over_ratio_limit_is_rejected() {
    let mut m = Vec::new();
    let names: Vec<String> = (0..4).map(|i| format!("{i}.bin")).collect();
    for n in &names {
        let mut x = ZipMember::new(n, b"tiny");
        x.usize = Some(u32::MAX);
        m.push(x);
    }
    let (_b, out, r) = extract(&zip(&m), "zip");
    let e = r.expect_err("bomb must be rejected");
    assert!(format!("{e:#}").contains("압축 폭탄"), "{e:#}");
    assert!(!out.join("0.bin").exists());
}

/// A central entry whose data lies past the end of the file.
#[test]
fn zip_member_outside_the_file_is_rejected() {
    let mut x = ZipMember::new("a.bin", b"data");
    x.csize = Some(0x7FFF_FFFF);
    let (_b, _out, r) = extract(&zip(&[x]), "zip");
    let e = r.expect_err("must be rejected");
    assert!(format!("{e:#}").contains("파일 밖"), "{e:#}");
}

/// Links pointing outside the output folder are not created, including
/// ones that only escape when a link already extracted is followed
/// (`p/q/up -> ..`, then a link inside `up` or through it). Without the
/// symlink privilege (Developer Mode off) nz never creates links at all,
/// which the test also accepts. Runs with real links turned on (the
/// risky mode; the default writes text files).
#[test]
fn links_cannot_escape_the_output_folder() {
    let t = tar(&[
        ("p/q/", b'5', ""),
        ("p/q/file.txt", b'0', "inside"),
        ("abs", b'2', "/etc/passwd"),
        ("up2", b'2', "../.."),
        ("p/q/up", b'2', ".."),
        ("p/q/up/w", b'2', "../.."),
        ("p/w2", b'2', "q/up/../.."),
        ("hard", b'1', "../outside.txt"),
    ]);
    let opt = nz_archive::Options {
        symlinks: true,
        ..Default::default()
    };
    let (base, out, _r) = extract_opt(&t, "tar", &opt);
    assert!(files_outside(base.path(), &out).is_empty());
    let root = std::fs::canonicalize(&out).unwrap();
    let mut stack = vec![out.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let ft = std::fs::symlink_metadata(&p).unwrap().file_type();
            if ft.is_symlink() {
                if let Ok(real) = std::fs::canonicalize(&p) {
                    assert!(
                        real.starts_with(&root),
                        "{} -> {} leaves the output folder",
                        p.display(),
                        real.display()
                    );
                }
            } else if ft.is_dir() {
                stack.push(p);
            }
        }
    }
}

/// Renamed names are reported to the user (spec 9: "이름 변경 후 알림").
#[test]
fn renamed_names_are_reported() {
    let z = zip(&[
        ZipMember::new("CON", b"a"),
        ZipMember::new("dir/nul.txt", b"b"),
        ZipMember::new("ok.txt", b"c"),
    ]);
    let base = tempfile::tempdir().unwrap();
    let arc = base.path().join("a.zip");
    std::fs::write(&arc, &z).unwrap();
    let prog = nz_archive::Progress::default();
    nz_archive::extract(
        &arc,
        &base.path().join("out"),
        &nz_archive::Options::default(),
        Some(&prog),
    )
    .unwrap();
    let notes = prog.notes.lock().unwrap().clone();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("2") && notes[0].contains("CON → _CON"),
        "{notes:?}"
    );

    // Nothing renamed, nothing reported.
    let z = zip(&[ZipMember::new("dir/ok.txt", b"c")]);
    std::fs::write(&arc, &z).unwrap();
    let prog = nz_archive::Progress::default();
    nz_archive::extract(
        &arc,
        &base.path().join("out2"),
        &nz_archive::Options::default(),
        Some(&prog),
    )
    .unwrap();
    assert!(prog.notes.lock().unwrap().is_empty());
}

/// tar family: output beyond the bomb limit stops extraction before the
/// data is written (the limit is 4096 times the archive plus 1 GiB).
#[test]
fn tar_output_over_the_limit_is_rejected() {
    let mut t = tar_header("big.bin", 3 << 30, b'0', "").to_vec();
    t.resize(t.len() + 4096, 0);
    let (_b, out, r) = extract(&t, "tar");
    let e = format!("{:#}", r.unwrap_err());
    assert!(e.contains("압축 폭탄"), "{e}");
    assert!(!out.join("big.bin").exists());
}

/// tar family (nz-core writes the files): renamed names are reported too.
#[test]
fn tar_renamed_names_are_reported() {
    let t = tar(&[("aux.c", b'0', "a"), ("src/ok.c", b'0', "b")]);
    let base = tempfile::tempdir().unwrap();
    let arc = base.path().join("a.tar");
    std::fs::write(&arc, &t).unwrap();
    let prog = nz_archive::Progress::default();
    nz_archive::extract(
        &arc,
        &base.path().join("out"),
        &nz_archive::Options::default(),
        Some(&prog),
    )
    .unwrap();
    let notes = prog.notes.lock().unwrap().clone();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("aux.c → _aux.c"), "{notes:?}");
}

/// Spec 9 default: a symbolic link becomes a regular file holding its
/// target path; a link pointing outside is not extracted at all.
#[test]
fn links_become_text_files_by_default() {
    let t = tar(&[
        ("d/", b'5', ""),
        ("d/f.txt", b'0', "data"),
        ("link", b'2', "d/f.txt"),
        ("d/up", b'2', "../d"),
        ("out", b'2', "../x"),
        ("abs", b'2', "/etc/passwd"),
    ]);
    let (_b, out, r) = extract(&t, "tar");
    r.unwrap();
    for (name, target) in [("link", "d/f.txt"), ("d/up", "../d")] {
        let p = out.join(name);
        let ft = std::fs::symlink_metadata(&p).unwrap().file_type();
        assert!(ft.is_file(), "{name} is not a regular file");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), target);
    }
    assert!(!out.join("out").exists() && !out.join("abs").exists());
}

/// nz-core's tar limits stop extraction (D2, D3), and nz-archive's member
/// count limit is one per archive byte plus 10,000.
#[test]
fn tar_entry_and_size_limits() {
    let t = tar(&[("a", b'0', "1"), ("b", b'0', "2"), ("c", b'0', "3")]);
    let base = tempfile::tempdir().unwrap();
    let arc = base.path().join("t.tar");
    std::fs::write(&arc, &t).unwrap();
    for (opt, want) in [
        (
            nz_core::ExtractOptions {
                max_entries: Some(2),
                ..Default::default()
            },
            nz_core::LimitExceeded::Entries,
        ),
        (
            nz_core::ExtractOptions {
                max_total: Some(2),
                ..Default::default()
            },
            nz_core::LimitExceeded::Total,
        ),
    ] {
        let e = nz_core::extract_with(&arc, &base.path().join("o"), 1, &opt).unwrap_err();
        assert_eq!(e.downcast_ref::<nz_core::LimitExceeded>(), Some(&want));
    }
    let ok = nz_core::ExtractOptions {
        max_entries: Some(3),
        max_total: Some(3),
        ..Default::default()
    };
    nz_core::extract_with(&arc, &base.path().join("ok"), 1, &ok).unwrap();
    assert_eq!(nz_archive::max_entries(0), 10_000);
    assert_eq!(nz_archive::max_entries(1 << 20), (1 << 20) + 10_000);
}
