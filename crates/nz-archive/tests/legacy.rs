//! ALZ / EGG / legacy ZIP round trips: our writer -> our reader, and our
//! writer -> an external extractor (`NZ_REF_ARCHIVER`) when one is set, so the layout is
//! confirmed by an independent implementation.

mod common;

use common::*;
use nz_archive::{ArchiveError, Codepage, Kind, Options, archive_error};

fn items() -> Vec<Item> {
    vec![
        dir("문서"),
        file("문서/보고서 2026.txt", &content(1, 70_000)),
        file("문서/빈 파일.txt", b""),
        file("사진/여행.bin", &content(2, 300_000)),
        file("readme.txt", b"hello ALZ/EGG\r\n"),
    ]
}

fn check_ours(path: &std::path::Path, items: &[Item], pw: Option<&str>, kind: Kind) {
    let opt = Options {
        password: pw.map(str::to_owned),
        ..Default::default()
    };
    let l = nz_archive::list(path, &opt).unwrap();
    assert_eq!(l.kind, kind);
    let names: Vec<_> = l.entries.iter().map(|e| e.name.clone()).collect();
    for it in items {
        assert!(names.contains(&it.name), "{} not in {names:?}", it.name);
    }
    let out = tempfile::tempdir().unwrap();
    let s = nz_archive::extract(path, out.path(), &opt, None).unwrap();
    assert_eq!(s.files, items.iter().filter(|i| !i.dir).count());
    assert_tree(out.path(), items);
}

fn check_ref(path: &std::path::Path, items: &[Item], pw: Option<&str>) {
    if ref_tool().is_none() {
        eprintln!("NZ_REF_ARCHIVER not set; skipping cross-check");
        return;
    }
    let out = tempfile::tempdir().unwrap();
    if let Err(e) = ref_extract(path, out.path(), pw) {
        panic!("reference tool rejected {}: {e}", path.display());
    }
    assert_tree(out.path(), items);
}

#[test]
fn alz_methods() {
    let d = tempfile::tempdir().unwrap();
    for (m, tag) in [
        (AlzMethod::Store, "store"),
        (AlzMethod::Deflate, "deflate"),
        (AlzMethod::Bzip2, "bzip2"),
    ] {
        let p = d.path().join(format!("{tag}.alz"));
        std::fs::write(&p, alz_bytes(&items(), m, None)).unwrap();
        check_ours(&p, &items(), None, Kind::Alz);
        check_ref(&p, &items(), None);
    }
}

#[test]
fn alz_names_are_detected_as_cp949() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("names.alz");
    std::fs::write(&p, alz_bytes(&items(), AlzMethod::Store, None)).unwrap();
    let l = nz_archive::list(&p, &Options::default()).unwrap();
    assert_eq!(l.codepage, Some(Codepage::Cp949));
    assert!(l.detection.unwrap().summary_ko().contains("한글"));
}

#[test]
fn alz_encrypted() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("enc.alz");
    std::fs::write(
        &p,
        alz_bytes(&items(), AlzMethod::Deflate, Some(b"pass1234")),
    )
    .unwrap();
    check_ours(&p, &items(), Some("pass1234"), Kind::Alz);
    check_ref(&p, &items(), Some("pass1234"));
    let out = tempfile::tempdir().unwrap();
    let e = nz_archive::extract(&p, out.path(), &Options::default(), None).unwrap_err();
    assert_eq!(archive_error(&e), Some(&ArchiveError::PasswordRequired));
    let bad = Options {
        password: Some("nope".into()),
        ..Default::default()
    };
    let e = nz_archive::extract(&p, out.path(), &bad, None).unwrap_err();
    assert_eq!(
        archive_error(&e),
        Some(&ArchiveError::WrongPassword),
        "{e:#}"
    );
}

#[test]
fn alz_split() {
    let d = tempfile::tempdir().unwrap();
    let stream = alz_bytes(&items(), AlzMethod::Deflate, None);
    let p = d.path().join("split.alz");
    let vols = write_alz_split(&stream, &p, 20_000);
    assert!(vols.len() >= 3);
    let l = nz_archive::list(&p, &Options::default()).unwrap();
    assert_eq!(l.volumes.len(), vols.len());
    check_ours(&p, &items(), None, Kind::Alz);
    // With the volume number in each head and the "CLZ\x03" tail that real
    // ALZip sets carry, other extractors read the synthetic set too.
    check_ref(&p, &items(), None);
}

/// A split set made by ALZip itself (ALZipCon 26.11.11.19,
/// `-a -v64KB src 분할.alz`, renamed): three volumes, a Korean folder and
/// file name, Deflate. NextZip extracts it byte-exact.
#[test]
fn alz_split_made_by_alzip() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/alz_split_real.alz");
    let l = nz_archive::list(&p, &Options::default()).unwrap();
    assert_eq!(l.kind, Kind::Alz);
    assert_eq!(l.volumes.len(), 3);
    let want: [(&str, usize, u32); 2] = [
        ("src/readme.txt", 1040, 0x30fd_b814),
        ("src/한글/데이터.bin", 140_000, 0xc15f_c371),
    ];
    let names: Vec<_> = l.entries.iter().map(|e| e.name.as_str()).collect();
    for (n, _, _) in want {
        assert!(names.contains(&n), "{n} not in {names:?}");
    }
    let check = |root: &std::path::Path| {
        for (n, len, crc) in want {
            let b = std::fs::read(root.join(n)).unwrap();
            assert_eq!(b.len(), len, "{n}");
            assert_eq!(crc32fast::hash(&b), crc, "{n}");
        }
    };
    let out = tempfile::tempdir().unwrap();
    nz_archive::extract(&p, out.path(), &Options::default(), None).unwrap();
    check(out.path());
    if ref_tool().is_some() {
        let o = tempfile::tempdir().unwrap();
        ref_extract(&p, o.path(), None).unwrap();
        check(o.path());
    }
}

fn egg_opts(method: EggMethod, crypt: EggCrypt) -> EggOpts {
    EggOpts {
        method,
        crypt,
        password: b"pass1234".to_vec(),
        locale_949: false,
        solid: false,
    }
}

#[test]
fn egg_methods() {
    let d = tempfile::tempdir().unwrap();
    for m in [
        EggMethod::Store,
        EggMethod::Deflate,
        EggMethod::Bzip2,
        EggMethod::Lzma,
    ] {
        let p = d.path().join(format!("{m:?}.egg"));
        write_egg(&p, &items(), &egg_opts(m, EggCrypt::None));
        check_ours(&p, &items(), None, Kind::Egg);
        check_ref(&p, &items(), None);
    }
}

#[test]
fn egg_locale_names() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("cp949.egg");
    let mut o = egg_opts(EggMethod::Deflate, EggCrypt::None);
    o.locale_949 = true;
    write_egg(&p, &items(), &o);
    check_ours(&p, &items(), None, Kind::Egg);
    // Not cross-checked: some extractors ignore the locale field and read
    // every EGG name as UTF-8.
}

#[test]
fn egg_encrypted() {
    let d = tempfile::tempdir().unwrap();
    for c in [EggCrypt::ZipCrypto, EggCrypt::Aes128, EggCrypt::Aes256] {
        let p = d.path().join(format!("{c:?}.egg"));
        write_egg(&p, &items(), &egg_opts(EggMethod::Deflate, c));
        check_ours(&p, &items(), Some("pass1234"), Kind::Egg);
        check_ref(&p, &items(), Some("pass1234"));
        let out = tempfile::tempdir().unwrap();
        let bad = Options {
            password: Some("wrong".into()),
            ..Default::default()
        };
        let e = nz_archive::extract(&p, out.path(), &bad, None).unwrap_err();
        assert_eq!(
            archive_error(&e),
            Some(&ArchiveError::WrongPassword),
            "{c:?}: {e:#}"
        );
    }
}

#[test]
fn egg_solid() {
    let d = tempfile::tempdir().unwrap();
    for m in [EggMethod::Deflate, EggMethod::Lzma] {
        let p = d.path().join(format!("solid-{m:?}.egg"));
        let mut o = egg_opts(m, EggCrypt::None);
        o.solid = true;
        write_egg(&p, &items(), &o);
        let l = nz_archive::list(&p, &Options::default()).unwrap();
        assert!(l.solid);
        check_ours(&p, &items(), None, Kind::Egg);
        check_ref(&p, &items(), None);
    }
}

#[test]
fn egg_split() {
    let d = tempfile::tempdir().unwrap();
    let vols = write_egg_split(
        d.path(),
        "big",
        &items(),
        &egg_opts(EggMethod::Store, EggCrypt::None),
        120_000,
    );
    assert!(vols.len() >= 3);
    let l = nz_archive::list(&vols[0], &Options::default()).unwrap();
    assert_eq!(l.volumes.len(), vols.len());
    check_ours(&vols[0], &items(), None, Kind::Egg);
    check_ref(&vols[0], &items(), None);
}

#[test]
fn legacy_zip_codepages() {
    let d = tempfile::tempdir().unwrap();
    let cases: [(Codepage, &[&str]); 3] = [
        (Codepage::Cp949, &["보고서/결산 자료.txt", "사진.jpg"]),
        (Codepage::ShiftJis, &["資料/会議の議事録.txt", "写真.jpg"]),
        (Codepage::Gbk, &["新建文件夹/工作报告.txt", "照片.jpg"]),
    ];
    for (cp, names) in cases {
        let enc = match cp {
            Codepage::Cp949 => encoding_rs::EUC_KR,
            Codepage::ShiftJis => encoding_rs::SHIFT_JIS,
            _ => encoding_rs::GBK,
        };
        let raw: Vec<(Vec<u8>, Vec<u8>)> = names
            .iter()
            .map(|n| (enc.encode(n).0.into_owned(), n.as_bytes().to_vec()))
            .collect();
        let p = d.path().join(format!("{cp:?}.zip"));
        write_legacy_zip(&p, &raw);
        let l = nz_archive::list(&p, &Options::default()).unwrap();
        assert_eq!(l.codepage, Some(cp));
        let got: Vec<_> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(got, names.to_vec());
        // Manual override wins.
        let forced = Options {
            codepage: Some(Codepage::Cp437),
            ..Default::default()
        };
        let l2 = nz_archive::list(&p, &forced).unwrap();
        assert_eq!(l2.codepage, Some(Codepage::Cp437));
        assert_ne!(l2.entries[0].name, names[0]);
        let out = tempfile::tempdir().unwrap();
        nz_archive::extract(&p, out.path(), &Options::default(), None).unwrap();
        for n in names {
            assert_eq!(std::fs::read(out.path().join(n)).unwrap(), n.as_bytes());
        }
    }
}

#[test]
fn zip_slip_is_blocked() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("out");
    for evil in [
        &b"../evil.txt"[..],
        b"..\\evil.txt",
        b"a/../../evil.txt",
        b"C:/evil.txt",
        b"/evil.txt",
        b".. /evil.txt",
        b"ok.txt:stream",
    ] {
        let p = d.path().join("evil.zip");
        write_legacy_zip(
            &p,
            &[
                (b"ok.txt".to_vec(), b"x".to_vec()),
                (evil.to_vec(), b"pwn".to_vec()),
            ],
        );
        assert!(
            nz_archive::extract(&p, &out, &Options::default(), None).is_err(),
            "{:?} not rejected",
            String::from_utf8_lossy(evil)
        );
        assert!(!d.path().join("evil.txt").exists());
    }
    // ALZ and EGG go through the same guard.
    let a = d.path().join("evil.alz");
    std::fs::write(
        &a,
        alz_bytes(&[file("../evil.txt", b"pwn")], AlzMethod::Store, None),
    )
    .unwrap();
    assert!(nz_archive::extract(&a, &out, &Options::default(), None).is_err());
    let e = d.path().join("evil.egg");
    write_egg(
        &e,
        &[file("..\\evil.txt", b"pwn")],
        &egg_opts(EggMethod::Store, EggCrypt::None),
    );
    assert!(nz_archive::extract(&e, &out, &Options::default(), None).is_err());
    assert!(!d.path().join("evil.txt").exists());
}

#[test]
fn corrupt_inputs_error_cleanly() {
    let d = tempfile::tempdir().unwrap();
    let alz = alz_bytes(&items(), AlzMethod::Bzip2, None);
    let p = d.path().join("c.egg");
    write_egg(&p, &items(), &egg_opts(EggMethod::Deflate, EggCrypt::None));
    let egg = std::fs::read(&p).unwrap();
    for (ext, data) in [("alz", alz), ("egg", egg)] {
        for cut in [10, data.len() / 3, data.len() - 5] {
            let q = d.path().join(format!("cut.{ext}"));
            std::fs::write(&q, &data[..cut]).unwrap();
            let out = d.path().join("o");
            let _ = nz_archive::list(&q, &Options::default());
            let _ = nz_archive::extract(&q, &out, &Options::default(), None);
        }
        for i in (0..data.len()).step_by(997) {
            let mut m = data.clone();
            m[i] ^= 0xA5;
            let q = d.path().join(format!("flip.{ext}"));
            std::fs::write(&q, &m).unwrap();
            let out = d.path().join("o2");
            let _ = nz_archive::list(&q, &Options::default());
            let _ = nz_archive::extract(&q, &out, &Options::default(), None);
        }
    }
}
