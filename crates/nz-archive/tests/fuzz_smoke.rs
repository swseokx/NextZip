//! Deterministic mutation smoke test over the same bodies the cargo-fuzz
//! targets run (`nz_archive::fuzzing`). It runs on stable in `cargo test`;
//! coverage-guided fuzzing lives in `/fuzz` (nightly + cargo-fuzz).
//!
//! `NZ_FUZZ_ITERS=<n>` changes the mutations per seed (default 120).
//! `NZ_FUZZ_CORPUS=<dir>` also writes the seed corpus there, laid out as
//! `<dir>/<target>/<name>` for `cargo fuzz run <target> <dir>/<target>`.

mod common;

use std::path::Path;

use common::*;
use nz_archive::fuzzing;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: [u8; 8] = [0x00, 0xff, 0x7f, 0x80, 0x01, 0xfe, 0x40, 0x10];

fn mutate(seed: &[u8], r: &mut Rng) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + r.below(4) {
        if v.is_empty() {
            v.push(r.next() as u8);
            continue;
        }
        let i = r.below(v.len());
        match r.below(7) {
            0 => v[i] ^= 1 << r.below(8),
            1 => v[i] = INTERESTING[r.below(INTERESTING.len())],
            2 => v[i] = r.next() as u8,
            // 32-bit field overwrite (sizes, offsets, counts)
            3 => {
                let val = [0u32, u32::MAX, 0x7fff_ffff, 1, r.next() as u32][r.below(5)];
                for (k, b) in val.to_le_bytes().iter().enumerate() {
                    if let Some(x) = v.get_mut(i + k) {
                        *x = *b;
                    }
                }
            }
            4 => v.truncate(i),
            5 => {
                let n = r.below(64).min(v.len() - i);
                let chunk = v[i..i + n].to_vec();
                let at = r.below(v.len());
                v.splice(at..at, chunk);
            }
            _ => {
                let n = r.below(16).min(v.len() - i);
                v.drain(i..i + n);
            }
        }
    }
    v
}

fn iters() -> usize {
    std::env::var("NZ_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120)
}

fn save_corpus(target: &str, name: &str, data: &[u8]) {
    if let Ok(dir) = std::env::var("NZ_FUZZ_CORPUS") {
        let d = Path::new(&dir).join(target);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(name), data).unwrap();
    }
}

fn items() -> Vec<Item> {
    vec![
        dir("docs"),
        file("docs/readme.txt", &content(1, 3000)),
        file("한글 파일.bin", &content(2, 900)),
        file("empty.txt", b""),
    ]
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

/// (file name, bytes) seeds for the `archive` body.
fn archive_seeds() -> Vec<(String, Vec<u8>)> {
    let tmp = tempfile::tempdir().unwrap();
    let it = items();
    let mut s = Vec::new();
    for (m, tag) in [
        (AlzMethod::Store, "store"),
        (AlzMethod::Bzip2, "bzip2"),
        (AlzMethod::Deflate, "deflate"),
    ] {
        s.push((format!("{tag}.alz"), alz_bytes(&it, m, None)));
    }
    s.push((
        "zc.alz".into(),
        alz_bytes(&it, AlzMethod::Deflate, Some(b"fuzz")),
    ));
    for (method, crypt, solid, tag) in [
        (EggMethod::Store, EggCrypt::None, false, "store"),
        (EggMethod::Deflate, EggCrypt::None, false, "deflate"),
        (EggMethod::Bzip2, EggCrypt::None, false, "bzip2"),
        (EggMethod::Lzma, EggCrypt::None, false, "lzma"),
        (EggMethod::Deflate, EggCrypt::None, true, "solid"),
        (EggMethod::Deflate, EggCrypt::ZipCrypto, false, "zc"),
        (EggMethod::Deflate, EggCrypt::Aes256, false, "aes"),
    ] {
        let p = tmp.path().join(format!("{tag}.egg"));
        write_egg(
            &p,
            &it,
            &EggOpts {
                method,
                crypt,
                password: b"fuzz".to_vec(),
                locale_949: tag == "store",
                solid,
            },
        );
        s.push((format!("{tag}.egg"), read(&p)));
    }
    let p = tmp.path().join("legacy.zip");
    write_legacy_zip(
        &p,
        &[
            (cp949("문서/보고서.txt"), content(3, 500)),
            (b"../evil.txt".to_vec(), b"x".to_vec()),
        ],
    );
    s.push(("legacy.zip".into(), read(&p)));
    let rar = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/rar");
    for f in [
        "test_read_format_rar.rar",
        "test_read_format_rar5_compressed.rar",
        "test_read_format_rar5_stored.rar",
        "test_read_format_rar5_solid.rar",
    ] {
        let p = rar.join(f);
        if p.exists() {
            s.push((f.into(), read(&p)));
        }
    }
    s
}

#[test]
fn archive_seeds_are_valid() {
    // Unmutated seeds must still list: otherwise the mutations below would
    // only exercise the sniffer.
    let tmp = tempfile::tempdir().unwrap();
    for (name, data) in archive_seeds() {
        let p = tmp.path().join(&name);
        std::fs::write(&p, &data).unwrap();
        let opt = nz_archive::Options {
            password: Some("fuzz".into()),
            ..Default::default()
        };
        nz_archive::list(&p, &opt).unwrap_or_else(|e| panic!("{name}: {e:#}"));
    }
}

#[test]
fn archive_mutations() {
    let n = iters();
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    for (name, seed) in archive_seeds() {
        save_corpus("archive", &name, &seed);
        fuzzing::archive(&name, &seed);
        for _ in 0..n {
            let m = mutate(&seed, &mut r);
            fuzzing::archive(&name, &m);
        }
    }
}

#[test]
fn bzip2_mutations() {
    let n = iters() * 4;
    let mut r = Rng(42);
    for (i, data) in [
        content(4, 5000),
        b"aaaaaaaaaaaaaaaaaaaaaaaaab".repeat(40),
        vec![],
    ]
    .iter()
    .enumerate()
    {
        let seed = bzip2_std(data);
        save_corpus("bzip2", &format!("seed{i}.bz2"), &seed);
        fuzzing::bzip2(&seed);
        for _ in 0..n {
            fuzzing::bzip2(&mutate(&seed, &mut r));
        }
    }
}

#[test]
fn names_mutations() {
    let n = iters() * 8;
    let mut r = Rng(7);
    let seeds: Vec<Vec<u8>> = vec![
        [cp949("문서/보고서.txt"), cp949("사진/여름 휴가.jpg")].join(&b'\n'),
        "日本語/テスト.txt\nreadme.md".as_bytes().to_vec(),
        b"../../etc/passwd\nC:\\Windows\\x\n\\\\?\\C:\\a\n/abs\nok/../../x\nCON\na:b".to_vec(),
        vec![0x82, 0xa0, 0x82, 0xa2, b'\n', 0xb0, 0xa1, 0xc7, 0xd1],
    ];
    for (i, seed) in seeds.iter().enumerate() {
        save_corpus("names", &format!("seed{i}"), seed);
        fuzzing::names(seed);
        for _ in 0..n {
            fuzzing::names(&mutate(seed, &mut r));
        }
    }
}

/// Inputs libFuzzer reported (out-of-memory from header sizes); each must
/// now be rejected without allocating gigabytes. The extension picks the
/// target (`x.egg`, `x.zip`, ...).
#[test]
fn fuzz_regressions() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fuzz-regressions");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let ext = p.extension().unwrap().to_string_lossy().into_owned();
        nz_archive::fuzzing::archive(&format!("x.{ext}"), &std::fs::read(&p).unwrap());
        n += 1;
    }
    assert!(n >= 2);
}

/// Seeds for the C codec targets (D4): small archives nz-core writes in
/// every tar codec and as 7z, plus raw Deflate/LZMA2 streams.
#[test]
fn core_codec_mutations() {
    use nz_core::{CompressOptions, Format};
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    std::fs::write(src.join("docs/readme.txt"), content(1, 3000)).unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    let n = iters() / 2;
    let mut r = Rng(99);
    let make = |fmt: Format, ext: &str| {
        let out = tmp.path().join(format!("seed.{ext}"));
        nz_core::compress(
            std::slice::from_ref(&src),
            &out,
            &CompressOptions::new(fmt, 5, 1),
        )
        .unwrap();
        read(&out)
    };
    // core_tar: first byte = codec index (gz, bz2, xz, zst, lz4, plain).
    for (sel, fmt, ext) in [
        (0u8, Format::TarGz, "tar.gz"),
        (1, Format::TarBz2, "tar.bz2"),
        (2, Format::TarXz, "tar.xz"),
        (3, Format::TarZst, "tar.zst"),
        (4, Format::TarLz4, "tar.lz4"),
        (5, Format::Tar, "tar"),
    ] {
        let mut seed = vec![sel];
        seed.extend(make(fmt, ext));
        save_corpus("core_tar", ext, &seed);
        fuzzing::core_tar(&seed);
        for _ in 0..n {
            fuzzing::core_tar(&mutate(&seed, &mut r));
        }
    }
    let seed = make(Format::SevenZ, "7z");
    save_corpus("core_7z", "seed.7z", &seed);
    fuzzing::core_7z(&seed);
    for _ in 0..n {
        fuzzing::core_7z(&mutate(&seed, &mut r));
    }
    // codecs: [selector, size/16 (u16 LE), data...].
    let data = content(3, 4096);
    let size = ((data.len() / 16) as u16).to_le_bytes();
    let deflated = nz_core::deflate::deflate_parallel(&data, 6, 1 << 20)
        .map(|d| d.data)
        .unwrap_or_default();
    let p = nz_core::lzma::Lzma2Params::preset(1);
    let lz2 = nz_core::lzma::lzma2_parallel(&data, &p, 1 << 20, 0).unwrap();
    // Unmutated seeds must decode, or the mutations would only test errors.
    assert_eq!(
        nz_core::deflate::inflate_exact(&deflated, data.len()).unwrap(),
        data
    );
    assert_eq!(
        nz_core::lzma::lzma2_decode(&lz2.data, lz2.prop, data.len()).unwrap(),
        data
    );
    for (i, seed) in [
        [&[0u8, size[0], size[1]][..], &deflated].concat(),
        [&[1u8, size[0], size[1], lz2.prop][..], &lz2.data].concat(),
    ]
    .iter()
    .enumerate()
    {
        save_corpus("codecs", &format!("seed{i}"), seed);
        fuzzing::codecs(seed);
        for _ in 0..n {
            fuzzing::codecs(&mutate(seed, &mut r));
        }
    }
}
