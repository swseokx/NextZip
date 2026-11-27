//! Fuzz bodies shared by the cargo-fuzz targets in `/fuzz` and the stable
//! mutation smoke test (`tests/fuzz_smoke.rs`). Each body must never panic,
//! hang or write outside its output directory, whatever the input.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::bzip2::{self, Variant};
use crate::codepage;
use crate::safepath;

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("nz-fuzz-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_inside(root: &Path, dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        let root_c = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        assert!(
            canon.starts_with(&root_c),
            "escaped output dir: {}",
            p.display()
        );
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            assert_inside(root, &p);
        }
    }
}

/// List and extract an archive given as bytes (any supported format; the
/// kind is sniffed from the content). `name` is the file name to use, so a
/// target can steer multi-volume naming (`x.alz`, `x.egg`, `x.rar`).
pub fn archive(name: &str, data: &[u8]) {
    let tmp = TempDir::new();
    let path = tmp.0.join(name);
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let opt = crate::Options {
        password: Some("fuzz".into()),
        threads: 1,
        ..Default::default()
    };
    if let Ok(l) = crate::list(&path, &opt) {
        // Refuse inputs that claim huge members: extraction would only
        // measure the allocator.
        if l.total_size() > 64 << 20 {
            return;
        }
    }
    let out = tmp.0.join("out");
    let _ = crate::extract(&path, &out, &opt, None);
    assert_inside(&out, &out);
}

/// Prefix `data` with `magic` unless it already starts with it, so the
/// fuzzer spends its time behind the signature.
fn with_magic(magic: &[u8], data: &[u8]) -> Vec<u8> {
    if data.starts_with(magic) {
        return data.to_vec();
    }
    let mut v = magic.to_vec();
    v.extend_from_slice(data);
    v
}

/// The tar family through nz-core (D4: gzip, bzip2, xz, zstd and lz4 are C
/// decoders running in the main process). The first byte picks the codec.
pub fn core_tar(data: &[u8]) {
    const CODECS: [(&str, &[u8]); 6] = [
        ("x.tar.gz", &[0x1f, 0x8b]),
        ("x.tar.bz2", b"BZh"),
        ("x.tar.xz", &[0xfd, b'7', b'z', b'X', b'Z', 0]),
        ("x.tar.zst", &[0x28, 0xb5, 0x2f, 0xfd]),
        ("x.tar.lz4", &[0x04, 0x22, 0x4d, 0x18]),
        ("x.tar", b""),
    ];
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let (name, magic) = CODECS[usize::from(sel) % CODECS.len()];
    archive(name, &with_magic(magic, rest));
}

/// 7z through nz-core's native reader (D4: LZMA/LZMA2 on liblzma, Deflate
/// on libdeflate, in the main process).
pub fn core_7z(data: &[u8]) {
    archive("x.7z", &with_magic(b"7z\xbc\xaf\x27\x1c", data));
}

/// The raw C decoders as nz-core calls them for ZIP and 7z members, with
/// the declared size and properties taken from the input (D4).
pub fn codecs(data: &[u8]) {
    let [sel, a, b, rest @ ..] = data else {
        return;
    };
    // Up to 1 MiB of claimed output.
    let size = usize::from(u16::from_le_bytes([*a, *b])) * 16;
    match sel % 3 {
        0 => {
            let _ = nz_core::deflate::inflate_exact(rest, size);
        }
        1 => {
            if let Some((prop, packed)) = rest.split_first() {
                let _ = nz_core::lzma::lzma2_decode(packed, *prop, size);
            }
        }
        _ => {
            if let Some((props, packed)) = rest.split_first_chunk::<5>() {
                let _ = nz_core::lzma::lzma1_decode(packed, props, size);
            }
        }
    }
}

/// Raw bzip2 decoding, standard and ALZ flavours.
pub fn bzip2(data: &[u8]) {
    let _ = bzip2::decompress(data, Variant::Standard, 1 << 20);
    let _ = bzip2::decompress(data, Variant::Alz, 1 << 20);
}

/// Code page detection and the zip-slip guard on arbitrary name bytes.
pub fn names(data: &[u8]) {
    let names: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
    let d = codepage::detect(names.iter().copied(), None);
    assert!((0.0..=1.0).contains(&d.confidence));
    for n in &names {
        let s = d.codepage.decode_lossy(n);
        if let Some(p) = safepath::sanitize(&s) {
            assert!(p.is_relative(), "{s:?} -> {p:?}");
            for c in p.components() {
                assert!(
                    matches!(c, Component::Normal(_)),
                    "{s:?} -> {p:?} has {c:?}"
                );
            }
        }
    }
}
