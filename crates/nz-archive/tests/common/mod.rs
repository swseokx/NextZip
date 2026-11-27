//! Sample writers for ALZ, EGG and legacy-code-page ZIP, used to build test
//! archives (no tool on this PC can create ALZ/EGG). Every layout choice here
//! can be cross-checked by extracting the result with an external console
//! archiver (`NZ_REF_ARCHIVER`) in the tests, so the writer, the reader and an
//! independent implementation agree.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};

use nz_archive::crypto::{AesBits, AesCtr, ZipCrypto, derive_aes};

pub struct Item {
    pub name: String,
    pub data: Vec<u8>,
    pub dir: bool,
}

pub fn file(name: &str, data: &[u8]) -> Item {
    Item {
        name: name.into(),
        data: data.to_vec(),
        dir: false,
    }
}

pub fn dir(name: &str) -> Item {
    Item {
        name: name.into(),
        data: vec![],
        dir: true,
    }
}

/// Mixed sample content: text, repeated runs, pseudo-random bytes.
pub fn content(seed: u32, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    while v.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        match (x >> 16) % 5 {
            0 => v.extend_from_slice("압축 테스트 문장입니다. ".as_bytes()),
            1 => v.extend_from_slice(b"NextZip sample line\r\n"),
            2 => v.extend(std::iter::repeat_n((x >> 8) as u8, 40)),
            _ => v.extend((0..16).map(|i| (x >> (i % 24)) as u8)),
        }
    }
    v.truncate(n);
    v
}

pub fn cp949(s: &str) -> Vec<u8> {
    let (b, _, bad) = encoding_rs::EUC_KR.encode(s);
    assert!(!bad);
    b.into_owned()
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut c = libdeflater::Compressor::new(libdeflater::CompressionLvl::new(6).unwrap());
    let mut out = vec![0u8; c.deflate_compress_bound(data.len())];
    let n = c.deflate_compress(data, &mut out).unwrap();
    out.truncate(n);
    out
}

pub fn bzip2_std(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(9));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// LZMA "alone" stream re-packed as EGG expects: 4 reserved bytes, 5 props,
/// raw stream (with end marker).
pub fn egg_lzma(data: &[u8]) -> Vec<u8> {
    let opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
    let mut s = liblzma::stream::Stream::new_lzma_encoder(&opts).unwrap();
    let mut out = Vec::with_capacity(data.len() + 1024);
    loop {
        let used = s.total_in() as usize;
        let st = s
            .process_vec(&data[used..], &mut out, liblzma::stream::Action::Finish)
            .unwrap();
        if st == liblzma::stream::Status::StreamEnd {
            break;
        }
        out.reserve(out.capacity().max(1 << 16));
    }
    // LZMA SDK version 9.20 and a 5-byte property size, as in ZIP method 14;
    // common extractors reject the archive when these bytes are zero.
    let mut v = vec![9u8, 20, 5, 0];
    v.extend_from_slice(&out[..5]);
    v.extend_from_slice(&out[13..]);
    v
}

const DOS_TIME: u32 = ((2026 - 1980) << 25) | (11 << 21) | (20 << 16) | (9 << 11) | (30 << 5) | 10;

// ------------------------------------------------------------------ ALZ

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AlzMethod {
    Store,
    Bzip2,
    Deflate,
}

/// Build one ALZ byte stream.
pub fn alz_bytes(items: &[Item], method: AlzMethod, password: Option<&[u8]>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ALZ\x01\x0a\x00\x00\x00");
    for (k, it) in items.iter().enumerate() {
        let name = cp949(&it.name.replace('/', "\\"));
        let crc = crc32fast::hash(&it.data);
        let (m, mut payload) = if it.dir {
            (0u8, vec![])
        } else {
            match method {
                AlzMethod::Store => (0u8, it.data.clone()),
                AlzMethod::Bzip2 => (
                    1,
                    nz_archive::bzip2::standard_to_alz(&bzip2_std(&it.data)).unwrap(),
                ),
                AlzMethod::Deflate => (2, deflate(&it.data)),
            }
        };
        let enc = password.filter(|_| !it.dir);
        v.extend_from_slice(b"BLZ\x01");
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.push(if it.dir { 0x10 } else { 0x20 });
        v.extend_from_slice(&DOS_TIME.to_le_bytes());
        let desc = if it.dir { 0 } else { 0x40 } | u8::from(enc.is_some());
        v.push(desc);
        v.push(0);
        if !it.dir {
            v.push(m);
            v.push(0);
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            v.extend_from_slice(&(it.data.len() as u32).to_le_bytes());
        }
        v.extend_from_slice(&name);
        if let Some(pw) = enc {
            let mut zc = ZipCrypto::new(pw);
            let mut head = [0u8; 12];
            for (i, b) in head.iter_mut().enumerate() {
                *b = (k * 31 + i * 7) as u8;
            }
            head[11] = (crc >> 24) as u8;
            zc.encrypt(&mut head);
            v.extend_from_slice(&head);
            zc.encrypt(&mut payload);
        }
        v.extend_from_slice(&payload);
    }
    v.extend_from_slice(b"CLZ\x01");
    v.extend_from_slice(&[0u8; 12]);
    v.extend_from_slice(b"CLZ\x02");
    v
}

/// Split an ALZ stream into `x.alz, x.a00 ...` with 8-byte heads and
/// 16-byte tails as unalz expects.
pub fn write_alz_split(stream: &[u8], first: &Path, chunk: usize) -> Vec<PathBuf> {
    let chunks: Vec<&[u8]> = stream.chunks(chunk).collect();
    let n = chunks.len();
    let mut paths = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        let p = if i == 0 {
            first.to_path_buf()
        } else {
            let k = i - 1;
            first.with_extension(format!(
                "{}{:02}",
                char::from(b'a' + (k / 100) as u8),
                k % 100
            ))
        };
        // Layout of ALZip 26.11 split sets (tests/data/alz_split_real.*):
        // volumes after the first start with "ALZ\x01\x0a\x00" + u16 volume
        // number; every volume but the last ends with
        // "CLZ\x01" + 8 zero bytes + "CLZ\x03".
        let mut v = Vec::new();
        if i > 0 {
            v.extend_from_slice(b"ALZ\x01\x0a\x00");
            v.extend_from_slice(&(i as u16).to_le_bytes());
        }
        v.extend_from_slice(c);
        if i + 1 < n {
            v.extend_from_slice(b"CLZ\x01\0\0\0\0\0\0\0\0CLZ\x03");
        }
        std::fs::write(&p, v).unwrap();
        paths.push(p);
    }
    paths
}

// ------------------------------------------------------------------ EGG

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EggMethod {
    Store,
    Deflate,
    Bzip2,
    Lzma,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EggCrypt {
    None,
    ZipCrypto,
    Aes128,
    Aes256,
}

fn extra(v: &mut Vec<u8>, sig: u32, flags: u8, body: &[u8]) {
    v.extend_from_slice(&sig.to_le_bytes());
    v.push(flags);
    v.extend_from_slice(&(body.len() as u16).to_le_bytes());
    v.extend_from_slice(body);
}

const END: u32 = 0x08E2_8222;

fn egg_header(v: &mut Vec<u8>, id: u32) {
    v.extend_from_slice(&0x4147_4745u32.to_le_bytes());
    v.extend_from_slice(&0x0100u16.to_le_bytes());
    v.extend_from_slice(&id.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
}

fn compress(method: EggMethod, data: &[u8]) -> (u8, Vec<u8>) {
    match method {
        EggMethod::Store => (0, data.to_vec()),
        EggMethod::Deflate => (1, deflate(data)),
        EggMethod::Bzip2 => (2, bzip2_std(data)),
        EggMethod::Lzma => (4, egg_lzma(data)),
    }
}

pub struct EggOpts {
    pub method: EggMethod,
    pub crypt: EggCrypt,
    pub password: Vec<u8>,
    /// Store names as CP949 with locale 949 instead of UTF-8.
    pub locale_949: bool,
    pub solid: bool,
}

/// Build the file part of an EGG stream (after the prefix), ending with END.
fn egg_files(items: &[Item], o: &EggOpts) -> Vec<u8> {
    let mut v = Vec::new();
    // Solid (spec example "a.txt, b.txt"): no blocks per file; one block
    // after the last file header holds the whole compressed stream.
    let solid_block: Option<(u8, Vec<u8>, Vec<u8>)> = o.solid.then(|| {
        let all: Vec<u8> = items.iter().flat_map(|i| i.data.clone()).collect();
        let (m, comp) = compress(o.method, &all);
        (m, comp, all)
    });
    for (k, it) in items.iter().enumerate() {
        v.extend_from_slice(&0x0A85_90E3u32.to_le_bytes());
        v.extend_from_slice(&(k as u32 + 1).to_le_bytes());
        v.extend_from_slice(&(it.data.len() as u64).to_le_bytes());
        // Filename
        let mut body = Vec::new();
        let flags = if o.locale_949 {
            body.extend_from_slice(&949u16.to_le_bytes());
            body.extend_from_slice(&cp949(&it.name));
            0x08
        } else {
            body.extend_from_slice(it.name.as_bytes());
            0
        };
        extra(&mut v, 0x0A85_91AC, flags, &body);
        // Windows file info: FILETIME 2026-11-20 00:30:10 UTC, attribute
        let ft: u64 = (1_795_221_010 + 11_644_473_600) * 10_000_000;
        let mut wi = ft.to_le_bytes().to_vec();
        wi.push(if it.dir { 0x80 } else { 0x20 });
        extra(&mut v, 0x2C86_950B, 0, &wi);
        // Blocks (computed first so the AES tag is known)
        let crc = crc32fast::hash(&it.data);
        let (m, mut payload) = if it.dir || o.solid {
            (0, vec![])
        } else {
            compress(o.method, &it.data)
        };
        let encrypt = o.crypt != EggCrypt::None && !it.dir;
        if encrypt {
            let mut enc = vec![];
            match o.crypt {
                EggCrypt::ZipCrypto => {
                    let mut zc = ZipCrypto::new(&o.password);
                    let mut head = [0x5Au8; 12];
                    head[11] = (crc >> 24) as u8;
                    zc.encrypt(&mut head);
                    zc.encrypt(&mut payload);
                    enc.push(0);
                    enc.extend_from_slice(&head);
                    enc.extend_from_slice(&crc.to_le_bytes());
                }
                EggCrypt::Aes128 | EggCrypt::Aes256 => {
                    let (bits, method) = if o.crypt == EggCrypt::Aes128 {
                        (AesBits::Aes128, 1u8)
                    } else {
                        (AesBits::Aes256, 2u8)
                    };
                    let salt: Vec<u8> = (0..bits.salt_len()).map(|i| (i * 13 + k) as u8).collect();
                    let keys = derive_aes(&o.password, &salt, bits);
                    let mut a = AesCtr::new(&keys);
                    a.encrypt(&mut payload);
                    enc.push(method);
                    enc.extend_from_slice(&salt);
                    enc.extend_from_slice(&keys.verifier);
                    enc.extend_from_slice(&a.tag());
                }
                EggCrypt::None => unreachable!(),
            }
            extra(&mut v, 0x08D1_470F, 0, &enc);
        }
        v.extend_from_slice(&END.to_le_bytes());
        let block = |v: &mut Vec<u8>, m: u8, usize: usize, crc: u32, payload: &[u8]| {
            v.extend_from_slice(&0x02B5_0C13u32.to_le_bytes());
            v.push(m);
            v.push(0);
            v.extend_from_slice(&(usize as u32).to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&END.to_le_bytes());
            v.extend_from_slice(payload);
        };
        if !it.dir && !o.solid {
            block(&mut v, m, it.data.len(), crc, &payload);
        }
        if let (Some((m, comp, all)), true) = (&solid_block, k + 1 == items.len()) {
            block(&mut v, *m, all.len(), crc32fast::hash(all), comp);
        }
    }
    v.extend_from_slice(&END.to_le_bytes());
    v
}

pub fn write_egg(path: &Path, items: &[Item], o: &EggOpts) {
    let mut v = Vec::new();
    egg_header(&mut v, 0x1234_5678);
    if o.solid {
        extra(&mut v, 0x24E5_A060, 0, &[]);
    }
    v.extend_from_slice(&END.to_le_bytes());
    v.extend_from_slice(&egg_files(items, o));
    std::fs::write(path, v).unwrap();
}

/// Split EGG: `<stem>.vol1.egg, <stem>.vol2.egg, ...`.
pub fn write_egg_split(
    dir: &Path,
    stem: &str,
    items: &[Item],
    o: &EggOpts,
    chunk: usize,
) -> Vec<PathBuf> {
    let stream = egg_files(items, o);
    let chunks: Vec<&[u8]> = stream.chunks(chunk).collect();
    let n = chunks.len() as u32;
    let id = |i: u32| 0x1000_0000 + i;
    let mut paths = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        let i = i as u32;
        let mut v = Vec::new();
        egg_header(&mut v, id(i + 1));
        let prev = if i == 0 { 0 } else { id(i) };
        let next = if i + 1 == n { 0 } else { id(i + 2) };
        let mut sp = prev.to_le_bytes().to_vec();
        sp.extend_from_slice(&next.to_le_bytes());
        extra(&mut v, 0x24F5_A262, 0, &sp);
        if o.solid {
            extra(&mut v, 0x24E5_A060, 0, &[]);
        }
        v.extend_from_slice(&END.to_le_bytes());
        v.extend_from_slice(c);
        let p = dir.join(format!("{stem}.vol{}.egg", i + 1));
        std::fs::write(&p, v).unwrap();
        paths.push(p);
    }
    paths
}

// ------------------------------------------------------------------ ZIP

/// Minimal ZIP (store) with raw name bytes and no UTF-8 flag, like old
/// Korean/Japanese tools wrote.
pub fn write_legacy_zip(path: &Path, items: &[(Vec<u8>, Vec<u8>)]) {
    let mut v = Vec::new();
    let mut central = Vec::new();
    for (name, data) in items {
        let off = v.len() as u32;
        let crc = crc32fast::hash(data);
        let dos = DOS_TIME;
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // flags: no UTF-8
        v.extend_from_slice(&0u16.to_le_bytes()); // store
        v.extend_from_slice(&dos.to_le_bytes());
        v.extend_from_slice(&crc.to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&dos.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 12]);
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_off = v.len() as u32;
    v.extend_from_slice(&central);
    v.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    v.extend_from_slice(&(items.len() as u16).to_le_bytes());
    v.extend_from_slice(&(items.len() as u16).to_le_bytes());
    v.extend_from_slice(&(central.len() as u32).to_le_bytes());
    v.extend_from_slice(&cd_off.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    std::fs::write(path, v).unwrap();
}

// ------------------------------------------------------- reference archiver

/// External console archiver named by `NZ_REF_ARCHIVER` (`x -y -aoa -o:
/// -p:` switches); cross-checks are skipped when it is not set.
pub fn ref_tool() -> Option<PathBuf> {
    std::env::var_os("NZ_REF_ARCHIVER")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

/// Extract with the reference tool; returns Err(stdout+stderr) on failure.
pub fn ref_extract(archive: &Path, out: &Path, password: Option<&str>) -> Result<(), String> {
    let tool = ref_tool().ok_or("NZ_REF_ARCHIVER not set")?;
    let mut cmd = std::process::Command::new(tool);
    cmd.arg("x")
        .arg("-y")
        .arg("-aoa")
        .arg(format!("-o:{}", out.display()));
    if let Some(pw) = password {
        cmd.arg(format!("-p:{pw}"));
    }
    let o = cmd.arg(archive).output().map_err(|e| e.to_string())?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    if o.status.success() {
        Ok(())
    } else {
        Err(text)
    }
}

/// Assert every file item exists below `root` with the same bytes.
pub fn assert_tree(root: &Path, items: &[Item]) {
    for it in items {
        let p = root.join(it.name.replace('/', std::path::MAIN_SEPARATOR_STR));
        if it.dir {
            assert!(p.is_dir(), "missing dir {}", p.display());
        } else {
            let got = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            assert!(got == it.data, "content differs: {}", p.display());
        }
    }
}
