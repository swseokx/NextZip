//! ALZ (ALZip) reader.
//!
//! Layout from unalz 0.65 (zlib licence, kippler): little-endian records,
//! read sequentially.
//!
//! ```text
//! "ALZ\x01" u32 unknown                       archive header (8 bytes)
//! "BLZ\x01" u16 name_len u8 attr u32 dos_datetime u8 descriptor u8 unknown
//!           [if descriptor>>4 = n > 0:
//!              u8 method u8 unknown u32 crc  n-byte csize  n-byte usize]
//!           name[name_len]  [if descriptor&1: 12-byte ZipCrypto header]
//!           data[csize]
//! "CLZ\x01" 12 bytes                          central directory (ignored)
//! "CLZ\x02"                                   end
//! ```
//!
//! Methods: 0 store, 1 bzip2 without headers (see [`crate::bzip2`]), 2 raw
//! Deflate. Split archives `x.alz, x.a00, x.a01 ...` form one stream after
//! dropping an 8-byte head from every volume but the first and a 16-byte tail
//! from every volume but the last. Names are CP949.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};

use crate::multivol::{MultiReader, ReadLe, Segment};
use crate::{ArchiveError, bzip2, crypto::ZipCrypto};

const SIG_ALZ: u32 = 0x015A_4C41;
const SIG_LOCAL: u32 = 0x015A_4C42;
const SIG_CENTRAL: u32 = 0x015A_4C43;
const SIG_END: u32 = 0x025A_4C43;

pub const ATTR_DIRECTORY: u8 = 0x10;
const DESC_ENCRYPTED: u8 = 0x01;
const DESC_DATA_DESCRIPTOR: u8 = 0x08;

#[derive(Debug, Clone)]
pub struct Member {
    pub raw_name: Vec<u8>,
    pub attr: u8,
    pub dos_datetime: u32,
    pub descriptor: u8,
    pub method: u8,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    pub data_pos: u64,
    pub enc_header: Option<[u8; 12]>,
}

impl Member {
    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }
    pub fn encrypted(&self) -> bool {
        self.enc_header.is_some()
    }
    pub fn mtime(&self) -> Option<SystemTime> {
        crate::dos_to_system(
            (self.dos_datetime & 0xFFFF) as u16,
            (self.dos_datetime >> 16) as u16,
        )
    }
    pub fn method_name(&self) -> String {
        match self.method {
            0 => "Store".into(),
            1 => "BZip2".into(),
            2 => "Deflate".into(),
            m => format!("Method {m}"),
        }
    }
}

pub struct Alz {
    pub reader: MultiReader,
    pub members: Vec<Member>,
}

/// `x.alz` -> `[x.alz, x.a00, x.a01, ...]` (only the ones that exist).
pub fn volume_paths(first: &Path) -> Vec<PathBuf> {
    let mut v = vec![first.to_path_buf()];
    for i in 0..1000u32 {
        let ext = format!("{}{:02}", char::from(b'a' + (i / 100) as u8), i % 100);
        let p = first.with_extension(ext);
        if !p.is_file() {
            break;
        }
        v.push(p);
    }
    v
}

pub fn open(path: &Path) -> Result<Alz> {
    let paths = volume_paths(path);
    let n = paths.len();
    let mut segs = Vec::with_capacity(n);
    for (i, p) in paths.into_iter().enumerate() {
        let file =
            std::fs::File::open(&p).with_context(|| format!("cannot open {}", p.display()))?;
        let size = file.metadata()?.len();
        let head = if i == 0 { 0 } else { 8 };
        let tail = if n == 1 || i == n - 1 { 0 } else { 16 };
        ensure!(size >= head + tail, "{}: volume too short", p.display());
        segs.push(Segment {
            path: p,
            file,
            start: head,
            len: size - head - tail,
        });
    }
    let mut r = MultiReader::new(segs);
    let members = parse(&mut r)?;
    Ok(Alz { reader: r, members })
}

fn parse(r: &mut MultiReader) -> Result<Vec<Member>> {
    let total = r.len();
    let mut members = Vec::new();
    let mut first = true;
    loop {
        if r.position() + 4 > total {
            break; // tolerate a missing end record
        }
        let sig = r.u32()?;
        if first {
            ensure!(sig == SIG_ALZ, "not an ALZ archive");
            first = false;
        }
        match sig {
            SIG_ALZ => {
                r.seek(SeekFrom::Current(4))?;
            }
            SIG_LOCAL => {
                let name_len = usize::from(r.u16()?);
                let attr = r.u8()?;
                let dos_datetime = r.u32()?;
                let descriptor = r.u8()?;
                let _unknown2 = r.u8()?;
                let width = usize::from(descriptor >> 4);
                let (mut method, mut crc, mut csize, mut usize) = (0u8, 0u32, 0u64, 0u64);
                if width > 0 {
                    ensure!(
                        matches!(width, 1 | 2 | 4 | 8),
                        "corrupt ALZ header (size width {width})"
                    );
                    method = r.u8()?;
                    let _unknown = r.u8()?;
                    crc = r.u32()?;
                    csize = r.uint(width)?;
                    usize = r.uint(width)?;
                }
                ensure!(
                    r.position() + name_len as u64 <= total,
                    "corrupt ALZ header (name)"
                );
                let raw_name = r.read_bytes(name_len)?;
                let enc_header = if descriptor & DESC_ENCRYPTED != 0 {
                    let mut h = [0u8; 12];
                    r.read_exact(&mut h)?;
                    Some(h)
                } else {
                    None
                };
                let data_pos = r.position();
                ensure!(
                    data_pos.checked_add(csize).is_some_and(|e| e <= total),
                    "ALZ member data runs past the end of the archive (missing volume?)"
                );
                r.seek(SeekFrom::Start(data_pos + csize))?;
                members.push(Member {
                    raw_name,
                    attr,
                    dos_datetime,
                    descriptor,
                    method,
                    crc,
                    csize,
                    usize,
                    data_pos,
                    enc_header,
                });
            }
            SIG_CENTRAL => {
                r.seek(SeekFrom::Current(12))?;
            }
            SIG_END => break,
            other => bail!("corrupt ALZ archive (unknown record {other:#010x})"),
        }
    }
    Ok(members)
}

impl Alz {
    /// Read, decrypt, decompress and CRC-check one member.
    pub fn read(&self, m: &Member, password: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut data = self.reader.read_vec_at(m.data_pos, m.csize)?;
        if let Some(h) = &m.enc_header {
            let pw = password.ok_or(ArchiveError::PasswordRequired)?;
            let mut zc = ZipCrypto::new(pw);
            let check = zc.check_header(h);
            // unalz compares the CRC's high byte, or the time's second byte
            // when a data descriptor is flagged (masked here; unalz forgot).
            let expect = if m.descriptor & DESC_DATA_DESCRIPTOR != 0 {
                ((m.dos_datetime >> 8) & 0xFF) as u8
            } else {
                (m.crc >> 24) as u8
            };
            if check != expect {
                return Err(ArchiveError::WrongPassword.into());
            }
            zc.decrypt(&mut data);
        }
        ensure!(m.usize <= crate::MAX_MEMBER, "member too large");
        let out = match m.method {
            0 => data,
            1 => bzip2::decompress(&data, bzip2::Variant::Alz, m.usize as usize)?,
            2 => crate::inflate(&data, m.usize as usize)?,
            x => {
                return Err(
                    ArchiveError::Unsupported(nz_front::trf("ALZ 압축 방식 {}", &[&x])).into(),
                );
            }
        };
        ensure!(out.len() as u64 == m.usize, "size mismatch");
        if crc32fast::hash(&out) != m.crc {
            if m.encrypted() {
                return Err(ArchiveError::WrongPassword.into());
            }
            bail!("CRC mismatch");
        }
        Ok(out)
    }
}
