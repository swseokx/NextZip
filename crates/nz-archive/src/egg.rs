//! EGG (ALZip 7+) reader.
//!
//! Layout cross-checked between two independent open-source readers
//! (alkegi/unegg in Rust and akolman/EggDotNet in C#, both MIT) and validated
//! with the sample writer in the tests.
//! Little-endian throughout.
//!
//! ```text
//! EGG header     "EGGA" u16 version u32 header_id u32 reserved
//! prefix records SPLIT / SOLID / GLOBAL_ENCRYPT / SKIP ... END
//! file           FILE u32 file_id u64 size
//!                  sub-records (FILENAME, WINFILE, POSIX, ENCRYPT, COMMENT) ... END
//!                  BLOCK u8 method u8 hint u32 usize u32 csize u32 crc END data[csize]
//!                  (more blocks)
//! END                                        end of archive
//! ```
//!
//! Every sub-record starts with an "extra field": u8 flags, then a u16 size
//! (u32 if flags bit 0 is set). Split volumes chain through the SPLIT record's
//! next header id and continue the same byte stream after their own prefix.
//! A SOLID prefix record means all blocks of all files form one compressed
//! stream (method of the first block).

use nz_front::tr;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};

use crate::crypto::{AesBits, AesCtr, ZipCrypto, derive_aes};
use crate::multivol::{MultiReader, ReadLe, Segment};
use crate::{ArchiveError, bzip2, codepage::Codepage};

pub const SIG_EGG: u32 = 0x4147_4745;
const SIG_SPLIT: u32 = 0x24F5_A262;
const SIG_SOLID: u32 = 0x24E5_A060;
const SIG_FILE: u32 = 0x0A85_90E3;
const SIG_FILENAME: u32 = 0x0A85_91AC;
const SIG_COMMENT: u32 = 0x04C6_3672;
const SIG_WINFILE: u32 = 0x2C86_950B;
const SIG_POSIX: u32 = 0x1EE9_22E5;
const SIG_ENCRYPT: u32 = 0x08D1_470F;
const SIG_BLOCK: u32 = 0x02B5_0C13;
const SIG_DUMMY: u32 = 0x0746_3307;
const SIG_END: u32 = 0x08E2_8222;
const SIG_SKIP: u32 = 0xFFFF_0000;
const SIG_GLOBAL_ENCRYPT: u32 = 0x08D1_44A8;

const WIN_ATTR_DIRECTORY: u8 = 0x80;
const NAME_FLAG_ENCRYPTED: u8 = 0x04;
const NAME_FLAG_LOCALE: u8 = 0x08;
const NAME_FLAG_PARENT: u8 = 0x10;

#[derive(Debug, Clone)]
pub struct Block {
    pub method: u8,
    pub usize: u32,
    pub csize: u32,
    pub crc: u32,
    pub data_pos: u64,
}

#[derive(Debug, Clone)]
pub enum Encryption {
    ZipCrypto {
        header: [u8; 12],
        crc: u32,
    },
    Aes {
        bits: AesBits,
        salt: Vec<u8>,
        verifier: [u8; 2],
        tag: Option<[u8; 10]>,
    },
    Lea(u8),
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct Member {
    pub file_id: u32,
    pub raw_name: Vec<u8>,
    /// Code page from the filename record's locale (None: UTF-8).
    pub locale: Option<u16>,
    pub parent_id: Option<u32>,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<SystemTime>,
    pub encryption: Option<Encryption>,
    pub blocks: Vec<Block>,
}

impl Member {
    pub fn csize(&self) -> u64 {
        self.blocks.iter().map(|b| u64::from(b.csize)).sum()
    }
    pub fn method_name(&self) -> String {
        let m = self.blocks.first().map_or(0, |b| b.method);
        let base = match m {
            0 => "Store".to_string(),
            1 => "Deflate".into(),
            2 => "BZip2".into(),
            3 => "AZO".into(),
            4 => "LZMA".into(),
            x => format!("Method {x}"),
        };
        match &self.encryption {
            Some(Encryption::ZipCrypto { .. }) => format!("{base} · ZipCrypto"),
            Some(Encryption::Aes {
                bits: AesBits::Aes128,
                ..
            }) => format!("{base} · AES-128"),
            Some(Encryption::Aes {
                bits: AesBits::Aes256,
                ..
            }) => format!("{base} · AES-256"),
            Some(Encryption::Lea(_)) => format!("{base} · LEA"),
            Some(Encryption::Unknown(x)) => format!("{base} · 암호 {x}"),
            None => base,
        }
    }
}

pub struct Egg {
    pub reader: MultiReader,
    pub members: Vec<Member>,
    pub solid: bool,
}

fn locale_codepage(locale: u16) -> Codepage {
    match locale {
        932 => Codepage::ShiftJis,
        936 => Codepage::Gbk,
        950 => Codepage::Big5,
        65001 => Codepage::Utf8,
        _ => Codepage::Cp949, // 949 and the 0/unknown default of ALZip
    }
}

/// Header id and prefix information of one volume.
struct VolInfo {
    header_id: u32,
    prev: u32,
    next: u32,
    solid: bool,
    data_start: u64,
    size: u64,
}

/// Extra-field head: flags byte, then a u16 size (u32 if flags bit 0).
fn read_extra(r: &mut impl ReadLe) -> Result<(u8, u64)> {
    let flags = r.u8()?;
    let len = if flags & 1 != 0 {
        u64::from(r.u32()?)
    } else {
        u64::from(r.u16()?)
    };
    Ok((flags, len))
}

fn vol_info(path: &Path) -> Result<VolInfo> {
    let mut f = std::io::BufReader::new(
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?,
    );
    let size = f.get_ref().metadata()?.len();
    ensure!(f.u32()? == SIG_EGG, "not an EGG archive");
    let _version = f.u16()?;
    let header_id = f.u32()?;
    let _reserved = f.u32()?;
    let (mut prev, mut next, mut solid) = (0, 0, false);
    let mut pos = 14u64;
    loop {
        let sig = f.u32()?;
        pos += 4;
        if sig == SIG_END {
            break;
        }
        let start = pos;
        let (_, len) = read_extra(&mut f)?;
        let hdr = f.stream_position()? - start;
        pos = start + hdr;
        ensure!(pos + len <= size, "corrupt EGG prefix");
        match sig {
            SIG_SPLIT => {
                ensure!(len >= 8, "corrupt EGG split record");
                prev = f.u32()?;
                next = f.u32()?;
                f.seek_relative(len as i64 - 8)?;
            }
            SIG_SOLID => {
                solid = true;
                f.seek_relative(len as i64)?;
            }
            SIG_SKIP | SIG_GLOBAL_ENCRYPT | SIG_DUMMY | SIG_COMMENT => {
                f.seek_relative(len as i64)?
            }
            other => bail!("corrupt EGG prefix (record {other:#010x})"),
        }
        pos += len;
    }
    Ok(VolInfo {
        header_id,
        prev,
        next,
        solid,
        data_start: pos,
        size,
    })
}

/// Follow the split chain starting at `first` (volumes are found by header
/// id among the `.egg` files of the same folder).
fn chain(first: &Path) -> Result<(Vec<(PathBuf, VolInfo)>, bool)> {
    let info = vol_info(first)?;
    let solid = info.solid;
    let mut out = vec![(first.to_path_buf(), info)];
    if out[0].1.next == 0 && out[0].1.prev == 0 {
        return Ok((out, solid));
    }
    ensure!(
        out[0].1.prev == 0,
        tr("이 파일은 분할 압축의 첫 번째 볼륨이 아닙니다")
    );
    let dir = first.parent().unwrap_or(Path::new("."));
    let mut candidates: Vec<(PathBuf, VolInfo)> = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let p = e.path();
        if p == first || !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("egg")) {
            continue;
        }
        if let Ok(v) = vol_info(&p) {
            candidates.push((p, v));
        }
    }
    let mut seen = vec![out[0].1.header_id];
    while out.last().map(|v| v.1.next).unwrap_or(0) != 0 {
        let want = out.last().map(|v| v.1.next).unwrap_or(0);
        ensure!(!seen.contains(&want), "EGG split chain loops");
        seen.push(want);
        let i = candidates
            .iter()
            .position(|c| c.1.header_id == want)
            .with_context(|| {
                nz_front::trf(
                    "분할 볼륨이 없습니다 (header id {})",
                    &[&format!("{want:#x}")],
                )
            })?;
        out.push(candidates.swap_remove(i));
        ensure!(out.len() <= 10_000, "too many EGG volumes");
    }
    Ok((out, solid))
}

pub fn open(path: &Path) -> Result<Egg> {
    let (vols, solid) = chain(path)?;
    let segs = vols
        .into_iter()
        .map(|(p, v)| -> Result<Segment> {
            Ok(Segment {
                file: std::fs::File::open(&p)?,
                path: p,
                start: v.data_start,
                len: v.size - v.data_start,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut r = MultiReader::new(segs);
    let mut members = parse(&mut r)?;
    resolve_names(&mut members);
    Ok(Egg {
        reader: r,
        members,
        solid,
    })
}

fn parse(r: &mut MultiReader) -> Result<Vec<Member>> {
    let total = r.len();
    let mut members = Vec::new();
    let remaining = |r: &MultiReader| total - r.position().min(total);
    loop {
        if remaining(r) < 4 {
            break;
        }
        let sig = r.u32()?;
        match sig {
            SIG_FILE => {}
            SIG_END => {
                // A volume boundary inside the stream, or the archive end.
                if remaining(r) < 4 {
                    break;
                }
                let next = r.u32()?;
                r.seek(SeekFrom::Current(-4))?;
                if matches!(next, SIG_FILE | SIG_COMMENT | SIG_DUMMY) {
                    continue;
                }
                break;
            }
            SIG_COMMENT | SIG_DUMMY | SIG_SKIP => {
                let (_, len) = read_extra(r)?;
                ensure!(len <= remaining(r), "corrupt EGG record");
                r.seek(SeekFrom::Current(len as i64))?;
                continue;
            }
            other => bail!("corrupt EGG archive (record {other:#010x})"),
        }
        let file_id = r.u32()?;
        let size = r.u64()?;
        let mut m = Member {
            file_id,
            raw_name: Vec::new(),
            locale: None,
            parent_id: None,
            name: String::new(),
            is_dir: false,
            size,
            mtime: None,
            encryption: None,
            blocks: Vec::new(),
        };
        // Sub-records up to END.
        loop {
            let sig = r.u32()?;
            if sig == SIG_END {
                break;
            }
            let (flags, len) = read_extra(r)?;
            ensure!(len <= remaining(r), "corrupt EGG file record");
            let body_start = r.position();
            match sig {
                SIG_FILENAME => {
                    let mut used = 0u64;
                    if flags & NAME_FLAG_LOCALE != 0 {
                        m.locale = Some(r.u16()?);
                        used += 2;
                    }
                    if flags & NAME_FLAG_PARENT != 0 {
                        m.parent_id = Some(r.u32()?);
                        used += 4;
                    }
                    ensure!(used <= len, "corrupt EGG filename record");
                    m.raw_name = r.read_bytes((len - used) as usize)?;
                    if flags & NAME_FLAG_ENCRYPTED != 0 {
                        return Err(ArchiveError::Unsupported(
                            tr("EGG 이름 암호화(이름까지 숨긴 압축 파일)").into(),
                        )
                        .into());
                    }
                }
                SIG_WINFILE => {
                    ensure!(len >= 9, "corrupt EGG Windows file info");
                    let ft = r.u64()?;
                    let attr = r.u8()?;
                    m.is_dir |= attr & WIN_ATTR_DIRECTORY != 0;
                    m.mtime = filetime(ft);
                }
                SIG_POSIX => {
                    ensure!(len >= 20, "corrupt EGG POSIX file info");
                    let mode = r.u32()?;
                    let _uid = r.u32()?;
                    let _gid = r.u32()?;
                    let t = r.u64()?;
                    m.is_dir |= mode & 0xF000 == 0x4000;
                    m.mtime = UNIX_EPOCH.checked_add(Duration::from_secs(t));
                }
                SIG_ENCRYPT => {
                    ensure!(len >= 1, "corrupt EGG encryption record");
                    let method = r.u8()?;
                    let body = r.read_bytes((len - 1) as usize)?;
                    m.encryption = Some(parse_encryption(method, &body)?);
                }
                _ => {} // comments and unknown records are skipped
            }
            r.seek(SeekFrom::Start(body_start + len))?;
        }
        // Blocks.
        loop {
            if remaining(r) < 4 {
                break;
            }
            let sig = r.u32()?;
            if sig != SIG_BLOCK {
                r.seek(SeekFrom::Current(-4))?;
                break;
            }
            let method = r.u8()?;
            let _hint = r.u8()?;
            let usize = r.u32()?;
            let csize = r.u32()?;
            let crc = r.u32()?;
            ensure!(r.u32()? == SIG_END, "corrupt EGG block header");
            let data_pos = r.position();
            ensure!(
                u64::from(csize) <= remaining(r),
                "EGG block runs past the end of the archive (missing volume?)"
            );
            r.seek(SeekFrom::Current(i64::from(csize)))?;
            m.blocks.push(Block {
                method,
                usize,
                csize,
                crc,
                data_pos,
            });
            ensure!(m.blocks.len() <= 1 << 24, "too many EGG blocks");
        }
        members.push(m);
    }
    Ok(members)
}

fn parse_encryption(method: u8, body: &[u8]) -> Result<Encryption> {
    Ok(match method {
        0 => {
            ensure!(body.len() >= 16, "corrupt EGG ZipCrypto header");
            let mut header = [0u8; 12];
            header.copy_from_slice(&body[..12]);
            Encryption::ZipCrypto {
                header,
                crc: u32::from_le_bytes([body[12], body[13], body[14], body[15]]),
            }
        }
        1 | 2 => {
            let bits = if method == 1 {
                AesBits::Aes128
            } else {
                AesBits::Aes256
            };
            let s = bits.salt_len();
            ensure!(body.len() >= s + 2, "corrupt EGG AES header");
            let tag = (body.len() >= s + 12).then(|| {
                let mut t = [0u8; 10];
                t.copy_from_slice(&body[s + 2..s + 12]);
                t
            });
            Encryption::Aes {
                bits,
                salt: body[..s].to_vec(),
                verifier: [body[s], body[s + 1]],
                tag,
            }
        }
        5 | 6 => Encryption::Lea(method),
        x => Encryption::Unknown(x),
    })
}

fn filetime(ft: u64) -> Option<SystemTime> {
    const EPOCH_DIFF: u64 = 11_644_473_600;
    let secs = ft / 10_000_000;
    let nanos = (ft % 10_000_000) * 100;
    secs.checked_sub(EPOCH_DIFF)
        .and_then(|s| UNIX_EPOCH.checked_add(Duration::new(s, nanos as u32)))
}

/// Decode names (UTF-8, or the record's locale code page) and prepend
/// parent folders for records that carry a parent id.
fn resolve_names(members: &mut [Member]) {
    for m in members.iter_mut() {
        let cp = m.locale.map_or(Codepage::Utf8, locale_codepage);
        m.name = cp.decode_lossy(&m.raw_name).replace('\\', "/");
        if m.name.ends_with('/') {
            m.is_dir = true;
        }
    }
    let ids: std::collections::HashMap<u32, usize> = members
        .iter()
        .enumerate()
        .map(|(i, m)| (m.file_id, i))
        .collect();
    let full: Vec<String> = (0..members.len())
        .map(|i| {
            let mut parts = vec![members[i].name.trim_end_matches('/').to_string()];
            let mut cur = members[i].parent_id;
            let mut depth = 0;
            while let Some(pid) = cur.filter(|&p| p != 0) {
                let Some(&j) = ids.get(&pid) else { break };
                if j == i || depth > 256 {
                    break;
                }
                parts.push(members[j].name.trim_end_matches('/').to_string());
                cur = members[j].parent_id;
                depth += 1;
            }
            parts.reverse();
            parts.join("/")
        })
        .collect();
    for (m, n) in members.iter_mut().zip(full) {
        m.name = n;
    }
}

enum Dec {
    Zc(ZipCrypto),
    Aes(Box<AesCtr>, Option<[u8; 10]>),
}

impl Dec {
    fn new(enc: &Encryption, password: Option<&[u8]>) -> Result<Dec> {
        let pw = password.ok_or(ArchiveError::PasswordRequired)?;
        match enc {
            Encryption::ZipCrypto { header, crc } => {
                let mut z = ZipCrypto::new(pw);
                if z.check_header(header) != (crc >> 24) as u8 {
                    return Err(ArchiveError::WrongPassword.into());
                }
                Ok(Dec::Zc(z))
            }
            Encryption::Aes {
                bits,
                salt,
                verifier,
                tag,
            } => {
                let k = derive_aes(pw, salt, *bits);
                if &k.verifier != verifier {
                    return Err(ArchiveError::WrongPassword.into());
                }
                Ok(Dec::Aes(Box::new(AesCtr::new(&k)), *tag))
            }
            Encryption::Lea(_) => {
                Err(ArchiveError::Unsupported(tr("EGG LEA 암호화").into()).into())
            }
            Encryption::Unknown(x) => {
                Err(ArchiveError::Unsupported(nz_front::trf("EGG 암호 방식 {}", &[&x])).into())
            }
        }
    }
    fn decrypt(&mut self, buf: &mut [u8]) {
        match self {
            Dec::Zc(z) => z.decrypt(buf),
            Dec::Aes(a, _) => a.decrypt(buf),
        }
    }
    fn finish(&self) -> Result<()> {
        if let Dec::Aes(a, Some(t)) = self
            && &a.tag() != t
        {
            bail!("AES authentication failed (data corrupted)");
        }
        Ok(())
    }
}

fn decompress(method: u8, data: &[u8], usize: usize) -> Result<Vec<u8>> {
    ensure!(usize as u64 <= crate::MAX_MEMBER, "member too large");
    Ok(match method {
        0 => data.to_vec(),
        1 => crate::inflate(data, usize)?,
        2 => bzip2::decompress(data, bzip2::Variant::Standard, usize)?,
        4 => lzma(data, usize)?,
        3 => return Err(ArchiveError::Unsupported(tr("EGG AZO 압축").into()).into()),
        x => {
            return Err(ArchiveError::Unsupported(nz_front::trf("EGG 압축 방식 {}", &[&x])).into());
        }
    })
}

/// EGG LZMA block: 4 reserved bytes, 5 property bytes, raw LZMA1 stream.
fn lzma(data: &[u8], usize: usize) -> Result<Vec<u8>> {
    ensure!(data.len() >= 9, "corrupt EGG LZMA block");
    let try_with = |size: u64| -> Result<Vec<u8>> {
        let mut alone = Vec::with_capacity(data.len() + 4);
        alone.extend_from_slice(&data[4..9]);
        alone.extend_from_slice(&size.to_le_bytes());
        alone.extend_from_slice(&data[9..]);
        let mut s = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)?;
        let mut out = Vec::with_capacity(usize.min(crate::PREALLOC));
        s.process_vec(&alone, &mut out, liblzma::stream::Action::Finish)?;
        while out.len() < usize && s.total_in() < alone.len() as u64 {
            out.reserve((usize - out.len()).min(crate::PREALLOC));
            let used = s.total_in() as usize;
            let st = s.process_vec(&alone[used..], &mut out, liblzma::stream::Action::Finish)?;
            if st == liblzma::stream::Status::StreamEnd {
                break;
            }
        }
        Ok(out)
    };
    match try_with(usize as u64) {
        Ok(v) if v.len() == usize => Ok(v),
        _ => {
            let v = try_with(u64::MAX)?;
            ensure!(v.len() == usize, "EGG LZMA size mismatch");
            Ok(v)
        }
    }
}

impl Egg {
    /// Read, decrypt, decompress and CRC-check one member (non-solid archives).
    pub fn read(&self, m: &Member, password: Option<&[u8]>) -> Result<Vec<u8>> {
        ensure!(!self.solid, "solid archive: use read_solid");
        let mut dec = match &m.encryption {
            Some(e) => Some(Dec::new(e, password)?),
            None => None,
        };
        let mut out = Vec::with_capacity(m.size.min(crate::PREALLOC as u64) as usize);
        let mut raw_blocks = Vec::with_capacity(m.blocks.len());
        for b in &m.blocks {
            let mut data = self.reader.read_vec_at(b.data_pos, u64::from(b.csize))?;
            if let Some(d) = dec.as_mut() {
                d.decrypt(&mut data);
            }
            raw_blocks.push(data);
        }
        if let Some(d) = &dec {
            d.finish()?;
        }
        for (b, data) in m.blocks.iter().zip(raw_blocks) {
            let plain = decompress(b.method, &data, b.usize as usize).map_err(|e| {
                if dec.is_some() && e.downcast_ref::<ArchiveError>().is_none() {
                    anyhow::Error::from(ArchiveError::WrongPassword)
                } else {
                    e
                }
            })?;
            ensure!(
                plain.len() == b.usize as usize,
                "{}: block size mismatch",
                m.name
            );
            ensure!(crc32fast::hash(&plain) == b.crc, "{}: CRC mismatch", m.name);
            out.extend_from_slice(&plain);
        }
        ensure!(out.len() as u64 == m.size, "{}: size mismatch", m.name);
        Ok(out)
    }

    /// Decode a solid archive: calls `sink(index, data)` for every member in
    /// order. All blocks form one compressed stream.
    pub fn read_solid(
        &self,
        password: Option<&[u8]>,
        mut sink: impl FnMut(usize, Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        let mut comp = Vec::new();
        let mut method = None;
        let mut total = 0u64;
        for m in &self.members {
            let mut dec = match &m.encryption {
                Some(e) => Some(Dec::new(e, password)?),
                None => None,
            };
            for b in &m.blocks {
                method.get_or_insert(b.method);
                let mut data = self.reader.read_vec_at(b.data_pos, u64::from(b.csize))?;
                if let Some(d) = dec.as_mut() {
                    d.decrypt(&mut data);
                }
                comp.extend_from_slice(&data);
                total += u64::from(b.usize);
            }
            if let Some(d) = &dec {
                d.finish()?;
            }
        }
        ensure!(total <= crate::MAX_MEMBER, "solid block too large");
        let plain = decompress(method.unwrap_or(0), &comp, total as usize)?;
        ensure!(plain.len() as u64 == total, "solid size mismatch");
        // Spec example: the blocks follow the last file header and each CRC
        // covers its own slice of the joined output, independent of files.
        let mut off = 0usize;
        for b in self.members.iter().flat_map(|m| &m.blocks) {
            let end = off + b.usize as usize;
            ensure!(
                crc32fast::hash(&plain[off..end]) == b.crc,
                "solid block CRC mismatch"
            );
            off = end;
        }
        let want: u64 = self.members.iter().map(|m| m.size).sum();
        ensure!(
            want == total,
            "solid archive: file sizes do not match the data"
        );
        let mut off = 0usize;
        for (i, m) in self.members.iter().enumerate() {
            let end = off + m.size as usize;
            sink(i, plain[off..end].to_vec())?;
            off = end;
        }
        Ok(())
    }
}
