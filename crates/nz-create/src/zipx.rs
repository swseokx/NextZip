//! ZIPX: a ZIP archive whose members use the newer APPNOTE methods,
//! Zstandard (93), LZMA (14), PPMd var. I (98), XZ (95) or BZip2 (12).
//! The container is plain ZIP (ZIP64 where sizes need it, UTF-8 names,
//! extended UTC timestamps), readable by 7-Zip, WinZip and other ZIPX readers.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use nz_core::walk::{self, Kind as EntryKind};

use crate::{Options, Stats};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Zstd,
    Lzma,
    Ppmd,
    Xz,
    Bzip2,
}

impl Method {
    pub fn parse(s: &str) -> Option<Method> {
        Some(match s.to_ascii_lowercase().as_str() {
            "zstd" | "zst" => Method::Zstd,
            "lzma" => Method::Lzma,
            "ppmd" => Method::Ppmd,
            "xz" => Method::Xz,
            "bzip2" | "bz2" => Method::Bzip2,
            _ => return None,
        })
    }

    /// APPNOTE compression method number.
    pub fn id(self) -> u16 {
        match self {
            Method::Zstd => 93,
            Method::Lzma => 14,
            Method::Ppmd => 98,
            Method::Xz => 95,
            Method::Bzip2 => 12,
        }
    }

    fn version_needed(self) -> u16 {
        match self {
            Method::Bzip2 => 46,
            _ => 63,
        }
    }
}

/// Counts bytes passing through to the inner writer.
struct Counter<W: Write> {
    inner: W,
    n: u64,
}

impl<W: Write> Write for Counter<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(b)?;
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// CRC-32 and byte count of everything read.
struct CrcReader<R: Read> {
    inner: R,
    crc: crc32fast::Hasher,
    n: u64,
}

impl<R: Read> Read for CrcReader<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(b)?;
        self.crc.update(&b[..n]);
        self.n += n as u64;
        Ok(n)
    }
}

/// Drops the 13-byte `.lzma` header (props, dictionary, size) liblzma's
/// "alone" encoder writes, keeping its first 5 bytes for the ZIP header.
struct StripAlone<W: Write> {
    inner: W,
    head: Vec<u8>,
}

impl<W: Write> Write for StripAlone<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let mut rest = b;
        if self.head.len() < 13 {
            let k = (13 - self.head.len()).min(rest.len());
            self.head.extend_from_slice(&rest[..k]);
            rest = &rest[k..];
        }
        self.inner.write_all(rest)?;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Pick PPMd order and memory (MiB) for a 0..9 level, like 7-Zip's presets.
fn ppmd_params(level: u32) -> (u32, u32) {
    let l = level.min(9) as usize;
    (
        [4, 4, 4, 5, 5, 6, 8, 10, 16, 32][l],
        [1, 2, 4, 8, 8, 16, 32, 64, 128, 192][l],
    )
}

/// Compress `r` into `w` with `m`. Returns extra general-purpose flags.
fn encode(m: Method, r: &mut dyn Read, w: &mut dyn Write, opt: &Options) -> Result<u16> {
    let level = opt.level.min(9);
    match m {
        Method::Zstd => {
            let zl = [1, 2, 3, 4, 6, 9, 12, 15, 17, 19][level as usize];
            let mut e = zstd::stream::write::Encoder::new(w, zl)?;
            let t = crate::threads(opt);
            if t > 1 {
                e.multithread(t as u32)?;
            }
            std::io::copy(r, &mut e)?;
            e.finish()?;
            Ok(0)
        }
        Method::Xz => {
            let stream = liblzma::stream::MtStreamBuilder::new()
                .preset(level)
                .threads(crate::threads(opt).clamp(1, 64) as u32)
                // CRC32, as 7-Zip writes: some XZ-in-ZIP decoders
                // fail on CRC64 checks.
                .check(liblzma::stream::Check::Crc32)
                .encoder()?;
            let mut e = liblzma::write::XzEncoder::new_stream(w, stream);
            std::io::copy(r, &mut e)?;
            e.finish()?;
            Ok(0)
        }
        Method::Bzip2 => {
            let mut e = bzip2::write::BzEncoder::new(w, bzip2::Compression::new(level.max(1)));
            std::io::copy(r, &mut e)?;
            e.finish()?;
            Ok(0)
        }
        Method::Lzma => {
            // ZIP LZMA header: SDK version 9.20, props size 5, then the
            // props and dictionary size from the .lzma header.
            let lz = liblzma::stream::LzmaOptions::new_preset(level)?;
            let stream = liblzma::stream::Stream::new_lzma_encoder(&lz)?;
            let mut strip = StripAlone {
                inner: Vec::new(),
                head: Vec::new(),
            };
            {
                let mut e = liblzma::write::XzEncoder::new_stream(&mut strip, stream);
                std::io::copy(r, &mut e)?;
                e.finish()?;
            }
            if strip.head.len() < 5 {
                bail!("LZMA encoder produced no header");
            }
            w.write_all(&[9, 20, 5, 0])?;
            w.write_all(&strip.head[..5])?;
            w.write_all(&strip.inner)?;
            // Bit 1: the stream ends with an end-of-stream marker.
            Ok(1 << 1)
        }
        Method::Ppmd => {
            let (order, mem) = ppmd_params(level);
            let restore = if order < 7 {
                ppmd_rust::RestoreMethod::Restart
            } else {
                ppmd_rust::RestoreMethod::CutOff
            };
            let props: u16 =
                (order - 1) as u16 | ((mem - 1) as u16) << 4 | (u16::from(order >= 7)) << 12;
            w.write_all(&props.to_le_bytes())?;
            let mut e = ppmd_rust::Ppmd8Encoder::new(w, order, mem << 20, restore)
                .map_err(|e| anyhow::anyhow!("PPMd: {e:?}"))?;
            std::io::copy(r, &mut e)?;
            e.finish(true)?;
            Ok(0)
        }
    }
}

/// DOS date and time (local time) for `t`.
fn dos_time(t: SystemTime) -> (u16, u16) {
    use chrono::{Datelike, Local, Timelike};
    let dt: chrono::DateTime<Local> = t.into();
    if dt.year() < 1980 {
        return (0, (1 << 5) | 1);
    }
    let time = ((dt.hour() << 11) | (dt.minute() << 5) | (dt.second() / 2)) as u16;
    let date = ((((dt.year() - 1980).min(127) as u32) << 9) | (dt.month() << 5) | dt.day()) as u16;
    (time, date)
}

fn unix_secs(t: SystemTime) -> u32 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(u64::from(u32::MAX)) as u32)
}

struct Central {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    version: u16,
    time: u16,
    date: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    offset: u64,
    dir: bool,
    mtime: u32,
}

const MAX32: u64 = 0xFFFF_FFFF;

fn le16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn le32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn le64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn timestamp_extra(v: &mut Vec<u8>, mtime: u32) {
    le16(v, 0x5455);
    le16(v, 5);
    v.push(1);
    le32(v, mtime);
}

pub(crate) fn create(m: Method, sources: &[PathBuf], out: &Path, opt: &Options) -> Result<Stats> {
    let entries = walk::collect(sources)?;
    let f = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, f);
    let mut pos = 0u64;
    let mut cd = Vec::with_capacity(entries.len());
    let mut stats = Stats::default();
    for e in &entries {
        let dir = e.kind == EntryKind::Dir;
        let mut name = e.name.clone().into_bytes();
        if dir {
            name.push(b'/');
        }
        let utf8 = if name.is_ascii() { 0 } else { 1 << 11 };
        let (time, date) = dos_time(e.mtime);
        let mtime = unix_secs(e.mtime);
        let (method, version) = if dir || e.size == 0 {
            (0u16, if dir { 20 } else { 10 })
        } else {
            (m.id(), m.version_needed().max(45))
        };
        // Local header; files carry a ZIP64 extra so sizes are patched in
        // place whatever they turn out to be.
        let mut h = Vec::with_capacity(64 + name.len());
        le32(&mut h, 0x0403_4b50);
        le16(&mut h, version);
        let flags_pos = h.len();
        le16(&mut h, utf8);
        le16(&mut h, method);
        le16(&mut h, time);
        le16(&mut h, date);
        le32(&mut h, 0); // crc, patched
        let z64 = !dir;
        le32(&mut h, if z64 { MAX32 as u32 } else { 0 });
        le32(&mut h, if z64 { MAX32 as u32 } else { 0 });
        le16(&mut h, name.len() as u16);
        le16(&mut h, if z64 { 20 + 9 } else { 9 });
        h.extend_from_slice(&name);
        let z64_pos = h.len() + 4;
        if z64 {
            le16(&mut h, 0x0001);
            le16(&mut h, 16);
            le64(&mut h, 0);
            le64(&mut h, 0);
        }
        timestamp_extra(&mut h, mtime);
        if name.len() > u16::MAX as usize {
            bail!(nz_front::trf("이름이 너무 깁니다: {}", &[&e.name]));
        }
        let offset = pos;
        w.write_all(&h)?;
        pos += h.len() as u64;
        let (mut crc, mut csize, mut usize, mut flags) = (0u32, 0u64, 0u64, utf8);
        if dir {
            stats.dirs += 1;
        } else {
            let input =
                File::open(&e.path).with_context(|| format!("cannot open {}", e.path.display()))?;
            let mut r = CrcReader {
                inner: std::io::BufReader::with_capacity(1 << 20, input),
                crc: crc32fast::Hasher::new(),
                n: 0,
            };
            let mut c = Counter {
                inner: &mut w,
                n: 0,
            };
            if method == 0 {
                std::io::copy(&mut r, &mut c)?;
            } else {
                flags |= encode(m, &mut r, &mut c, opt)?;
            }
            csize = c.n;
            usize = r.n;
            crc = r.crc.finalize();
            pos += csize;
            // Patch flags, CRC and the ZIP64 sizes.
            w.flush()?;
            let f = w.get_mut();
            f.seek(SeekFrom::Start(offset + flags_pos as u64))?;
            f.write_all(&flags.to_le_bytes())?;
            f.seek(SeekFrom::Start(offset + 14))?;
            f.write_all(&crc.to_le_bytes())?;
            f.seek(SeekFrom::Start(offset + z64_pos as u64))?;
            let mut s = Vec::with_capacity(16);
            le64(&mut s, usize);
            le64(&mut s, csize);
            f.write_all(&s)?;
            f.seek(SeekFrom::Start(pos))?;
            stats.files += 1;
            stats.bytes_in += usize;
        }
        cd.push(Central {
            name,
            flags,
            method,
            version: if usize > MAX32 || csize > MAX32 || offset > MAX32 {
                version.max(45)
            } else {
                version
            },
            time,
            date,
            crc,
            csize,
            usize,
            offset,
            dir,
            mtime,
        });
    }
    // Central directory.
    let cd_start = pos;
    for c in &cd {
        let mut z = Vec::new();
        let us = if c.usize >= MAX32 {
            le64(&mut z, c.usize);
            MAX32 as u32
        } else {
            c.usize as u32
        };
        let cs = if c.csize >= MAX32 {
            le64(&mut z, c.csize);
            MAX32 as u32
        } else {
            c.csize as u32
        };
        let off = if c.offset >= MAX32 {
            le64(&mut z, c.offset);
            MAX32 as u32
        } else {
            c.offset as u32
        };
        let mut h = Vec::with_capacity(64 + c.name.len());
        le32(&mut h, 0x0201_4b50);
        le16(&mut h, 63); // made by: MS-DOS / NTFS attributes, APPNOTE 6.3
        le16(&mut h, c.version);
        le16(&mut h, c.flags);
        le16(&mut h, c.method);
        le16(&mut h, c.time);
        le16(&mut h, c.date);
        le32(&mut h, c.crc);
        le32(&mut h, cs);
        le32(&mut h, us);
        le16(&mut h, c.name.len() as u16);
        let z_len = if z.is_empty() { 0 } else { 4 + z.len() };
        le16(&mut h, (z_len + 9) as u16);
        le16(&mut h, 0); // comment
        le16(&mut h, 0); // disk
        le16(&mut h, 0); // internal attributes
        le32(&mut h, if c.dir { 0x10 } else { 0x20 });
        le32(&mut h, off);
        h.extend_from_slice(&c.name);
        if !z.is_empty() {
            le16(&mut h, 0x0001);
            le16(&mut h, z.len() as u16);
            h.extend_from_slice(&z);
        }
        timestamp_extra(&mut h, c.mtime);
        w.write_all(&h)?;
        pos += h.len() as u64;
    }
    let cd_size = pos - cd_start;
    let n = cd.len() as u64;
    let mut t = Vec::new();
    if n >= 0xFFFF || cd_start >= MAX32 || cd_size >= MAX32 {
        let z64_eocd = pos;
        le32(&mut t, 0x0606_4b50);
        le64(&mut t, 44);
        le16(&mut t, 63);
        le16(&mut t, 45);
        le32(&mut t, 0);
        le32(&mut t, 0);
        le64(&mut t, n);
        le64(&mut t, n);
        le64(&mut t, cd_size);
        le64(&mut t, cd_start);
        le32(&mut t, 0x0706_4b50);
        le32(&mut t, 0);
        le64(&mut t, z64_eocd);
        le32(&mut t, 1);
    }
    le32(&mut t, 0x0605_4b50);
    le16(&mut t, 0);
    le16(&mut t, 0);
    le16(&mut t, n.min(0xFFFF) as u16);
    le16(&mut t, n.min(0xFFFF) as u16);
    le32(&mut t, cd_size.min(MAX32) as u32);
    le32(&mut t, cd_start.min(MAX32) as u32);
    le16(&mut t, 0);
    w.write_all(&t)?;
    pos += t.len() as u64;
    w.flush()?;
    stats.bytes_out = pos;
    Ok(stats)
}
