//! Virtual disk images: VHD (fixed, dynamic), VHDX, VMDK (monolithic
//! sparse and stream-optimized) and QCOW2 (v2/v3, zlib clusters). Like
//! 7-Zip, the archive view is the raw disk as one member (`<name>.img`);
//! differencing disks, backing files and encryption are reported as
//! unsupported.

use std::io::Read;
use std::path::Path;

use anyhow::{Result, bail};
use nz_front::tr;

use crate::{Format, FormatError, Listing, Member, Options, Sink, util};

/// Largest virtual disk accepted (16 TiB).
const MAX_DISK: u64 = 16 << 40;

pub fn sniff(src: &util::Src, h: &[u8]) -> Option<Format> {
    if h.starts_with(b"vhdxfile") {
        return Some(Format::Vhdx);
    }
    if h.starts_with(b"KDMV") {
        return Some(Format::Vmdk);
    }
    if h.starts_with(b"QFI\xFB") {
        return Some(Format::Qcow2);
    }
    if h.starts_with(b"conectix") {
        return Some(Format::Vhd);
    }
    if src.len >= 512 {
        let mut f = [0u8; 8];
        if src.read_at(src.len - 512, &mut f).is_ok() && &f == b"conectix" {
            return Some(Format::Vhd);
        }
    }
    None
}

fn unsupported(what: &str) -> anyhow::Error {
    FormatError::Unsupported(what.to_string()).into()
}

/// Where the bytes of one block of the virtual disk come from.
enum Piece {
    Zero,
    Raw(u64),
    /// Compressed cluster: file offset, compressed length, zlib header.
    Deflate(u64, u64, bool),
}

/// Block index -> where its bytes are.
type BlockMap = Box<dyn Fn(&util::Src, u64) -> Result<Piece>>;

/// A virtual disk as a map from fixed-size blocks to pieces.
struct Disk {
    size: u64,
    block: u64,
    map: BlockMap,
}

fn vhd(src: &util::Src) -> Result<Disk> {
    if src.len < 512 {
        bail!("truncated VHD");
    }
    let foot = src.bytes(src.len - 512, 512)?;
    let foot = if &foot[..8] == b"conectix" {
        foot
    } else {
        src.bytes(0, 512)?
    };
    let size = util::be64(&foot, 0x30);
    let kind = util::be32(&foot, 0x3C);
    match kind {
        2 => {
            if size > src.len {
                bail!("truncated fixed VHD");
            }
            Ok(Disk {
                size,
                block: 1 << 20,
                map: Box::new(|_, b| Ok(Piece::Raw(b << 20))),
            })
        }
        3 => {
            let dh_off = util::be64(&foot, 0x10);
            let dh = src.bytes(dh_off, 1024)?;
            if &dh[..8] != b"cxsparse" {
                bail!("bad VHD dynamic header");
            }
            let bat_off = util::be64(&dh, 0x10);
            let entries = u64::from(util::be32(&dh, 0x1C));
            let bs = u64::from(util::be32(&dh, 0x20));
            if !(512..=256 << 20).contains(&bs) || !bs.is_power_of_two() || entries > 1 << 26 {
                bail!("bad VHD block layout");
            }
            let bat = src.bytes(bat_off, entries * 4)?;
            let bitmap = (bs / 512 / 8).div_ceil(512) * 512;
            Ok(Disk {
                size,
                block: bs,
                map: Box::new(move |_, b| {
                    let Some(e) = bat.get(b as usize * 4..b as usize * 4 + 4) else {
                        return Ok(Piece::Zero);
                    };
                    let s = util::be32(e, 0);
                    Ok(if s == u32::MAX {
                        Piece::Zero
                    } else {
                        Piece::Raw(u64::from(s) * 512 + bitmap)
                    })
                }),
            })
        }
        4 => Err(unsupported(tr("VHD 차등 디스크(부모 디스크 필요)"))),
        k => bail!("unknown VHD disk type {k}"),
    }
}

fn guid(b: &[u8]) -> [u8; 16] {
    b[..16].try_into().unwrap()
}

fn vhdx(src: &util::Src) -> Result<Disk> {
    // Region tables at 192 KiB and 256 KiB; take the first valid one.
    const BAT: [u8; 16] = [
        0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A,
        0x08,
    ];
    const META: [u8; 16] = [
        0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88,
        0x6E,
    ];
    const FILE_PARAMS: [u8; 16] = [
        0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7,
        0x6B,
    ];
    const DISK_SIZE: [u8; 16] = [
        0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4,
        0xB8,
    ];
    const SECTOR_SIZE: [u8; 16] = [
        0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB,
        0x5F,
    ];
    let mut regions = None;
    for off in [192u64 << 10, 256 << 10] {
        let rt = src.bytes(off, 64 << 10)?;
        if &rt[..4] == b"regi" {
            regions = Some(rt);
            break;
        }
    }
    let rt = regions.ok_or_else(|| anyhow::anyhow!("no VHDX region table"))?;
    let n = util::le32(&rt, 8) as usize;
    let (mut bat, mut meta) = (None, None);
    for i in 0..n.min(2047) {
        let e = &rt[16 + i * 32..16 + i * 32 + 32];
        let loc = (util::le64(e, 16), u64::from(util::le32(e, 24)));
        match guid(e) {
            BAT => bat = Some(loc),
            META => meta = Some(loc),
            _ => {}
        }
    }
    let (Some(bat), Some(meta)) = (bat, meta) else {
        bail!("VHDX without BAT or metadata region");
    };
    let md = src.bytes(meta.0, meta.1.min(1 << 20))?;
    if md.len() < 32 || &md[..8] != b"metadata" {
        bail!("bad VHDX metadata");
    }
    let count = (util::le16(&md, 10) as usize).min((md.len() - 32) / 32);
    let (mut block, mut size, mut sector, mut has_parent) = (0u64, 0u64, 512u64, false);
    for i in 0..count.min(2047) {
        let e = &md[32 + i * 32..32 + i * 32 + 32];
        let off = util::le32(e, 16) as usize;
        let get = |n: usize| md.get(off..off + n);
        match guid(e) {
            FILE_PARAMS => {
                if let Some(v) = get(8) {
                    block = u64::from(util::le32(v, 0));
                    has_parent = util::le32(v, 4) & 2 != 0;
                }
            }
            DISK_SIZE => size = get(8).map(|v| util::le64(v, 0)).unwrap_or(0),
            SECTOR_SIZE => sector = get(4).map(|v| u64::from(util::le32(v, 0))).unwrap_or(512),
            _ => {}
        }
    }
    if has_parent {
        return Err(unsupported(tr("VHDX 차등 디스크(부모 디스크 필요)")));
    }
    if !(1 << 20..=256 << 20).contains(&block) || !block.is_power_of_two() || sector == 0 {
        bail!("bad VHDX block size");
    }
    let chunk = (1u64 << 23) * sector / block;
    let table = src.bytes(bat.0, bat.1.min(1 << 30))?;
    Ok(Disk {
        size,
        block,
        map: Box::new(move |_, b| {
            // A sector-bitmap entry follows every `chunk` payload entries.
            let idx = (b + b / chunk.max(1)) as usize;
            let Some(e) = table.get(idx * 8..idx * 8 + 8) else {
                return Ok(Piece::Zero);
            };
            let e = util::le64(e, 0);
            Ok(match e & 7 {
                6 | 7 => Piece::Raw((e >> 20) << 20),
                _ => Piece::Zero,
            })
        }),
    })
}

fn vmdk(src: &util::Src) -> Result<Disk> {
    let mut h = src.bytes(0, 512)?;
    let mut gd_off = util::le64(&h, 56);
    if gd_off == u64::MAX {
        // Stream-optimized: the real header is in the footer.
        let foot = src.bytes(src.len.saturating_sub(1024), 512)?;
        if &foot[..4] != b"KDMV" {
            bail!("VMDK footer missing");
        }
        h = foot;
        gd_off = util::le64(&h, 56);
    }
    // Sector counts from the file: saturate, the size checks below reject.
    let capacity = util::le64(&h, 12).saturating_mul(512);
    let grain = util::le64(&h, 20).saturating_mul(512);
    let gtes = u64::from(util::le32(&h, 44));
    let compressed = util::le16(&h, 77) == 1;
    if grain == 0 || !grain.is_power_of_two() || grain > 1 << 30 || gtes == 0 || gtes > 1 << 20 {
        bail!("bad VMDK geometry");
    }
    let gt_cover = gtes * grain;
    let gds = capacity.div_ceil(gt_cover);
    if gds > 1 << 24 {
        bail!("bad VMDK size");
    }
    let gd = src.bytes(gd_off.saturating_mul(512), gds * 4)?;
    let mut tables: Vec<Option<Vec<u8>>> = Vec::with_capacity(gds as usize);
    for i in 0..gds as usize {
        let s = util::le32(&gd, i * 4);
        tables.push(if s == 0 {
            None
        } else {
            Some(src.bytes(u64::from(s) * 512, gtes * 4)?)
        });
    }
    Ok(Disk {
        size: capacity,
        block: grain,
        map: Box::new(move |src, b| {
            let t = (b / gtes) as usize;
            let Some(Some(gt)) = tables.get(t) else {
                return Ok(Piece::Zero);
            };
            let s = u64::from(util::le32(gt, ((b % gtes) * 4) as usize));
            if s <= 1 {
                return Ok(Piece::Zero); // 0 unallocated, 1 zeroed grain
            }
            if compressed {
                let m = src.bytes(s * 512, 12)?;
                let len = u64::from(util::le32(&m, 8));
                Ok(Piece::Deflate(s * 512 + 12, len, true))
            } else {
                Ok(Piece::Raw(s * 512))
            }
        }),
    })
}

fn qcow2(src: &util::Src) -> Result<Disk> {
    let h = src.bytes(0, 72)?;
    if util::be64(&h, 8) != 0 {
        return Err(unsupported(tr("QCOW2 백킹 파일(부모 이미지 필요)")));
    }
    if util::be32(&h, 32) != 0 {
        return Err(unsupported(tr("암호화된 QCOW2")));
    }
    if util::be32(&h, 4) >= 3 {
        // Incompatible features: bit 0 dirty and bit 1 corrupt are fine
        // for reading; anything else (external data file, zstd clusters,
        // extended L2) changes the layout.
        let feat = util::be64(&src.bytes(72, 8)?, 0);
        if feat & !3 != 0 {
            return Err(unsupported(&nz_front::trf(
                "QCOW2 기능 {}",
                &[&format!("{feat:#x}")],
            )));
        }
    }
    let bits = util::be32(&h, 20);
    if !(9..=21).contains(&bits) {
        bail!("bad QCOW2 cluster size");
    }
    let cluster = 1u64 << bits;
    let size = util::be64(&h, 24);
    let l1_size = u64::from(util::be32(&h, 36));
    if l1_size > 1 << 25 {
        bail!("bad QCOW2 L1 size");
    }
    let l1 = src.bytes(util::be64(&h, 40), l1_size * 8)?;
    let l2_entries = cluster / 8;
    let x = 62 - (bits - 8);
    let cache = std::cell::RefCell::new((u64::MAX, Vec::new()));
    Ok(Disk {
        size,
        block: cluster,
        map: Box::new(move |src, b| {
            let l1i = (b / l2_entries) as usize;
            let Some(e) = l1.get(l1i * 8..l1i * 8 + 8) else {
                return Ok(Piece::Zero);
            };
            let l2_off = util::be64(e, 0) & 0x00FF_FFFF_FFFF_FE00;
            if l2_off == 0 {
                return Ok(Piece::Zero);
            }
            let mut c = cache.borrow_mut();
            if c.0 != l2_off {
                *c = (l2_off, src.bytes(l2_off, cluster)?);
            }
            let e = util::be64(&c.1, ((b % l2_entries) * 8) as usize);
            if e & (1 << 62) != 0 {
                let off = e & ((1 << x) - 1);
                let sectors = ((e >> x) & ((1 << (bits - 8)) - 1)) + 1;
                let len = (sectors * 512 - (off & 511)).min(src.len.saturating_sub(off));
                return Ok(Piece::Deflate(off, len, false));
            }
            if e & 1 != 0 {
                return Ok(Piece::Zero); // v3 "reads as zeros"
            }
            let off = e & 0x00FF_FFFF_FFFF_FE00;
            Ok(if off == 0 {
                Piece::Zero
            } else {
                Piece::Raw(off)
            })
        }),
    })
}

fn open(format: Format, src: &util::Src) -> Result<Disk> {
    let d = match format {
        Format::Vhd => vhd(src)?,
        Format::Vhdx => vhdx(src)?,
        Format::Vmdk => vmdk(src)?,
        Format::Qcow2 => qcow2(src)?,
        _ => bail!("not a virtual disk format"),
    };
    if d.size > MAX_DISK {
        bail!("virtual disk too large");
    }
    Ok(d)
}

fn member(format: Format, path: &Path, d: &Disk, src: &util::Src) -> Member {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "disk".into());
    Member {
        name: format!("{stem}.img"),
        size: d.size,
        csize: src.len,
        method: format.label().into(),
        ..Default::default()
    }
}

pub(crate) fn list(format: Format, path: &Path, _opt: &Options) -> Result<Listing> {
    let src = util::Src::open(path)?;
    let d = open(format, &src)?;
    Ok(Listing {
        members: vec![member(format, path, &d, &src)],
        solid: false,
        volumes: vec![path.to_path_buf()],
    })
}

pub(crate) fn extract(
    format: Format,
    path: &Path,
    _opt: &Options,
    sink: &mut dyn Sink,
) -> Result<()> {
    let src = util::Src::open(path)?;
    let d = open(format, &src)?;
    if !sink.start(0, &member(format, path, &d, &src))? {
        return Ok(());
    }
    let zeros = vec![0u8; d.block.min(1 << 20) as usize];
    let mut out = Vec::new();
    let mut pos = 0u64;
    let mut b = 0u64;
    while pos < d.size {
        let n = d.block.min(d.size - pos);
        match (d.map)(&src, b)? {
            Piece::Zero => {
                let mut left = n;
                while left > 0 {
                    let k = left.min(zeros.len() as u64);
                    sink.data(&zeros[..k as usize])?;
                    left -= k;
                }
            }
            Piece::Raw(off) => {
                if off.saturating_add(n) > src.len {
                    // Sparse tail beyond the end of the file reads as zeros
                    // only if the whole piece is missing.
                    bail!("virtual disk block {b} points past the end of the file");
                }
                util::pump_exact(&mut src.section(off, n)?, sink, n)?;
            }
            Piece::Deflate(off, len, zlib) => {
                let raw = src.bytes(off, len.min(src.len.saturating_sub(off)))?;
                out.clear();
                let r: &mut dyn Read = if zlib {
                    &mut flate2::read::ZlibDecoder::new(&raw[..])
                } else {
                    &mut flate2::read::DeflateDecoder::new(&raw[..])
                };
                r.take(d.block).read_to_end(&mut out)?;
                out.resize(d.block as usize, 0);
                sink.data(&out[..n as usize])?;
            }
        }
        pos += n;
        b += 1;
    }
    sink.finish()
}
