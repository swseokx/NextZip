//! Standard 7z container with per-type solid blocks (M1, design fix A).
//!
//! Writer:
//! 1. Every file is classified ([`planner::Class`]): text, x86 code, other,
//!    mostly-compressed (fast tier) or incompressible (store);
//! 2. files of one class are sorted by extension and cut into solid blocks of
//!    roughly equal size; every block is one 7z *folder* with its own coder
//!    chain: `BCJ x86 + LZMA2` for code, `LZMA2` for text and other data,
//!    `Deflate` (or LZMA2 / Copy) for the fast tier, `Copy` for the store tier;
//! 3. folders are compressed in parallel, and a folder larger than the LZMA2
//!    segment size is itself split into independently encoded LZMA2 segments
//!    ([`lzma::lzma2_parallel`]);
//! 4. the header is LZMA2-compressed (`kEncodedHeader`), like 7-Zip does.
//!
//! Block and segment sizes depend only on the input and the options, never on
//! the thread count, so the archive bytes are identical for any `-t`.
//!
//! Reader: any 7z whose folders are chains of single-stream coders among
//! Copy, LZMA, LZMA2, BCJ x86 and Deflate (unencrypted), with plain or
//! encoded headers. Folders are decoded in parallel.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;

use crate::lzma::{self, Lzma2Params, Mf};
use crate::planner::{self, Class};
use crate::walk::{self, Entry, Kind};
use crate::zip::{ExtractStats, WriteStats};
use crate::{bcj, deflate};

const SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

/// Minimum solid block size.
pub const MIN_BLOCK: u64 = 4 << 20;
/// The default block size is `max(MIN_BLOCK, total / PLAN_SPLIT)`.
///
/// This is a fixed planning constant (the 12 logical CPUs of the reference
/// machine), *not* the `-t` thread count, so that the archive does not depend
/// on how many threads compress it.
pub const PLAN_SPLIT: u64 = 12;
/// Uncompressed bytes per parallel batch of folders (bounds memory use).
const BATCH_BYTES: u64 = 512 << 20;
/// Folder size for zstd-coded ZIP containers (2x the 128 MiB long window).
const ZIP_BLOCK: u64 = 256 << 20;

// Method ids.
const M_COPY: &[u8] = &[0x00];
const M_LZMA2: &[u8] = &[0x21];
const M_LZMA: &[u8] = &[0x03, 0x01, 0x01];
const M_BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
const M_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
/// zstd as registered by 7-Zip ZS (also read by NanaZip and other readers).
const M_ZSTD: &[u8] = &[0x04, 0xF7, 0x11, 0x01];
/// PPMd var. H with the 7z range coder (props: order, memory size LE32).
const M_PPMD: &[u8] = &[0x03, 0x04, 0x01];

// Property ids.
const K_END: u64 = 0x00;
const K_HEADER: u64 = 0x01;
const K_ARCHIVE_PROPERTIES: u64 = 0x02;
const K_ADDITIONAL_STREAMS: u64 = 0x03;
const K_MAIN_STREAMS: u64 = 0x04;
const K_FILES_INFO: u64 = 0x05;
const K_PACK_INFO: u64 = 0x06;
const K_UNPACK_INFO: u64 = 0x07;
const K_SUBSTREAMS: u64 = 0x08;
const K_SIZE: u64 = 0x09;
const K_CRC: u64 = 0x0A;
const K_FOLDER: u64 = 0x0B;
const K_CODERS_UNPACK_SIZE: u64 = 0x0C;
const K_NUM_UNPACK_STREAM: u64 = 0x0D;
const K_EMPTY_STREAM: u64 = 0x0E;
const K_EMPTY_FILE: u64 = 0x0F;
const K_NAME: u64 = 0x11;
const K_MTIME: u64 = 0x14;
const K_WIN_ATTRIBUTES: u64 = 0x15;
const K_ENCODED_HEADER: u64 = 0x17;

const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_ARCHIVE: u32 = 0x20;

/// Codec for the fast tier ([`Class::Fast`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastCodec {
    Deflate,
    Lzma2,
    Copy,
    /// zstd with a long window over the whole tier in one folder (7-Zip ZS
    /// method id, like [`ZipCodec::Zstd`]); incompressible files join it.
    Zstd,
}

impl FastCodec {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "deflate" => Self::Deflate,
            "lzma" | "lzma2" => Self::Lzma2,
            "copy" | "store" => Self::Copy,
            "zstd" => Self::Zstd,
            other => bail!("unknown fast codec '{other}' (deflate, lzma2, copy, zstd)"),
        })
    }
}

/// Codec for ZIP-family containers ([`Class::Zip`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipCodec {
    /// zstd with a long window in one folder (7-Zip ZS method id; readable
    /// by 7-Zip ZS, NanaZip and other zstd-aware readers, not by mainline 7-Zip).
    Zstd,
    /// LZMA2 with the `other` settings (readable by every 7z tool).
    Lzma2,
}

impl ZipCodec {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "zstd" => Self::Zstd,
            "lzma" | "lzma2" => Self::Lzma2,
            other => bail!("unknown zip-container codec '{other}' (zstd, lzma2)"),
        })
    }
}

/// Codec for text ([`Class::Text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextCodec {
    Lzma2,
    /// PPMd (7z method `03 04 01`, readable by every 7z tool) with the given
    /// model order and memory in bytes. One independent model per folder.
    Ppmd {
        order: u32,
        mem: u32,
    },
}

/// 7z writer options. [`SevenZOptions::for_level`] fills every field from a
/// NextZip level; the CLI then applies explicit overrides.
#[derive(Debug, Clone)]
pub struct SevenZOptions {
    /// NextZip level 0..=9 (0 = store everything).
    pub level: u8,
    /// LZMA2 for text.
    pub text: Lzma2Params,
    /// Text codec (LZMA2 with `text`, or PPMd).
    pub text_codec: TextCodec,
    /// Solid block size for PPMd text (None = `block_size`).
    pub ppmd_block: Option<u64>,
    /// LZMA2 for x86 code (after BCJ).
    pub exec: Lzma2Params,
    /// LZMA2 for other (non-text, non-code) data.
    pub other: Lzma2Params,
    /// LZMA2 for the fast tier when `fast == FastCodec::Lzma2`.
    pub fast_lzma: Lzma2Params,
    /// Solid block size in bytes (None = `max(4 MiB, total / 12)`).
    pub block: Option<u64>,
    /// LZMA2 segment size for intra-folder parallelism (None = block size).
    pub segment: Option<u64>,
    /// Chained-segment preload in bytes for text LZMA2 (0 = independent
    /// segments, None = whole dictionary).
    pub preload: Option<u64>,
    /// LZMA2 segment size for other and fast-tier data (None = `segment`).
    pub other_seg: Option<u64>,
    /// Chained-segment preload for other and fast-tier data. M1: on the text set at -l:6,
    /// 1 MiB segments with a 1 MiB preload ran 1.00 s -> 0.80 s for +0.01 pp
    /// (binary data files, which LZMA2 compresses 5 pp better than zstd).
    pub other_preload: u64,
    /// Solid block, segment and preload sizes for x86 code. Code compresses
    /// much better in one large folder (shared libraries and runtime code
    /// repeat across executables: M1 measured 26.5% in one folder vs 32.0%
    /// in three), so it uses chained segments instead of independent ones.
    pub exec_block: u64,
    pub exec_seg: u64,
    pub exec_preload: u64,
    pub fast: FastCodec,
    /// libdeflate level for the fast tier.
    pub fast_level: i32,
    /// zstd level for the fast tier when `fast == FastCodec::Zstd`.
    pub fast_zstd_level: i32,
    /// Apply BCJ x86 to code.
    pub bcj: bool,
    /// Route files by class; false = one class (text) for all data.
    pub classify: bool,
    /// Use the incompressible-data planner (fast / store tiers).
    pub planner: bool,
    /// ZIP-family containers: codec, zstd level and long-window log
    /// (0 = no long-distance matching).
    pub zip_codec: ZipCodec,
    pub zip_level: i32,
    pub zip_wlog: u32,
    /// Memory budget in bytes (None = [`crate::mem::default_budget`]). Limits
    /// concurrent encoders only; the archive bytes do not depend on it.
    pub mem_budget: Option<u64>,
}

impl Default for SevenZOptions {
    fn default() -> Self {
        Self::for_level(5)
    }
}

impl SevenZOptions {
    /// Settings for a NextZip level (M1 measurements, see bench/results/M1-*).
    ///
    /// | level | text / code LZMA2 | other, fast tier | segments |
    /// |---|---|---|---|
    /// | 1 | preset 3 (hc4, 4 MiB) | preset 0, lc0 pb0 | 2 MiB |
    /// | 2 | preset 6 + hc4 | preset 0, lc0 pb0 | 2 MiB |
    /// | 3 | preset 6 + hc4 | preset 1, lc0 pb0 | 2 MiB |
    /// | 4 | preset 6 (bt4) | preset 0, lc0 pb0 | 2 MiB |
    /// | 5 | preset 6 (bt4) | preset 1, lc0 pb0 | 2 MiB |
    /// | 6 | preset 6, nice 64 (text pb0) | preset 6 hc4 normal depth 2, lc0 pb0; 2 MiB segments, 512 KiB preload | 2 MiB |
    /// | 7 | as 6 | as 6 | 4 MiB |
    /// | 8 | preset 9, nice 273, text pb0 | preset 6, lc0 pb0 | 8 MiB |
    /// | 9 | as 8, text chained (8 MiB preload) | as 8 | 4 MiB |
    ///
    /// Levels 6+ also disable the fast / store tiers (`planner = false`): on
    /// the benchmark sets, files that LZ4 sampling calls incompressible still
    /// repeat *across* files (e.g. variants of one binary data file type), which LZMA2 finds (text set
    /// 45.38% -> 45.03% at level 9). Other data uses 4 MiB segments there.
    ///
    /// Code always gets BCJ x86 and one large folder with chained 4 MiB
    /// segments (4 MiB preload).
    pub fn for_level(level: u8) -> Self {
        let level = level.min(9);
        let p = Lzma2Params::preset;
        let hc = |n| Lzma2Params {
            mf: Some(Mf::Hc4),
            ..p(n)
        };
        let nice = |mut x: Lzma2Params, n| {
            x.nice = Some(n);
            x
        };
        // lc=0 / pb=0: no literal context for data that is already compressed.
        let lit0 = |mut x: Lzma2Params| {
            x.lc = Some(0);
            x.pb = Some(0);
            x
        };
        let pb0 = |mut x: Lzma2Params| {
            x.pb = Some(0);
            x
        };
        let (code, other) = match level {
            0 | 1 => (hc(3), lit0(p(0))),
            2 => (hc(6), lit0(p(0))),
            3 => (hc(6), lit0(p(1))),
            4 => (p(6), lit0(p(0))),
            5 => (p(6), lit0(p(1))),
            // v1-release: code nice 128 -> 64 (same size, about 5% less CPU);
            // other data hc4 normal parsing with depth 2. Other data here is
            // mostly already-compressed streams where bt4 spends its time on
            // match-finder cache misses: single-thread class cost -25..35% for
            // +0.06% size.
            6 | 7 => (
                nice(p(6), 64),
                Lzma2Params {
                    mf: Some(Mf::Hc4Normal),
                    depth: Some(2),
                    ..lit0(p(6))
                },
            ),
            _ => (nice(p(9), 273), lit0(p(6))),
        };
        // Text at 6/7 keeps preset 6's nice length 64: on the text set 13%
        // faster for +0.19% size (12,965,546 -> 12,990,789 B).
        let text = match level {
            6 | 7 => pb0(nice(code, 64)),
            8 | 9 => pb0(code),
            _ => code,
        };
        let seg: u64 = match level {
            7 | 9 => 4 << 20,
            8 => 8 << 20,
            _ => 2 << 20,
        };
        Self {
            level,
            text,
            text_codec: TextCodec::Lzma2,
            ppmd_block: None,
            exec: code,
            other,
            fast_lzma: other,
            block: if level == 9 { Some(64 << 20) } else { None },
            segment: Some(seg),
            preload: Some(if level == 9 { 8 << 20 } else { 0 }),
            other_seg: Some(match level {
                0..=4 | 6 | 7 => 2 << 20,
                5 | 8 => 1 << 20,
                _ => 4 << 20,
            }),
            // 6/7: 2 MiB segments with a 512 KiB preload (v1-release: the
            // preload skip costs about as much as hc4 normal encoding, so less
            // history per byte is cheaper at the same size).
            other_preload: match level {
                0..=4 => 0,
                6 | 7 => 512 << 10,
                _ => 1 << 20,
            },
            exec_block: 64 << 20,
            exec_seg: 4 << 20,
            exec_preload: 4 << 20,
            fast: FastCodec::Lzma2,
            fast_level: 6,
            fast_zstd_level: if level >= 9 { 19 } else { 18 },
            bcj: true,
            classify: true,
            planner: level < 6,
            zip_codec: ZipCodec::Zstd,
            zip_level: match level {
                0..=2 => 3,
                // 6/7: 9, not 12 (v1-release: this zstd frame of ZIP-family
                // containers was the mixed set's critical path; +0.2% size).
                3..=7 => 9,
                _ => 19,
            },
            zip_wlog: 27,
            mem_budget: None,
        }
    }
    pub fn text_params(&self) -> Lzma2Params {
        self.text
    }
    pub fn exec_params(&self) -> Lzma2Params {
        self.exec
    }
    /// Solid block size for an input of `total` bytes.
    pub fn block_size(&self, total: u64) -> u64 {
        self.block
            .unwrap_or_else(|| MIN_BLOCK.max(total / PLAN_SPLIT))
            .max(64 * 1024)
    }
}

// ---------------------------------------------------------------- encoding helpers

fn put_number(v: &mut Vec<u8>, x: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 {
        if x < (1u64 << (7 * (extra + 1))) {
            first |= (x >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    v.push(first);
    v.extend_from_slice(&x.to_le_bytes()[..extra]);
}

fn put_bits(v: &mut Vec<u8>, bits: &[bool]) {
    for chunk in bits.chunks(8) {
        let mut b = 0u8;
        for (i, &x) in chunk.iter().enumerate() {
            if x {
                b |= 0x80 >> i;
            }
        }
        v.push(b);
    }
}

fn filetime(t: SystemTime) -> u64 {
    const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => EPOCH_DIFF + d.as_secs() * 10_000_000 + u64::from(d.subsec_nanos()) / 100,
        Err(e) => EPOCH_DIFF.saturating_sub((e.duration().as_nanos() / 100) as u64),
    }
}

fn from_filetime(ft: u64) -> Option<SystemTime> {
    const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
    let ticks = ft.checked_sub(EPOCH_DIFF)?;
    Some(UNIX_EPOCH + Duration::new(ticks / 10_000_000, (ticks % 10_000_000) as u32 * 100))
}

/// One coder of a folder.
#[derive(Debug, Clone)]
pub struct Coder {
    pub id: Vec<u8>,
    pub props: Vec<u8>,
    pub num_in: usize,
    pub num_out: usize,
}

impl Coder {
    fn simple(id: &[u8], props: &[u8]) -> Self {
        Self {
            id: id.to_vec(),
            props: props.to_vec(),
            num_in: 1,
            num_out: 1,
        }
    }
}

/// A 7z folder (coder graph + sizes).
#[derive(Debug, Clone, Default)]
pub struct Folder {
    pub coders: Vec<Coder>,
    /// (in index, out index)
    pub bind_pairs: Vec<(usize, usize)>,
    /// In-stream indices fed by packed streams.
    pub packed: Vec<usize>,
    /// Size of every coder output stream.
    pub unpack_sizes: Vec<u64>,
    pub crc: Option<u32>,
}

impl Folder {
    /// Linear chain: coder 0 reads the packed stream, coder i reads coder i-1.
    fn chain(coders: Vec<Coder>, size: u64) -> Self {
        let n = coders.len();
        Self {
            coders,
            bind_pairs: (1..n).map(|i| (i, i - 1)).collect(),
            packed: vec![0],
            unpack_sizes: vec![size; n],
            crc: None,
        }
    }

    /// Size of the folder's final output (the unbound out stream).
    pub fn unpack_size(&self) -> u64 {
        (0..self.unpack_sizes.len())
            .rev()
            .find(|i| !self.bind_pairs.iter().any(|b| b.1 == *i))
            .map_or(0, |i| self.unpack_sizes[i])
    }

    fn write(&self, v: &mut Vec<u8>) {
        put_number(v, self.coders.len() as u64);
        for c in &self.coders {
            let complex = c.num_in != 1 || c.num_out != 1;
            let mut flag = c.id.len() as u8;
            if complex {
                flag |= 0x10;
            }
            if !c.props.is_empty() {
                flag |= 0x20;
            }
            v.push(flag);
            v.extend_from_slice(&c.id);
            if complex {
                put_number(v, c.num_in as u64);
                put_number(v, c.num_out as u64);
            }
            if !c.props.is_empty() {
                put_number(v, c.props.len() as u64);
                v.extend_from_slice(&c.props);
            }
        }
        for &(i, o) in &self.bind_pairs {
            put_number(v, i as u64);
            put_number(v, o as u64);
        }
        if self.packed.len() > 1 {
            for &p in &self.packed {
                put_number(v, p as u64);
            }
        }
    }
}

/// Write PackInfo + UnpackInfo (and optional folder CRCs).
fn write_streams_core(v: &mut Vec<u8>, pack_pos: u64, pack_sizes: &[u64], folders: &[Folder]) {
    put_number(v, K_PACK_INFO);
    put_number(v, pack_pos);
    put_number(v, pack_sizes.len() as u64);
    put_number(v, K_SIZE);
    for &s in pack_sizes {
        put_number(v, s);
    }
    put_number(v, K_END);

    put_number(v, K_UNPACK_INFO);
    put_number(v, K_FOLDER);
    put_number(v, folders.len() as u64);
    v.push(0); // not external
    for f in folders {
        f.write(v);
    }
    put_number(v, K_CODERS_UNPACK_SIZE);
    for f in folders {
        for &s in &f.unpack_sizes {
            put_number(v, s);
        }
    }
    if folders.iter().any(|f| f.crc.is_some()) {
        put_number(v, K_CRC);
        let defined: Vec<bool> = folders.iter().map(|f| f.crc.is_some()).collect();
        if defined.iter().all(|&d| d) {
            v.push(1);
        } else {
            v.push(0);
            put_bits(v, &defined);
        }
        for c in folders.iter().filter_map(|f| f.crc) {
            v.extend_from_slice(&c.to_le_bytes());
        }
    }
    put_number(v, K_END);
}

// ---------------------------------------------------------------- writer

/// A planned solid block.
struct Block {
    class: Class,
    files: Vec<usize>,
    bytes: u64,
}

struct Encoded {
    folder: Folder,
    packed: Vec<u8>,
    /// (file index, crc)
    crcs: Vec<(usize, u32)>,
    class: Class,
    cpu_ms: f64,
}

fn ext_key(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.rsplit_once('.')
        .map(|(_, x)| x.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Cut one class's files (already sorted) into blocks of about `target` bytes.
fn split_blocks(class: Class, files: &[usize], sizes: &[u64], target: u64) -> Vec<Block> {
    let sum: u64 = files.iter().map(|&i| sizes[i]).sum();
    if files.is_empty() {
        return Vec::new();
    }
    let k = sum.div_ceil(target).max(1);
    let mut out = Vec::new();
    let mut cur = Block {
        class,
        files: Vec::new(),
        bytes: 0,
    };
    let mut acc = 0u64;
    let mut j = 1u64;
    for &i in files {
        cur.files.push(i);
        cur.bytes += sizes[i];
        acc += sizes[i];
        if j < k && acc >= sum * j / k {
            while j < k && acc >= sum * j / k {
                j += 1;
            }
            out.push(std::mem::replace(
                &mut cur,
                Block {
                    class,
                    files: Vec::new(),
                    bytes: 0,
                },
            ));
        }
    }
    if !cur.files.is_empty() {
        out.push(cur);
    }
    out
}

/// (file index, CRC32) of each file in a block.
type FileCrcs = Vec<(usize, u32)>;

fn read_block(entries: &[Entry], b: &Block) -> Result<(Vec<u8>, FileCrcs)> {
    let mut buf = vec![0u8; b.bytes as usize];
    let mut crcs = Vec::with_capacity(b.files.len());
    let mut off = 0usize;
    for &i in &b.files {
        let e = &entries[i];
        let n = e.size as usize;
        let dst = &mut buf[off..off + n];
        File::open(&e.path)
            .and_then(|mut f| f.read_exact(dst))
            .with_context(|| format!("cannot read {}", e.path.display()))?;
        crcs.push((i, crc32fast::hash(dst)));
        off += n;
    }
    Ok((buf, crcs))
}

/// How one solid block is coded.
#[derive(Clone, Copy)]
enum Codec {
    Copy,
    Deflate,
    /// LZMA2 in chained segments, optionally after BCJ x86.
    Lzma2 {
        p: Lzma2Params,
        seg: u64,
        preload: Option<u64>,
        bcj: bool,
    },
    Zstd(i32),
    Ppmd {
        order: u32,
        mem: u32,
    },
}

fn block_codec(class: Class, opt: &SevenZOptions, seg: u64) -> Codec {
    let other_seg = opt.other_seg.unwrap_or(seg).max(64 * 1024);
    let lz = |p, seg, preload, bcj| Codec::Lzma2 {
        p,
        seg,
        preload,
        bcj,
    };
    let other = lz(opt.other, other_seg, Some(opt.other_preload), false);
    match class {
        Class::Store => Codec::Copy,
        Class::Fast => match opt.fast {
            FastCodec::Copy => Codec::Copy,
            FastCodec::Deflate => Codec::Deflate,
            FastCodec::Lzma2 => lz(opt.fast_lzma, other_seg, Some(opt.other_preload), false),
            FastCodec::Zstd => Codec::Zstd(opt.fast_zstd_level),
        },
        Class::Exec => lz(
            opt.exec_params(),
            opt.exec_seg,
            Some(opt.exec_preload),
            opt.bcj,
        ),
        Class::Text => match opt.text_codec {
            TextCodec::Lzma2 => lz(opt.text_params(), seg, opt.preload, false),
            TextCodec::Ppmd { order, mem } => Codec::Ppmd { order, mem },
        },
        Class::Other => other,
        Class::Zip => match opt.zip_codec {
            ZipCodec::Zstd => Codec::Zstd(opt.zip_level),
            ZipCodec::Lzma2 => other,
        },
    }
}

/// A block read into memory, ready for its encode jobs.
struct Loaded {
    class: Class,
    codec: Codec,
    data: Vec<u8>,
    crcs: FileCrcs,
    /// Segment plan for LZMA2 blocks.
    plan: Option<lzma::SegPlan>,
}

fn load_block(entries: &[Entry], b: &Block, codec: Codec) -> Result<Loaded> {
    let (mut data, crcs) = read_block(entries, b)?;
    let plan = match codec {
        Codec::Lzma2 {
            p,
            seg,
            preload,
            bcj,
        } => {
            if bcj {
                bcj::x86_convert(&mut data, true);
            }
            let pre = preload.map_or(p.preset_dict() as usize, |x| x as usize);
            Some(lzma::SegPlan::new(data.len(), &p, seg as usize, pre))
        }
        _ => None,
    };
    Ok(Loaded {
        class: b.class,
        codec,
        data,
        crcs,
        plan,
    })
}

/// One unit of encode work: segment `seg` of block `block` (LZMA2), or the
/// whole block (other codecs).
struct Job {
    block: usize,
    seg: usize,
    /// Scheduling estimate (bigger first); never affects the bytes.
    cost: u64,
}

fn block_jobs(k: usize, l: &Loaded, jobs: &mut Vec<Job>) {
    let len = l.data.len() as u64;
    let mut push = |seg, cost| {
        jobs.push(Job {
            block: k,
            seg,
            cost,
        })
    };
    match (l.codec, &l.plan) {
        (Codec::Lzma2 { p, bcj, .. }, Some(plan)) => {
            // Single-threaded cost per MiB on the 1.0 sets (segbench, ms):
            // encode / history (match finder skip). x86 code: 270 / 78;
            // text (nice 64): 127 / 30; other (mostly compressed, lc0): 250 / 30.
            // Fast mode costs about a third.
            let (enc, hist) = if bcj || l.class == Class::Exec {
                (270, 78)
            } else if p.lc == Some(0) {
                (250, 30)
            } else {
                (127, 30)
            };
            let fast = matches!(p.mf, Some(Mf::Hc4 | Mf::Bt4Fast)) || p.preset <= 3;
            for i in 0..plan.n {
                let (h, start, end) = plan.range(l.data.len(), i);
                let w = ((end - start) as u64 * enc + (start - h) as u64 * hist) >> 10;
                push(i, if fast { w / 3 } else { w });
            }
        }
        (Codec::Zstd(_), _) => push(0, u64::MAX / 2),
        (Codec::Ppmd { .. }, _) => push(0, len * 2),
        (Codec::Deflate, _) => push(0, len / 4),
        _ => {}
    }
}

fn run_job(
    l: &Loaded,
    seg: usize,
    gate: &crate::mem::Gate,
    opt: &SevenZOptions,
) -> Result<Vec<u8>> {
    match (l.codec, &l.plan) {
        (Codec::Lzma2 { p, .. }, Some(plan)) => {
            let _permit = gate.acquire(plan.need);
            plan.encode(&l.data, &p, seg)
        }
        (Codec::Zstd(level), _) => zstd_encode(&l.data, level.clamp(1, 22), opt.zip_wlog, gate),
        (Codec::Ppmd { order, mem }, _) => {
            let _permit = gate.acquire(u64::from(mem) + l.data.len() as u64 / 2);
            ppmd_encode(&l.data, order, mem)
        }
        (Codec::Deflate, _) => {
            Ok(deflate::deflate_parallel(&l.data, opt.fast_level, 256 * 1024)?.data)
        }
        _ => bail!("7z: block has no encode job"),
    }
}

/// Finish a block from its job outputs (in segment order).
fn assemble(l: Loaded, parts: Vec<Vec<u8>>) -> Result<Encoded> {
    let size = l.data.len() as u64;
    let (packed, coders) = match l.codec {
        Codec::Copy => (l.data, vec![Coder::simple(M_COPY, &[])]),
        Codec::Deflate => (one(parts)?, vec![Coder::simple(M_DEFLATE, &[])]),
        Codec::Lzma2 { bcj, .. } => {
            let prop = l.plan.map_or(0, |p| p.prop);
            let o = lzma::splice(parts, prop)?;
            let mut c = vec![Coder::simple(M_LZMA2, &[o.prop])];
            if bcj {
                c.push(Coder::simple(M_BCJ, &[]));
            }
            (o.data, c)
        }
        Codec::Zstd(level) => {
            let level = level.clamp(1, 22);
            // 7-Zip ZS properties: zstd version major, minor, level, 2 reserved.
            let props = [1, 5, level as u8, 0, 0];
            (one(parts)?, vec![Coder::simple(M_ZSTD, &props)])
        }
        Codec::Ppmd { order, mem } => {
            let mut props = vec![order as u8];
            props.extend_from_slice(&mem.to_le_bytes());
            (one(parts)?, vec![Coder::simple(M_PPMD, &props)])
        }
    };
    Ok(Encoded {
        folder: Folder::chain(coders, size),
        packed,
        crcs: l.crcs,
        class: l.class,
        cpu_ms: 0.0,
    })
}

fn one(parts: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let mut it = parts.into_iter();
    match (it.next(), it.next()) {
        (Some(p), None) => Ok(p),
        _ => bail!("7z: expected one encoded part"),
    }
}

/// Encode a batch of blocks. All blocks are read first; then every LZMA2
/// segment and every whole-block job goes into one list, largest estimate
/// first, which the pool's threads take in order. Jobs are independent and
/// their bytes do not depend on which thread runs them or when, so the
/// archive stays identical for any thread count; only the schedule changes.
/// (Before, blocks ran as nested Rayon tasks: the x86 code block's chained
/// 4 MiB segments often started late and set the run's length.)
fn encode_batch(
    entries: &[Entry],
    blocks: &[Block],
    opt: &SevenZOptions,
    seg: u64,
    gate: &crate::mem::Gate,
) -> Result<Vec<Encoded>> {
    let t0 = std::time::Instant::now();
    // Read the biggest blocks first (the x86 code block's BCJ pass, too).
    let mut order: Vec<usize> = (0..blocks.len()).collect();
    order.sort_by_key(|&k| std::cmp::Reverse(blocks[k].bytes));
    let mut loaded: Vec<(usize, Result<Loaded>)> = order
        .par_iter()
        .with_max_len(1)
        .map(|&k| {
            let b = &blocks[k];
            (k, load_block(entries, b, block_codec(b.class, opt, seg)))
        })
        .collect();
    loaded.sort_by_key(|x| x.0);
    let loaded: Vec<Loaded> = loaded.into_iter().map(|x| x.1).collect::<Result<_>>()?;
    let t_read = t0.elapsed().as_secs_f64() * 1e3;

    let mut jobs = Vec::new();
    for (k, l) in loaded.iter().enumerate() {
        block_jobs(k, l, &mut jobs);
    }
    // Stable sort: equal estimates keep block / segment order.
    jobs.sort_by_key(|j| std::cmp::Reverse(j.cost));
    type Slot = std::sync::Mutex<Option<(Result<Vec<u8>>, f64)>>;
    let slots: Vec<Slot> = jobs.iter().map(|_| std::sync::Mutex::new(None)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let trace_jobs = std::env::var_os("NZ_TRACE_JOBS").is_some();
    let workers = rayon::current_num_threads().clamp(1, jobs.len().max(1));
    rayon::scope(|s| {
        for _ in 0..workers {
            s.spawn(|_| {
                loop {
                    let j = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(job) = jobs.get(j) else { break };
                    let t = std::time::Instant::now();
                    let r = run_job(&loaded[job.block], job.seg, gate, opt);
                    let ms = t.elapsed().as_secs_f64() * 1e3;
                    if trace_jobs {
                        let l = &loaded[job.block];
                        eprintln!(
                            "[nz] job {j:>3} {:<5} block {} seg {:>2} start {:>7.1} ms dur {ms:>7.1} ms",
                            l.class.name(),
                            job.block,
                            job.seg,
                            (t - t0).as_secs_f64() * 1e3
                        );
                    }
                    *slots[j].lock().expect("job slot") = Some((r, ms));
                }
            });
        }
    });
    // Collect each block's parts in segment order.
    let mut parts: Vec<Vec<(usize, Vec<u8>)>> = loaded.iter().map(|_| Vec::new()).collect();
    let mut cpu = vec![0f64; loaded.len()];
    for (job, slot) in jobs.iter().zip(slots) {
        let (r, ms) = slot
            .into_inner()
            .expect("job slot")
            .ok_or_else(|| anyhow::anyhow!("7z: encode job did not run"))?;
        parts[job.block].push((job.seg, r?));
        cpu[job.block] += ms;
    }
    crate::trace(&format!(
        "7z batch: {} blocks read in {t_read:.1} ms, {} jobs encoded at {:.1} ms",
        blocks.len(),
        jobs.len(),
        t0.elapsed().as_secs_f64() * 1e3
    ));
    loaded
        .into_iter()
        .zip(parts)
        .zip(cpu)
        .map(|((l, mut p), ms)| {
            p.sort_by_key(|x| x.0);
            let mut e = assemble(l, p.into_iter().map(|x| x.1).collect())?;
            e.cpu_ms = ms;
            Ok(e)
        })
        .collect()
}

/// PPMd model order and memory accepted by 7-Zip.
fn ppmd_params(order: u32, mem: u32) -> Result<(u32, u32)> {
    if !(2..=32).contains(&order) || !(1 << 11..=0xFFFF_FFFF - 12 * 3).contains(&mem) {
        bail!("PPMd: bad order {order} / memory {mem}");
    }
    Ok((order, mem))
}

/// One PPMd7 (7z) stream without end marker; the folder size bounds it.
fn ppmd_encode(data: &[u8], order: u32, mem: u32) -> Result<Vec<u8>> {
    let (order, mem) = ppmd_params(order, mem)?;
    let mut e = ppmd_rust::Ppmd7Encoder::new(Vec::with_capacity(data.len() / 3), order, mem)
        .map_err(|e| anyhow::anyhow!("PPMd encoder: {e:?}"))?;
    e.write_all(data)?;
    Ok(e.finish(false)?)
}

fn ppmd_decode(data: &[u8], props: &[u8], size: usize) -> Result<Vec<u8>> {
    let [order, m0, m1, m2, m3] = props else {
        bail!("7z: bad PPMd properties");
    };
    let (order, mem) = ppmd_params(u32::from(*order), u32::from_le_bytes([*m0, *m1, *m2, *m3]))?;
    let mut d = ppmd_rust::Ppmd7Decoder::new(data, order, mem)
        .map_err(|e| anyhow::anyhow!("PPMd decoder: {e:?}"))?;
    let mut out = vec![0u8; size];
    d.read_exact(&mut out).context("7z: PPMd data error")?;
    Ok(out)
}

/// Window log for `len` bytes of input: no larger than needed (a 128 MiB
/// long-distance window over 1 MiB of data only costs set-up time).
fn zstd_wlog(wlog: u32, len: usize) -> u32 {
    let need = usize::BITS - len.max(1).saturating_sub(1).leading_zeros();
    wlog.min(need.max(10))
}

/// One zstd frame. Multithreaded zstd gives the same bytes for every worker
/// count >= 1, so the archive stays independent of `-t`.
fn zstd_encode(data: &[u8], level: i32, wlog: u32, gate: &crate::mem::Gate) -> Result<Vec<u8>> {
    // Each 2 MiB job sees `window >> (9 - overlap log)` bytes before it; keep
    // that overlap at its 27 / 6 size (16 MiB) when the window shrinks.
    let (wlog, ovlog) = if wlog > 0 {
        let w = zstd_wlog(wlog, data.len());
        (w, (6 + wlog.saturating_sub(w)).min(9))
    } else {
        (0, 6)
    };
    use zstd::stream::raw::CParameter;
    let mut e = zstd::stream::write::Encoder::new(Vec::with_capacity(data.len() / 2), level)?;
    // Workers within half of the memory gate; the bytes do not depend on
    // the worker count.
    let overlap = if wlog > 0 {
        1u64 << (wlog - (9 - ovlog.min(9)))
    } else {
        0
    };
    let per = crate::mem::zstd_worker_bytes(level, overlap);
    // No more workers than 2 MiB jobs: a small frame gains nothing from idle
    // workers but still reserves their memory in the gate.
    let jobs = (data.len() as u64).div_ceil(2 << 20).max(1);
    let workers = (gate.capacity() / 2 / per)
        .clamp(1, rayon::current_num_threads().max(1) as u64)
        .min(jobs);
    let _permit = gate.acquire(workers * per);
    e.multithread(workers as u32)?;
    e.set_parameter(CParameter::JobSize(2 << 20))?;
    e.set_parameter(CParameter::OverlapSizeLog(ovlog))?;
    if wlog > 0 {
        e.long_distance_matching(true)?;
        e.window_log(wlog.min(27))?;
    }
    e.include_checksum(false)?;
    e.write_all(data)?;
    let mut out = e.finish()?;
    out.shrink_to_fit();
    Ok(out)
}

/// Put all `Other` / `Fast` files of one extension into the class holding
/// most of that extension's bytes. Variants of one file type (binary data
/// files for related targets) repeat each other; split between an LZMA2 folder
/// and the zstd fast tier, neither folder sees the repeats (1.0: text set
/// +100 KB). The decision depends only on the input.
fn unify_by_extension(entries: &[Entry], mut classes: Vec<Option<Class>>) -> Vec<Option<Class>> {
    let mut bytes: std::collections::HashMap<String, (u64, u64)> = Default::default();
    for (e, c) in entries.iter().zip(&classes) {
        let slot = bytes.entry(ext_key(&e.name)).or_default();
        match c {
            Some(Class::Other) => slot.0 += e.size,
            Some(Class::Fast) => slot.1 += e.size,
            _ => {}
        }
    }
    for (e, c) in entries.iter().zip(classes.iter_mut()) {
        if matches!(c, Some(Class::Other | Class::Fast)) {
            let (other, fast) = bytes[&ext_key(&e.name)];
            *c = Some(if fast > other {
                Class::Fast
            } else {
                Class::Other
            });
        }
    }
    classes
}

/// Create a 7z archive.
pub fn write_7z(entries: &[Entry], out: &Path, opt: &SevenZOptions) -> Result<WriteStats> {
    let t0 = std::time::Instant::now();
    let sizes: Vec<u64> = entries.iter().map(|e| e.size).collect();
    let classes: Vec<Option<Class>> = entries
        .par_iter()
        .map(|e| {
            if e.kind == Kind::Dir || e.size == 0 {
                return None;
            }
            if opt.level == 0 {
                return Some(Class::Store);
            }
            let c = if opt.planner || opt.classify {
                planner::classify_path(&e.path, e.size).0
            } else {
                Class::Text
            };
            let c = match c {
                Class::Fast | Class::Store if !opt.planner => Class::Other,
                // One long-window zstd frame finds files repeated across the
                // tier (binary data file variants); random data costs zstd little.
                Class::Store if opt.fast == FastCodec::Zstd => Class::Fast,
                c => c,
            };
            Some(match c {
                Class::Exec | Class::Other | Class::Zip if !opt.classify => Class::Text,
                c => c,
            })
        })
        .collect();
    let classes = if opt.fast == FastCodec::Zstd {
        unify_by_extension(entries, classes)
    } else {
        classes
    };
    if std::env::var_os("NZ_TRACE_FILES").is_some() {
        for (e, c) in entries.iter().zip(&classes) {
            if let Some(c) = c {
                eprintln!("[nz] class {:<5} {:>10} {}", c.name(), e.size, e.name);
            }
        }
    }
    let total: u64 = walk::total_bytes(entries);
    let target = opt.block_size(total);
    let seg = opt.segment.unwrap_or(target).max(64 * 1024);

    let mut blocks = Vec::new();
    let mut stats = WriteStats::default();
    for class in Class::ALL {
        let mut files: Vec<usize> = (0..entries.len())
            .filter(|&i| classes[i] == Some(class))
            .collect();
        files.sort_by_cached_key(|&i| (ext_key(&entries[i].name), entries[i].name.clone()));
        if matches!(class, Class::Fast | Class::Store) {
            stats.stored_by_planner += files.len();
        }
        let bytes: u64 = files.iter().map(|&i| sizes[i]).sum();
        let before = blocks.len();
        let t = match class {
            Class::Exec => opt.exec_block.max(64 * 1024),
            // One zstd frame over all containers: the long window finds
            // libraries repeated across JARs; zstd parallelises internally.
            Class::Zip if opt.zip_codec == ZipCodec::Zstd => ZIP_BLOCK,
            Class::Fast if opt.fast == FastCodec::Zstd => ZIP_BLOCK,
            Class::Text if matches!(opt.text_codec, TextCodec::Ppmd { .. }) => {
                opt.ppmd_block.unwrap_or(target).max(64 * 1024)
            }
            _ => target,
        };
        blocks.extend(split_blocks(class, &files, &sizes, t));
        crate::trace(&format!(
            "7z class {:<5} {:>5} files {:>11} bytes {} blocks",
            class.name(),
            files.len(),
            bytes,
            blocks.len() - before
        ));
    }
    crate::trace(&format!(
        "7z plan: block {target} seg {seg}, {:.1} ms",
        t0.elapsed().as_secs_f64() * 1e3
    ));

    // Memory: the batch's input and output buffers, then encoders under a gate.
    let budget = opt.mem_budget.unwrap_or_else(crate::mem::default_budget);
    let batch_limit = BATCH_BYTES.min(budget / 4).max(MIN_BLOCK);
    let buffers = 2 * total.min(batch_limit) + (32 << 20);
    let gate = crate::mem::Gate::new(budget.saturating_sub(buffers).max(64 << 20));
    crate::trace(&format!(
        "7z memory budget {} MiB, encoder gate {} MiB",
        budget >> 20,
        gate.capacity() >> 20
    ));
    let file = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, file);
    w.write_all(&[0u8; 32])?;
    let mut folders = Vec::new();
    let mut per_class = std::collections::BTreeMap::new();
    let mut pack_sizes = Vec::new();
    let mut stream_files: Vec<(usize, u32)> = Vec::new();
    let mut num_unpack: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < blocks.len() {
        let mut j = i;
        let mut bytes = 0;
        while j < blocks.len() && (j == i || bytes + blocks[j].bytes <= batch_limit) {
            bytes += blocks[j].bytes;
            j += 1;
        }
        let enc = encode_batch(entries, &blocks[i..j], opt, seg, &gate)?;
        for e in enc {
            w.write_all(&e.packed)?;
            pack_sizes.push(e.packed.len() as u64);
            num_unpack.push(e.crcs.len());
            stream_files.extend_from_slice(&e.crcs);
            let u = e.folder.unpack_size();
            let s = per_class.entry(e.class).or_insert((0u64, 0u64, 0f64, 0f64));
            s.0 += u;
            s.1 += e.packed.len() as u64;
            s.2 += e.cpu_ms;
            s.3 = s.3.max(e.cpu_ms);
            folders.push(e.folder);
        }
        i = j;
    }
    for (c, (u, p, cpu, mx)) in &per_class {
        crate::trace(&format!(
            "7z {:<5} {u:>10} -> {p:>10} ({:.2}%) cpu {cpu:.0} ms, slowest block {mx:.0} ms",
            c.name(),
            100.0 * *p as f64 / (*u).max(1) as f64
        ));
    }
    crate::trace(&format!(
        "7z data written {:.1} ms",
        t0.elapsed().as_secs_f64() * 1e3
    ));

    // ---- header
    let mut order: Vec<usize> = Vec::new();
    for (k, e) in entries.iter().enumerate() {
        match e.kind {
            Kind::Dir => stats.dirs += 1,
            Kind::File => {
                stats.files += 1;
                stats.input_bytes += e.size;
            }
        }
        if e.kind == Kind::Dir || e.size == 0 {
            order.push(k);
        }
    }
    let n_empty = order.len();
    order.extend(stream_files.iter().map(|&(k, _)| k));

    let mut h = Vec::new();
    put_number(&mut h, K_HEADER);
    if !folders.is_empty() {
        put_number(&mut h, K_MAIN_STREAMS);
        write_streams_core(&mut h, 0, &pack_sizes, &folders);
        put_number(&mut h, K_SUBSTREAMS);
        put_number(&mut h, K_NUM_UNPACK_STREAM);
        for &n in &num_unpack {
            put_number(&mut h, n as u64);
        }
        put_number(&mut h, K_SIZE);
        let mut it = stream_files.iter();
        for &n in &num_unpack {
            let files: Vec<_> = it.by_ref().take(n).collect();
            for &&(k, _) in &files[..n.saturating_sub(1)] {
                put_number(&mut h, sizes[k]);
            }
        }
        put_number(&mut h, K_CRC);
        h.push(1);
        for &(_, c) in &stream_files {
            h.extend_from_slice(&c.to_le_bytes());
        }
        put_number(&mut h, K_END);
        put_number(&mut h, K_END);
    }
    if !order.is_empty() {
        put_number(&mut h, K_FILES_INFO);
        put_number(&mut h, order.len() as u64);
        if n_empty > 0 {
            let mut bits = vec![false; order.len()];
            bits[..n_empty].fill(true);
            let mut p = Vec::new();
            put_bits(&mut p, &bits);
            put_number(&mut h, K_EMPTY_STREAM);
            put_number(&mut h, p.len() as u64);
            h.extend_from_slice(&p);
            let empty_files: Vec<bool> = order[..n_empty]
                .iter()
                .map(|&k| entries[k].kind == Kind::File)
                .collect();
            if empty_files.iter().any(|&x| x) {
                let mut p = Vec::new();
                put_bits(&mut p, &empty_files);
                put_number(&mut h, K_EMPTY_FILE);
                put_number(&mut h, p.len() as u64);
                h.extend_from_slice(&p);
            }
        }
        let mut names = vec![0u8]; // not external
        for &k in &order {
            for u in entries[k].name.encode_utf16() {
                names.extend_from_slice(&u.to_le_bytes());
            }
            names.extend_from_slice(&[0, 0]);
        }
        put_number(&mut h, K_NAME);
        put_number(&mut h, names.len() as u64);
        h.extend_from_slice(&names);
        put_number(&mut h, K_MTIME);
        put_number(&mut h, 2 + 8 * order.len() as u64);
        h.extend_from_slice(&[1, 0]); // all defined, not external
        for &k in &order {
            h.extend_from_slice(&filetime(entries[k].mtime).to_le_bytes());
        }
        put_number(&mut h, K_WIN_ATTRIBUTES);
        put_number(&mut h, 2 + 4 * order.len() as u64);
        h.extend_from_slice(&[1, 0]);
        for &k in &order {
            let a = match entries[k].kind {
                Kind::Dir => ATTR_DIRECTORY,
                Kind::File => ATTR_ARCHIVE,
            };
            h.extend_from_slice(&a.to_le_bytes());
        }
        put_number(&mut h, K_END);
    }
    put_number(&mut h, K_END);

    // Compress the header (kEncodedHeader) like 7-Zip does.
    let h_len = h.len();
    let data_end: u64 = pack_sizes.iter().sum();
    let hp = Lzma2Params::preset(6);
    let dict = lzma::segment_dict(&hp, h.len(), h.len());
    let hpacked = lzma::lzma2_encode(&h, &hp, dict)?;
    let (next, next_off) = if hpacked.len() + 32 < h.len() {
        w.write_all(&hpacked)?;
        let mut f = Folder::chain(
            vec![Coder::simple(
                M_LZMA2,
                &[lzma::lzma2_prop_for(u64::from(dict))],
            )],
            h.len() as u64,
        );
        f.crc = Some(crc32fast::hash(&h));
        let mut e = Vec::new();
        put_number(&mut e, K_ENCODED_HEADER);
        write_streams_core(&mut e, data_end, &[hpacked.len() as u64], &[f]);
        put_number(&mut e, K_END);
        (e, data_end + hpacked.len() as u64)
    } else {
        (h, data_end)
    };
    w.write_all(&next)?;
    let mut start = Vec::with_capacity(20);
    start.extend_from_slice(&next_off.to_le_bytes());
    start.extend_from_slice(&(next.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32fast::hash(&next).to_le_bytes());
    let mut sig = Vec::with_capacity(32);
    sig.extend_from_slice(&SIGNATURE);
    sig.extend_from_slice(&[0, 4]);
    sig.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
    sig.extend_from_slice(&start);
    w.seek(SeekFrom::Start(0))?;
    w.write_all(&sig)?;
    w.flush()?;
    stats.output_bytes = std::fs::metadata(out)?.len();
    crate::trace(&format!(
        "7z done: header {} -> {} bytes, {:.1} ms",
        h_len,
        next.len(),
        t0.elapsed().as_secs_f64() * 1e3
    ));
    Ok(stats)
}

// ---------------------------------------------------------------- reader

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.p).context("7z header truncated")?;
        self.p += 1;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).context("7z header overflow")?;
        let s = self.b.get(self.p..end).context("7z header truncated")?;
        self.p = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        let s = self.bytes(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let s = self.bytes(8)?;
        Ok(u64::from_le_bytes(s.try_into().expect("8 bytes")))
    }
    fn number(&mut self) -> Result<u64> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                return Ok(value | (high << (8 * i)));
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }
    fn small(&mut self, limit: u64) -> Result<usize> {
        let n = self.number()?;
        if n > limit {
            bail!("7z header: count {n} too large");
        }
        Ok(n as usize)
    }
    fn bits(&mut self, n: usize) -> Result<Vec<bool>> {
        let bytes = self.bytes(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
            .collect())
    }
    fn defined(&mut self, n: usize) -> Result<Vec<bool>> {
        if self.byte()? != 0 {
            Ok(vec![true; n])
        } else {
            self.bits(n)
        }
    }
    fn digests(&mut self, n: usize) -> Result<Vec<Option<u32>>> {
        let def = self.defined(n)?;
        def.into_iter()
            .map(|d| if d { self.u32().map(Some) } else { Ok(None) })
            .collect()
    }
}

const LIMIT: u64 = 1 << 24;

#[derive(Debug, Default)]
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    /// Per folder: (size, crc) of each substream.
    substreams: Vec<Vec<(u64, Option<u32>)>>,
}

fn read_folder(r: &mut Rd) -> Result<Folder> {
    let nc = r.small(64)?;
    let mut f = Folder::default();
    for _ in 0..nc {
        let flag = r.byte()?;
        if flag & 0x80 != 0 {
            bail!("7z: alternative coder methods are not supported");
        }
        let id = r.bytes((flag & 0x0F) as usize)?.to_vec();
        let (num_in, num_out) = if flag & 0x10 != 0 {
            (r.small(64)?, r.small(64)?)
        } else {
            (1, 1)
        };
        let props = if flag & 0x20 != 0 {
            let n = r.small(LIMIT)?;
            r.bytes(n)?.to_vec()
        } else {
            Vec::new()
        };
        f.coders.push(Coder {
            id,
            props,
            num_in,
            num_out,
        });
    }
    let total_out: usize = f.coders.iter().map(|c| c.num_out).sum();
    let total_in: usize = f.coders.iter().map(|c| c.num_in).sum();
    if total_out == 0 {
        bail!("7z: folder without output");
    }
    for _ in 0..total_out - 1 {
        f.bind_pairs.push((r.small(64)?, r.small(64)?));
    }
    let npacked = total_in
        .checked_sub(f.bind_pairs.len())
        .context("7z: bad bind pairs")?;
    if npacked == 1 {
        let free = (0..total_in)
            .find(|i| !f.bind_pairs.iter().any(|b| b.0 == *i))
            .context("7z: no packed stream")?;
        f.packed.push(free);
    } else {
        for _ in 0..npacked {
            f.packed.push(r.small(64)?);
        }
    }
    Ok(f)
}

fn read_streams_info(r: &mut Rd) -> Result<StreamsInfo> {
    let mut s = StreamsInfo::default();
    loop {
        match r.number()? {
            K_END => break,
            K_PACK_INFO => {
                s.pack_pos = r.number()?;
                let n = r.small(LIMIT)?;
                loop {
                    match r.number()? {
                        K_END => break,
                        K_SIZE => {
                            s.pack_sizes = (0..n).map(|_| r.number()).collect::<Result<_>>()?;
                        }
                        K_CRC => {
                            r.digests(n)?;
                        }
                        other => bail!("7z: unexpected id {other} in PackInfo"),
                    }
                }
            }
            K_UNPACK_INFO => {
                if r.number()? != K_FOLDER {
                    bail!("7z: expected Folder");
                }
                let n = r.small(LIMIT)?;
                if r.byte()? != 0 {
                    bail!("7z: external folders are not supported");
                }
                s.folders = (0..n).map(|_| read_folder(r)).collect::<Result<_>>()?;
                if r.number()? != K_CODERS_UNPACK_SIZE {
                    bail!("7z: expected CodersUnpackSize");
                }
                for f in &mut s.folders {
                    let outs: usize = f.coders.iter().map(|c| c.num_out).sum();
                    f.unpack_sizes = (0..outs).map(|_| r.number()).collect::<Result<_>>()?;
                }
                loop {
                    match r.number()? {
                        K_END => break,
                        K_CRC => {
                            let d = r.digests(n)?;
                            for (f, c) in s.folders.iter_mut().zip(d) {
                                f.crc = c;
                            }
                        }
                        other => bail!("7z: unexpected id {other} in UnpackInfo"),
                    }
                }
            }
            K_SUBSTREAMS => {
                let nf = s.folders.len();
                let mut counts = vec![1usize; nf];
                let mut id = r.number()?;
                if id == K_NUM_UNPACK_STREAM {
                    for c in &mut counts {
                        *c = r.small(LIMIT)?;
                    }
                    id = r.number()?;
                }
                let mut subs: Vec<Vec<(u64, Option<u32>)>> = Vec::with_capacity(nf);
                let has_sizes = id == K_SIZE;
                for (f, &c) in s.folders.iter().zip(&counts) {
                    let total = f.unpack_size();
                    let mut v = Vec::with_capacity(c);
                    if c > 0 {
                        let mut sum = 0u64;
                        for _ in 0..c - 1 {
                            let x = if has_sizes { r.number()? } else { 0 };
                            sum += x;
                            v.push((x, None));
                        }
                        let last = total
                            .checked_sub(sum)
                            .context("7z: substream sizes exceed folder")?;
                        v.push((last, None));
                    }
                    subs.push(v);
                }
                if has_sizes {
                    id = r.number()?;
                }
                // Folders with one substream and a folder CRC inherit it.
                for (f, v) in s.folders.iter().zip(&mut subs) {
                    if v.len() == 1 && f.crc.is_some() {
                        v[0].1 = f.crc;
                    }
                }
                while id != K_END {
                    if id != K_CRC {
                        bail!("7z: unexpected id {id} in SubStreamsInfo");
                    }
                    let need: usize = s
                        .folders
                        .iter()
                        .zip(&subs)
                        .filter(|(f, v)| !(v.len() == 1 && f.crc.is_some()))
                        .map(|(_, v)| v.len())
                        .sum();
                    let mut d = r.digests(need)?.into_iter();
                    for (f, v) in s.folders.iter().zip(&mut subs) {
                        if v.len() == 1 && f.crc.is_some() {
                            continue;
                        }
                        for x in v.iter_mut() {
                            x.1 = d.next().flatten();
                        }
                    }
                    id = r.number()?;
                }
                s.substreams = subs;
            }
            other => bail!("7z: unexpected id {other} in StreamsInfo"),
        }
    }
    if s.substreams.is_empty() {
        s.substreams = s
            .folders
            .iter()
            .map(|f| vec![(f.unpack_size(), f.crc)])
            .collect();
    }
    Ok(s)
}

/// One item of a 7z archive.
#[derive(Debug, Clone)]
pub struct Item {
    pub name: String,
    pub is_dir: bool,
    pub has_stream: bool,
    pub size: u64,
    pub crc: Option<u32>,
    pub mtime: Option<SystemTime>,
}

/// Parsed archive.
pub struct Archive {
    streams: StreamsInfo,
    pub items: Vec<Item>,
}

impl Archive {
    /// Per folder: coder chain, packed bytes, unpacked bytes and file count
    /// (for inspecting archives made by other tools).
    pub fn folders(&self) -> Vec<(&Folder, u64, u64, usize)> {
        let s = &self.streams;
        let mut pack = s.pack_sizes.iter();
        s.folders
            .iter()
            .zip(&s.substreams)
            .map(|(f, sub)| {
                let packed = pack.by_ref().take(f.packed.len()).sum();
                (f, packed, f.unpack_size(), sub.len())
            })
            .collect()
    }
}

fn read_files_info(r: &mut Rd) -> Result<Vec<Item>> {
    let n = r.small(LIMIT)?;
    let mut empty_stream = vec![false; n];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut anti: Vec<bool> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut mtimes: Vec<Option<u64>> = vec![None; n];
    let mut attrs: Vec<Option<u32>> = vec![None; n];
    loop {
        let t = r.number()?;
        if t == K_END {
            break;
        }
        let size = r.small(1 << 32)?;
        let mut p = Rd::new(r.bytes(size)?);
        let n_empty = empty_stream.iter().filter(|&&x| x).count();
        match t {
            K_EMPTY_STREAM => empty_stream = p.bits(n)?,
            K_EMPTY_FILE => empty_file = p.bits(n_empty)?,
            0x10 => anti = p.bits(n_empty)?,
            K_NAME => {
                if p.byte()? != 0 {
                    bail!("7z: external names are not supported");
                }
                let raw = &p.b[p.p..];
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                names = units
                    .split(|&u| u == 0)
                    .take(n)
                    .map(String::from_utf16_lossy)
                    .collect();
            }
            K_MTIME => {
                let def = p.defined(n)?;
                if p.byte()? != 0 {
                    bail!("7z: external times are not supported");
                }
                for (slot, d) in mtimes.iter_mut().zip(def) {
                    if d {
                        *slot = Some(p.u64()?);
                    }
                }
            }
            K_WIN_ATTRIBUTES => {
                let def = p.defined(n)?;
                if p.byte()? != 0 {
                    bail!("7z: external attributes are not supported");
                }
                for (slot, d) in attrs.iter_mut().zip(def) {
                    if d {
                        *slot = Some(p.u32()?);
                    }
                }
            }
            _ => {} // CTime, ATime, kDummy, StartPos, ...: ignored
        }
    }
    if names.len() != n {
        bail!("7z: {} names for {n} files", names.len());
    }
    let mut items = Vec::with_capacity(n);
    let mut ei = 0;
    for (i, name) in names.into_iter().enumerate() {
        let has_stream = !empty_stream[i];
        let (is_dir, is_anti) = if has_stream {
            (false, false)
        } else {
            let ef = empty_file.get(ei).copied().unwrap_or(false);
            let an = anti.get(ei).copied().unwrap_or(false);
            ei += 1;
            let attr_dir = attrs[i].is_some_and(|a| a & ATTR_DIRECTORY != 0);
            (!ef || attr_dir, an)
        };
        if is_anti {
            continue;
        }
        items.push(Item {
            name,
            is_dir,
            has_stream,
            size: 0,
            crc: None,
            mtime: mtimes[i].and_then(from_filetime),
        });
    }
    Ok(items)
}

fn read_packed(f: &File, off: u64, len: u64) -> Result<Vec<u8>> {
    let mut v = vec![0u8; usize::try_from(len).context("packed stream too large")?];
    crate::zip::read_at(f, &mut v, off)?;
    Ok(v)
}

/// Decode folder `fi` of `s` to its final output.
fn decode_folder(f: &File, s: &StreamsInfo, fi: usize) -> Result<Vec<u8>> {
    let folder = &s.folders[fi];
    if folder.packed.len() != 1
        || folder
            .coders
            .iter()
            .any(|c| c.num_in != 1 || c.num_out != 1)
    {
        bail!("7z: multi-stream coders (e.g. BCJ2) are not supported");
    }
    let first_pack: usize = s.folders[..fi].iter().map(|f| f.packed.len()).sum();
    let off = 32 + s.pack_pos + s.pack_sizes[..first_pack].iter().sum::<u64>();
    let mut data = read_packed(
        f,
        off,
        *s.pack_sizes.get(first_pack).context("7z: pack size")?,
    )?;
    // Chain from the final coder back to the packed stream.
    let n = folder.coders.len();
    let mut c = (0..n)
        .find(|i| !folder.bind_pairs.iter().any(|b| b.1 == *i))
        .context("7z: no final coder")?;
    let mut chain = vec![c];
    while let Some(b) = folder.bind_pairs.iter().find(|b| b.0 == c) {
        c = b.1;
        if chain.contains(&c) || chain.len() > n {
            bail!("7z: coder cycle");
        }
        chain.push(c);
    }
    if folder.packed[0] != c {
        bail!("7z: unsupported coder graph");
    }
    for &ci in chain.iter().rev() {
        let coder = &folder.coders[ci];
        let size = usize::try_from(folder.unpack_sizes[ci]).context("folder too large")?;
        data = match coder.id.as_slice() {
            M_COPY => data,
            M_LZMA2 => {
                lzma::lzma2_decode(&data, *coder.props.first().context("LZMA2 props")?, size)?
            }
            M_LZMA => lzma::lzma1_decode(&data, &coder.props, size)?,
            M_PPMD => ppmd_decode(&data, &coder.props, size)?,
            M_BCJ => {
                bcj::x86_convert(&mut data, false);
                data
            }
            M_DEFLATE => deflate::inflate_exact(&data, size)?,
            M_ZSTD => {
                let mut out = Vec::with_capacity(size);
                let mut d = zstd::stream::read::Decoder::new(data.as_slice())?;
                d.window_log_max(31)?;
                std::io::copy(&mut d, &mut out).context("7z: zstd data error")?;
                out
            }
            [0x06, 0xF1, 0x07, 0x01] => bail!("7z: encrypted archives are not supported"),
            id => bail!("7z: unsupported method {id:02X?}"),
        };
        if data.len() != size {
            bail!("7z: coder output size mismatch");
        }
    }
    if let Some(crc) = folder.crc
        && crc32fast::hash(&data) != crc
    {
        bail!("7z: folder CRC mismatch");
    }
    Ok(data)
}

/// Read the archive structure.
pub fn open(f: &File) -> Result<Archive> {
    let mut sig = [0u8; 32];
    crate::zip::read_at(f, &mut sig, 0).context("not a 7z archive")?;
    if sig[..6] != SIGNATURE {
        bail!("not a 7z archive");
    }
    if crc32fast::hash(&sig[12..32]) != u32::from_le_bytes(sig[8..12].try_into()?) {
        bail!("7z: start header CRC mismatch");
    }
    let next_off = u64::from_le_bytes(sig[12..20].try_into()?);
    let next_len = u64::from_le_bytes(sig[20..28].try_into()?);
    let next_crc = u32::from_le_bytes(sig[28..32].try_into()?);
    if next_len == 0 {
        return Ok(Archive {
            streams: StreamsInfo::default(),
            items: Vec::new(),
        });
    }
    let mut header = read_packed(f, 32 + next_off, next_len)?;
    if crc32fast::hash(&header) != next_crc {
        bail!("7z: header CRC mismatch");
    }
    for _ in 0..4 {
        let mut r = Rd::new(&header);
        match r.number()? {
            K_ENCODED_HEADER => {
                let s = read_streams_info(&mut r)?;
                let mut out = Vec::new();
                for fi in 0..s.folders.len() {
                    out.extend(decode_folder(f, &s, fi)?);
                }
                header = out;
            }
            K_HEADER => {
                let mut streams = StreamsInfo::default();
                let mut items = Vec::new();
                loop {
                    match r.number()? {
                        K_END => break,
                        K_ARCHIVE_PROPERTIES => loop {
                            if r.number()? == K_END {
                                break;
                            }
                            let n = r.small(1 << 32)?;
                            r.bytes(n)?;
                        },
                        K_ADDITIONAL_STREAMS => {
                            read_streams_info(&mut r)?;
                        }
                        K_MAIN_STREAMS => streams = read_streams_info(&mut r)?,
                        K_FILES_INFO => items = read_files_info(&mut r)?,
                        other => bail!("7z: unexpected id {other} in header"),
                    }
                }
                // Attach sizes / CRCs to items with streams.
                let mut subs = streams.substreams.iter().flatten();
                for it in items.iter_mut().filter(|i| i.has_stream) {
                    let (size, crc) = subs.next().context("7z: more files than streams")?;
                    it.size = *size;
                    it.crc = *crc;
                }
                return Ok(Archive { streams, items });
            }
            other => bail!("7z: unknown header type {other}"),
        }
    }
    bail!("7z: too many nested encoded headers")
}

/// Extract a 7z archive into `out_dir`; folders are decoded in parallel.
pub fn extract_7z(archive: &Path, out_dir: &Path) -> Result<ExtractStats> {
    let f = File::open(archive).with_context(|| format!("cannot open {}", archive.display()))?;
    let ar = open(&f)?;
    std::fs::create_dir_all(out_dir)?;
    let mut stats = ExtractStats::default();
    let mut dirs = std::collections::BTreeSet::new();
    for it in &ar.items {
        let rel =
            walk::safe_relative(&it.name).with_context(|| format!("unsafe path {}", it.name))?;
        if it.is_dir {
            stats.dirs += 1;
            dirs.insert(rel);
        } else if let Some(p) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            dirs.insert(p.to_path_buf());
        }
    }
    for d in &dirs {
        std::fs::create_dir_all(out_dir.join(d))?;
    }
    let write_file = |it: &Item, data: &[u8]| -> Result<()> {
        let rel = walk::safe_relative(&it.name).context("unsafe path")?;
        let dest = out_dir.join(rel);
        let out =
            File::create(&dest).with_context(|| format!("cannot create {}", dest.display()))?;
        if data.len() > 64 * 1024 {
            out.set_len(data.len() as u64)?;
        }
        (&out).write_all(data)?;
        if let Some(t) = it.mtime {
            let _ = out.set_modified(t);
        }
        Ok(())
    };
    for it in ar.items.iter().filter(|i| !i.is_dir && !i.has_stream) {
        write_file(it, &[])?;
        stats.files += 1;
    }
    // Items per folder.
    let mut per_folder: Vec<Vec<&Item>> = Vec::with_capacity(ar.streams.folders.len());
    let mut it = ar.items.iter().filter(|i| i.has_stream);
    for subs in &ar.streams.substreams {
        per_folder.push(it.by_ref().take(subs.len()).collect());
    }
    let nf = ar.streams.folders.len();
    let mut i = 0;
    while i < nf {
        let mut j = i;
        let mut bytes = 0u64;
        while j < nf && (j == i || bytes + ar.streams.folders[j].unpack_size() <= BATCH_BYTES) {
            bytes += ar.streams.folders[j].unpack_size();
            j += 1;
        }
        let done: Result<Vec<(usize, u64)>> = (i..j)
            .into_par_iter()
            .map(|fi| {
                let data = decode_folder(&f, &ar.streams, fi)?;
                let items = &per_folder[fi];
                let mut off = 0usize;
                let mut total = 0u64;
                for item in items {
                    let n = usize::try_from(item.size)?;
                    let piece = data.get(off..off + n).context("7z: substream overrun")?;
                    if let Some(c) = item.crc
                        && crc32fast::hash(piece) != c
                    {
                        bail!("7z: CRC mismatch in {}", item.name);
                    }
                    write_file(item, piece)?;
                    off += n;
                    total += item.size;
                }
                Ok((items.len(), total))
            })
            .collect();
        for (n, b) in done? {
            stats.files += n;
            stats.bytes += b;
        }
        i = j;
    }
    for it in ar.items.iter().filter(|i| i.is_dir) {
        if let (Some(t), Some(rel)) = (it.mtime, walk::safe_relative(&it.name))
            && let Ok(d) = File::open(out_dir.join(rel))
        {
            let _ = d.set_modified(t);
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_roundtrip() {
        for x in [
            0u64,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            1 << 20,
            (1 << 56) - 1,
            1 << 56,
            u64::MAX,
        ] {
            let mut v = Vec::new();
            put_number(&mut v, x);
            let mut r = Rd::new(&v);
            assert_eq!(r.number().unwrap(), x, "{x:#x}");
            assert_eq!(r.p, v.len());
        }
        let mut v = Vec::new();
        put_number(&mut v, 0x80);
        assert_eq!(v, [0x80, 0x80]);
    }

    #[test]
    fn blocks_are_balanced() {
        let sizes = vec![10u64; 100];
        let files: Vec<usize> = (0..100).collect();
        let b = split_blocks(Class::Text, &files, &sizes, 250);
        assert_eq!(b.len(), 4);
        assert!(b.iter().all(|x| x.bytes == 250));
        let sizes = vec![1000u64, 1, 1, 1];
        let b = split_blocks(Class::Text, &[0, 1, 2, 3], &sizes, 300);
        assert_eq!(b.iter().map(|x| x.files.len()).sum::<usize>(), 4);
    }

    #[test]
    fn filetime_roundtrip() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_700);
        assert_eq!(from_filetime(filetime(t)), Some(t));
    }

    #[test]
    fn job_schedule_keeps_bytes_and_roundtrips() {
        // Several blocks with multi-segment chained LZMA2 (text, other) and
        // a zstd folder: the job order must not change the archive.
        let src = tempfile::tempdir().unwrap();
        let mut s = 7u64;
        for i in 0..24 {
            let text: String = (0..6000)
                .map(|k| {
                    format!(
                        "line {} of file {i} value {}
",
                        k % 97,
                        k * i
                    )
                })
                .collect();
            std::fs::write(src.path().join(format!("t{i:02}.txt")), text).unwrap();
            let noise: Vec<u8> = (0..150_000)
                .map(|_| {
                    s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (s >> 59) as u8
                })
                .collect();
            std::fs::write(src.path().join(format!("b{i:02}.bin")), noise).unwrap();
        }
        let entries = walk::collect(&[src.path().to_path_buf()]).unwrap();
        let mut opt = SevenZOptions::for_level(6);
        opt.block = Some(1 << 20);
        opt.segment = Some(256 << 10);
        opt.other_seg = Some(128 << 10);
        opt.other_preload = 128 << 10;
        let out = tempfile::tempdir().unwrap();
        let mut archives = Vec::new();
        for threads in [1, 3, 8] {
            let a = out.path().join(format!("t{threads}.7z"));
            crate::cpu::pool(threads)
                .unwrap()
                .install(|| write_7z(&entries, &a, &opt))
                .unwrap();
            archives.push(std::fs::read(&a).unwrap());
        }
        assert!(archives.windows(2).all(|w| w[0] == w[1]));
        let x = out.path().join("x");
        extract_7z(&out.path().join("t3.7z"), &x).unwrap();
        for e in entries.iter().filter(|e| e.kind == Kind::File) {
            let back = std::fs::read(x.join(&e.name)).unwrap();
            assert_eq!(back, std::fs::read(&e.path).unwrap(), "{}", e.name);
        }
    }
}
