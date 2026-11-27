//! Block payload codecs and filters.

use anyhow::{Result, anyhow, bail, ensure};
use nz_core::lzma::{
    Lzma2Params, lzma2_decode, lzma2_dict_from_prop, lzma2_parallel, lzma2_prop_for,
};

/// LZMA2 segment and chained preload (level 9).
const LZMA2_SEGMENT: usize = 4 << 20;
const LZMA2_PRELOAD: usize = 8 << 20;
/// LZMA2 segment for mostly-compressed data (independent segments: such
/// data has few long matches).
const FAST_SEGMENT: usize = 1 << 20;

use crate::fmt::{Codec, Filter};

/// What a block holds; files are routed to blocks by their content class
/// (the NextZip planner samples every file) so that each block gets the
/// codec and filter that suit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// Text and everything not listed below.
    Normal = 0,
    /// x86 / x86-64 machine code: BCJ-filtered, larger blocks.
    Exec = 1,
    /// Mostly compressed data (the planner's "fast" and "store" classes),
    /// only kept apart when [`Method::fast`] is set.
    Fast = 2,
    /// Incompressible files (the planner's "store" class) at levels
    /// without [`Method::fast`]: stored.
    Store = 3,
}

impl BlockKind {
    /// Order in which open blocks are sealed at the end.
    pub const ALL: [BlockKind; 4] = [
        BlockKind::Normal,
        BlockKind::Exec,
        BlockKind::Fast,
        BlockKind::Store,
    ];
}

/// Compression settings for one archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    pub codec: Codec,
    /// zstd level or xz preset.
    pub level: i32,
    /// Target raw block size.
    pub block: usize,
    /// Target raw size of x86 code blocks (0: no separate code blocks and
    /// no BCJ filter).
    pub exec_block: usize,
    /// Codec and level for mostly-compressed data, kept in blocks of its
    /// own (None: such data goes with the rest).
    pub fast: Option<(Codec, i32)>,
}

impl Method {
    /// The `-l:0..9` mapping (measurements: `bench/results/M4b-*`).
    pub fn for_level(level: u8) -> Self {
        let (codec, l, block) = match level {
            0 => (Codec::Store, 0, 4 << 20),
            1 => (Codec::Lz4, 1, 4 << 20),
            2 => (Codec::Zstd, 1, 4 << 20),
            3 => (Codec::Zstd, 3, 4 << 20),
            4 => (Codec::Zstd, 5, 4 << 20),
            5 => (Codec::Zstd, 7, 4 << 20),
            6 => (Codec::Zstd, 9, 4 << 20),
            7 => (Codec::Zstd, 15, 16 << 20),
            8 => (Codec::Zstd, 19, 16 << 20),
            _ => (Codec::Lzma2, 9, 64 << 20),
        };
        let exec_block = match level {
            0 => 0,
            1 => block,
            _ => block.max(8 << 20),
        };
        let fast = matches!(level, 6..=8).then_some((Codec::Lzma2, 1));
        Self {
            codec,
            level: l,
            block,
            exec_block,
            fast,
        }
    }

    /// Target raw size of a block of `kind`.
    pub fn target(&self, kind: BlockKind) -> usize {
        match kind {
            BlockKind::Exec => self.exec_block.max(1),
            _ => self.block,
        }
    }

    /// The block a file of content class `class` goes to.
    pub fn kind_for(&self, class: nz_core::planner::Class) -> BlockKind {
        use nz_core::planner::Class;
        match class {
            Class::Exec if self.exec_block > 0 => BlockKind::Exec,
            Class::Fast | Class::Store if self.fast.is_some() => BlockKind::Fast,
            // Level 9 tries LZMA2 on everything; levels 1-5 store.
            Class::Store if !matches!(self.codec, Codec::Store | Codec::Lzma2) => BlockKind::Store,
            _ => BlockKind::Normal,
        }
    }
}

/// zstd with the window sized to the block (capped at the reader limit).
fn zstd_compress(raw: &[u8], level: i32) -> Result<Vec<u8>> {
    let mut c = zstd::bulk::Compressor::new(level)?;
    let wlog = raw.len().max(1 << 10).next_power_of_two().trailing_zeros();
    c.window_log(wlog.min(27))?;
    Ok(c.compress(raw)?)
}

/// Compress a block of `kind`; stores store-class blocks, and falls back to
/// Store (without filter) when the compressed form is not smaller.
pub fn compress(raw: &[u8], m: &Method, kind: BlockKind) -> Result<(Codec, Filter, Vec<u8>)> {
    let (codec, level) = match (kind, m.fast) {
        (BlockKind::Fast, Some(f)) => f,
        _ => (m.codec, m.level),
    };
    let store = || Ok((Codec::Store, Filter::None, raw.to_vec()));
    if codec == Codec::Store || kind == BlockKind::Store || raw.is_empty() {
        return store();
    }
    let filtered;
    let (filter, input) = if kind == BlockKind::Exec && m.exec_block > 0 {
        let mut f = raw.to_vec();
        nz_core::bcj::x86_convert(&mut f, true);
        filtered = f;
        (Filter::X86, filtered.as_slice())
    } else {
        (Filter::None, raw)
    };
    let out = match codec {
        Codec::Store => unreachable!(),
        Codec::Lz4 => {
            lz4::block::compress(input, Some(lz4::block::CompressionMode::DEFAULT), false)?
        }
        Codec::Zstd => zstd_compress(input, level)?,
        Codec::Lzma2 => {
            // One LZMA2 stream per block, encoded as segments in parallel
            // (identical bytes for any thread count).
            let mut p = Lzma2Params::preset(level as u32);
            let o = if kind == BlockKind::Fast {
                p.lc = Some(0);
                p.pb = Some(0);
                lzma2_parallel(input, &p, FAST_SEGMENT, 0)?
            } else {
                lzma2_parallel(input, &p, LZMA2_SEGMENT, LZMA2_PRELOAD)?
            };
            let mut v = vec![o.prop];
            v.extend_from_slice(&o.data);
            v
        }
    };
    if out.len() >= raw.len() {
        return store();
    }
    Ok((codec, filter, out))
}

/// Decompress a payload to exactly `raw_len` bytes and undo its filter.
pub fn decompress(codec: Codec, filter: Filter, data: &[u8], raw_len: usize) -> Result<Vec<u8>> {
    let mut out = match codec {
        Codec::Store => data.to_vec(),
        Codec::Lz4 => {
            lz4::block::decompress(data, Some(raw_len as i32)).map_err(|e| anyhow!("lz4: {e}"))?
        }
        Codec::Zstd => {
            // Single frame whose content must be exactly raw_len bytes.
            if let Ok(Some(n)) = zstd::zstd_safe::get_frame_content_size(data) {
                ensure!(
                    n == raw_len as u64,
                    "zstd: frame size differs from the header"
                );
            }
            let mut d = zstd::bulk::Decompressor::new()?;
            d.window_log_max(27)?;
            let mut out = Vec::with_capacity(raw_len);
            let n = d
                .decompress_to_buffer(data, &mut out)
                .map_err(|e| anyhow!("zstd: {e}"))?;
            ensure!(n == raw_len, "zstd: wrong size");
            out
        }
        Codec::Lzma2 => {
            let Some((&prop, rest)) = data.split_first() else {
                bail!("empty LZMA2 payload")
            };
            ensure!(prop < 40, "bad LZMA2 property");
            let allowed = lzma2_dict_from_prop(lzma2_prop_for(raw_len.max(4096) as u64));
            ensure!(
                lzma2_dict_from_prop(prop) <= allowed,
                "LZMA2 dictionary larger than the block"
            );
            lzma2_decode(rest, prop, raw_len)?
        }
    };
    ensure!(out.len() == raw_len, "{}: wrong decoded size", codec.name());
    if filter == Filter::X86 {
        nz_core::bcj::x86_convert(&mut out, false);
    }
    Ok(out)
}
