//! LZMA / LZMA2 on liblzma (raw streams, as used inside 7z folders).
//!
//! Parallel LZMA2: a buffer is cut into fixed-size segments that are encoded
//! in parallel and concatenated into one LZMA2 stream (the end markers of all
//! but the last segment are dropped). Two modes:
//!
//! * **independent** (`preload == 0`): every segment starts with a
//!   dictionary reset, like 7-Zip's multithreaded LZMA2 blocks. Matches
//!   cannot cross segment boundaries.
//! * **chained** (`preload > 0`): segment *k* is encoded with the last
//!   `preload` bytes before it as a liblzma *preset dictionary* (via
//!   [`nz_xz`]), so its first chunk does not reset the dictionary and it can
//!   reference earlier data, exactly as a single-threaded encoder could (up to
//!   `preload` bytes back at the segment start). The decoder sees one ordinary
//!   LZMA2 stream. Cost: each encoder first indexes its preload.
//!
//! The result depends only on the data, the encoder options, the segment size
//! and the preload, never on the thread count.

use anyhow::{Result, anyhow, bail};
use liblzma::stream::{Action, Filters, Status, Stream};
use rayon::prelude::*;

/// LZMA2 encoder settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lzma2Params {
    /// xz preset 0..=9.
    pub preset: u32,
    /// Match finder and mode override (None = preset default).
    pub mf: Option<Mf>,
    /// nice_len override.
    pub nice: Option<u32>,
    /// Match finder depth override (0 = automatic).
    pub depth: Option<u32>,
    /// Dictionary size override in bytes (None = preset dictionary).
    pub dict: Option<u32>,
    /// lc / lp / pb overrides.
    pub lc: Option<u32>,
    pub lp: Option<u32>,
    pub pb: Option<u32>,
}

/// Match finder + parsing mode. `Hc4` is hc4 with fast parsing and `Bt4`
/// bt4 with normal (optimal) parsing, liblzma's two preset families; the
/// other combinations exist for tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mf {
    Hc4,
    Bt4,
    /// hc4 with normal (optimal) parsing.
    Hc4Normal,
    /// bt4 with fast parsing.
    Bt4Fast,
    /// bt3 / bt2 with normal parsing.
    Bt3,
    Bt2,
}

impl Mf {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "hc4" => Self::Hc4,
            "bt4" => Self::Bt4,
            "hc4n" => Self::Hc4Normal,
            "bt4f" => Self::Bt4Fast,
            "bt3" => Self::Bt3,
            "bt2" => Self::Bt2,
            other => bail!("unknown match finder '{other}' (hc4, bt4, hc4n, bt4f, bt3, bt2)"),
        })
    }

    fn xz(self) -> (nz_xz::MatchFinder, bool) {
        use nz_xz::MatchFinder as M;
        match self {
            Self::Hc4 => (M::Hc4, true),
            Self::Bt4 => (M::Bt4, false),
            Self::Hc4Normal => (M::Hc4, false),
            Self::Bt4Fast => (M::Bt4, true),
            Self::Bt3 => (M::Bt3, false),
            Self::Bt2 => (M::Bt2, false),
        }
    }
}

impl Lzma2Params {
    pub fn preset(preset: u32) -> Self {
        Self {
            preset,
            mf: None,
            nice: None,
            depth: None,
            dict: None,
            lc: None,
            lp: None,
            pb: None,
        }
    }

    /// Dictionary size (override or preset).
    pub fn preset_dict(&self) -> u32 {
        // liblzma's lzma_lzma_preset() table.
        const DICT_POW2: [u32; 10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
        self.dict
            .unwrap_or(1 << DICT_POW2[self.preset.min(9) as usize])
    }

    fn xz(&self, dict: u32) -> nz_xz::Params {
        nz_xz::Params {
            preset: self.preset.min(9),
            dict_size: dict,
            mf: self.mf.map(|m| m.xz().0),
            fast: self.mf.map(|m| m.xz().1),
            nice_len: self.nice,
            depth: self.depth,
            lc: self.lc,
            lp: self.lp,
            pb: self.pb,
        }
    }
}

/// Dictionary size encoded by a 7z/xz LZMA2 property byte.
pub fn lzma2_dict_from_prop(p: u8) -> u64 {
    if p >= 40 {
        return u64::from(u32::MAX);
    }
    (2 | u64::from(p & 1)) << (p / 2 + 11)
}

/// Smallest LZMA2 property byte whose dictionary holds `dict` bytes.
pub fn lzma2_prop_for(dict: u64) -> u8 {
    (0..40u8)
        .find(|&p| lzma2_dict_from_prop(p) >= dict)
        .unwrap_or(40)
}

/// Encode one raw LZMA2 stream (with end marker); `history` is the data
/// preceding `data` in the stream (empty = dictionary reset).
pub fn lzma2_encode_with(
    data: &[u8],
    history: &[u8],
    p: &Lzma2Params,
    dict: u32,
) -> Result<Vec<u8>> {
    nz_xz::lzma2_encode(data, history, &p.xz(dict)).map_err(|e| anyhow!("LZMA2 encoder: {e}"))
}

/// Encode one raw LZMA2 stream (with end marker).
pub fn lzma2_encode(data: &[u8], p: &Lzma2Params, dict: u32) -> Result<Vec<u8>> {
    lzma2_encode_with(data, &[], p, dict)
}

/// Encoded parallel LZMA2 stream and the dictionary property it needs.
pub struct Lzma2Out {
    pub data: Vec<u8>,
    pub prop: u8,
}

/// Dictionary for a stream of `total` bytes whose matches may reach `span`
/// bytes back (never larger than the preset dictionary or than needed).
pub fn segment_dict(p: &Lzma2Params, span: usize, total: usize) -> u32 {
    let need = span.min(total).max(4096) as u64;
    // Round up to a size the property byte can express exactly.
    let rounded = lzma2_dict_from_prop(lzma2_prop_for(need));
    rounded.min(u64::from(p.preset_dict())) as u32
}

/// Compress `data` as one LZMA2 stream made of `seg`-byte segments encoded in
/// parallel on the current Rayon pool. `preload > 0` chains the segments
/// (see the module documentation).
pub fn lzma2_parallel(
    data: &[u8],
    p: &Lzma2Params,
    seg: usize,
    preload: usize,
) -> Result<Lzma2Out> {
    lzma2_parallel_gated(data, p, seg, preload, None)
}

/// Memory of one segment encoder with dictionary `dict` (liblzma's estimate,
/// plus the segment's output buffer).
pub fn encoder_memory(p: &Lzma2Params, dict: u32, seg: usize) -> u64 {
    let enc = nz_xz::encoder_memusage(&p.xz(dict)).unwrap_or(u64::from(dict) * 12);
    enc + seg as u64
}

/// How [`lzma2_parallel_gated`] cuts `len` bytes into chained segments. The
/// plan depends only on the length and the options, so callers may encode
/// the segments in any order (or on any thread) and [`splice`] them.
#[derive(Debug, Clone, Copy)]
pub struct SegPlan {
    /// Dictionary size of every segment encoder.
    pub dict: u32,
    /// LZMA2 dictionary property byte of the spliced stream.
    pub prop: u8,
    /// Segment length (the last one may be shorter).
    pub seg: usize,
    /// History bytes each segment sees before its start.
    pub preload: usize,
    /// Number of segments (at least 1).
    pub n: usize,
    /// Memory of one segment encoder ([`encoder_memory`]).
    pub need: u64,
}

impl SegPlan {
    pub fn new(len: usize, p: &Lzma2Params, seg: usize, preload: usize) -> Self {
        let seg = seg.max(64 * 1024);
        let span = seg.saturating_add(preload);
        let dict = segment_dict(p, span, len);
        let prop = lzma2_prop_for(u64::from(dict));
        let preload = preload.min(dict as usize);
        let need = encoder_memory(p, dict, seg.min(len));
        let n = if len <= seg { 1 } else { len.div_ceil(seg) };
        Self {
            dict,
            prop,
            seg,
            preload,
            n,
            need,
        }
    }

    /// Byte range of segment `i` and the start of its history.
    pub fn range(&self, len: usize, i: usize) -> (usize, usize, usize) {
        if self.n == 1 {
            return (0, 0, len);
        }
        let start = i * self.seg;
        let end = (start + self.seg).min(len);
        (start.saturating_sub(self.preload), start, end)
    }

    /// Encode segment `i` of `data` (the whole input, not just the segment).
    pub fn encode(&self, data: &[u8], p: &Lzma2Params, i: usize) -> Result<Vec<u8>> {
        let (h, start, end) = self.range(data.len(), i);
        lzma2_encode_with(&data[start..end], &data[h..start], p, self.dict)
    }
}

/// Join encoded segments (in order) into one LZMA2 stream: every segment
/// but the last loses its end marker.
pub fn splice(parts: Vec<Vec<u8>>, prop: u8) -> Result<Lzma2Out> {
    let n = parts.len();
    if n == 1 {
        let data = parts.into_iter().next().unwrap_or_default();
        return Ok(Lzma2Out { data, prop });
    }
    let total: usize = parts.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    for (i, mut part) in parts.into_iter().enumerate() {
        if i + 1 < n {
            if part.last() != Some(&0) {
                bail!("LZMA2 segment without end marker");
            }
            part.pop();
        }
        out.extend_from_slice(&part);
    }
    Ok(Lzma2Out { data: out, prop })
}

/// [`lzma2_parallel`] where every segment encoder first takes its memory from
/// `gate` (the output does not depend on the gate).
pub fn lzma2_parallel_gated(
    data: &[u8],
    p: &Lzma2Params,
    seg: usize,
    preload: usize,
    gate: Option<&crate::mem::Gate>,
) -> Result<Lzma2Out> {
    let plan = SegPlan::new(data.len(), p, seg, preload);
    let parts: Vec<Result<Vec<u8>>> = (0..plan.n)
        .into_par_iter()
        .map(|i| {
            let _permit = gate.map(|g| g.acquire(plan.need));
            plan.encode(data, p, i)
        })
        .collect();
    splice(parts.into_iter().collect::<Result<Vec<_>>>()?, plan.prop)
}
fn run_decoder(mut s: Stream, data: &[u8], size: usize, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let before = (s.total_in(), out.len());
        let st = s
            .process_vec(&data[s.total_in() as usize..], &mut out, Action::Run)
            .map_err(|e| anyhow!("{what} data error: {e}"))?;
        if st == Status::StreamEnd || (s.total_in(), out.len()) == before {
            break;
        }
    }
    if out.len() != size {
        bail!("{what}: decoded {} bytes, expected {size}", out.len());
    }
    Ok(out)
}

/// Dictionary a decoder needs for `size` output bytes. A raw stream cannot
/// refer further back than its own output, so a larger dictionary in the
/// header only costs memory: liblzma allocates all of it up front, and a
/// forged header asked for 4 GiB to decode a few bytes.
fn decode_dict(size: usize) -> u64 {
    (size as u64).max(4096)
}

/// Decode a raw LZMA2 stream with 7z property byte `prop`.
pub fn lzma2_decode(data: &[u8], prop: u8, size: usize) -> Result<Vec<u8>> {
    let prop = prop.min(lzma2_prop_for(decode_dict(size)));
    let mut f = Filters::new();
    f.lzma2_properties(&[prop])
        .map_err(|e| anyhow!("bad LZMA2 properties: {e}"))?;
    let s = Stream::new_raw_decoder(&f).map_err(|e| anyhow!("LZMA2 init: {e}"))?;
    run_decoder(s, data, size, "LZMA2")
}

/// Decode a raw LZMA (v1) stream with the 5-byte 7z properties.
pub fn lzma1_decode(data: &[u8], props: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut props = props.to_vec();
    if let Some(d) = props.get_mut(1..5) {
        let dict = u64::from(u32::from_le_bytes([d[0], d[1], d[2], d[3]]));
        let dict = dict.min(decode_dict(size)) as u32;
        d.copy_from_slice(&dict.to_le_bytes());
    }
    let mut f = Filters::new();
    f.lzma1_properties(&props)
        .map_err(|e| anyhow!("bad LZMA properties: {e}"))?;
    let s = Stream::new_raw_decoder(&f).map_err(|e| anyhow!("LZMA init: {e}"))?;
    run_decoder(s, data, size, "LZMA")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dict_props() {
        assert_eq!(lzma2_dict_from_prop(0), 4096);
        assert_eq!(lzma2_dict_from_prop(1), 6144);
        assert_eq!(lzma2_dict_from_prop(18), 2 << 20);
        assert_eq!(lzma2_prop_for(8 << 20), 22);
        assert_eq!(lzma2_prop_for((8 << 20) + 1), 23);
        assert_eq!(lzma2_prop_for(1), 0);
    }

    #[test]
    fn spliced_segments_decode_as_one_stream() {
        let data: Vec<u8> = (0..700_000u32)
            .flat_map(|i| format!("{} {}\n", i % 1013, i / 7).into_bytes())
            .collect();
        let p = Lzma2Params::preset(1);
        let one = lzma2_parallel(&data, &p, usize::MAX, 0).unwrap();
        let many = lzma2_parallel(&data, &p, 300_000, 0).unwrap();
        let chained = lzma2_parallel(&data, &p, 300_000, 1 << 20).unwrap();
        assert!(chained.data.len() < many.data.len());
        // The dictionary covers preload + segment, not the whole preset
        // dictionary (preset 9 = 64 MiB ran out of memory with 12 encoders).
        let big = lzma2_parallel(&data, &Lzma2Params::preset(9), 300_000, 1 << 20).unwrap();
        assert!(lzma2_dict_from_prop(big.prop) <= 2 * (300_000 + (1 << 20)));
        assert_eq!(lzma2_decode(&big.data, big.prop, data.len()).unwrap(), data);
        assert_ne!(one.data, many.data);
        for o in [&one, &many, &chained] {
            assert_eq!(lzma2_decode(&o.data, o.prop, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn huge_dictionary_in_header_is_not_allocated() {
        // 4 GiB dictionaries in the properties: decoding must still work
        // (and not try to allocate 4 GiB).
        let data = b"hello hello hello hello".repeat(50);
        let e = lzma2_parallel(&data, &Lzma2Params::preset(1), 1 << 20, 0).unwrap();
        assert_eq!(lzma2_decode(&e.data, 40, data.len()).unwrap(), data);
        // .lzma ("alone") file = 5 property bytes, 8 size bytes, raw stream.
        let opts = liblzma::stream::LzmaOptions::new_preset(1).unwrap();
        let mut enc = Stream::new_lzma_encoder(&opts).unwrap();
        let mut alone = Vec::with_capacity(data.len() + 1024);
        enc.process_vec(&data, &mut alone, Action::Finish).unwrap();
        let mut props = alone[..5].to_vec();
        props[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            lzma1_decode(&alone[13..], &props, data.len()).unwrap(),
            data
        );
    }

    #[test]
    fn empty_and_incompressible() {
        let p = Lzma2Params::preset(6);
        let e = lzma2_parallel(&[], &p, 1 << 20, 0).unwrap();
        assert!(lzma2_decode(&e.data, e.prop, 0).unwrap().is_empty());
        let mut s = 1u64;
        let noise: Vec<u8> = (0..200_000)
            .map(|_| {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (s >> 56) as u8
            })
            .collect();
        let n = lzma2_parallel(&noise, &p, 70_000, 100_000).unwrap();
        assert_eq!(lzma2_decode(&n.data, n.prop, noise.len()).unwrap(), noise);
    }
}
