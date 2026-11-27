//! Raw LZMA2 encoding with a *preset dictionary* via liblzma.
//!
//! The safe `liblzma` crate does not expose `lzma_options_lzma::preset_dict`.
//! NextZip needs it to encode one LZMA2 stream in parallel without losing
//! the dictionary: segment *k* is encoded with the bytes before it as preset
//! dictionary. liblzma's LZMA2 encoder then omits the dictionary reset in the
//! first chunk (`lzma2_encoder.c`: `need_dictionary_reset = preset_dict ==
//! NULL`), so the decoder, which already holds the preceding output in its
//! dictionary, decodes the concatenated segments as one stream.
//!
//! This is the only crate of the workspace that contains `unsafe` code.

use std::ptr;

use liblzma_sys as sys;

/// Encoder parameters (a liblzma preset plus overrides).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// xz preset 0..=9.
    pub preset: u32,
    pub dict_size: u32,
    /// Match finder override (None = preset default).
    pub mf: Option<MatchFinder>,
    /// Some(true) = fast mode, Some(false) = normal (optimal parsing) mode.
    pub fast: Option<bool>,
    pub nice_len: Option<u32>,
    pub depth: Option<u32>,
    /// Literal context / literal position / position bits overrides.
    pub lc: Option<u32>,
    pub lp: Option<u32>,
    pub pb: Option<u32>,
}

/// liblzma match finders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFinder {
    Hc3,
    Hc4,
    Bt2,
    Bt3,
    Bt4,
}

impl MatchFinder {
    fn raw(self) -> sys::lzma_match_finder {
        match self {
            Self::Hc3 => sys::LZMA_MF_HC3,
            Self::Hc4 => sys::LZMA_MF_HC4,
            Self::Bt2 => sys::LZMA_MF_BT2,
            Self::Bt3 => sys::LZMA_MF_BT3,
            Self::Bt4 => sys::LZMA_MF_BT4,
        }
    }
}

/// liblzma error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub u32);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "liblzma error {}", self.0)
    }
}

impl std::error::Error for Error {}

struct StreamGuard(sys::lzma_stream);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        // SAFETY: the stream was zero-initialised (LZMA_STREAM_INIT) and
        // lzma_end accepts both initialised and never-initialised streams.
        unsafe { sys::lzma_end(&mut self.0) };
    }
}

/// liblzma LZMA options for `p`.
fn options(p: &Params) -> Result<sys::lzma_options_lzma, Error> {
    // SAFETY: an all-zero lzma_options_lzma is valid input for
    // lzma_lzma_preset, which fills every field.
    let mut opt: sys::lzma_options_lzma = unsafe { std::mem::zeroed() };
    // SAFETY: `opt` is a valid, exclusively borrowed options struct.
    if unsafe { sys::lzma_lzma_preset(&mut opt, p.preset.min(9)) } != 0 {
        return Err(Error(u32::MAX));
    }
    opt.dict_size = p.dict_size.max(4096);
    if let Some(mf) = p.mf {
        opt.mf = mf.raw();
    }
    match p.fast {
        Some(true) => opt.mode = sys::LZMA_MODE_FAST,
        Some(false) => opt.mode = sys::LZMA_MODE_NORMAL,
        None => {}
    }
    if let Some(n) = p.nice_len {
        opt.nice_len = n.clamp(2, 273);
    }
    if let Some(d) = p.depth {
        opt.depth = d;
    }
    if let Some(v) = p.lc {
        opt.lc = v.min(4);
    }
    if let Some(v) = p.lp {
        opt.lp = v.min(4);
    }
    if let Some(v) = p.pb {
        opt.pb = v.min(4);
    }
    if opt.lc + opt.lp > 4 {
        return Err(Error(u32::MAX - 1));
    }
    Ok(opt)
}

/// Memory in bytes an LZMA2 encoder with `p` needs (liblzma's own estimate,
/// `lzma_raw_encoder_memusage`), excluding the input and output buffers.
pub fn encoder_memusage(p: &Params) -> Result<u64, Error> {
    let mut opt = options(p)?;
    let filters = [
        sys::lzma_filter {
            id: sys::LZMA_FILTER_LZMA2,
            options: (&mut opt as *mut sys::lzma_options_lzma).cast(),
        },
        sys::lzma_filter {
            id: sys::LZMA_VLI_UNKNOWN,
            options: ptr::null_mut(),
        },
    ];
    // SAFETY: `filters` is terminated by LZMA_VLI_UNKNOWN and `opt` lives
    // until the call returns.
    let n = unsafe { sys::lzma_raw_encoder_memusage(filters.as_ptr()) };
    if n == u64::MAX {
        Err(Error(u32::MAX - 2))
    } else {
        Ok(n)
    }
}

/// Encode `data` as one raw LZMA2 stream (with end marker). When `dict` is
/// non-empty, its last `dict_size` bytes act as already-seen history and the
/// stream starts *without* a dictionary reset.
pub fn lzma2_encode(data: &[u8], dict: &[u8], p: &Params) -> Result<Vec<u8>, Error> {
    let mut opt = options(p)?;
    let dict = &dict[dict.len().saturating_sub(opt.dict_size as usize)..];
    if !dict.is_empty() {
        opt.preset_dict = dict.as_ptr();
        opt.preset_dict_size = dict.len() as u32;
    }
    let filters = [
        sys::lzma_filter {
            id: sys::LZMA_FILTER_LZMA2,
            options: (&mut opt as *mut sys::lzma_options_lzma).cast(),
        },
        sys::lzma_filter {
            id: sys::LZMA_VLI_UNKNOWN,
            options: ptr::null_mut(),
        },
    ];
    // SAFETY: LZMA_STREAM_INIT is the all-zero value.
    let mut s = StreamGuard(unsafe { std::mem::zeroed() });
    // SAFETY: `filters` is terminated by LZMA_VLI_UNKNOWN and `opt` and
    // `dict` outlive the encoder (liblzma copies the preset dictionary into
    // its window during initialisation; `opt` is read during init only).
    let ret = unsafe { sys::lzma_raw_encoder(&mut s.0, filters.as_ptr()) };
    if ret != sys::LZMA_OK {
        return Err(Error(ret as u32));
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() + data.len() / 32 + 1024);
    s.0.next_in = data.as_ptr();
    s.0.avail_in = data.len();
    loop {
        let spare = out.capacity() - out.len();
        // SAFETY: next_out points to `spare` writable bytes inside `out`.
        s.0.next_out = unsafe { out.as_mut_ptr().add(out.len()) };
        s.0.avail_out = spare;
        // SAFETY: the stream was initialised by lzma_raw_encoder and its
        // input/output pointers are valid for the given lengths.
        let ret = unsafe { sys::lzma_code(&mut s.0, sys::LZMA_FINISH) };
        let written = spare - s.0.avail_out;
        // SAFETY: liblzma initialised `written` bytes after out.len().
        unsafe { out.set_len(out.len() + written) };
        if ret == sys::LZMA_STREAM_END {
            // The capacity was sized for incompressible input; give the
            // unused part back (many segment outputs are held at once).
            out.shrink_to_fit();
            return Ok(out);
        }
        if ret != sys::LZMA_OK {
            return Err(Error(ret as u32));
        }
        if out.len() == out.capacity() {
            out.reserve(out.capacity() / 2 + 4096);
        }
    }
}
