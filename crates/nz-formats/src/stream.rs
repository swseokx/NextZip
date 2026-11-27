//! Single-stream compressors (spec 3.2 "단일 스트림"): GZ, BZ2, XZ, LZMA,
//! LZ (lzip), ZST, LZ4, BR (Brotli), Z (Unix compress). A stream that
//! decodes to a tar archive is listed as that tar archive (tar.lz,
//! tar.lzma, tar.Z, tar.br and friends); anything else is one member named
//! after the archive without its extension.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{Format, Listing, Member, Options, Sink, limits, util};

/// Codec of a stream format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Gzip,
    Zlib,
    Bzip2,
    Xz,
    Lzma,
    Lzip,
    Zstd,
    Lz4,
    Brotli,
    Compress,
}

pub fn codec(f: Format) -> Option<Codec> {
    Some(match f {
        Format::Gz => Codec::Gzip,
        Format::Bz2 => Codec::Bzip2,
        Format::Xz => Codec::Xz,
        Format::Lzma => Codec::Lzma,
        Format::Lzip => Codec::Lzip,
        Format::Zst => Codec::Zstd,
        Format::Lz4 => Codec::Lz4,
        Format::Br => Codec::Brotli,
        Format::Z => Codec::Compress,
        _ => return None,
    })
}

/// Recognise a stream by its magic bytes (Brotli has none: by extension).
pub fn sniff(path: &Path, h: &[u8]) -> Option<Format> {
    Some(if h.starts_with(&[0x1F, 0x8B]) {
        Format::Gz
    } else if h.starts_with(b"BZh") && h.len() > 3 && (b'1'..=b'9').contains(&h[3]) {
        Format::Bz2
    } else if h.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        Format::Xz
    } else if h.starts_with(b"LZIP") {
        Format::Lzip
    } else if h.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Format::Zst
    } else if h.starts_with(&[0x04, 0x22, 0x4D, 0x18]) || h.starts_with(&[0x02, 0x21, 0x4C, 0x18]) {
        Format::Lz4
    } else if h.starts_with(&[0x1F, 0x9D]) {
        Format::Z
    } else if is_lzma_alone(h) {
        Format::Lzma
    } else {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "br" | "tbr" => Format::Br,
            _ => return None,
        }
    })
}

/// `.lzma` (LZMA_Alone): properties byte < 225, a power-of-two-ish
/// dictionary, and a plausible size field.
fn is_lzma_alone(h: &[u8]) -> bool {
    if h.len() < 13 || h[0] >= 225 {
        return false;
    }
    let dict = util::le32(h, 1);
    let size = util::le64(h, 5);
    let dict_ok = dict >= 1 << 12 && (dict.is_power_of_two() || (dict / 3).is_power_of_two());
    let size_ok = size == u64::MAX || size < 1 << 48;
    // The first byte of the range-coded data is always 0.
    dict_ok && size_ok && h[13..].first() == Some(&0)
}

/// Decoding reader for `codec` over `r`.
pub fn decoder<'a>(c: Codec, r: impl Read + 'a) -> Result<Box<dyn Read + 'a>> {
    Ok(match c {
        Codec::Gzip => Box::new(flate2::read::MultiGzDecoder::new(BufReader::new(r))),
        Codec::Zlib => Box::new(flate2::read::ZlibDecoder::new(BufReader::new(r))),
        Codec::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(BufReader::new(r))),
        Codec::Xz => Box::new(liblzma::read::XzDecoder::new_multi_decoder(BufReader::new(
            r,
        ))),
        Codec::Lzma => Box::new(liblzma::read::XzDecoder::new_stream(
            BufReader::new(r),
            liblzma::stream::Stream::new_lzma_decoder(limits::DICT_MEMORY)?,
        )),
        Codec::Lzip => Box::new(liblzma::read::XzDecoder::new_stream(
            BufReader::new(r),
            // LZMA_CONCATENATED: multi-member files.
            liblzma::stream::Stream::new_lzip_decoder(limits::DICT_MEMORY, 0x08)?,
        )),
        Codec::Zstd => {
            let mut d = zstd::stream::read::Decoder::new(r)?;
            d.window_log_max(31)?;
            Box::new(d)
        }
        Codec::Lz4 => Box::new(Lz4Reader::new(BufReader::new(r))),
        Codec::Brotli => Box::new(brotli_decompressor::Decompressor::new(r, 1 << 16)),
        Codec::Compress => Box::new(crate::lzw::Decoder::new(BufReader::new(r))?),
    })
}

/// LZ4 frame (and legacy) streams, concatenated frames allowed.
struct Lz4Reader<R: Read> {
    inner: Option<lz4::Decoder<R>>,
}

impl<R: Read> Lz4Reader<R> {
    fn new(r: R) -> Self {
        Lz4Reader {
            inner: lz4::Decoder::new(r).ok(),
        }
    }
}

impl<R: Read> Read for Lz4Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            Some(d) => d.read(buf),
            None => Err(std::io::Error::other("bad LZ4 frame")),
        }
    }
}

fn open(format: Format, path: &Path) -> Result<Box<dyn Read>> {
    let c = codec(format).context("not a stream format")?;
    decoder(c, File::open(path)?)
}

/// Whether the decoded stream starts with a tar header.
pub fn inner_is_tar(format: Format, path: &Path) -> bool {
    let Ok(mut r) = open(format, path) else {
        return false;
    };
    let mut head = [0u8; 512];
    let mut got = 0;
    while got < 512 {
        match r.read(&mut head[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    got == 512 && crate::tar::is_header(&head)
}

/// Member name for a single-file stream: the archive name minus its
/// compression extension (`x.txt.gz` → `x.txt`, `x.tgz` → `x.tar`).
pub fn single_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    for (ext, repl) in [
        (".tgz", ".tar"),
        (".tbz2", ".tar"),
        (".tbz", ".tar"),
        (".txz", ".tar"),
        (".tlz", ".tar"),
        (".tzst", ".tar"),
        (".taz", ".tar"),
    ] {
        if lower.ends_with(ext) {
            return format!("{}{repl}", &name[..name.len() - ext.len()]);
        }
    }
    for ext in [
        ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".lzma", ".lz", ".zst", ".zstd", ".lz4", ".br",
        ".z",
    ] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    format!("{name}.out")
}

pub(crate) fn list(format: Format, path: &Path, _opt: &Options) -> Result<Listing> {
    if inner_is_tar(format, path) {
        let mut l = crate::tar::list(open(format, path)?)?;
        l.solid = true;
        return Ok(l);
    }
    let meta = std::fs::metadata(path)?;
    // The size is unknown without decoding; gzip stores it modulo 2^32.
    let size = if format == Format::Gz && meta.len() >= 18 {
        let mut f = File::open(path)?;
        use std::io::{Seek, SeekFrom};
        f.seek(SeekFrom::End(-4))?;
        let mut b = [0u8; 4];
        f.read_exact(&mut b)?;
        u64::from(u32::from_le_bytes(b))
    } else {
        0
    };
    Ok(Listing {
        members: vec![Member {
            name: single_name(path),
            size,
            csize: meta.len(),
            mtime: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            method: format.label().to_string(),
            ..Default::default()
        }],
        solid: false,
        volumes: vec![path.to_path_buf()],
    })
}

pub(crate) fn extract(
    format: Format,
    path: &Path,
    opt: &Options,
    sink: &mut dyn Sink,
) -> Result<()> {
    if inner_is_tar(format, path) {
        return crate::tar::extract(open(format, path)?, sink);
    }
    let l = list(format, path, opt)?;
    if !sink.start(0, &l.members[0])? {
        return Ok(());
    }
    let mut r = open(format, path)?;
    let n = util::pump(&mut r, sink, limits::MAX_STREAM).context("decoding failed")?;
    if format == Format::Gz && l.members[0].size != n & 0xFFFF_FFFF {
        bail!("gzip size check failed");
    }
    sink.finish()
}
