//! Single-file compressed streams: `file.txt` -> `file.txt.gz` etc. These
//! formats hold exactly one file without a directory, so the source must
//! be one regular file.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::{Options, Stats};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Gzip,
    Xz,
    Bzip2,
    Zstd,
    Lz4,
}

impl Codec {
    pub fn parse(name: &str) -> Option<Codec> {
        Some(match name {
            "gz" | "gzip" => Codec::Gzip,
            "xz" => Codec::Xz,
            "bz2" | "bzip2" => Codec::Bzip2,
            "zst" | "zstd" => Codec::Zstd,
            "lz4" => Codec::Lz4,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Codec::Gzip => "GZ",
            Codec::Xz => "XZ",
            Codec::Bzip2 => "BZ2",
            Codec::Zstd => "ZST",
            Codec::Lz4 => "LZ4",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Codec::Gzip => "gz",
            Codec::Xz => "xz",
            Codec::Bzip2 => "bz2",
            Codec::Zstd => "zst",
            Codec::Lz4 => "lz4",
        }
    }
}

/// Whether `sources` can go into a single-file stream.
pub fn fits(sources: &[PathBuf]) -> bool {
    sources.len() == 1 && sources[0].is_file()
}

/// Compress everything `r` yields into `w` with `codec`; returns bytes read.
pub fn compress(
    codec: Codec,
    r: &mut dyn std::io::Read,
    w: &mut dyn Write,
    name: Option<&str>,
    mtime: u32,
    opt: &Options,
) -> Result<u64> {
    let level = opt.level.min(9);
    let threads = crate::threads(opt);
    let n = match codec {
        Codec::Gzip => {
            let mut b = flate2::GzBuilder::new().mtime(mtime);
            if let Some(n) = name {
                // RFC 1952 names are ISO 8859-1; keep ASCII-only ones.
                if n.is_ascii() && !n.contains('\0') {
                    b = b.filename(n.as_bytes());
                }
            }
            let mut e = b.write(w, flate2::Compression::new(level));
            let n = std::io::copy(r, &mut e)?;
            e.finish()?;
            n
        }
        Codec::Xz => {
            let stream = liblzma::stream::MtStreamBuilder::new()
                .preset(level)
                .threads(threads.clamp(1, 64) as u32)
                .check(liblzma::stream::Check::Crc64)
                .encoder()?;
            let mut e = liblzma::write::XzEncoder::new_stream(w, stream);
            let n = std::io::copy(r, &mut e)?;
            e.finish()?;
            n
        }
        Codec::Bzip2 => {
            let mut e = bzip2::write::BzEncoder::new(w, bzip2::Compression::new(level.max(1)));
            let n = std::io::copy(r, &mut e)?;
            e.finish()?;
            n
        }
        Codec::Zstd => {
            // 0..9 onto zstd 1..19.
            let zl = [1, 2, 3, 4, 6, 9, 12, 15, 17, 19][level as usize];
            let mut e = zstd::stream::write::Encoder::new(w, zl)?;
            e.include_checksum(true)?;
            if threads > 1 {
                e.multithread(threads as u32)?;
            }
            let n = std::io::copy(r, &mut e)?;
            e.finish()?;
            n
        }
        Codec::Lz4 => {
            let mut e = lz4::EncoderBuilder::new()
                .level(level)
                .checksum(lz4::ContentChecksum::ChecksumEnabled)
                .build(w)?;
            let n = std::io::copy(r, &mut e)?;
            let (_, res) = e.finish();
            res?;
            n
        }
    };
    Ok(n)
}

pub(crate) fn create(
    codec: Codec,
    sources: &[PathBuf],
    out: &Path,
    opt: &Options,
) -> Result<Stats> {
    if !fits(sources) {
        bail!(nz_front::trf(
            "{}에는 파일 하나만 담을 수 있습니다. 파일 하나를 고르거나, 폴더나 여러 파일은 tar.{}를 쓰세요",
            &[&codec.label(), &codec.extension()],
        ));
    }
    let src = &sources[0];
    let mut input = File::open(src).with_context(|| format!("cannot open {}", src.display()))?;
    let meta = input.metadata()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs().min(u64::from(u32::MAX)) as u32);
    let name = src.file_name().map(|n| n.to_string_lossy().into_owned());
    let f = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, f);
    let n = compress(codec, &mut input, &mut w, name.as_deref(), mtime, opt)?;
    w.flush()?;
    let bytes_out = w.get_ref().metadata()?.len();
    Ok(Stats {
        files: 1,
        dirs: 0,
        bytes_in: n,
        bytes_out,
    })
}
