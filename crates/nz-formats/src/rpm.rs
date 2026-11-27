//! RPM packages: lead, signature and header sections, then a compressed
//! cpio payload (gzip, bzip2, xz, lzma or zstd), listed as its cpio members.

use std::io::Read;
use std::path::Path;

use anyhow::{Result, bail};

use crate::stream::Codec;
use crate::{Listing, Options, Sink, cpio, util};

pub fn sniff(h: &[u8]) -> bool {
    h.starts_with(&[0xED, 0xAB, 0xEE, 0xDB])
}

/// Offset of the payload (after lead, signature and header).
fn payload_offset(src: &util::Src) -> Result<u64> {
    let mut pos = 96u64;
    for pass in 0..2 {
        let h = src.bytes(pos, 16)?;
        if h[..3] != [0x8E, 0xAD, 0xE8] {
            bail!("bad RPM header");
        }
        let nindex = u64::from(util::be32(&h, 8));
        let hsize = u64::from(util::be32(&h, 12));
        if nindex > 1 << 20 || hsize > 1 << 30 {
            bail!("bad RPM header size");
        }
        pos += 16 + nindex * 16 + hsize;
        if pass == 0 {
            pos = pos.div_ceil(8) * 8; // signature is padded to 8 bytes
        }
    }
    Ok(pos)
}

fn payload(path: &Path) -> Result<Box<dyn Read>> {
    let src = util::Src::open(path)?;
    let off = payload_offset(&src)?;
    let head = src.bytes(off, 6.min(src.len.saturating_sub(off)))?;
    let codec = if head.starts_with(&[0x1F, 0x8B]) {
        Some(Codec::Gzip)
    } else if head.starts_with(b"BZh") {
        Some(Codec::Bzip2)
    } else if head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        Some(Codec::Xz)
    } else if head.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Some(Codec::Zstd)
    } else if head.starts_with(b"07070") {
        None
    } else {
        Some(Codec::Lzma)
    };
    let mut f = std::fs::File::open(path)?;
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(off))?;
    match codec {
        Some(c) => crate::stream::decoder(c, f),
        None => Ok(Box::new(f)),
    }
}

pub(crate) fn list(path: &Path, _opt: &Options) -> Result<Listing> {
    let mut l = cpio::list(&mut payload(path)?)?;
    l.volumes = vec![path.to_path_buf()];
    Ok(l)
}

pub(crate) fn extract(path: &Path, _opt: &Options, sink: &mut dyn Sink) -> Result<()> {
    cpio::extract(&mut payload(path)?, sink)
}
