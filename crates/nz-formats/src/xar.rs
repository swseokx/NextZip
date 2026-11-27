//! XAR archives (macOS .pkg, .xip, Safari extensions): a zlib-compressed XML
//! table of contents followed by a heap of member data.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::stream::Codec;
use crate::xml::Node;
use crate::{Listing, Member, Options, Sink, limits, util};

pub fn sniff(h: &[u8]) -> bool {
    h.starts_with(b"xar!")
}

struct Ent {
    m: Member,
    off: u64,
    len: u64,
    codec: Option<Codec>,
}

fn walk(n: &Node, prefix: &str, heap: u64, depth: usize, out: &mut Vec<Ent>) -> Result<()> {
    if depth > 256 {
        bail!("XAR tree too deep");
    }
    for f in n.children("file") {
        let name = f.child_text("name").unwrap_or("").replace('/', "_");
        if name.is_empty() {
            continue;
        }
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = f.child_text("type").unwrap_or("file");
        if out.len() >= limits::MAX_MEMBERS {
            bail!("too many members");
        }
        match kind {
            "directory" => {
                out.push(Ent {
                    m: Member {
                        name: path.clone(),
                        is_dir: true,
                        ..Default::default()
                    },
                    off: 0,
                    len: 0,
                    codec: None,
                });
                walk(f, &path, heap, depth + 1, out)?;
            }
            "file" | "hardlink" => {
                let d = f.child("data");
                let num = |k: &str| {
                    d.and_then(|d| d.child_text(k))
                        .and_then(|t| t.parse::<u64>().ok())
                        .unwrap_or(0)
                };
                let style = d
                    .and_then(|d| d.child("encoding"))
                    .and_then(|e| e.attr("style"))
                    .unwrap_or("application/octet-stream");
                let codec = match style {
                    "application/x-gzip" => Some(Codec::Zlib),
                    "application/x-bzip2" => Some(Codec::Bzip2),
                    "application/x-lzma" => Some(Codec::Lzma),
                    "application/x-xz" => Some(Codec::Xz),
                    _ => None,
                };
                let supported = codec.is_some() || style == "application/octet-stream";
                out.push(Ent {
                    m: Member {
                        name: path,
                        size: if d.is_some() { num("size") } else { 0 },
                        csize: num("length"),
                        method: style.trim_start_matches("application/").into(),
                        // Unknown encodings are listed but not extracted.
                        link: (!supported).then(String::new),
                        ..Default::default()
                    },
                    off: heap.saturating_add(num("offset")),
                    len: num("length"),
                    codec,
                });
            }
            _ => out.push(Ent {
                m: Member {
                    name: path,
                    link: Some(String::new()),
                    ..Default::default()
                },
                off: 0,
                len: 0,
                codec: None,
            }),
        }
    }
    Ok(())
}

fn entries(src: &util::Src) -> Result<Vec<Ent>> {
    let h = src.bytes(0, 28)?;
    let hsize = u64::from(util::be16(&h, 4));
    let toc_c = util::be64(&h, 8);
    let toc_u = util::be64(&h, 16);
    if toc_c > 256 << 20 || toc_u > 256 << 20 || hsize < 28 {
        bail!("bad XAR header");
    }
    let comp = src.bytes(hsize, toc_c)?;
    let mut xml = Vec::with_capacity(toc_u as usize);
    flate2::read::ZlibDecoder::new(&comp[..])
        .take(toc_u + 1)
        .read_to_end(&mut xml)
        .context("bad XAR table of contents")?;
    let doc = crate::xml::parse(&String::from_utf8_lossy(&xml))?;
    let toc = doc.child("toc").context("XAR TOC without <toc>")?;
    let mut out = Vec::new();
    walk(toc, "", hsize + toc_c, 0, &mut out)?;
    Ok(out)
}

pub(crate) fn list(path: &Path, _opt: &Options) -> Result<Listing> {
    let src = util::Src::open(path)?;
    Ok(Listing {
        members: entries(&src)?.into_iter().map(|e| e.m).collect(),
        solid: false,
        volumes: vec![path.to_path_buf()],
    })
}

pub(crate) fn extract(path: &Path, _opt: &Options, sink: &mut dyn Sink) -> Result<()> {
    let src = util::Src::open(path)?;
    for (i, e) in entries(&src)?.iter().enumerate() {
        if e.m.is_dir || e.m.link.is_some() || !sink.start(i, &e.m)? {
            continue;
        }
        let sec = src.section(e.off, e.len)?;
        match e.codec {
            None => util::pump_exact(&mut src.section(e.off, e.len)?, sink, e.len)?,
            Some(c) => {
                let mut d = crate::stream::decoder(c, sec)?;
                util::pump_exact(&mut d, sink, e.m.size)?;
            }
        }
        sink.finish()?;
    }
    Ok(())
}
