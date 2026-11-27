//! Electron ASAR archives: a Chromium pickle holding a JSON directory tree,
//! followed by the file data.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{Listing, Member, Options, Sink, limits, util};

/// Largest JSON header accepted.
const MAX_HEADER: u64 = 256 << 20;

pub fn sniff(h: &[u8]) -> bool {
    // u32 4, u32 pickle size, u32 payload size, u32 json length, '{'.
    h.len() >= 17
        && util::le32(h, 0) == 4
        && util::le32(h, 8) == util::le32(h, 4).wrapping_sub(4)
        && h[16] == b'{'
}

struct Ent {
    m: Member,
    off: u64,
    unpacked: bool,
}

fn walk(
    node: &serde_json::Value,
    prefix: &str,
    base: u64,
    depth: usize,
    out: &mut Vec<Ent>,
) -> Result<()> {
    if depth > 256 {
        bail!("ASAR tree too deep");
    }
    let Some(files) = node.get("files").and_then(|f| f.as_object()) else {
        return Ok(());
    };
    for (name, v) in files {
        if out.len() >= limits::MAX_MEMBERS {
            bail!("too many members");
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if v.get("files").is_some() {
            out.push(Ent {
                m: Member {
                    name: path.clone(),
                    is_dir: true,
                    ..Default::default()
                },
                off: 0,
                unpacked: false,
            });
            walk(v, &path, base, depth + 1, out)?;
            continue;
        }
        let size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
        let off = v
            .get("offset")
            .and_then(|o| {
                o.as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or(o.as_u64())
            })
            .unwrap_or(0);
        let link = v.get("link").and_then(|l| l.as_str()).map(str::to_owned);
        let unpacked = v.get("unpacked").and_then(|u| u.as_bool()).unwrap_or(false);
        out.push(Ent {
            m: Member {
                name: path,
                size,
                csize: size,
                method: if unpacked {
                    "unpacked".into()
                } else {
                    "Store".into()
                },
                link,
                ..Default::default()
            },
            off: base.saturating_add(off),
            unpacked,
        });
    }
    Ok(())
}

fn entries(src: &util::Src) -> Result<Vec<Ent>> {
    let h = src.bytes(0, 16)?;
    let pickle = u64::from(util::le32(&h, 4));
    let json_len = u64::from(util::le32(&h, 12));
    if json_len > MAX_HEADER || json_len + 8 > pickle {
        bail!("bad ASAR header");
    }
    let json = src.bytes(16, json_len)?;
    let v: serde_json::Value = serde_json::from_slice(&json).context("bad ASAR JSON header")?;
    let mut out = Vec::new();
    walk(&v, "", 8 + pickle, 0, &mut out)?;
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
        // Unpacked files live beside the archive (app.asar.unpacked) and
        // are not part of it.
        if e.m.is_dir || e.m.link.is_some() || e.unpacked || !sink.start(i, &e.m)? {
            continue;
        }
        util::pump_exact(&mut src.section(e.off, e.m.size)?, sink, e.m.size)?;
        sink.finish()?;
    }
    Ok(())
}
