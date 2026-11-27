//! Compound File Binary (OLE2) containers: MSI/MSP/MST installers and other
//! structured storage files. Streams are listed as members, with MSI's
//! compressed stream names decoded (as 7-Zip does), so embedded cabinets
//! (`*.cab` streams) can be extracted and opened in turn.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{Listing, Member, Options, Sink, limits, util};

pub fn sniff(h: &[u8]) -> bool {
    h.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

fn mime(x: u32) -> char {
    match x {
        0..=9 => char::from(b'0' + x as u8),
        10..=35 => char::from(b'A' + (x - 10) as u8),
        36..=61 => char::from(b'a' + (x - 36) as u8),
        62 => '.',
        _ => '_',
    }
}

/// Decode an MSI stream name (two characters packed per code unit in
/// U+3800..U+47FF, one in U+4800..U+483F, U+4840 marks database tables).
pub fn decode_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        let u = c as u32;
        match u {
            0x3800..=0x47FF => {
                let v = u - 0x3800;
                out.push(mime(v & 0x3F));
                out.push(mime((v >> 6) & 0x3F));
            }
            0x4800..=0x483F => out.push(mime(u - 0x4800)),
            0x4840 => out.push('!'),
            c if c < 0x20 => out.push_str(&format!("[{c}]")),
            _ => out.push(c),
        }
    }
    out
}

struct Ent {
    m: Member,
    path: std::path::PathBuf,
}

fn entries(path: &Path) -> Result<(cfb::CompoundFile<std::fs::File>, Vec<Ent>)> {
    let cf = cfb::open(path).context("bad compound file")?;
    let mut out = Vec::new();
    for e in cf.walk() {
        if e.is_root() {
            continue;
        }
        if out.len() >= limits::MAX_MEMBERS {
            bail!("too many members");
        }
        let name = e
            .path()
            .iter()
            .skip(1)
            .map(|p| decode_name(&p.to_string_lossy()))
            .collect::<Vec<_>>()
            .join("/");
        out.push(Ent {
            m: Member {
                name,
                is_dir: e.is_storage(),
                size: e.len(),
                csize: e.len(),
                mtime: e
                    .modified()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs() as i64),
                method: "Store".into(),
                ..Default::default()
            },
            path: e.path().to_path_buf(),
        });
    }
    Ok((cf, out))
}

pub(crate) fn list(path: &Path, _opt: &Options) -> Result<Listing> {
    Ok(Listing {
        members: entries(path)?.1.into_iter().map(|e| e.m).collect(),
        solid: false,
        volumes: vec![path.to_path_buf()],
    })
}

pub(crate) fn extract(path: &Path, _opt: &Options, sink: &mut dyn Sink) -> Result<()> {
    let (mut cf, ents) = entries(path)?;
    for (i, e) in ents.iter().enumerate() {
        if e.m.is_dir || !sink.start(i, &e.m)? {
            continue;
        }
        let mut s = cf.open_stream(&e.path)?;
        let n = util::pump(&mut (&mut s).take(e.m.size), sink, e.m.size)?;
        if n != e.m.size {
            bail!("truncated stream {}", e.m.name);
        }
        sink.finish()?;
    }
    Ok(())
}
