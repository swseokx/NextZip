//! uuencode (UUE) and xxencode (XXE) text archives. One file may hold
//! several `begin … end` blocks, possibly after mail or news text.

use std::path::Path;

use anyhow::{Result, bail};

use crate::{Format, Listing, Member, Options, Sink, util};

const XX: &[u8; 64] = b"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Largest text file decoded in memory.
const MAX_TEXT: u64 = 1 << 30;

fn begin(line: &[u8]) -> Option<(u32, String)> {
    let rest = line.strip_prefix(b"begin ")?;
    let sp = rest.iter().position(|c| *c == b' ')?;
    let mode = util::octal(&rest[..sp])? as u32;
    if !(3..=4).contains(&sp) {
        return None;
    }
    let name = String::from_utf8_lossy(&rest[sp + 1..]).trim().to_string();
    (!name.is_empty()).then_some((mode, name))
}

/// The encoding of the block whose first data line is `line`.
fn kind_of(line: &[u8]) -> Format {
    // A full UU line starts with 'M' (45 bytes); a full XX line with 'h'.
    if line.first() == Some(&b'h') && line.iter().all(|c| XX.contains(c)) {
        Format::Xxe
    } else {
        Format::Uue
    }
}

pub fn sniff(h: &[u8]) -> Option<Format> {
    let mut lines = h
        .split(|c| *c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    while let Some(l) = lines.next() {
        if begin(l).is_some() {
            return lines.next().map(kind_of);
        }
    }
    None
}

fn val(c: u8, xx: bool) -> Option<u8> {
    if xx {
        XX.iter().position(|x| *x == c).map(|p| p as u8)
    } else if (b' '..=b'`').contains(&c) {
        Some((c - b' ') & 63)
    } else {
        None
    }
}

fn decode_line(l: &[u8], xx: bool, out: &mut Vec<u8>) -> Result<bool> {
    let Some(&first) = l.first() else {
        return Ok(true);
    };
    let n = val(first, xx).ok_or_else(|| anyhow::anyhow!("bad encoded line"))? as usize;
    if n == 0 {
        return Ok(false);
    }
    let body = &l[1..];
    let mut got = 0;
    for q in body.chunks(4) {
        let mut v = [0u8; 4];
        for (i, c) in q.iter().enumerate() {
            v[i] = val(*c, xx).unwrap_or(0);
        }
        let b = [
            (v[0] << 2) | (v[1] >> 4),
            (v[1] << 4) | (v[2] >> 2),
            (v[2] << 6) | v[3],
        ];
        for x in b {
            if got < n {
                out.push(x);
                got += 1;
            }
        }
    }
    if got < n {
        bail!("short encoded line");
    }
    Ok(true)
}

struct Block {
    name: String,
    data: Vec<u8>,
}

fn blocks(path: &Path, format: Format) -> Result<Vec<Block>> {
    let text = util::read_all(path, MAX_TEXT)?;
    let mut out = Vec::new();
    let mut lines = text
        .split(|c| *c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    while let Some(l) = lines.next() {
        let Some((_, name)) = begin(l) else { continue };
        let mut data = Vec::new();
        let mut ended = false;
        for l in lines.by_ref() {
            if l == b"end" || l.starts_with(b"end ") {
                ended = true;
                break;
            }
            if l == b"`" || l.is_empty() {
                continue;
            }
            decode_line(l, format == Format::Xxe, &mut data)?;
        }
        if !ended {
            bail!("{name}: missing 'end' line");
        }
        out.push(Block { name, data });
    }
    if out.is_empty() {
        bail!("no encoded file found");
    }
    Ok(out)
}

fn member(b: &Block, format: Format) -> Member {
    Member {
        name: b.name.replace('\\', "/"),
        size: b.data.len() as u64,
        csize: 0,
        method: format.label().into(),
        ..Default::default()
    }
}

pub(crate) fn list(format: Format, path: &Path, _opt: &Options) -> Result<Listing> {
    Ok(Listing {
        members: blocks(path, format)?
            .iter()
            .map(|b| member(b, format))
            .collect(),
        solid: false,
        volumes: vec![path.to_path_buf()],
    })
}

pub(crate) fn extract(
    format: Format,
    path: &Path,
    _opt: &Options,
    sink: &mut dyn Sink,
) -> Result<()> {
    for (i, b) in blocks(path, format)?.iter().enumerate() {
        if sink.start(i, &member(b, format))? {
            sink.data(&b.data)?;
            sink.finish()?;
        }
    }
    Ok(())
}
