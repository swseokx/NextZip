//! cpio: newc (070701), crc (070702), odc (070707) and binary (0x71C7, both
//! byte orders). Sequential over any reader, so RPM payloads reuse it.

use std::io::Read;

use anyhow::{Result, bail};

use crate::{Listing, Member, Sink, limits, util};

pub fn sniff(h: &[u8]) -> bool {
    h.starts_with(b"07070") && matches!(h.get(5), Some(b'1' | b'2' | b'7'))
        || h.starts_with(&[0xC7, 0x71])
        || h.starts_with(&[0x71, 0xC7])
}

struct Head {
    name: String,
    /// Name bytes when they are not UTF-8.
    raw_name: Option<Vec<u8>>,
    mode: u32,
    size: u64,
    mtime: i64,
    /// Bytes of padding after the name and after the data.
    align: u64,
}

fn read_n(r: &mut dyn Read, n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn skip(r: &mut dyn Read, n: u64) -> Result<()> {
    let got = std::io::copy(&mut r.take(n), &mut std::io::sink())?;
    if got != n {
        bail!("truncated cpio archive");
    }
    Ok(())
}

fn pad(pos: u64, align: u64) -> u64 {
    if align <= 1 {
        0
    } else {
        (align - pos % align) % align
    }
}

/// Read one header; `pos` tracks the stream offset for alignment.
fn header(r: &mut dyn Read, pos: &mut u64) -> Result<Option<Head>> {
    let mut magic = [0u8; 6];
    let mut got = 0;
    while got < 6 {
        let n = r.read(&mut magic[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            bail!("truncated cpio header");
        }
        got += n;
    }
    let field = |b: &[u8], what: &str| -> Result<u64> {
        util::hex(b).ok_or_else(|| anyhow::anyhow!("bad cpio {what}"))
    };
    let (namesize, head) = match &magic {
        b"070701" | b"070702" => {
            let b = read_n(r, 104)?;
            *pos += 110;
            let namesize = field(&b[88..96], "name size")?;
            let h = Head {
                name: String::new(),
                raw_name: None,
                mode: field(&b[8..16], "mode")? as u32,
                size: field(&b[48..56], "size")?,
                mtime: field(&b[40..48], "mtime")? as i64,
                align: 4,
            };
            (namesize, h)
        }
        b"070707" => {
            let b = read_n(r, 70)?;
            *pos += 76;
            let oct =
                |s: &[u8], w: &str| util::octal(s).ok_or_else(|| anyhow::anyhow!("bad cpio {w}"));
            let namesize = oct(&b[53..59], "name size")?;
            let h = Head {
                name: String::new(),
                raw_name: None,
                mode: oct(&b[12..18], "mode")? as u32,
                size: oct(&b[59..70], "size")?,
                mtime: oct(&b[42..53], "mtime")? as i64,
                align: 1,
            };
            (namesize, h)
        }
        m if (m[0] == 0xC7 && m[1] == 0x71) || (m[0] == 0x71 && m[1] == 0xC7) => {
            let le = m[0] == 0xC7;
            let mut b = magic.to_vec();
            b.extend(read_n(r, 20)?);
            *pos += 26;
            let w = |o: usize| -> u64 {
                u64::from(if le {
                    util::le16(&b, o)
                } else {
                    util::be16(&b, o)
                })
            };
            let pair = |o: usize| (w(o) << 16) | w(o + 2);
            let h = Head {
                name: String::new(),
                raw_name: None,
                mode: w(6) as u32,
                size: pair(22),
                mtime: pair(16) as i64,
                align: 2,
            };
            (w(20), h)
        }
        _ => bail!("bad cpio header magic"),
    };
    if namesize == 0 || namesize > 64 << 10 {
        bail!("bad cpio name size");
    }
    let raw = read_n(r, namesize as usize)?;
    *pos += namesize;
    let p = pad(*pos, head.align);
    skip(r, p)?;
    *pos += p;
    let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
    let (name, raw_name) = crate::name_from_bytes(&raw[..end]);
    Ok(Some(Head {
        name,
        raw_name,
        ..head
    }))
}

fn member(h: &Head) -> Member {
    let kind = h.mode & 0o170000;
    let name = h.name.trim_start_matches("./").to_string();
    Member {
        name,
        is_dir: kind == 0o040000,
        size: h.size,
        mtime: Some(h.mtime),
        method: "cpio".into(),
        link: (kind == 0o120000).then(String::new),
        raw_name: h.raw_name.clone(),
        ..Default::default()
    }
}

/// Walk all entries; `each(index, member, data_reader)` must consume
/// exactly `member.size` bytes or none (the walker skips the rest).
fn walk(
    mut r: &mut dyn Read,
    each: &mut dyn FnMut(usize, &Member, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut pos = 0u64;
    let mut i = 0usize;
    while let Some(h) = header(r, &mut pos)? {
        if h.name == "TRAILER!!!" {
            break;
        }
        if i >= limits::MAX_MEMBERS {
            bail!("too many members");
        }
        let m = member(&h);
        let mut data = (&mut r).take(h.size);
        each(i, &m, &mut data)?;
        let rest = data.limit();
        skip(r, rest)?;
        pos += h.size;
        let p = pad(pos, h.align);
        skip(r, p)?;
        pos += p;
        if m.name.is_empty() || m.name == "." {
            continue;
        }
        i += 1;
    }
    Ok(())
}

pub fn list(r: &mut dyn Read) -> Result<Listing> {
    let mut members = Vec::new();
    walk(r, &mut |_, m, _| {
        if !(m.name.is_empty() || m.name == ".") {
            members.push(m.clone());
        }
        Ok(())
    })?;
    Ok(Listing {
        members,
        solid: true,
        volumes: Vec::new(),
    })
}

pub fn extract(r: &mut dyn Read, sink: &mut dyn Sink) -> Result<()> {
    walk(r, &mut |i, m, data| {
        if m.is_dir || m.link.is_some() || m.name.is_empty() || m.name == "." {
            return Ok(());
        }
        // Hard-linked newc entries carry their data on the last link only;
        // earlier links are empty files, as GNU cpio writes them.
        if sink.start(i, m)? {
            util::pump_exact(data, sink, m.size)?;
            sink.finish()?;
        }
        Ok(())
    })
}
