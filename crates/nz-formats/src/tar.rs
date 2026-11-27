//! tar inside a stream (tar.lz, tar.lzma, tar.Z, tar.br, RPM-less cases):
//! the `tar` crate over a decoding reader. Sequential: list and extract
//! both decode the whole stream.

use std::io::Read;

use anyhow::Result;

use crate::{Listing, Member, Sink, limits, util};

/// A tar header block: "ustar" magic or a valid checksum.
pub fn is_header(h: &[u8]) -> bool {
    if h.len() < 512 || h[0] == 0 {
        return false;
    }
    if &h[257..262] == b"ustar" {
        return true;
    }
    let Some(want) = util::octal(&h[148..156]) else {
        return false;
    };
    let sum: u64 = h[..512]
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(*b)
            }
        })
        .sum();
    sum == want
}

fn member(e: &tar::Entry<'_, impl Read>) -> Result<Member> {
    let h = e.header();
    let t = h.entry_type();
    let (name, raw_name) = crate::name_from_bytes(&e.path_bytes());
    Ok(Member {
        name: name.replace('\\', "/"),
        raw_name,
        is_dir: t.is_dir(),
        size: h.size().unwrap_or(0),
        csize: 0,
        mtime: h.mtime().ok().map(|t| t as i64),
        method: "tar".into(),
        crc: None,
        encrypted: false,
        link: if t.is_symlink() || t.is_hard_link() {
            Some(
                e.link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default(),
            )
        } else {
            None
        },
    })
}

fn wanted(t: tar::EntryType) -> bool {
    t.is_file()
        || t.is_dir()
        || t.is_symlink()
        || t.is_hard_link()
        || t == tar::EntryType::Continuous
}

pub fn list(r: impl Read) -> Result<Listing> {
    let mut a = tar::Archive::new(r);
    let mut members = Vec::new();
    for e in a.entries()? {
        let e = e?;
        if !wanted(e.header().entry_type()) {
            continue;
        }
        if members.len() >= limits::MAX_MEMBERS {
            anyhow::bail!("too many members");
        }
        members.push(member(&e)?);
    }
    Ok(Listing {
        members,
        solid: true,
        volumes: Vec::new(),
    })
}

pub fn extract(r: impl Read, sink: &mut dyn Sink) -> Result<()> {
    let mut a = tar::Archive::new(r);
    let mut i = 0usize;
    for e in a.entries()? {
        let mut e = e?;
        if !wanted(e.header().entry_type()) {
            continue;
        }
        let m = member(&e)?;
        let index = i;
        i += 1;
        if m.is_dir || m.link.is_some() {
            continue;
        }
        if sink.start(index, &m)? {
            util::pump_exact(&mut e, sink, m.size)?;
            sink.finish()?;
        }
    }
    Ok(())
}
