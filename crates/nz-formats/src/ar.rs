//! Unix ar (`!<arch>`): Debian packages, static libraries. GNU (`//` name
//! table, `/n` references) and BSD (`#1/len`) long names.

use std::path::Path;

use anyhow::{Result, bail};

use crate::{Listing, Member, Options, Sink, limits, util};

pub fn sniff(h: &[u8]) -> bool {
    h.starts_with(b"!<arch>\n")
}

struct Ent {
    m: Member,
    /// Data offset and length in the file.
    off: u64,
    len: u64,
}

fn entries(src: &util::Src) -> Result<Vec<Ent>> {
    let mut pos = 8u64;
    let mut names: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    while pos + 60 <= src.len {
        let h = src.bytes(pos, 60)?;
        if &h[58..60] != b"`\n" {
            bail!("bad ar member header at {pos}");
        }
        let size = util::decimal(&h[48..58]).ok_or_else(|| anyhow::anyhow!("bad ar size"))?;
        let mtime = util::decimal(&h[16..28]).unwrap_or(0);
        let mode = util::octal(&h[40..48]).unwrap_or(0o100644);
        let raw = &h[..16];
        let mut data_off = pos + 60;
        let mut data_len = size;
        let name: String;
        if raw.starts_with(b"// ") || raw == b"//              " {
            names = src.bytes(data_off, size.min(16 << 20))?;
            pos = data_off + size + (size & 1);
            continue;
        } else if raw.starts_with(b"/ ")
            || raw.starts_with(b"/SYM64/")
            || raw.starts_with(b"__.SYMDEF")
        {
            pos = data_off + size + (size & 1);
            continue;
        } else if raw[0] == b'/' && raw[1].is_ascii_digit() {
            let o = util::decimal(&raw[1..]).unwrap_or(u64::MAX) as usize;
            let rest = names.get(o..).unwrap_or_default();
            let end = rest
                .iter()
                .position(|c| *c == b'\n' || *c == 0)
                .unwrap_or(rest.len());
            name = String::from_utf8_lossy(&rest[..end])
                .trim_end_matches('/')
                .to_string();
        } else if raw.starts_with(b"#1/") {
            let n = util::decimal(&raw[3..]).unwrap_or(0);
            if n > size || n > 4096 {
                bail!("bad BSD ar name length");
            }
            name = util::cstr(&src.bytes(data_off, n)?);
            data_off += n;
            data_len -= n;
        } else {
            let s = String::from_utf8_lossy(raw).trim_end().to_string();
            name = s.strip_suffix('/').unwrap_or(&s).to_string();
        }
        if data_off + data_len > src.len {
            bail!("truncated ar member {name}");
        }
        if out.len() >= limits::MAX_MEMBERS {
            bail!("too many members");
        }
        out.push(Ent {
            m: Member {
                name,
                is_dir: false,
                size: data_len,
                csize: data_len,
                mtime: Some(mtime as i64),
                method: "Store".into(),
                link: (mode & 0o170000 == 0o120000).then(String::new),
                ..Default::default()
            },
            off: data_off,
            len: data_len,
        });
        pos = pos + 60 + size + (size & 1);
    }
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
        if e.m.link.is_some() || !sink.start(i, &e.m)? {
            continue;
        }
        util::pump_exact(&mut src.section(e.off, e.len)?, sink, e.len)?;
        sink.finish()?;
    }
    Ok(())
}
