//! ISO 9660 CD/DVD images with Joliet (UTF-16 names) and Rock Ridge (POSIX
//! names, symlinks) extensions, multi-extent files, and the El Torito boot
//! image. Joliet is preferred when present; Rock Ridge names otherwise;
//! plain 8.3 names (without `;1`) last. Pure UDF discs go to [`crate::udf`].

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, bail};

use crate::{Listing, Member, Options, Sink, limits, util};

const SECTOR: u64 = 2048;

/// Primary volume descriptor present at sector 16.
pub fn sniff(src: &util::Src) -> bool {
    let mut b = [0u8; 6];
    src.read_at(16 * SECTOR, &mut b).is_ok() && &b[1..6] == b"CD001"
}

struct Ent {
    m: Member,
    /// (LBA, length) of each extent.
    extents: Vec<(u64, u64)>,
}

#[derive(Clone, Copy)]
enum Names {
    Joliet,
    Plain,
}

fn iso_time(d: &[u8]) -> Option<i64> {
    // 7-byte directory record date: years since 1900, month, day, h, m, s, tz (15 min units).
    let y = 1900 + i64::from(d[0]);
    let t = crate::dos_to_unix(
        y,
        i64::from(d[1]),
        i64::from(d[2]),
        i64::from(d[3]),
        i64::from(d[4]),
        i64::from(d[5]),
    )?;
    Some(t - i64::from(d[6] as i8) * 15 * 60)
}

/// Rock Ridge NM name and SL symlink flag from a system use area.
fn rock_ridge(mut su: &[u8]) -> (Option<String>, bool) {
    let mut name: Vec<u8> = Vec::new();
    let mut have = false;
    let mut link = false;
    while su.len() >= 4 {
        let len = su[2] as usize;
        if len < 4 || len > su.len() {
            break;
        }
        let e = &su[..len];
        match &e[..2] {
            b"NM" if len >= 5 => {
                // Flags: 2 = current dir, 4 = parent.
                if e[4] & 0x06 == 0 {
                    name.extend_from_slice(&e[5..]);
                    have = true;
                }
            }
            b"SL" => link = true,
            _ => {}
        }
        su = &su[len..];
    }
    (
        have.then(|| String::from_utf8_lossy(&name).into_owned()),
        link,
    )
}

struct Walker<'a> {
    src: &'a util::Src,
    names: Names,
    /// Bytes to skip at the start of each system use area (SUSP SP).
    su_skip: usize,
    seen: HashSet<u64>,
    out: Vec<Ent>,
}

impl Walker<'_> {
    fn dir(&mut self, lba: u64, len: u64, prefix: &str, depth: usize) -> Result<()> {
        if depth > 64 || !self.seen.insert(lba) {
            return Ok(()); // loops and absurd depth are ignored
        }
        let len = len.min(64 << 20);
        let data = self.src.bytes(lba * SECTOR, len)?;
        let mut pos = 0usize;
        // Multi-extent files: records with flag 0x80 continue in the next.
        let mut pending: Option<Ent> = None;
        while pos < data.len() {
            let rl = data[pos] as usize;
            if rl == 0 {
                // Records never cross sectors: skip to the next one.
                pos = (pos / SECTOR as usize + 1) * SECTOR as usize;
                continue;
            }
            if rl < 34 || pos + rl > data.len() {
                bail!("bad ISO directory record");
            }
            let r = &data[pos..pos + rl];
            pos += rl;
            let nl = r[32] as usize;
            if 33 + nl > rl {
                bail!("bad ISO name length");
            }
            let raw = &r[33..33 + nl];
            if nl == 1 && (raw[0] == 0 || raw[0] == 1) {
                continue; // "." and ".."
            }
            let flags = r[25];
            let extent = u64::from(util::le32(r, 2));
            let size = u64::from(util::le32(r, 10));
            let su_start = 33 + nl + (1 - nl % 2) + self.su_skip;
            let (rr_name, rr_link) = if su_start < rl {
                rock_ridge(&r[su_start..])
            } else {
                (None, false)
            };
            let name = match self.names {
                Names::Joliet => {
                    let u: Vec<u16> = raw
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| util::be16(c, 0))
                        .collect();
                    let s = String::from_utf16_lossy(&u);
                    s.split(';').next().unwrap_or_default().to_string()
                }
                Names::Plain => rr_name.unwrap_or_else(|| {
                    let s = String::from_utf8_lossy(raw);
                    let s = s.split(';').next().unwrap_or_default();
                    s.strip_suffix('.').unwrap_or(s).to_string()
                }),
            };
            if name.is_empty() {
                continue;
            }
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let is_dir = flags & 0x02 != 0;
            if self.out.len() >= limits::MAX_MEMBERS {
                bail!("too many members");
            }
            if is_dir {
                self.out.push(Ent {
                    m: Member {
                        name: path.clone(),
                        is_dir: true,
                        mtime: iso_time(&r[18..25]),
                        ..Default::default()
                    },
                    extents: Vec::new(),
                });
                self.dir(extent, size, &path, depth + 1)?;
                continue;
            }
            match &mut pending {
                Some(p) if p.m.name == path => {
                    p.extents.push((extent, size));
                    p.m.size += size;
                }
                _ => {
                    if let Some(p) = pending.take() {
                        self.out.push(p);
                    }
                    pending = Some(Ent {
                        m: Member {
                            name: path,
                            size,
                            csize: size,
                            mtime: iso_time(&r[18..25]),
                            method: "Store".into(),
                            link: rr_link.then(String::new),
                            ..Default::default()
                        },
                        extents: vec![(extent, size)],
                    });
                }
            }
            if flags & 0x80 == 0
                && let Some(p) = pending.take()
            {
                self.out.push(p);
            }
        }
        if let Some(p) = pending.take() {
            self.out.push(p);
        }
        Ok(())
    }
}

fn entries(src: &util::Src) -> Result<Vec<Ent>> {
    let mut pvd = None;
    let mut joliet = None;
    for s in 16..64u64 {
        let Ok(vd) = src.bytes(s * SECTOR, SECTOR) else {
            break;
        };
        if &vd[1..6] != b"CD001" {
            break;
        }
        match vd[0] {
            1 if pvd.is_none() => pvd = Some(vd),
            2 if matches!(&vd[88..91], b"%/@" | b"%/C" | b"%/E") => joliet = Some(vd),
            255 => break,
            _ => {}
        }
    }
    let (vd, names) = match (joliet, pvd) {
        (Some(j), _) => (j, Names::Joliet),
        (None, Some(p)) => (p, Names::Plain),
        _ => bail!("no ISO 9660 volume descriptor"),
    };
    let root = &vd[156..190];
    let lba = u64::from(util::le32(root, 2));
    let len = u64::from(util::le32(root, 10));
    // SUSP "SP" entry in the root's "." record gives the skip length.
    let mut su_skip = 0;
    if let Ok(first) = src.bytes(lba * SECTOR, 256) {
        let rl = first[0] as usize;
        if rl >= 34 + 7 && first[32] == 1 && &first[34..36] == b"SP" && rl <= first.len() {
            su_skip = first[40] as usize;
        }
    }
    let mut w = Walker {
        src,
        names,
        su_skip,
        seen: HashSet::new(),
        out: Vec::new(),
    };
    w.dir(lba, len, "", 0)?;
    Ok(w.out)
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
        for &(lba, len) in &e.extents {
            let off = lba
                .checked_mul(SECTOR)
                .ok_or_else(|| anyhow::anyhow!("bad extent"))?;
            util::pump_exact(&mut src.section(off, len)?, sink, len)?;
        }
        sink.finish()?;
    }
    Ok(())
}
