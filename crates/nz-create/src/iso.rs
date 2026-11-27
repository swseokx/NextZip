//! ISO 9660 images with a Joliet hierarchy (ECMA-119 + Joliet level 3).
//!
//! The primary hierarchy uses Level 2 identifiers (`A-Z 0-9 _`, up to 30
//! characters, made unique); the Joliet one keeps the real names in UCS-2
//! (up to 103 code units, as `mkisofs -joliet-long`), which is what Windows,
//! macOS and 7-Zip show. Files of 4 GiB and more are written as multi-extent
//! files (Level 3). Both hierarchies point at the same file data.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use nz_core::walk::{self, Kind as EntryKind};

use crate::{Options, Stats};

const SECTOR: u64 = 2048;
/// Largest extent: a multiple of the sector size below 4 GiB.
const MAX_EXTENT: u64 = 0xFFFF_F800;
/// Joliet name limit used by mkisofs `-joliet-long`.
const JOLIET_MAX: usize = 103;

struct Node {
    name: String,
    dir: bool,
    path: PathBuf,
    size: u64,
    mtime: SystemTime,
    children: Vec<usize>,
    /// Identifiers in the two hierarchies.
    iso_id: Vec<u8>,
    joliet_id: Vec<u8>,
    /// Directory extents (LBA, size) per hierarchy, or file data LBA.
    iso_ext: (u64, u64),
    joliet_ext: (u64, u64),
    data_lba: u64,
    parent: usize,
}

fn both16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
    v.extend_from_slice(&x.to_be_bytes());
}
fn both32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
    v.extend_from_slice(&x.to_be_bytes());
}

fn utc(t: SystemTime) -> chrono::DateTime<chrono::Utc> {
    t.into()
}

/// 7-byte directory record date (UTC).
fn rec_date(t: SystemTime) -> [u8; 7] {
    use chrono::{Datelike, Timelike};
    let d = utc(t);
    let y = (d.year() - 1900).clamp(0, 255) as u8;
    [
        y,
        d.month() as u8,
        d.day() as u8,
        d.hour() as u8,
        d.minute() as u8,
        d.second() as u8,
        0,
    ]
}

/// 17-byte volume descriptor date (UTC).
fn vd_date(t: SystemTime) -> [u8; 17] {
    let s = utc(t).format("%Y%m%d%H%M%S00").to_string();
    let mut out = [0u8; 17];
    out[..16].copy_from_slice(&s.as_bytes()[..16]);
    out
}

fn record(lba: u64, size: u64, flags: u8, id: &[u8], t: SystemTime) -> Vec<u8> {
    let pad = usize::from(id.len().is_multiple_of(2));
    let len = 33 + id.len() + pad;
    let mut r = Vec::with_capacity(len);
    r.push(len as u8);
    r.push(0);
    both32(&mut r, lba as u32);
    both32(&mut r, size as u32);
    r.extend_from_slice(&rec_date(t));
    r.push(flags);
    r.push(0);
    r.push(0);
    both16(&mut r, 1);
    r.push(id.len() as u8);
    r.extend_from_slice(id);
    r.resize(len, 0);
    r
}

/// Records of one file: one per extent (multi-extent for 4 GiB and up).
fn file_records(n: &Node, id: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut left = n.size;
    let mut lba = n.data_lba;
    loop {
        let len = left.min(MAX_EXTENT);
        left -= len;
        let flags = if left > 0 { 0x80 } else { 0 };
        out.push(record(lba, len, flags, id, n.mtime));
        lba += len / SECTOR;
        if left == 0 {
            break;
        }
    }
    out
}

/// Primary-hierarchy identifier for `name` (Level 2, d-characters).
fn iso_name(name: &str, dir: bool) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| {
                let c = c.to_ascii_uppercase();
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    if dir {
        return clean(name).chars().take(31).collect();
    }
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (clean(b), clean(e)),
        _ => (clean(name), String::new()),
    };
    let ext: String = ext.chars().take(8).collect();
    let base: String = base.chars().take(30 - 1 - ext.len()).collect();
    format!("{base}.{ext}")
}

/// Make `ids` (already per-hierarchy names) unique within one directory by
/// replacing a tail with `~N`; `limit` is the identifier length cap.
fn uniquify(ids: &mut [String], limit: usize, units: fn(&str) -> usize) {
    let mut seen = std::collections::HashSet::new();
    for id in ids.iter_mut() {
        if seen.insert(id.to_uppercase()) {
            continue;
        }
        let (base, ext) = match id.rsplit_once('.') {
            Some((b, e)) => (b.to_string(), format!(".{e}")),
            None => (id.clone(), String::new()),
        };
        for n in 1.. {
            let suffix = format!("~{n}");
            let mut b = base.clone();
            while units(&b) + units(&suffix) + units(&ext) > limit && !b.is_empty() {
                b.pop();
            }
            let cand = format!("{b}{suffix}{ext}");
            if seen.insert(cand.to_uppercase()) {
                *id = cand;
                break;
            }
        }
    }
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Joliet name, shortened to the limit with its extension kept.
fn joliet_name(name: &str) -> String {
    if utf16_len(name) <= JOLIET_MAX {
        return name.to_string();
    }
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) if utf16_len(e) < 16 => (b, format!(".{e}")),
        _ => (name, String::new()),
    };
    let mut b: String = base.to_string();
    while utf16_len(&b) + utf16_len(&ext) > JOLIET_MAX {
        b.pop();
    }
    format!("{b}{ext}")
}

fn ucs2(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// Lay out a directory's records into sectors; returns the extent bytes.
fn dir_bytes(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        let used = out.len() as u64 % SECTOR;
        if used + r.len() as u64 > SECTOR {
            out.resize(out.len().div_ceil(SECTOR as usize) * SECTOR as usize, 0);
        }
        out.extend_from_slice(r);
    }
    out.resize(
        out.len().div_ceil(SECTOR as usize).max(1) * SECTOR as usize,
        0,
    );
    out
}

/// Size of a directory extent from record lengths alone.
fn dir_size(lens: impl Iterator<Item = usize>) -> u64 {
    let mut pos = 0u64;
    for l in lens {
        let l = l as u64;
        if pos % SECTOR + l > SECTOR {
            pos = pos.div_ceil(SECTOR) * SECTOR;
        }
        pos += l;
    }
    pos.div_ceil(SECTOR).max(1) * SECTOR
}

fn rec_len(id_len: usize) -> usize {
    33 + id_len + usize::from(id_len.is_multiple_of(2))
}

fn extents(size: u64) -> usize {
    size.div_ceil(MAX_EXTENT).max(1) as usize
}

/// Directories in path-table order (breadth first, children sorted).
fn bfs(nodes: &[Node]) -> Vec<usize> {
    let mut order = vec![0usize];
    let mut i = 0;
    while i < order.len() {
        let d = order[i];
        order.extend(nodes[d].children.iter().copied().filter(|c| nodes[*c].dir));
        i += 1;
    }
    order
}

fn path_table(nodes: &[Node], order: &[usize], joliet: bool, big: bool) -> Vec<u8> {
    let mut num = vec![0u16; nodes.len()];
    for (k, d) in order.iter().enumerate() {
        num[*d] = (k + 1) as u16;
    }
    let mut out = Vec::new();
    for &d in order {
        let n = &nodes[d];
        let id: &[u8] = if d == 0 {
            &[0]
        } else if joliet {
            &n.joliet_id
        } else {
            &n.iso_id
        };
        let lba = if joliet { n.joliet_ext.0 } else { n.iso_ext.0 } as u32;
        let parent = if d == 0 { 1 } else { num[n.parent] };
        out.push(id.len() as u8);
        out.push(0);
        if big {
            out.extend_from_slice(&lba.to_be_bytes());
            out.extend_from_slice(&parent.to_be_bytes());
        } else {
            out.extend_from_slice(&lba.to_le_bytes());
            out.extend_from_slice(&parent.to_le_bytes());
        }
        out.extend_from_slice(id);
        if id.len() % 2 == 1 {
            out.push(0);
        }
    }
    out
}

fn text_field(v: &mut [u8], s: &str, joliet: bool) {
    if joliet {
        v.fill(0);
        for c in v.as_chunks_mut::<2>().0 {
            c.copy_from_slice(&[0, b' ']);
        }
        let b = ucs2(s);
        let n = b.len().min(v.len()) & !1;
        v[..n].copy_from_slice(&b[..n]);
    } else {
        v.fill(b' ');
        let n = s.len().min(v.len());
        v[..n].copy_from_slice(&s.as_bytes()[..n]);
    }
}

#[allow(clippy::too_many_arguments)]
fn volume_descriptor(
    joliet: bool,
    label: &str,
    space: u64,
    pt_len: usize,
    pt_l: u64,
    pt_m: u64,
    root: &[u8],
    now: SystemTime,
) -> Vec<u8> {
    let mut v = vec![0u8; SECTOR as usize];
    v[0] = if joliet { 2 } else { 1 };
    v[1..6].copy_from_slice(b"CD001");
    v[6] = 1;
    text_field(&mut v[8..40], "", joliet);
    let vol = if joliet {
        label.to_string()
    } else {
        iso_name(label, true)
    };
    text_field(&mut v[40..72], &vol, joliet);
    let mut b = Vec::new();
    both32(&mut b, space as u32);
    v[80..88].copy_from_slice(&b);
    if joliet {
        v[88..91].copy_from_slice(b"%/E");
    }
    let mut b = Vec::new();
    both16(&mut b, 1);
    both16(&mut b, 1);
    both16(&mut b, SECTOR as u16);
    both32(&mut b, pt_len as u32);
    v[120..140].copy_from_slice(&b);
    v[140..144].copy_from_slice(&(pt_l as u32).to_le_bytes());
    v[148..152].copy_from_slice(&(pt_m as u32).to_be_bytes());
    v[156..156 + root.len()].copy_from_slice(root);
    for r in [190..318, 318..446, 446..574, 702..739, 739..776, 776..813] {
        text_field(&mut v[r], "", joliet);
    }
    text_field(&mut v[574..702], "NEXTZIP", joliet);
    let d = vd_date(now);
    v[813..830].copy_from_slice(&d);
    v[830..847].copy_from_slice(&d);
    v[847..863].fill(b'0');
    v[864..880].fill(b'0');
    v[881] = 1;
    v
}

pub(crate) fn create(sources: &[PathBuf], out: &Path, opt: &Options) -> Result<Stats> {
    let entries = walk::collect(sources)?;
    let now = SystemTime::now();
    let mut nodes = vec![Node {
        name: String::new(),
        dir: true,
        path: PathBuf::new(),
        size: 0,
        mtime: now,
        children: Vec::new(),
        iso_id: Vec::new(),
        joliet_id: Vec::new(),
        iso_ext: (0, 0),
        joliet_ext: (0, 0),
        data_lba: 0,
        parent: 0,
    }];
    // Build the tree; `walk` lists parents before children.
    let mut by_path = std::collections::HashMap::new();
    by_path.insert(String::new(), 0usize);
    for e in &entries {
        let (parent, leaf) = match e.name.rsplit_once('/') {
            Some((p, l)) => (p.to_string(), l.to_string()),
            None => (String::new(), e.name.clone()),
        };
        let Some(&p) = by_path.get(&parent) else {
            bail!("{}: parent folder missing from the input list", e.name);
        };
        let dir = e.kind == EntryKind::Dir;
        let i = nodes.len();
        nodes.push(Node {
            name: leaf,
            dir,
            path: e.path.clone(),
            size: if dir { 0 } else { e.size },
            mtime: e.mtime,
            children: Vec::new(),
            iso_id: Vec::new(),
            joliet_id: Vec::new(),
            iso_ext: (0, 0),
            joliet_ext: (0, 0),
            data_lba: 0,
            parent: p,
        });
        nodes[p].children.push(i);
        if dir {
            by_path.insert(e.name.clone(), i);
        }
    }
    // Identifiers, unique per directory, children sorted per hierarchy.
    for d in 0..nodes.len() {
        if !nodes[d].dir {
            continue;
        }
        let kids = nodes[d].children.clone();
        let mut iso: Vec<String> = kids
            .iter()
            .map(|&c| iso_name(&nodes[c].name, nodes[c].dir))
            .collect();
        uniquify(&mut iso, 30, str::len);
        let mut jol: Vec<String> = kids.iter().map(|&c| joliet_name(&nodes[c].name)).collect();
        uniquify(&mut jol, JOLIET_MAX, utf16_len);
        for (k, &c) in kids.iter().enumerate() {
            let suffix = if nodes[c].dir { "" } else { ";1" };
            nodes[c].iso_id = format!("{}{suffix}", iso[k]).into_bytes();
            nodes[c].joliet_id = ucs2(&format!("{}{suffix}", jol[k]));
        }
    }
    // Layout: system area, PVD, SVD, terminator, four path tables.
    let order = bfs(&nodes);
    let pt_len = |joliet: bool| -> usize {
        order
            .iter()
            .map(|&d| {
                let l = if d == 0 {
                    1
                } else if joliet {
                    nodes[d].joliet_id.len()
                } else {
                    nodes[d].iso_id.len()
                };
                8 + l + l % 2
            })
            .sum()
    };
    let (pt_iso, pt_jol) = (pt_len(false), pt_len(true));
    let pt_sectors = |n: usize| (n as u64).div_ceil(SECTOR);
    let mut lba = 19u64;
    let pt = [
        lba,
        lba + pt_sectors(pt_iso),
        lba + 2 * pt_sectors(pt_iso),
        lba + 2 * pt_sectors(pt_iso) + pt_sectors(pt_jol),
    ];
    lba += 2 * pt_sectors(pt_iso) + 2 * pt_sectors(pt_jol);
    for joliet in [false, true] {
        for &d in &order {
            let lens =
                [rec_len(1), rec_len(1)]
                    .into_iter()
                    .chain(nodes[d].children.iter().flat_map(|&c| {
                        let n = &nodes[c];
                        let id = if joliet {
                            n.joliet_id.len()
                        } else {
                            n.iso_id.len()
                        };
                        let k = if n.dir { 1 } else { extents(n.size) };
                        std::iter::repeat_n(rec_len(id), k)
                    }));
            let size = dir_size(lens);
            if joliet {
                nodes[d].joliet_ext = (lba, size);
            } else {
                nodes[d].iso_ext = (lba, size);
            }
            lba += size / SECTOR;
        }
    }
    // File data in directory order.
    let mut files = Vec::new();
    for &d in &order {
        for &c in &nodes[d].children {
            if !nodes[c].dir {
                files.push(c);
            }
        }
    }
    let mut stats = Stats::default();
    for &f in &files {
        nodes[f].data_lba = if nodes[f].size == 0 { 0 } else { lba };
        lba += nodes[f].size.div_ceil(SECTOR);
        stats.files += 1;
        stats.bytes_in += nodes[f].size;
    }
    stats.dirs = order.len() - 1;
    let space = lba;
    if space > u64::from(u32::MAX) {
        bail!(nz_front::tr("ISO 9660에 담기에는 이미지가 너무 큽니다"));
    }
    // Sort children for the directory records (by identifier bytes).
    let sorted = |d: usize, joliet: bool| -> Vec<usize> {
        let mut k = nodes[d].children.clone();
        k.sort_by(|a, b| {
            if joliet {
                nodes[*a].joliet_id.cmp(&nodes[*b].joliet_id)
            } else {
                nodes[*a].iso_id.cmp(&nodes[*b].iso_id)
            }
        });
        k
    };
    let ext = |n: &Node, joliet: bool| if joliet { n.joliet_ext } else { n.iso_ext };
    let label = opt.volume.clone().unwrap_or_else(|| {
        out.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "NEXTZIP".into())
    });
    let jlabel: String = label.chars().take(16).collect();
    let f = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, f);
    w.write_all(&vec![0u8; 16 * SECTOR as usize])?;
    for joliet in [false, true] {
        let (l, s) = ext(&nodes[0], joliet);
        let root = record(l, s, 2, &[0], now);
        let (pl, pm) = if joliet {
            (pt[2], pt[3])
        } else {
            (pt[0], pt[1])
        };
        w.write_all(&volume_descriptor(
            joliet,
            if joliet { &jlabel } else { &label },
            space,
            if joliet { pt_jol } else { pt_iso },
            pl,
            pm,
            &root,
            now,
        ))?;
    }
    let mut term = vec![0u8; SECTOR as usize];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    w.write_all(&term)?;
    for (joliet, big) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut t = path_table(&nodes, &order, joliet, big);
        t.resize(
            (t.len() as u64).div_ceil(SECTOR) as usize * SECTOR as usize,
            0,
        );
        w.write_all(&t)?;
    }
    for joliet in [false, true] {
        for &d in &order {
            let me = ext(&nodes[d], joliet);
            let parent = ext(&nodes[nodes[d].parent], joliet);
            let mut recs = vec![
                record(me.0, me.1, 2, &[0], nodes[d].mtime),
                record(parent.0, parent.1, 2, &[1], nodes[d].mtime),
            ];
            for c in sorted(d, joliet) {
                let n = &nodes[c];
                let id = if joliet { &n.joliet_id } else { &n.iso_id };
                if n.dir {
                    let e = ext(n, joliet);
                    recs.push(record(e.0, e.1, 2, id, n.mtime));
                } else {
                    recs.extend(file_records(n, id));
                }
            }
            let b = dir_bytes(&recs);
            debug_assert_eq!(b.len() as u64, me.1);
            w.write_all(&b)?;
        }
    }
    let mut buf = vec![0u8; 1 << 20];
    for &f in &files {
        let n = &nodes[f];
        let mut r = File::open(&n.path)
            .with_context(|| format!("cannot open {}", n.path.display()))?
            .take(n.size);
        let mut left = n.size;
        while left > 0 {
            let k = r.read(&mut buf)?;
            if k == 0 {
                bail!(nz_front::trf(
                    "{}의 크기가 추가하는 도중 줄었습니다",
                    &[&n.path.display()]
                ));
            }
            w.write_all(&buf[..k])?;
            left -= k as u64;
        }
        let pad = (SECTOR - n.size % SECTOR) % SECTOR;
        w.write_all(&vec![0u8; pad as usize])?;
    }
    w.flush()?;
    stats.bytes_out = space * SECTOR;
    Ok(stats)
}
