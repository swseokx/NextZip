//! Recovery record: per-sector hashes (two copies) and Reed-Solomon parity
//! sectors (Leopard-RS, GF(2^16), high rate) per group of data sectors.
//!
//! Guarantee: a group is restored byte-exact when the number of damaged
//! sectors in it (its data sectors plus its parity sectors) is at most its
//! parity count `P_g = max(1, ceil(D_g * basis_points / 10000))`.

use anyhow::{Result, anyhow, ensure};
use rayon::prelude::*;
use reed_solomon_simd::engine::DefaultEngine;
use reed_solomon_simd::rate::{HighRateDecoder, HighRateEncoder, RateDecoder, RateEncoder};

use crate::fmt::{RR_HEADER_LEN, RrHeader, h8};
use crate::source::{Source, View};

/// Most data sectors in one group.
pub const MAX_GROUP_SECTORS: u32 = 32768;
pub const MIN_SECTOR: u32 = 64;
pub const MAX_SECTOR: u32 = 1 << 20;

/// Geometry of a recovery record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub covered_len: u64,
    pub sector_size: u32,
    pub group_sectors: u32,
    pub basis_points: u16,
    /// Data sectors.
    pub n: u64,
    pub groups: u64,
    /// Parity sectors in total.
    pub p: u64,
    pub rr_len: u64,
}

pub fn parity_for(d: u64, bp: u16) -> u64 {
    (d * u64::from(bp)).div_ceil(10000).max(1)
}

impl Layout {
    pub fn new(covered_len: u64, sector_size: u32, group_sectors: u32, bp: u16) -> Result<Self> {
        ensure!(
            sector_size.is_power_of_two() && (MIN_SECTOR..=MAX_SECTOR).contains(&sector_size),
            "bad recovery sector size {sector_size}"
        );
        ensure!(
            (1..=MAX_GROUP_SECTORS).contains(&group_sectors),
            "bad recovery group size {group_sectors}"
        );
        ensure!((1..=10000).contains(&bp), "bad recovery ratio {bp}");
        ensure!(covered_len > 0, "empty recovery coverage");
        let ss = u64::from(sector_size);
        let d = u64::from(group_sectors);
        let n = covered_len.div_ceil(ss);
        let groups = n.div_ceil(d);
        let last = n - (groups - 1) * d;
        let p = (groups - 1) * parity_for(d, bp) + parity_for(last, bp);
        let tables = (n + p)
            .checked_mul(16)
            .ok_or_else(|| anyhow!("recovery record too large"))?;
        let rr_len = p
            .checked_mul(ss)
            .and_then(|x| x.checked_add(tables))
            .and_then(|x| x.checked_add(2 * RR_HEADER_LEN as u64))
            .ok_or_else(|| anyhow!("recovery record too large"))?;
        ensure!(p <= u64::from(u32::MAX), "too many parity sectors");
        ensure!(groups <= u64::from(u32::MAX), "too many recovery groups");
        Ok(Self {
            covered_len,
            sector_size,
            group_sectors,
            basis_points: bp,
            n,
            groups,
            p,
            rr_len,
        })
    }

    /// Writer policy: sector size grows from 1 KiB to 4 KiB with the
    /// archive so that small archives get fine-grained protection.
    pub fn for_writer(covered_len: u64, bp: u16) -> Result<Self> {
        let want = covered_len.div_ceil(u64::from(MAX_GROUP_SECTORS));
        let ss = want.next_power_of_two().clamp(1024, 4096) as u32;
        Self::new(covered_len, ss, MAX_GROUP_SECTORS, bp)
    }

    pub fn header(&self) -> RrHeader {
        RrHeader {
            basis_points: self.basis_points,
            sector_size: self.sector_size,
            group_sectors: self.group_sectors,
            covered_len: self.covered_len,
            group_count: self.groups as u32,
            parity_sectors: self.p as u32,
            rr_len: self.rr_len,
        }
    }

    /// (first data sector, data sectors, first parity sector, parity sectors) of group `g`.
    pub fn group(&self, g: u64) -> (u64, u64, u64, u64) {
        let d = u64::from(self.group_sectors);
        let first = g * d;
        let dg = d.min(self.n - first);
        let pfull = parity_for(d, self.basis_points);
        (first, dg, g * pfull, parity_for(dg, self.basis_points))
    }

    pub fn table_a(&self) -> u64 {
        RR_HEADER_LEN as u64
    }
    pub fn parity_start(&self) -> u64 {
        self.table_a() + 8 * (self.n + self.p)
    }
    pub fn table_b(&self) -> u64 {
        self.parity_start() + self.p * u64::from(self.sector_size)
    }
}

/// Read the data sectors of a group into one zero-padded buffer; returns
/// the buffer and how many sectors were read completely.
fn read_group(src: &dyn Source, l: &Layout, first: u64, dg: u64) -> (Vec<u8>, u64) {
    let ss = u64::from(l.sector_size);
    let off = first * ss;
    let want = (dg * ss).min(l.covered_len - off) as usize;
    let mut buf = vec![0u8; (dg * ss) as usize];
    let got = src.read_at(off, &mut buf[..want]).unwrap_or(0);
    let complete = if got == want { dg } else { got as u64 / ss };
    (buf, complete)
}

/// Column stripes `(offset, width)` of a sector. Reed-Solomon works on each
/// 64-byte column independently, so stripes are coded in parallel and the
/// result is identical to coding whole sectors.
fn stripes(ss: usize) -> Vec<(usize, usize)> {
    let cols = ss / 64;
    let n = cols.min(rayon::current_num_threads().max(1));
    let per = cols.div_ceil(n) * 64;
    (0..ss).step_by(per).map(|o| (o, per.min(ss - o))).collect()
}

/// Parity sectors of one group.
fn encode_group(sectors: &[&[u8]], pg: usize, ss: usize) -> Result<Vec<Vec<u8>>> {
    let parts: Vec<Result<Vec<Vec<u8>>>> = stripes(ss)
        .into_par_iter()
        .map(|(o, w)| {
            let mut enc = HighRateEncoder::new(sectors.len(), pg, w, DefaultEngine::new(), None)
                .map_err(|e| anyhow!("recovery encoder: {e}"))?;
            for s in sectors {
                enc.add_original_shard(&s[o..o + w])
                    .map_err(|e| anyhow!("recovery encoder: {e}"))?;
            }
            let res = enc.encode().map_err(|e| anyhow!("recovery encoder: {e}"))?;
            Ok(res.recovery_iter().map(<[u8]>::to_vec).collect())
        })
        .collect();
    let mut out = vec![Vec::with_capacity(ss); pg];
    for part in parts {
        for (o, p) in out.iter_mut().zip(part?) {
            o.extend_from_slice(&p);
        }
    }
    Ok(out)
}

/// Rebuild the data sectors `bad` of one group from the intact ones.
fn decode_group(
    data: &[Option<&[u8]>],
    parity: &[Option<Vec<u8>>],
    bad: &[u64],
    ss: usize,
) -> Result<Vec<Vec<u8>>> {
    let parts: Vec<Result<Vec<Vec<u8>>>> = stripes(ss)
        .into_par_iter()
        .map(|(o, w)| {
            let mut dec =
                HighRateDecoder::new(data.len(), parity.len(), w, DefaultEngine::new(), None)
                    .map_err(|e| anyhow!("recovery decoder: {e}"))?;
            for (k, s) in data.iter().enumerate() {
                if let Some(s) = s {
                    dec.add_original_shard(k, &s[o..o + w])
                        .map_err(|e| anyhow!("recovery decoder: {e}"))?;
                }
            }
            for (j, p) in parity.iter().enumerate() {
                if let Some(p) = p {
                    dec.add_recovery_shard(j, &p[o..o + w])
                        .map_err(|e| anyhow!("recovery decoder: {e}"))?;
                }
            }
            let res = dec.decode().map_err(|e| anyhow!("recovery decoder: {e}"))?;
            bad.iter()
                .map(|&k| {
                    res.restored_original(k as usize)
                        .map(<[u8]>::to_vec)
                        .ok_or_else(|| anyhow!("recovery decoder did not restore sector {k}"))
                })
                .collect()
        })
        .collect();
    let mut out = vec![Vec::with_capacity(ss); bad.len()];
    for part in parts {
        for (o, p) in out.iter_mut().zip(part?) {
            o.extend_from_slice(&p);
        }
    }
    Ok(out)
}

/// Build the recovery record for `src[0..covered_len)`. Groups are encoded
/// one after another (each holds at most 32768 sectors in memory); sector
/// hashing and the encoder's work inside a group use the Rayon pool.
pub fn build(src: &dyn Source, l: &Layout) -> Result<Vec<u8>> {
    let ss = l.sector_size as usize;
    let mut table = Vec::with_capacity(((l.n + l.p) * 8) as usize);
    let mut parity = Vec::with_capacity(l.p as usize * ss);
    let mut parity_hashes = Vec::with_capacity(l.p as usize * 8);
    for g in 0..l.groups {
        let (first, dg, _, pg) = l.group(g);
        let (buf, complete) = read_group(src, l, first, dg);
        ensure!(complete == dg, "short read in recovery group {g}");
        let sectors: Vec<&[u8]> = buf.chunks(ss).collect();
        let hashes: Vec<[u8; 8]> = sectors.par_iter().map(|s| h8(s)).collect();
        for h in &hashes {
            table.extend_from_slice(h);
        }
        for r in encode_group(&sectors, pg as usize, ss)? {
            parity_hashes.extend_from_slice(&h8(&r));
            parity.extend_from_slice(&r);
        }
    }
    table.extend_from_slice(&parity_hashes);
    let hdr = l.header().encode();
    let mut out = Vec::with_capacity(l.rr_len as usize);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&table);
    out.extend_from_slice(&parity);
    out.extend_from_slice(&table);
    out.extend_from_slice(&hdr);
    debug_assert_eq!(out.len() as u64, l.rr_len);
    Ok(out)
}

/// Where the record lives and its geometry.
#[derive(Debug, Clone, Copy)]
pub struct Located {
    pub offset: u64,
    pub layout: Layout,
}

/// Result of checking (and possibly repairing) the covered bytes.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RepairReport {
    pub sector_size: u32,
    pub data_sectors: u64,
    pub parity_sectors: u64,
    pub groups: u64,
    /// Damaged data sectors found.
    pub damaged_sectors: u64,
    /// Damaged parity sectors found.
    pub damaged_parity: u64,
    /// Data sectors rebuilt.
    pub repaired_sectors: u64,
    /// Byte ranges of the covered area that could not be rebuilt.
    pub unrecoverable: Vec<(u64, u64)>,
    /// Groups whose damage exceeded the parity budget: (group, damaged, parity).
    pub failed_groups: Vec<(u64, u64, u64)>,
}

impl RepairReport {
    pub fn ok(&self) -> bool {
        self.unrecoverable.is_empty()
    }
}

/// Read one hash-table entry from both copies.
struct Tables {
    a: Vec<u8>,
    a_ok: Vec<bool>,
    b: Vec<u8>,
    b_ok: Vec<bool>,
}

impl Tables {
    fn load(src: &dyn Source, loc: &Located) -> Result<Self> {
        let l = &loc.layout;
        // The record follows the covered area, so a usable record implies a
        // source longer than the covered area; this also bounds the work.
        ensure!(
            loc.offset == l.covered_len && l.covered_len < src.len(),
            "recovery record outside the archive"
        );
        let entries = (l.n + l.p) as usize;
        // Bound allocation by what the file can hold.
        ensure!(
            (entries as u64) * 8 <= src.len().saturating_add(1 << 20),
            "recovery tables larger than the archive"
        );
        let load = |at: u64| -> (Vec<u8>, Vec<bool>) {
            let mut b = vec![0u8; entries * 8];
            let got = src.read_at(loc.offset + at, &mut b).unwrap_or(0);
            let ok = (0..entries).map(|i| (i + 1) * 8 <= got).collect();
            (b, ok)
        };
        let (a, a_ok) = load(l.table_a());
        let (b, b_ok) = load(l.table_b());
        Ok(Self { a, a_ok, b, b_ok })
    }
    fn matches(&self, i: usize, h: &[u8; 8]) -> bool {
        (self.a_ok[i] && self.a[i * 8..i * 8 + 8] == h[..])
            || (self.b_ok[i] && self.b[i * 8..i * 8 + 8] == h[..])
    }
}

/// Verify every covered sector and rebuild damaged ones into `view`.
pub fn repair(view: &mut View<'_>, loc: &Located) -> Result<RepairReport> {
    let l = loc.layout;
    let src = view.src;
    let ss = l.sector_size as usize;
    let tables = Tables::load(src, loc)?;
    let mut rep = RepairReport {
        sector_size: l.sector_size,
        data_sectors: l.n,
        parity_sectors: l.p,
        groups: l.groups,
        ..Default::default()
    };
    for g in 0..l.groups {
        let (first, dg, pfirst, pg) = l.group(g);
        // Data sectors: hash in parallel, keep them for decoding.
        let (buf, complete) = read_group(src, &l, first, dg);
        let data: Vec<Option<&[u8]>> = buf
            .par_chunks(ss)
            .enumerate()
            .map(|(k, s)| {
                let i = first + k as u64;
                ((k as u64) < complete && tables.matches(i as usize, &h8(s))).then_some(s)
            })
            .collect();
        let bad: Vec<u64> = (0..dg).filter(|&k| data[k as usize].is_none()).collect();
        if bad.is_empty() {
            continue;
        }
        rep.damaged_sectors += bad.len() as u64;
        let parity: Vec<Option<Vec<u8>>> = (pfirst..pfirst + pg)
            .into_par_iter()
            .map(|j| {
                let mut b = vec![0u8; ss];
                let off = loc.offset + l.parity_start() + j * ss as u64;
                match src.read_at(off, &mut b) {
                    Ok(n) if n == ss => {}
                    _ => return None,
                }
                tables.matches((l.n + j) as usize, &h8(&b)).then_some(b)
            })
            .collect();
        let good_parity = parity.iter().filter(|p| p.is_some()).count() as u64;
        rep.damaged_parity += pg - good_parity;
        if (bad.len() as u64) > good_parity {
            rep.failed_groups
                .push((g, bad.len() as u64 + pg - good_parity, pg));
            for &k in &bad {
                let s = (first + k) * ss as u64;
                let e = (s + ss as u64).min(l.covered_len);
                match rep.unrecoverable.last_mut() {
                    Some(last) if last.1 == s => last.1 = e,
                    _ => rep.unrecoverable.push((s, e)),
                }
            }
            continue;
        }
        let restored = decode_group(&data, &parity, &bad, ss)?;
        for (&k, r) in bad.iter().zip(restored) {
            let off = (first + k) * ss as u64;
            let len = (ss as u64).min(l.covered_len - off) as usize;
            view.patch(off, r[..len].to_vec());
            rep.repaired_sectors += 1;
        }
    }
    view.set_min_len(l.covered_len);
    Ok(rep)
}

/// Read and validate a recovery header at `off`.
pub fn header_at(src: &dyn Source, off: u64) -> Option<RrHeader> {
    let mut b = [0u8; RR_HEADER_LEN];
    match src.read_at(off, &mut b) {
        Ok(n) if n == RR_HEADER_LEN => RrHeader::decode(&b).ok(),
        _ => None,
    }
}

/// Find the record by scanning backwards for a valid header (used when the
/// main header and the trailer are both unusable).
pub fn scan(src: &dyn Source) -> Option<Located> {
    const WIN: u64 = 1 << 20;
    let len = src.len();
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(WIN);
        let n = (end - start + RR_HEADER_LEN as u64).min(len - start) as usize;
        let mut b = vec![0u8; n];
        let got = src.read_at(start, &mut b).ok()?;
        b.truncate(got);
        let mut i = b.len().saturating_sub(4);
        loop {
            if b[i..].starts_with(&crate::fmt::RR_MAGIC)
                && let Some(h) = header_at(src, start + i as u64)
            {
                let at = start + i as u64;
                // Either the leading header (record starts here) or the
                // trailing copy (record ends here).
                let offset = if at == h.covered_len {
                    at
                } else {
                    (at + RR_HEADER_LEN as u64).saturating_sub(h.rr_len)
                };
                if offset == h.covered_len {
                    let layout = Layout::new(
                        h.covered_len,
                        h.sector_size,
                        h.group_sectors,
                        h.basis_points,
                    )
                    .ok()?;
                    return Some(Located { offset, layout });
                }
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        end = start;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize) -> Vec<u8> {
        let mut x = 0x1234_5678_u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn striped_equals_whole() {
        let d = data(300 * 1024);
        let sectors: Vec<Vec<u8>> = d.chunks(1024).map(<[u8]>::to_vec).collect();
        let refs: Vec<&[u8]> = sectors.iter().map(Vec::as_slice).collect();
        let striped = nz_core::cpu::pool(8)
            .unwrap()
            .install(|| encode_group(&refs, 9, 1024).unwrap());
        let mut enc =
            HighRateEncoder::new(sectors.len(), 9, 1024, DefaultEngine::new(), None).unwrap();
        for s in &sectors {
            enc.add_original_shard(s).unwrap();
        }
        let whole: Vec<Vec<u8>> = enc
            .encode()
            .unwrap()
            .recovery_iter()
            .map(<[u8]>::to_vec)
            .collect();
        assert_eq!(striped, whole);
    }

    /// Several groups (small group size): damage up to P sectors in every
    /// group is repaired; P + 1 in one group is reported for that group only.
    #[test]
    fn multi_group_repair() {
        let len = 64 * 1024 * 5 + 777;
        let orig = data(len);
        let l = Layout::new(len as u64, 1024, 60, 1000).unwrap();
        assert!(l.groups >= 5);
        let rec = build(&orig.as_slice(), &l).unwrap();
        assert_eq!(rec.len() as u64, l.rr_len);
        let mut file = orig.clone();
        file.extend_from_slice(&rec);
        let pfull = parity_for(60, 1000);
        let mut bad = file.clone();
        for g in 0..l.groups {
            let (first, dg, _, pg) = l.group(g);
            for k in 0..pg.min(dg) {
                let s = first + (k * 7) % dg;
                bad[(s * 1024 + 5) as usize] ^= 0x80;
            }
        }
        let src = bad.as_slice();
        let loc = Located {
            offset: len as u64,
            layout: l,
        };
        let mut v = View::new(&src);
        let r = repair(&mut v, &loc).unwrap();
        assert!(r.ok(), "{r:?}");
        assert!(r.repaired_sectors >= pfull * (l.groups - 1));
        assert_eq!(v.read(0, len).unwrap(), orig);
        // One group over budget.
        let mut worse = file.clone();
        for k in 0..=pfull {
            worse[((60 + k) * 1024) as usize] ^= 1;
        }
        let src = worse.as_slice();
        let mut v = View::new(&src);
        let r = repair(&mut v, &loc).unwrap();
        assert_eq!(r.failed_groups.len(), 1);
        assert_eq!(r.failed_groups[0].0, 1);
        assert_eq!(r.unrecoverable.len(), 1);
        // Scanning finds the record from its headers.
        let found = scan(&file.as_slice()).unwrap();
        assert_eq!(found.offset, len as u64);
        assert_eq!(found.layout, l);
    }
}
