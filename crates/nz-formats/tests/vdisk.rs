//! Virtual disk readers against images built here from the published
//! layouts (VHD spec 1.0, MS-VHDX 1.0, VMware VMDK 5.0 sparse extents,
//! QEMU qcow2.txt). No real-world sample was at hand for these formats, so
//! these generators are the reference; each covers allocated, unallocated
//! and (where the format has them) compressed blocks.

use std::io::Write;
use std::path::Path;

use nz_formats::{Format, Options, VecSink};

const MIB: usize = 1 << 20;

/// A 3 MiB + 4 KiB disk: block 0 patterned, block 1 zero, block 2 patterned,
/// a short patterned tail.
fn disk() -> Vec<u8> {
    let mut d = vec![0u8; 3 * MIB + 4096];
    for (i, b) in d.iter_mut().enumerate() {
        let blk = i / MIB;
        if blk != 1 {
            *b = (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1] | 1;
        }
    }
    d
}

fn extract(p: &Path, want: Format) -> Vec<u8> {
    assert_eq!(nz_formats::detect(p), Some(want), "{}", p.display());
    let l = nz_formats::list(want, p, &Options::default()).unwrap();
    assert_eq!(l.members.len(), 1);
    assert!(l.members[0].name.ends_with(".img"));
    let mut s = VecSink::default();
    nz_formats::extract(want, p, &Options::default(), &mut s).unwrap();
    assert_eq!(s.files.len(), 1);
    assert_eq!(l.members[0].size, s.files[0].1.len() as u64);
    s.files.remove(0).1
}

fn vhd_footer(size: u64, kind: u32, data_off: u64) -> Vec<u8> {
    let mut f = vec![0u8; 512];
    f[..8].copy_from_slice(b"conectix");
    f[0x10..0x18].copy_from_slice(&data_off.to_be_bytes());
    f[0x28..0x30].copy_from_slice(&size.to_be_bytes());
    f[0x30..0x38].copy_from_slice(&size.to_be_bytes());
    f[0x3C..0x40].copy_from_slice(&kind.to_be_bytes());
    f
}

#[test]
fn vhd_fixed() {
    let mut d = disk();
    d.resize(d.len().div_ceil(512) * 512, 0);
    let mut img = d.clone();
    img.extend(vhd_footer(d.len() as u64, 2, u64::MAX));
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("fixed.vhd");
    std::fs::write(&p, img).unwrap();
    assert_eq!(extract(&p, Format::Vhd), d);
}

#[test]
fn vhd_dynamic() {
    let d = disk();
    let size = d.len().div_ceil(MIB) * MIB;
    let blocks = size / MIB;
    let mut img = vhd_footer(size as u64, 3, 512);
    let mut dh = vec![0u8; 1024];
    dh[..8].copy_from_slice(b"cxsparse");
    dh[0x10..0x18].copy_from_slice(&1536u64.to_be_bytes());
    dh[0x1C..0x20].copy_from_slice(&(blocks as u32).to_be_bytes());
    dh[0x20..0x24].copy_from_slice(&(MIB as u32).to_be_bytes());
    img.extend(dh);
    let bat_len = (blocks * 4).div_ceil(512) * 512;
    let mut bat = vec![0xFFu8; bat_len];
    let mut data = Vec::new();
    let mut next = (1536 + bat_len) / 512;
    for b in 0..blocks {
        let chunk = d.get(b * MIB..((b + 1) * MIB).min(d.len())).unwrap_or(&[]);
        if chunk.iter().all(|x| *x == 0) {
            continue; // unallocated
        }
        bat[b * 4..b * 4 + 4].copy_from_slice(&(next as u32).to_be_bytes());
        data.extend(vec![0xFFu8; 512]); // sector bitmap
        let mut c = chunk.to_vec();
        c.resize(MIB, 0);
        data.extend(c);
        next += 1 + MIB / 512;
    }
    img.extend(bat);
    img.extend(data);
    img.extend(vhd_footer(size as u64, 3, 512));
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("dyn.vhd");
    std::fs::write(&p, img).unwrap();
    let mut want = d.clone();
    want.resize(size, 0);
    assert_eq!(extract(&p, Format::Vhd), want);
}

fn guid(s: [u8; 16]) -> [u8; 16] {
    s
}

#[test]
fn vhdx_dynamic() {
    const BAT: [u8; 16] = [
        0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A,
        0x08,
    ];
    const META: [u8; 16] = [
        0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88,
        0x6E,
    ];
    const FILE_PARAMS: [u8; 16] = [
        0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7,
        0x6B,
    ];
    const DISK_SIZE: [u8; 16] = [
        0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4,
        0xB8,
    ];
    const SECTOR: [u8; 16] = [
        0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB,
        0x5F,
    ];
    let d = disk();
    let blocks = d.len().div_ceil(MIB);
    let mut img = vec![0u8; 3 * MIB];
    img[..8].copy_from_slice(b"vhdxfile");
    // Region table at 192 KiB: BAT at 2 MiB, metadata at 1 MiB.
    let rt = 192 << 10;
    img[rt..rt + 4].copy_from_slice(b"regi");
    img[rt + 8..rt + 12].copy_from_slice(&2u32.to_le_bytes());
    for (i, (g, off, len)) in [(BAT, 2 * MIB, MIB), (META, MIB, MIB)].iter().enumerate() {
        let e = rt + 16 + i * 32;
        img[e..e + 16].copy_from_slice(&guid(*g));
        img[e + 16..e + 24].copy_from_slice(&(*off as u64).to_le_bytes());
        img[e + 24..e + 28].copy_from_slice(&(*len as u32).to_le_bytes());
    }
    let md = MIB;
    img[md..md + 8].copy_from_slice(b"metadata");
    img[md + 10..md + 12].copy_from_slice(&3u16.to_le_bytes());
    let items: [([u8; 16], Vec<u8>); 3] = [
        (
            FILE_PARAMS,
            [(MIB as u32).to_le_bytes(), 0u32.to_le_bytes()].concat(),
        ),
        (DISK_SIZE, (d.len() as u64).to_le_bytes().to_vec()),
        (SECTOR, 512u32.to_le_bytes().to_vec()),
    ];
    for (i, (g, v)) in items.iter().enumerate() {
        let e = md + 32 + i * 32;
        let off = 64 << 10 | (i * 64);
        img[e..e + 16].copy_from_slice(g);
        img[e + 16..e + 20].copy_from_slice(&(off as u32).to_le_bytes());
        img[e + 20..e + 24].copy_from_slice(&(v.len() as u32).to_le_bytes());
        img[md + off..md + off + v.len()].copy_from_slice(v);
    }
    // BAT (chunk ratio 4096, so no bitmap entries for 4 blocks).
    let mut next = 3 * MIB;
    let mut data = Vec::new();
    for b in 0..blocks {
        let chunk = &d[b * MIB..((b + 1) * MIB).min(d.len())];
        let state: u64 = if chunk.iter().all(|x| *x == 0) {
            0
        } else {
            let mut c = chunk.to_vec();
            c.resize(MIB, 0);
            data.extend(c);
            let e = (next as u64) | 6;
            next += MIB;
            e
        };
        let e = 2 * MIB + b * 8;
        img[e..e + 8].copy_from_slice(&state.to_le_bytes());
    }
    img.extend(data);
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("d.vhdx");
    std::fs::write(&p, img).unwrap();
    assert_eq!(extract(&p, Format::Vhdx), d);
}

fn vmdk_header(capacity_sectors: u64, gd_sector: u64, compressed: bool) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..4].copy_from_slice(b"KDMV");
    h[4..8].copy_from_slice(&(if compressed { 3u32 } else { 1 }).to_le_bytes());
    h[12..20].copy_from_slice(&capacity_sectors.to_le_bytes());
    h[20..28].copy_from_slice(&128u64.to_le_bytes()); // 64 KiB grains
    h[44..48].copy_from_slice(&512u32.to_le_bytes());
    h[56..64].copy_from_slice(&gd_sector.to_le_bytes());
    if compressed {
        h[77..79].copy_from_slice(&1u16.to_le_bytes());
    }
    h
}

/// Sparse (`compressed == false`) or stream-optimized VMDK of `d`.
fn vmdk(d: &[u8], compressed: bool) -> Vec<u8> {
    let grain = 64 << 10;
    let cap = d.len().div_ceil(512) as u64;
    let grains = d.len().div_ceil(grain);
    let gts = grains.div_ceil(512);
    // Layout: header, GD at sector 1, GTs from sector 2 (4 sectors each),
    // then grains.
    let gt_start = 2u64;
    let mut img = vmdk_header(cap, if compressed { u64::MAX } else { 1 }, compressed);
    let mut gd = vec![0u8; 512];
    for t in 0..gts {
        gd[t * 4..t * 4 + 4].copy_from_slice(&((gt_start + 4 * t as u64) as u32).to_le_bytes());
    }
    let mut gt = vec![0u8; gts * 2048];
    let mut data = Vec::new();
    let mut next = gt_start + 4 * gts as u64;
    for g in 0..grains {
        let chunk = &d[g * grain..((g + 1) * grain).min(d.len())];
        if chunk.iter().all(|x| *x == 0) {
            continue;
        }
        gt[g * 4..g * 4 + 4].copy_from_slice(&(next as u32).to_le_bytes());
        let mut c = chunk.to_vec();
        c.resize(grain, 0);
        let block = if compressed {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            z.write_all(&c).unwrap();
            let z = z.finish().unwrap();
            let mut m = (g as u64 * 128).to_le_bytes().to_vec();
            m.extend((z.len() as u32).to_le_bytes());
            m.extend(z);
            m.resize(m.len().div_ceil(512) * 512, 0);
            m
        } else {
            c
        };
        next += (block.len() / 512) as u64;
        data.extend(block);
    }
    img.extend(gd);
    img.extend(gt);
    img.extend(data);
    if compressed {
        // Footer marker, footer (header copy with the real GD), EOS marker.
        img.extend(vec![0u8; 512]);
        img.extend(vmdk_header(cap, 1, true));
        img.extend(vec![0u8; 512]);
    }
    img
}

#[test]
fn vmdk_sparse_and_stream_optimized() {
    let d = disk();
    let t = tempfile::tempdir().unwrap();
    for compressed in [false, true] {
        let p = t.path().join(format!("d{compressed}.vmdk"));
        std::fs::write(&p, vmdk(&d, compressed)).unwrap();
        let mut want = d.clone();
        want.resize(d.len().div_ceil(512) * 512, 0);
        assert_eq!(extract(&p, Format::Vmdk), want, "compressed={compressed}");
    }
}

#[test]
fn qcow2_plain_and_compressed_clusters() {
    let d = disk();
    let bits = 16u32;
    let cluster = 1usize << bits;
    let clusters = d.len().div_ceil(cluster);
    let l2_entries = cluster / 8;
    let l1_size = clusters.div_ceil(l2_entries);
    // Clusters: 0 header, 1 L1, 2.. L2 tables, then data.
    let mut img = vec![0u8; cluster * (2 + l1_size)];
    img[..4].copy_from_slice(b"QFI\xFB");
    img[4..8].copy_from_slice(&2u32.to_be_bytes());
    img[20..24].copy_from_slice(&bits.to_be_bytes());
    img[24..32].copy_from_slice(&(d.len() as u64).to_be_bytes());
    img[36..40].copy_from_slice(&(l1_size as u32).to_be_bytes());
    img[40..48].copy_from_slice(&(cluster as u64).to_be_bytes());
    for i in 0..l1_size {
        let l2 = ((2 + i) * cluster) as u64 | 1 << 63;
        img[cluster + i * 8..cluster + i * 8 + 8].copy_from_slice(&l2.to_be_bytes());
    }
    let x = 62 - (bits - 8);
    for c in 0..clusters {
        let chunk = &d[c * cluster..((c + 1) * cluster).min(d.len())];
        if chunk.iter().all(|b| *b == 0) {
            continue;
        }
        let off = img.len() as u64;
        // Every third allocated cluster compressed (raw deflate, unaligned).
        let entry = if c % 3 == 0 {
            let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            let mut full = chunk.to_vec();
            full.resize(cluster, 0);
            z.write_all(&full).unwrap();
            let z = z.finish().unwrap();
            let off = off + 100; // deliberately not sector aligned
            img.resize(off as usize, 0);
            img.extend(&z);
            let end = off + z.len() as u64;
            let sectors = (end - 1) / 512 - off / 512; // additional sectors
            1u64 << 62 | sectors << x | off
        } else {
            let off = (img.len().div_ceil(cluster) * cluster) as u64;
            img.resize(off as usize, 0);
            let mut full = chunk.to_vec();
            full.resize(cluster, 0);
            img.extend(full);
            off | 1 << 63
        };
        let l2 = (2 + c / l2_entries) * cluster + (c % l2_entries) * 8;
        img[l2..l2 + 8].copy_from_slice(&entry.to_be_bytes());
    }
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("d.qcow2");
    std::fs::write(&p, &img).unwrap();
    assert_eq!(extract(&p, Format::Qcow2), d);

    // v3 with an unknown incompatible feature (e.g. zstd clusters) is
    // refused rather than misread.
    img[4..8].copy_from_slice(&3u32.to_be_bytes());
    img[72..80].copy_from_slice(&(1u64 << 3).to_be_bytes());
    std::fs::write(&p, &img).unwrap();
    let e = nz_formats::list(Format::Qcow2, &p, &Options::default()).unwrap_err();
    assert!(
        matches!(
            e.downcast_ref::<nz_formats::FormatError>(),
            Some(nz_formats::FormatError::Unsupported(_))
        ),
        "{e:#}"
    );
}

/// Header fields set to extremes must give an error, not a panic (caught
/// by the guard as "decoder fault"). Regression for the `fmt_image` fuzz
/// finding: a VMDK capacity whose byte size overflows u64.
#[test]
fn extreme_header_fields_fail_cleanly() {
    let d = disk();
    let t = tempfile::tempdir().unwrap();
    let mut cases: Vec<(&str, Format, Vec<u8>)> = Vec::new();
    for (off, v) in [
        (12usize, u64::MAX),
        (20, u64::MAX),
        (56, u64::MAX / 8),
        (12, 1 << 60),
    ] {
        let mut img = vmdk(&d, false);
        img[off..off + 8].copy_from_slice(&v.to_le_bytes());
        cases.push(("vmdk", Format::Vmdk, img));
    }
    let mut short = vmdk_header(8, 1, false);
    short.truncate(600);
    cases.push(("vmdk", Format::Vmdk, short));
    for v in [u64::MAX, 1 << 63] {
        let mut img = vec![0u8; 2048];
        img.extend(vhd_footer(v, 2, u64::MAX));
        cases.push(("vhd", Format::Vhd, img));
        let mut img = vec![0u8; 2048];
        img.extend(vhd_footer(v, 3, v));
        cases.push(("vhd", Format::Vhd, img));
    }
    let mut faults = Vec::new();
    for (i, (ext, f, img)) in cases.into_iter().enumerate() {
        let p = t.path().join(format!("x{i}.{ext}"));
        std::fs::write(&p, &img).unwrap();
        let r = nz_formats::list(f, &p, &Options::default())
            .and_then(|_| nz_formats::extract(f, &p, &Options::default(), &mut VecSink::default()));
        if let Err(e) = r
            && format!("{e:#}").contains("decoder fault")
        {
            faults.push(format!("case {i}: {e:#}"));
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}
