//! .nz round trips, encryption, determinism, backup and damage injection.

use std::path::{Path, PathBuf};

use nz_nzf::fmt::{BlockHeader, HEADER_LEN, Header};
use nz_nzf::read::{self, Archive, OpenOptions};
use nz_nzf::rr::Layout;
use nz_nzf::{Aead, KdfParams, Method, WriteOptions};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn text(rng: &mut Rng, n: usize) -> Vec<u8> {
    let words = [
        "alpha ", "beta ", "gamma ", "delta\n", "압축 ", "복구 ", "nz ", "0123 ",
    ];
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        v.extend_from_slice(words[rng.below(words.len() as u64) as usize].as_bytes());
    }
    v.truncate(n);
    v
}

/// A small tree: text, random data, an empty file, nested and Unicode names.
fn make_tree(root: &Path, seed: u64) {
    let mut rng = Rng(seed);
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("a.txt", text(&mut rng, 700_000)),
        ("dir/b.bin", rng.bytes(400_000)),
        ("dir/sub/c.txt", text(&mut rng, 1_300_000)),
        ("dir/empty.dat", Vec::new()),
        ("한글 폴더/파일.txt", text(&mut rng, 50_000)),
        ("dup1.bin", vec![7u8; 300_000]),
        ("dup2.bin", vec![7u8; 300_000]),
    ];
    for (n, d) in files {
        let p = root.join(n);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, d).unwrap();
    }
    std::fs::create_dir_all(root.join("emptydir")).unwrap();
}

fn tree_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, d: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                out.push((rel + "/", Vec::new()));
                walk(base, &p, out);
            } else {
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

fn opts(level: u8) -> WriteOptions {
    WriteOptions {
        method: Method::for_level(level),
        kdf: fast_kdf(),
        ..Default::default()
    }
}

fn create_in(pool: usize, src: &Path, out: &Path, o: &WriteOptions) {
    nz_core::cpu::pool(pool)
        .unwrap()
        .install(|| nz_nzf::create(&[src.to_path_buf()], out, o))
        .unwrap();
}

fn extract_bytes(
    data: &[u8],
    pw: Option<&str>,
    which: Option<usize>,
    out: &Path,
) -> read::ExtractReport {
    let opt = OpenOptions {
        password: pw.map(Into::into),
        verify: false,
    };
    let mut a = Archive::open(&data, &opt).expect("open");
    read::extract(&mut a, which, out).expect("extract")
}

#[test]
fn round_trip_levels() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    make_tree(&src, 1);
    let want = tree_files(&src);
    for level in [0u8, 1, 5, 9] {
        let arc = t.path().join(format!("l{level}.nz"));
        create_in(4, &src, &arc, &opts(level));
        let out = t.path().join(format!("out{level}"));
        let rep = extract_bytes(&std::fs::read(&arc).unwrap(), None, None, &out);
        assert!(rep.failed.is_empty(), "{:?}", rep.failed);
        assert_eq!(tree_files(&out), want, "level {level}");
    }
    // Duplicate files share chunks.
    let data = std::fs::read(t.path().join("l5.nz")).unwrap();
    let a = Archive::open(&data, &OpenOptions::default()).unwrap();
    let e = &a.index.snapshots[0].entries;
    let d1 = e.iter().find(|x| x.path == "dup1.bin").unwrap();
    let d2 = e.iter().find(|x| x.path == "dup2.bin").unwrap();
    assert_eq!(d1.chunks, d2.chunks);
}

#[test]
fn deterministic_across_threads() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    make_tree(&src, 2);
    let mut o = opts(5);
    o.method.block = 256 << 10; // many blocks
    let mut outs = Vec::new();
    for th in [1, 3, 8] {
        let arc = t.path().join(format!("t{th}.nz"));
        create_in(th, &src, &arc, &o);
        outs.push(std::fs::read(arc).unwrap());
    }
    assert_eq!(outs[0], outs[1]);
    assert_eq!(outs[0], outs[2]);
}

#[test]
fn encryption_both_ciphers() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    make_tree(&src, 3);
    let want = tree_files(&src);
    for aead in [Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
        let mut o = opts(5);
        o.password = Some("비밀 pw".into());
        o.aead = aead;
        let arc = t.path().join(format!("e{}.nz", aead as u8));
        create_in(4, &src, &arc, &o);
        let data = std::fs::read(&arc).unwrap();
        // Names are encrypted.
        let hay = String::from_utf8_lossy(&data);
        assert!(!hay.contains("a.txt") && !hay.contains("sub/c"));
        // Wrong or missing password.
        for pw in [None, Some("wrong".to_string())] {
            let r = Archive::open(
                &data,
                &OpenOptions {
                    password: pw,
                    verify: false,
                },
            );
            assert!(r.is_err());
        }
        let out = t.path().join(format!("eo{}", aead as u8));
        let rep = extract_bytes(&data, Some("비밀 pw"), None, &out);
        assert!(rep.failed.is_empty());
        assert_eq!(tree_files(&out), want);
    }
}

#[test]
fn backup_dedup_and_restore() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    make_tree(&src, 4);
    let arc = t.path().join("b.nz");
    let o = opts(5);
    let run = |label: &str| {
        let mut o = o.clone();
        o.label = label.into();
        nz_core::cpu::pool(4)
            .unwrap()
            .install(|| nz_nzf::backup(&arc, std::slice::from_ref(&src), &o))
            .unwrap()
    };
    let s1 = run("one");
    let v1 = tree_files(&src);
    assert!(s1.new_chunks > 0);
    // Unchanged tree: nothing new.
    let s2 = run("two");
    assert_eq!(s2.new_chunks, 0);
    assert_eq!(s2.new_bytes, 0);
    assert!(
        s2.written_bytes < s1.written_bytes / 10,
        "{} vs {}",
        s2.written_bytes,
        s1.written_bytes
    );
    // Small change in the middle of a large file + a new file.
    let c = src.join("dir/sub/c.txt");
    let mut d = std::fs::read(&c).unwrap();
    d.splice(600_000..600_000, b"INSERTED TEXT".iter().copied());
    std::fs::write(&c, &d).unwrap();
    std::fs::write(src.join("new.txt"), b"hello").unwrap();
    std::fs::remove_file(src.join("dup2.bin")).unwrap();
    let s3 = run("three");
    let v3 = tree_files(&src);
    assert!(s3.new_chunks <= 4, "new chunks {}", s3.new_chunks);
    assert!(s3.new_bytes < 600_000, "new bytes {}", s3.new_bytes);
    let data = std::fs::read(&arc).unwrap();
    let a = Archive::open(&data, &OpenOptions::default()).unwrap();
    assert_eq!(a.index.snapshots.len(), 3);
    assert_eq!(a.index.snapshots[1].label, "two");
    drop(a);
    for (i, want) in [(0usize, &v1), (1, &v1), (2, &v3)] {
        let out = t.path().join(format!("r{i}"));
        let rep = extract_bytes(&data, None, Some(i), &out);
        assert!(rep.failed.is_empty());
        assert_eq!(&tree_files(&out), want, "snapshot {i}");
    }
}

#[test]
fn encrypted_backup_needs_password() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    make_tree(&src, 5);
    let arc = t.path().join("eb.nz");
    let mut o = opts(3);
    o.password = Some("pw".into());
    nz_nzf::backup(&arc, std::slice::from_ref(&src), &o).unwrap();
    let mut o2 = o.clone();
    o2.password = None;
    assert!(nz_nzf::backup(&arc, std::slice::from_ref(&src), &o2).is_err());
    let s = nz_nzf::backup(&arc, std::slice::from_ref(&src), &o).unwrap();
    assert_eq!(s.new_chunks, 0);
    let out = t.path().join("o");
    let rep = extract_bytes(&std::fs::read(&arc).unwrap(), Some("pw"), Some(0), &out);
    assert!(rep.failed.is_empty());
    assert_eq!(tree_files(&out), tree_files(&src));
}

// ------------------------------------------------------------ damage

type Mutator = Box<dyn Fn(&mut Vec<u8>)>;

struct Geo {
    h: Header,
    l: Layout,
}

fn geo(data: &[u8]) -> Geo {
    let h = Header::decode(&data[..HEADER_LEN], false).unwrap();
    let l = Layout::new(
        h.recovery_offset,
        h.rr_sector_size,
        h.rr_group_sectors,
        h.rr_basis_points,
    )
    .unwrap();
    Geo { h, l }
}

impl Geo {
    /// Sector id of a byte: data sectors 0..n, parity sectors n.., None for
    /// bytes outside both (RR headers, hash tables, index copy, trailer).
    fn sector(&self, off: u64) -> Option<u64> {
        let ss = u64::from(self.l.sector_size);
        if off < self.l.covered_len {
            return Some(off / ss);
        }
        let ps = self.h.recovery_offset + self.l.parity_start();
        if off >= ps && off < ps + self.l.p * ss {
            return Some(self.l.n + (off - ps) / ss);
        }
        None
    }
    /// Group of a sector id.
    fn group(&self, s: u64) -> u64 {
        let d = u64::from(self.l.group_sectors);
        if s < self.l.n {
            s / d
        } else {
            let pfull = nz_nzf::rr::parity_for(d, self.l.basis_points);
            (s - self.l.n) / pfull
        }
    }
}

fn check_full(data: &[u8], want: &[(String, Vec<u8>)], dir: &Path) {
    let rep = extract_bytes(data, None, None, dir);
    assert!(rep.failed.is_empty(), "failed: {:?}", rep.failed);
    assert_eq!(tree_files(dir), want);
}

fn damage_setup(t: &Path, bp: u16) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let src = t.join("src");
    make_tree(&src, 6);
    let arc = t.join("d.nz");
    let mut o = opts(5);
    o.recovery_bp = bp;
    create_in(4, &src, &arc, &o);
    (std::fs::read(&arc).unwrap(), tree_files(&src))
}

#[test]
fn random_damage_within_budget() {
    let t = tempfile::tempdir().unwrap();
    let (orig, want) = damage_setup(t.path(), 300);
    let g = geo(&orig);
    let budget = nz_nzf::rr::parity_for(u64::from(g.l.group_sectors).min(g.l.n), g.l.basis_points);
    assert!(budget >= 5, "budget {budget}");
    let mut rng = Rng(99);
    let protected_end =
        g.h.recovery_offset + g.l.parity_start() + g.l.p * u64::from(g.l.sector_size);
    for round in 0..24 {
        let mut d = orig.clone();
        let mut hit = std::collections::BTreeMap::<u64, u64>::new(); // group -> sectors
        let mut sectors = std::collections::BTreeSet::new();
        // Mode 0: bit flips, 1: zeroed runs, 2: one contiguous run.
        let mode = round % 3;
        let mut tries = 0;
        while tries < 1000 {
            tries += 1;
            let (off, len) = match mode {
                0 => (rng.below(protected_end), 1),
                1 => (rng.below(protected_end), 1 + rng.below(700)),
                _ => {
                    let len = (budget - 1) * u64::from(g.l.sector_size) - 1;
                    (rng.below(g.l.covered_len - len), len)
                }
            };
            let end = (off + len).min(protected_end);
            let new: std::collections::BTreeSet<u64> =
                (off..end).filter_map(|o| g.sector(o)).collect();
            let mut trial = hit.clone();
            for s in new.difference(&sectors) {
                *trial.entry(g.group(*s)).or_default() += 1;
            }
            if trial.values().any(|&c| c > budget) {
                if mode == 2 {
                    continue;
                }
                break;
            }
            hit = trial;
            sectors.extend(new);
            for b in &mut d[off as usize..end as usize] {
                if mode == 0 {
                    *b ^= 1 << rng.below(8);
                } else {
                    *b = 0;
                }
            }
            if mode == 2 {
                break;
            }
        }
        assert!(!sectors.is_empty());
        check_full(&d, &want, &t.path().join(format!("r{round}")));
    }
}

#[test]
fn structural_damage() {
    let t = tempfile::tempdir().unwrap();
    let (orig, want) = damage_setup(t.path(), 300);
    let g = geo(&orig);
    let len = orig.len();
    let rr = g.h.recovery_offset as usize;
    let first_block = HEADER_LEN;
    let idx = g.h.index_offset as usize;
    let cases: Vec<(&str, Mutator)> = vec![
        ("header zeroed", Box::new(|d: &mut Vec<u8>| d[..64].fill(0))),
        (
            "first block header",
            Box::new(move |d: &mut Vec<u8>| d[first_block + 8] ^= 0xFF),
        ),
        (
            "primary index",
            Box::new(move |d: &mut Vec<u8>| d[idx + 100] ^= 0x10),
        ),
        (
            "index header",
            Box::new(move |d: &mut Vec<u8>| d[idx..idx + 8].fill(0)),
        ),
        (
            "rr header A",
            Box::new(move |d: &mut Vec<u8>| d[rr..rr + 64].fill(0xAA)),
        ),
        (
            "rr header both + main header",
            Box::new(move |d: &mut Vec<u8>| {
                d[rr..rr + 64].fill(0);
                let b = rr + g.l.rr_len as usize - 64;
                d[b..b + 64].fill(0);
                d[..64].fill(0);
            }),
        ),
        (
            "trailer zeroed",
            Box::new(move |d: &mut Vec<u8>| d[len - 64..].fill(0)),
        ),
        (
            "header and trailer zeroed",
            Box::new(move |d: &mut Vec<u8>| {
                d[..64].fill(0);
                d[len - 64..].fill(0);
            }),
        ),
        (
            "hash table A wiped",
            Box::new(move |d: &mut Vec<u8>| {
                let a = rr + 64;
                d[a..a + 4096].fill(0);
                d[100] ^= 1;
            }),
        ),
        (
            "truncate trailer",
            Box::new(move |d: &mut Vec<u8>| d.truncate(len - 64)),
        ),
        (
            "truncate index copy + trailer",
            Box::new(move |d: &mut Vec<u8>| d.truncate(rr + g.l.rr_len as usize)),
        ),
        (
            "truncate into parity",
            Box::new(move |d: &mut Vec<u8>| {
                let ps = rr + g.l.parity_start() as usize;
                d.truncate(ps + 2 * g.l.sector_size as usize);
            }),
        ),
        (
            "truncate whole recovery record",
            Box::new(move |d: &mut Vec<u8>| d.truncate(rr)),
        ),
        (
            "truncate covered tail (within budget)",
            Box::new(move |d: &mut Vec<u8>| {
                // Lose the last 2 covered sectors (the end of the primary index)
                // and everything after them except the recovery record: rebuild
                // a file whose tail is cut but the parity still present is not
                // possible, so instead zero those sectors.
                let ss = g.l.sector_size as usize;
                d[rr - 2 * ss..rr].fill(0);
            }),
        ),
    ];
    for (name, f) in cases {
        let mut d = orig.clone();
        f(&mut d);
        let dir = t.path().join(name.replace(' ', "_"));
        let rep = extract_bytes(&d, None, None, &dir);
        assert!(rep.failed.is_empty(), "{name}: {:?}", rep.failed);
        assert_eq!(tree_files(&dir), want, "{name}");
    }
}

#[test]
fn damage_beyond_budget_is_reported() {
    let t = tempfile::tempdir().unwrap();
    let (orig, _) = damage_setup(t.path(), 100);
    let g = geo(&orig);
    let ss = u64::from(g.l.sector_size);
    let p = nz_nzf::rr::parity_for(u64::from(g.l.group_sectors).min(g.l.n), g.l.basis_points);
    let mut d = orig.clone();
    // Damage p + 1 sectors inside block data (skip the first block header).
    for k in 0..=p {
        let off = (HEADER_LEN as u64 + 4096 + k * ss * 3) as usize;
        d[off] ^= 0x55;
    }
    let opt = OpenOptions::default();
    let mut a = Archive::open(&d, &opt).unwrap();
    let out = t.path().join("o");
    let rep = read::extract(&mut a, None, &out).unwrap();
    assert!(!rep.failed.is_empty());
    let r = rep.repair.expect("recovery was attempted");
    assert!(!r.ok());
    assert_eq!(r.failed_groups.len(), 1);
    assert!(r.damaged_sectors > p);
    // Files in undamaged blocks still came out.
    assert!(rep.files > 0);
    // The test command reports it too.
    let mut a = Archive::open(&d, &opt).unwrap();
    let tr = read::test(&mut a).unwrap();
    assert!(!tr.ok());
}

#[test]
fn no_recovery_record_reports_damage() {
    let t = tempfile::tempdir().unwrap();
    let (orig, _) = damage_setup(t.path(), 0);
    let h = Header::decode(&orig[..64], false).unwrap();
    assert!(!h.has_recovery());
    let mut d = orig.clone();
    let b = BlockHeader::decode(&d[64..128]).unwrap();
    d[64 + 64 + (b.stored_len as usize) / 2] ^= 1;
    let mut a = Archive::open(&d, &OpenOptions::default()).unwrap();
    let rep = read::extract(&mut a, None, &t.path().join("o")).unwrap();
    assert!(!rep.failed.is_empty());
    assert!(rep.repair.is_none());
}

#[test]
fn repair_command_rewrites_archive() {
    let t = tempfile::tempdir().unwrap();
    let (orig, want) = damage_setup(t.path(), 500);
    let mut d = orig.clone();
    for k in 0..10 {
        d[1000 + k * 5000] ^= 0xFF;
    }
    let bad = t.path().join("bad.nz");
    std::fs::write(&bad, &d).unwrap();
    let fixed = t.path().join("fixed.nz");
    let r = nz_nzf::repair_to(&bad, &fixed, None, None).unwrap();
    assert!(r.ok() && r.repaired_sectors > 0);
    assert_eq!(std::fs::read(&fixed).unwrap(), orig);
    check_full(&std::fs::read(&fixed).unwrap(), &want, &t.path().join("o"));
    let _: PathBuf = fixed;
}

/// NTFS alternate data streams: captured on create, deduplicated like file
/// data, restored on extract, skipped with `keep_streams: false`.
#[cfg(windows)]
#[test]
fn alternate_data_streams_round_trip() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    let mut rng = Rng(9);
    let big = text(&mut rng, 700_000);
    std::fs::write(src.join("a.txt"), b"main").unwrap();
    std::fs::write(src.join("d/b.bin"), &big).unwrap();
    std::fs::write(src.join("plain.txt"), b"no streams").unwrap();
    let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec();
    let ads = |p: &str, s: &str| src.join(format!("{p}:{s}"));
    if std::fs::write(ads("a.txt", "Zone.Identifier"), &zone).is_err() {
        eprintln!("file system without alternate data streams; skipped");
        return;
    }
    std::fs::write(ads("a.txt", "empty"), b"").unwrap();
    std::fs::write(ads("d/b.bin", "copy"), &big).unwrap();
    let arc = t.path().join("s.nz");
    let st = nz_nzf::create(std::slice::from_ref(&src), &arc, &opts(5)).unwrap();
    assert_eq!(st.streams, 3);
    assert!(st.skipped.is_empty(), "{:?}", st.skipped);
    let data = std::fs::read(&arc).unwrap();
    let a = Archive::open(&data, &OpenOptions::default()).unwrap();
    let e = &a.index.snapshots[0].entries;
    let b = e.iter().find(|x| x.path == "d/b.bin").unwrap();
    // The stream holding the same bytes as the file reuses its chunks.
    assert_eq!(b.streams[0].chunks, b.chunks);
    let names: Vec<&str> = e
        .iter()
        .find(|x| x.path == "a.txt")
        .unwrap()
        .streams
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, ["Zone.Identifier", "empty"]);

    let out = t.path().join("out");
    let rep = extract_bytes(&data, None, None, &out);
    assert!(rep.failed.is_empty() && rep.stream_errors.is_empty());
    assert_eq!(rep.streams, 3);
    let o = |p: &str| out.join(p);
    assert_eq!(std::fs::read(o("a.txt")).unwrap(), b"main");
    assert_eq!(std::fs::read(o("a.txt:Zone.Identifier")).unwrap(), zone);
    assert_eq!(std::fs::read(o("a.txt:empty")).unwrap(), b"");
    assert_eq!(std::fs::read(o("d/b.bin:copy")).unwrap(), big);
    assert!(
        nz_sys::alternate_streams(&o("plain.txt"))
            .unwrap()
            .is_empty()
    );

    let off = WriteOptions {
        keep_streams: false,
        ..opts(5)
    };
    let arc2 = t.path().join("n.nz");
    let st = nz_nzf::create(std::slice::from_ref(&src), &arc2, &off).unwrap();
    assert_eq!(st.streams, 0);
    let out2 = t.path().join("out2");
    extract_bytes(&std::fs::read(&arc2).unwrap(), None, None, &out2);
    assert!(
        nz_sys::alternate_streams(&out2.join("a.txt"))
            .unwrap()
            .is_empty()
    );
}

/// A stream name that would select a stream type or a path rejects the
/// archive before anything is written.
#[test]
fn unsafe_stream_names_are_rejected() {
    use nz_nzf::index::{Entry, Kind, Stream};
    let entry = |name: &str| Entry {
        path: "f".into(),
        kind: Kind::File,
        attrs: 0,
        mode: 0,
        mtime_ns: 0,
        size: 0,
        chunks: vec![],
        target: String::new(),
        streams: vec![Stream {
            kind: 0,
            name: name.into(),
            size: 0,
            chunks: vec![],
        }],
    };
    for bad in [
        "",
        "x:$DATA",
        "a/b",
        r"a\b",
        r"..\x",
        "a\u{1}",
        &"n".repeat(256),
    ] {
        assert!(read::checked_paths(&[entry(bad)]).is_err(), "{bad:?}");
    }
    assert!(read::checked_paths(&[entry("Zone.Identifier")]).is_ok());
}

/// A minimal x86-64 PE image: headers, then code full of near calls.
fn fake_pe(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[..2].copy_from_slice(b"MZ");
    v[0x3C] = 0x40;
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    v[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    let targets: Vec<u32> = (0..64).map(|_| rng.below(1 << 20) as u32).collect();
    while v.len() < n {
        // mov/push filler, then `call rel32` to one of a few functions.
        v.extend_from_slice(&[0x48, 0x89, 0x5C, 0x24, rng.below(256) as u8, 0x55]);
        let t = targets[rng.below(64) as usize];
        let rel = t.wrapping_sub(v.len() as u32 + 5);
        v.push(0xE8);
        v.extend_from_slice(&rel.to_le_bytes());
    }
    v.truncate(n);
    v
}

/// Mostly compressed data with a compressible middle (planner class "fast").
fn mostly_compressed(rng: &mut Rng) -> Vec<u8> {
    let mut v = rng.bytes(150_000);
    v.extend_from_slice(&text(rng, 100_000));
    v.extend_from_slice(&rng.bytes(150_000));
    v
}

/// Code goes to BCJ-filtered blocks, mostly-compressed data to LZMA2 blocks
/// at level 6; round trips and identical bytes for any thread count.
#[test]
fn content_classes_route_blocks() {
    use nz_nzf::fmt::{Codec, Filter};
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let mut rng = Rng(77);
    std::fs::write(src.join("app.exe"), fake_pe(&mut rng, 900_000)).unwrap();
    std::fs::write(src.join("lib.dll"), fake_pe(&mut rng, 300_000)).unwrap();
    std::fs::write(src.join("pack.bin"), mostly_compressed(&mut rng)).unwrap();
    std::fs::write(src.join("notes.txt"), text(&mut rng, 500_000)).unwrap();
    let want = tree_files(&src);
    for level in [1u8, 5, 6, 9] {
        let a1 = t.path().join(format!("c{level}a.nz"));
        let a8 = t.path().join(format!("c{level}b.nz"));
        create_in(1, &src, &a1, &opts(level));
        create_in(8, &src, &a8, &opts(level));
        let data = std::fs::read(&a1).unwrap();
        assert_eq!(data, std::fs::read(&a8).unwrap(), "level {level}");
        let out = t.path().join(format!("o{level}"));
        let rep = extract_bytes(&data, None, None, &out);
        assert!(rep.failed.is_empty(), "{:?}", rep.failed);
        assert_eq!(tree_files(&out), want, "level {level}");
        let a = Archive::open(&data, &OpenOptions::default()).unwrap();
        let heads: Vec<BlockHeader> = a
            .index
            .blocks
            .iter()
            .map(|b| {
                let o = b.offset as usize;
                BlockHeader::decode(&data[o..o + 64]).unwrap()
            })
            .collect();
        assert!(
            heads.iter().any(|h| h.filter == Filter::X86),
            "level {level}: no BCJ block"
        );
        let lzma = heads.iter().filter(|h| h.codec == Codec::Lzma2).count();
        match level {
            6 => assert_eq!(lzma, 1, "level 6: one LZMA2 block for the packed file"),
            9 => assert_eq!(lzma, heads.len()),
            _ => assert_eq!(lzma, 0),
        }
    }
}
