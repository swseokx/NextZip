//! Stable-toolchain smoke run of the fuzz entry points on seed archives and
//! deterministic mutations of them. `NZ_FUZZ_CORPUS=<dir>` also writes the
//! seeds to `<dir>/nz_read` and `<dir>/nz_recovery` for cargo-fuzz.

use std::path::Path;

use nz_nzf::{Aead, KdfParams, Method, WriteOptions};

fn seeds(dir: &Path) -> Vec<Vec<u8>> {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha beta gamma ".repeat(200)).unwrap();
    std::fs::write(
        src.join("d/b.bin"),
        (0..3000u32).map(|i| (i * 7) as u8).collect::<Vec<_>>(),
    )
    .unwrap();
    std::fs::write(src.join("d/c.txt"), b"alpha beta gamma ".repeat(200)).unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    let mut out = Vec::new();
    let variants: Vec<(u8, u16, Option<Aead>)> = vec![
        (0, 0, None),
        (1, 300, None),
        (5, 300, None),
        (9, 1000, None),
        (5, 300, Some(Aead::Aes256Gcm)),
        (3, 500, Some(Aead::ChaCha20Poly1305)),
    ];
    for (i, (level, rr, aead)) in variants.into_iter().enumerate() {
        let mut o = WriteOptions {
            method: Method::for_level(level),
            recovery_bp: rr,
            kdf: KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
            time_ns: Some(0),
            ..Default::default()
        };
        if let Some(a) = aead {
            o.password = Some("fuzz".into());
            o.aead = a;
        }
        let p = dir.join(format!("s{i}.nz"));
        nz_nzf::create(std::slice::from_ref(&src), &p, &o).unwrap();
        out.push(std::fs::read(&p).unwrap());
    }
    // A two-snapshot backup.
    let b = dir.join("bk.nz");
    let o = WriteOptions {
        time_ns: Some(0),
        ..Default::default()
    };
    nz_nzf::backup(&b, std::slice::from_ref(&src), &o).unwrap();
    std::fs::write(src.join("new.txt"), b"new").unwrap();
    nz_nzf::backup(&b, std::slice::from_ref(&src), &o).unwrap();
    out.push(std::fs::read(&b).unwrap());
    out
}

#[test]
fn smoke() {
    let t = tempfile::tempdir().unwrap();
    let seeds = seeds(t.path());
    if let Some(dir) = std::env::var_os("NZ_FUZZ_CORPUS") {
        for target in ["nz_read", "nz_recovery"] {
            let d = Path::new(&dir).join(target);
            std::fs::create_dir_all(&d).unwrap();
            for (i, s) in seeds.iter().enumerate() {
                std::fs::write(d.join(format!("seed{i}.nz")), s).unwrap();
            }
        }
    }
    let mut x = 0x9E37_79B9_7F4A_7C15_u64;
    let mut rnd = |n: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % n as u64) as usize
    };
    for s in &seeds {
        nz_nzf::fuzzing::open_and_test(s, false);
        nz_nzf::fuzzing::open_and_test(s, true);
        nz_nzf::fuzzing::recovery(s);
        for _ in 0..150 {
            let mut m = s.clone();
            match rnd(4) {
                0 => {
                    for _ in 0..1 + rnd(16) {
                        let i = rnd(m.len());
                        m[i] = rnd(256) as u8;
                    }
                }
                1 => m.truncate(rnd(m.len())),
                2 => {
                    let i = rnd(m.len());
                    let n = rnd(m.len() - i);
                    m[i..i + n].fill(0xFF);
                }
                _ => {
                    // Corrupt a varint-heavy region: the index frames.
                    let i = m.len().saturating_sub(1 + rnd(400.min(m.len())));
                    m[i] ^= 1 << rnd(8);
                }
            }
            nz_nzf::fuzzing::open_and_test(&m, false);
            nz_nzf::fuzzing::recovery(&m);
        }
    }
}
