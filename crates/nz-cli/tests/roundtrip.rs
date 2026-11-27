//! End-to-end tests through the `nz` binary.
//!
//! * nz c -> nz x round trip for zip, tar.zst and 7z (byte-exact)
//! * determinism: same bytes for 1, 3 and 12 threads
//! * Windows only: archives open in PowerShell `Expand-Archive` (the shell's
//!   .NET ZIP reader) and, when `NZ_REF_ARCHIVER` names an external console
//!   archiver, nz ZIP/7z archives pass its test and extract byte-exact with
//!   it, and nz reads ZIP/7z archives it writes
//!
//! Set `NZ_COMPAT_DATA=<dir>` to run the round-trip and compatibility tests on
//! a real data set (e.g. the benchmark corpus) instead of the
//! synthetic corpus.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn nz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nz"))
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn xorshift(len: usize, mut s: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

/// Synthetic corpus covering the writer's edge cases.
fn corpus(root: &Path) {
    let w = |rel: &str, data: &[u8]| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    };
    // ~2 MB of text: spans many 128 KiB chunks.
    let text: Vec<u8> = (0..60_000)
        .flat_map(|i| format!("line {i}: the quick brown fox {}\n", i % 97).into_bytes())
        .collect();
    w("big/text.log", &text);
    w("big/random.bin", &xorshift(700_000, 7)); // planner: store
    let mut jarlike = xorshift(400_000, 9);
    jarlike.extend("META-INF/MANIFEST.MF\n".repeat(3000).as_bytes());
    w("big/jarlike.jar", &jarlike); // planner: fast tier
    // ZIP container (PK\x03\x04 head), ~5 MB with long-range repeats: 7z zstd
    // folder spanning several multithreaded zstd jobs; ZIP fast tier.
    let unit = xorshift(256 * 1024, 11);
    let mut container = b"PK\x03\x04".to_vec();
    for i in 0..20u8 {
        container.extend_from_slice(&unit);
        container.extend_from_slice(&[i; 1000]);
    }
    w("big/inner.zip", &container);
    w("empty.txt", b"");
    w("one.txt", b"x");
    w(
        "\u{d55c}\u{ae00} folder/\u{d30c}\u{c77c} name.txt",
        "unicode \u{c774}\u{b984}\n".repeat(100).as_bytes(),
    );
    w("deep/a/b/c/d/e/f.txt", b"deep file");
    w("chunk_edge.dat", &vec![b'z'; 128 * 1024]);
    w("chunk_edge_plus1.dat", &vec![b'q'; 128 * 1024 + 1]);
    // Real x86 machine code (PE header + code): exercises the BCJ + LZMA2 path.
    let mut exe = std::fs::read(env!("CARGO_BIN_EXE_nz")).unwrap();
    exe.truncate(1 << 20);
    w("bin/tool.exe", &exe);
    w("bin/copy.dll", &exe[..300_000]);
    std::fs::create_dir_all(root.join("empty_dir")).unwrap();
    std::fs::create_dir_all(root.join("nested/empty")).unwrap();
}

/// Relative path -> contents (None for directories).
fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut m = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if e.file_type().unwrap().is_dir() {
                m.insert(rel, None);
                stack.push(p);
            } else {
                m.insert(rel, Some(std::fs::read(&p).unwrap()));
            }
        }
    }
    m
}

fn assert_same_tree(a: &Path, b: &Path) {
    let sa = snapshot(a);
    let sb = snapshot(b);
    let ka: Vec<_> = sa.keys().collect();
    let kb: Vec<_> = sb.keys().collect();
    assert_eq!(
        ka,
        kb,
        "file lists differ: {} vs {}",
        a.display(),
        b.display()
    );
    for (k, v) in &sa {
        assert!(v == &sb[k], "content differs: {k}");
    }
}

fn source_dir(tmp: &Path) -> PathBuf {
    if let Some(d) = std::env::var_os("NZ_COMPAT_DATA") {
        return PathBuf::from(d);
    }
    let src = tmp.join("src");
    corpus(&src);
    src
}

#[test]
fn zip_and_tarzst_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let src = source_dir(tmp.path());
    for (fmt, ext) in [("zip", "zip"), ("tar.zst", "tar.zst"), ("7z", "7z")] {
        for level in ["0", "1", "5", "9"] {
            let arc = tmp.path().join(format!("a{level}.{ext}"));
            let out = tmp.path().join(format!("x_{ext}_{level}"));
            run(nz()
                .args(["c", &format!("-fmt:{fmt}"), &format!("-l:{level}"), "-q"])
                .arg(&arc)
                .arg(&src));
            run(nz()
                .args(["x", "-q"])
                .arg(format!("-o:{}", out.display()))
                .arg(&arc));
            assert_same_tree(&src, &out);
        }
    }
}

#[test]
fn output_is_deterministic_across_thread_counts() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    corpus(&src);
    for (fmt, levels) in [
        ("zip", ["5", "8"]),
        ("tar.zst", ["5", "8"]),
        ("7z", ["5", "9"]),
    ] {
        for level in levels {
            let mut first: Option<Vec<u8>> = None;
            for t in ["1", "3", "12"] {
                let arc = tmp.path().join(format!("d{t}_{level}.{fmt}"));
                run(nz()
                    .args(["c", &format!("-fmt:{fmt}"), &format!("-l:{level}")])
                    .args([&format!("-t:{t}"), "-q"])
                    .arg(&arc)
                    .arg(&src));
                let bytes = std::fs::read(&arc).unwrap();
                match &first {
                    None => first = Some(bytes),
                    Some(f) if f != &bytes => {
                        // Keep both archives for inspection: the temp dir is
                        // deleted when the test panics.
                        let keep = Path::new(env!("CARGO_TARGET_TMPDIR")).join("determinism");
                        std::fs::create_dir_all(&keep).unwrap();
                        let a = keep.join(format!("t1_l{level}.{fmt}"));
                        let b = keep.join(format!("t{t}_l{level}.{fmt}"));
                        std::fs::write(&a, f).unwrap();
                        std::fs::write(&b, &bytes).unwrap();
                        let at = f.iter().zip(&bytes).position(|(x, y)| x != y);
                        panic!(
                            "{fmt} l{level}: -t:{t} differs from -t:1 (sizes {} vs {}, first \
                             difference at byte {at:?}); kept {} and {}",
                            f.len(),
                            bytes.len(),
                            a.display(),
                            b.display()
                        );
                    }
                    Some(_) => {}
                }
            }
        }
    }
}

/// Hand-made ZIP with one stored, empty member called `name`.
fn tiny_zip(name: &[u8]) -> Vec<u8> {
    let mut z = Vec::new();
    z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]); // ver, flags, method, time, date
    z.extend_from_slice(&[0u8; 12]); // crc, csize, usize
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z.extend_from_slice(name);
    let cd = z.len() as u32;
    z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
    z.extend_from_slice(&[0u8; 12]);
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&[0u8; 12]); // extra, comment, disk, int attr, ext attr
    z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    z.extend_from_slice(name);
    let cd_size = z.len() as u32 - cd;
    z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    z.extend_from_slice(&cd_size.to_le_bytes());
    z.extend_from_slice(&cd.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z
}

#[test]
fn rejects_path_traversal_on_extract() {
    let tmp = tempfile::tempdir().unwrap();
    for (i, name) in [&b"../evil.txt"[..], b"/abs.txt", b"C:/drive.txt"]
        .iter()
        .enumerate()
    {
        let arc = tmp.path().join(format!("evil{i}.zip"));
        std::fs::write(&arc, tiny_zip(name)).unwrap();
        let out = nz()
            .args(["x", "-q"])
            .arg(format!("-o:{}", tmp.path().join("o").display()))
            .arg(&arc)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "accepted {:?}",
            String::from_utf8_lossy(name)
        );
    }
    assert!(!tmp.path().join("evil.txt").exists());
}

#[test]
fn reads_minimal_foreign_zip() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = tmp.path().join("ok.zip");
    std::fs::write(&arc, tiny_zip(b"dir/ok.txt")).unwrap();
    let out = tmp.path().join("o");
    run(nz()
        .args(["x", "-q"])
        .arg(format!("-o:{}", out.display()))
        .arg(&arc));
    assert_eq!(std::fs::read(out.join("dir").join("ok.txt")).unwrap(), b"");
}

#[cfg(windows)]
mod windows_compat {
    use super::*;

    /// External console archiver used as an independent cross-check, from
    /// `NZ_REF_ARCHIVER` (`c`/`t`/`x` commands with `-fmt:` `-l:` `-y` `-r`
    /// `-o:` switches). The interop tests skip when it is not set.
    fn ref_tool() -> Option<PathBuf> {
        std::env::var_os("NZ_REF_ARCHIVER")
            .map(PathBuf::from)
            .filter(|p| p.is_file())
    }

    fn rt() -> PathBuf {
        ref_tool().expect("NZ_REF_ARCHIVER")
    }

    fn make_zip(tmp: &Path, src: &Path, level: &str) -> PathBuf {
        let arc = tmp.join(format!("compat{level}.zip"));
        run(nz()
            .args(["c", "-fmt:zip", &format!("-l:{level}"), "-q"])
            .arg(&arc)
            .arg(src));
        arc
    }

    #[test]
    fn expand_archive_reads_nz_zip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = source_dir(tmp.path());
        let arc = make_zip(tmp.path(), &src, "5");
        let out = tmp.path().join("ps");
        let script = format!(
            "$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
            arc.display(),
            out.display()
        );
        run(Command::new("powershell.exe").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ]));
        assert_same_tree(&src, &out);
    }

    #[test]
    fn ref_tool_reads_nz_zip() {
        if ref_tool().is_none() {
            eprintln!("skipped: NZ_REF_ARCHIVER not set");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = source_dir(tmp.path());
        for level in ["1", "5", "9"] {
            let arc = make_zip(tmp.path(), &src, level);
            // The reference tool's integrity test.
            run(Command::new(rt()).arg("t").arg(&arc));
            let out = tmp.path().join(format!("rt{level}"));
            run(Command::new(rt())
                .arg("x")
                .arg("-y")
                .arg(format!("-o:{}", out.display()))
                .arg(&arc));
            assert_same_tree(&src, &out);
        }
    }

    #[test]
    fn nz_reads_ref_tool_zip() {
        if ref_tool().is_none() {
            eprintln!("skipped: NZ_REF_ARCHIVER not set");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = source_dir(tmp.path());
        let arc = tmp.path().join("from_ref.zip");
        run(Command::new(rt())
            .args(["c", "-fmt:zip", "-l:5", "-y", "-r"])
            .arg(&arc)
            .arg(src.join("*")));
        let out = tmp.path().join("nzx");
        run(nz()
            .args(["x", "-q"])
            .arg(format!("-o:{}", out.display()))
            .arg(&arc));
        // Other tools may omit empty directories; compare files only.
        assert!(files_only(snapshot(&src)) == files_only(snapshot(&out)));
    }

    fn files_only(m: BTreeMap<String, Option<Vec<u8>>>) -> BTreeMap<String, Vec<u8>> {
        m.into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect()
    }

    #[test]
    fn ref_tool_reads_nz_7z() {
        if ref_tool().is_none() {
            eprintln!("skipped: NZ_REF_ARCHIVER not set");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = source_dir(tmp.path());
        for level in ["1", "5", "9"] {
            let arc = tmp.path().join(format!("compat{level}.7z"));
            run(nz()
                .args(["c", "-fmt:7z", &format!("-l:{level}"), "-q"])
                .arg(&arc)
                .arg(&src));
            // The reference tool's integrity test, then a byte-exact extraction.
            run(Command::new(rt()).arg("t").arg(&arc));
            let out = tmp.path().join(format!("rt7z{level}"));
            run(Command::new(rt())
                .arg("x")
                .arg("-y")
                .arg(format!("-o:{}", out.display()))
                .arg(&arc));
            assert_same_tree(&src, &out);
        }
    }

    #[test]
    fn nz_reads_ref_tool_7z() {
        if ref_tool().is_none() {
            eprintln!("skipped: NZ_REF_ARCHIVER not set");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = source_dir(tmp.path());
        let arc = tmp.path().join("from_ref.7z");
        run(Command::new(rt())
            .args(["c", "-fmt:7z", "-l:5", "-y", "-r"])
            .arg(&arc)
            .arg(src.join("*")));
        let out = tmp.path().join("nz7x");
        run(nz()
            .args(["x", "-q"])
            .arg(format!("-o:{}", out.display()))
            .arg(&arc));
        assert!(files_only(snapshot(&src)) == files_only(snapshot(&out)));
    }
}
