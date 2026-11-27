//! End-to-end tests for the tar family (tar, tar.gz, tar.xz, tar.bz2,
//! tar.lz4, tar.zst) through the `nz` binary.
//!
//! * nz c -> nz x round trip (byte-exact, empty directories included) with a
//!   PAX name (component longer than 100 bytes), a ustar prefix name, Korean
//!   names and, where the OS allows creating them, symbolic links
//! * determinism: same bytes for 1, 3 and 12 threads
//! * Windows only:
//!   - the built-in `tar.exe` (libarchive) lists and extracts nz archives,
//!     and nz extracts `tar.exe` archives (plain, gzip, xz, bzip2, zstd;
//!     `tar.exe` has no built-in lz4)
//!   - when `NZ_REF_ARCHIVER` names an external console archiver, it tests
//!     and extracts nz archives (tar and tar.gz directly; for
//!     .tar.xz/.bz2/.lz4/.zst a tool may unpack the inner .tar first, which
//!     is then extracted), and nz extracts its tar and tgz (GNU long names
//!     without magic, CP949 names)
//!
//! Paths stay well under MAX_PATH, which not every tool can exceed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const FORMATS: [&str; 6] = ["tar", "tar.gz", "tar.xz", "tar.bz2", "tar.lz4", "tar.zst"];

fn nz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nz"))
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Corpus with the tar edge cases. Returns true if it contains a symlink.
fn corpus(root: &Path) -> bool {
    let w = |rel: &str, data: &[u8]| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    };
    let text: Vec<u8> = (0..80_000)
        .flat_map(|i| format!("line {i}: tar family {}\n", i % 89).into_bytes())
        .collect();
    w("big/text.log", &text); // > 1 MiB: several gzip chunks
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let random: Vec<u8> = (0..600_000)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect();
    w("big/random.bin", &random); // tar.zst: planner fast frame
    w("empty.txt", b"");
    w(
        "\u{d55c}\u{ae00} \u{d3f4}\u{b354}/\u{d30c}\u{c77c} \u{c774}\u{b984}.txt",
        "\u{d55c}\u{ae00}\n".repeat(50).as_bytes(),
    );
    // One component longer than 100 bytes: needs PAX `path`.
    w(&format!("long/{}.txt", "L".repeat(110)), b"pax name");
    // Longer than 100 bytes in total but splittable: ustar prefix field.
    w(
        &format!("deep/{}/{}/z.txt", "p".repeat(50), "q".repeat(50)),
        b"prefix",
    );
    std::fs::create_dir_all(root.join("empty_dir")).unwrap();
    std::fs::create_dir_all(root.join("nested/empty")).unwrap();
    make_symlink(&root.join("link_to_text.log"), Path::new("big/text.log"))
}

#[cfg(windows)]
fn make_symlink(link: &Path, target: &Path) -> bool {
    // Needs Developer Mode or elevation; skipped otherwise.
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[cfg(unix)]
fn make_symlink(link: &Path, target: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

/// Relative path -> contents (None for directories, "-> target" for links).
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
            let ft = e.file_type().unwrap();
            if ft.is_symlink() {
                let t = std::fs::read_link(&p).unwrap();
                let t = t.to_string_lossy().replace('\\', "/");
                m.insert(rel, Some(format!("-> {t}").into_bytes()));
            } else if ft.is_dir() {
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

fn compress(arc: &Path, src: &Path, fmt: &str, level: &str, threads: Option<&str>) {
    let mut c = nz();
    c.args(["c", &format!("-fmt:{fmt}"), &format!("-l:{level}"), "-q"]);
    if let Some(t) = threads {
        c.arg(format!("-t:{t}"));
    }
    run(c.arg(arc).arg(src));
}

fn extract(arc: &Path, out: &Path) {
    // Round trips compare links as links (default: text files, spec 9).
    run(nz()
        .args(["x", "-q", "-symlinks"])
        .arg(format!("-o:{}", out.display()))
        .arg(arc));
}

#[test]
fn tar_family_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let has_link = corpus(&src);
    if !has_link {
        eprintln!("note: no symlink privilege; links are covered by the nz-core unit tests");
    }
    for fmt in FORMATS {
        for level in ["1", "5", "9"] {
            let arc = tmp.path().join(format!("a{level}.{fmt}"));
            compress(&arc, &src, fmt, level, None);
            let out = tmp.path().join(format!("x_{fmt}_{level}"));
            extract(&arc, &out);
            assert_same_tree(&src, &out);
        }
    }
}

#[test]
fn format_from_extension_and_default_output_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    corpus(&src);
    for (name, magic) in [
        ("e.tgz", &[0x1F, 0x8B][..]),
        ("e.tar.xz", &[0xFD, b'7', b'z', b'X', b'Z'][..]),
        ("e.tbz2", &b"BZh"[..]),
        ("e.tar.lz4", &[0x04, 0x22, 0x4D, 0x18][..]),
    ] {
        let arc = tmp.path().join(name);
        run(nz().args(["c", "-q"]).arg(&arc).arg(&src));
        assert!(std::fs::read(&arc).unwrap().starts_with(magic), "{name}");
    }
    // `nz x e.tar.xz` extracts into `e` next to the current directory.
    run(nz()
        .args(["x", "-q", "-symlinks", "e.tar.xz"])
        .current_dir(tmp.path()));
    assert_same_tree(&src, &tmp.path().join("e"));
}

#[test]
fn tar_family_is_deterministic_across_thread_counts() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    corpus(&src);
    for fmt in FORMATS {
        let mut first: Option<Vec<u8>> = None;
        for t in ["1", "3", "12"] {
            let arc = tmp.path().join(format!("d{t}.{fmt}"));
            compress(&arc, &src, fmt, "5", Some(t));
            let bytes = std::fs::read(&arc).unwrap();
            match &first {
                None => first = Some(bytes),
                Some(f) => assert!(f == &bytes, "{fmt}: -t:{t} differs from -t:1"),
            }
        }
    }
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

    fn tar_exe() -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join("System32").join("tar.exe")
    }

    /// Files and directories only (tar.exe and other tools copy links as files
    /// or skip them without privilege).
    fn plain_corpus(tmp: &Path) -> PathBuf {
        let plain = tmp.join("src");
        corpus(&plain);
        let _ = std::fs::remove_file(plain.join("link_to_text.log"));
        plain
    }

    #[test]
    fn windows_tar_reads_nz_archives() {
        let tar = tar_exe();
        if !tar.exists() {
            eprintln!("skipped: {} not found", tar.display());
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = plain_corpus(tmp.path());
        // tar.exe has no built-in lz4 (it would spawn an `lz4` program).
        for fmt in ["tar", "tar.gz", "tar.xz", "tar.bz2", "tar.zst"] {
            let arc = tmp.path().join(format!("w.{fmt}"));
            compress(&arc, &src, fmt, "5", None);
            let list = run(Command::new(&tar).arg("-tf").arg(&arc));
            assert!(list.contains(&"L".repeat(110)), "{fmt}: PAX name missing");
            let out = tmp.path().join(format!("wx_{}", fmt.replace('.', "_")));
            std::fs::create_dir_all(&out).unwrap();
            run(Command::new(&tar).arg("-xf").arg(&arc).arg("-C").arg(&out));
            assert_same_tree(&src, &out);
        }
    }

    #[test]
    fn nz_reads_windows_tar_archives() {
        let tar = tar_exe();
        if !tar.exists() {
            eprintln!("skipped: {} not found", tar.display());
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = plain_corpus(tmp.path());
        for (flag, name) in [
            ("", "t.tar"),
            ("-z", "t.tgz"),
            ("-J", "t.txz"),
            ("-j", "t.tbz2"),
            ("--zstd", "t.tzst"),
        ] {
            let arc = tmp.path().join(name);
            let mut c = Command::new(&tar);
            c.arg("-c");
            if !flag.is_empty() {
                c.arg(flag);
            }
            run(c.arg("-f").arg(&arc).arg("-C").arg(&src).arg("."));
            let out = tmp.path().join(format!("nx_{name}"));
            extract(&arc, &out);
            assert_same_tree(&src, &out);
        }
    }

    /// Reference-tool `x`: tar and tar.gz extract directly; for the other compressors
    /// the console tool writes the inner `.tar`, which is extracted next.
    fn ref_extract(arc: &Path, out: &Path) {
        run(Command::new(rt())
            .arg("x")
            .arg("-y")
            .arg(format!("-o:{}", out.display()))
            .arg(arc));
        let inner: Vec<PathBuf> = std::fs::read_dir(out)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        if let [single] = inner.as_slice()
            && single.extension().is_some_and(|x| x == "tar")
            && single.is_file()
        {
            let moved = out.with_extension("inner.tar");
            std::fs::rename(single, &moved).unwrap();
            std::fs::remove_dir(out).unwrap();
            run(Command::new(rt()).arg("t").arg(&moved));
            run(Command::new(rt())
                .arg("x")
                .arg("-y")
                .arg(format!("-o:{}", out.display()))
                .arg(&moved));
        }
    }

    #[test]
    fn ref_tool_reads_nz_archives() {
        if ref_tool().is_none() {
            eprintln!("skipped: NZ_REF_ARCHIVER not set");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = plain_corpus(tmp.path());
        for fmt in FORMATS {
            for level in ["1", "9"] {
                let arc = tmp.path().join(format!("b{level}.{fmt}"));
                compress(&arc, &src, fmt, level, None);
                run(Command::new(rt()).arg("t").arg(&arc));
                let out = tmp
                    .path()
                    .join(format!("bx_{}_{level}", fmt.replace('.', "_")));
                ref_extract(&arc, &out);
                assert_same_tree(&src, &out);
            }
        }
    }

    #[test]
    fn nz_reads_ref_tool_tar_and_tgz() {
        if ref_tool().is_none() {
            eprintln!("skipped: NZ_REF_ARCHIVER not set");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = plain_corpus(tmp.path());
        for fmt in ["tar", "tgz"] {
            let arc = tmp.path().join(format!("from_ref.{fmt}"));
            run(Command::new(rt())
                .args(["c", &format!("-fmt:{fmt}"), "-l:5", "-y", "-r"])
                .arg(&arc)
                .arg(src.join("*")));
            let out = tmp.path().join(format!("nzx_{fmt}"));
            extract(&arc, &out);
            assert_same_tree(&src, &out);
        }
    }

    /// File and directory symlinks; `None` without symlink privilege
    /// (Windows needs Developer Mode or elevation).
    fn link_corpus(root: &Path) -> Option<PathBuf> {
        let src = root.join("lsrc");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub").join("target.txt"), b"target data").unwrap();
        let file = std::os::windows::fs::symlink_file(
            Path::new("sub").join("target.txt"),
            src.join("file_link.txt"),
        );
        let dir = std::os::windows::fs::symlink_dir("sub", src.join("dir_link"));
        if file.is_err() || dir.is_err() {
            eprintln!("skipped: no symlink privilege (enable Developer Mode)");
            return None;
        }
        Some(src)
    }

    fn assert_links(out: &Path) {
        for (name, target, is_dir) in [
            ("file_link.txt", "sub/target.txt", false),
            ("dir_link", "sub", true),
        ] {
            let p = out.join(name);
            let meta = std::fs::symlink_metadata(&p).unwrap();
            assert!(meta.file_type().is_symlink(), "{}: not a link", p.display());
            let t = std::fs::read_link(&p).unwrap();
            assert_eq!(t.to_string_lossy().replace('\\', "/"), target);
            assert_eq!(p.is_dir(), is_dir, "{}", p.display());
        }
        assert_eq!(
            std::fs::read(out.join("dir_link").join("target.txt")).unwrap(),
            b"target data"
        );
    }

    /// nz stores links as tar symlinks; nz, tar.exe and the reference tool recreate
    /// them as links, and nz recreates links from tar.exe archives.
    #[test]
    fn symlinks_across_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let Some(src) = link_corpus(tmp.path()) else {
            return;
        };
        let arc = tmp.path().join("links.tgz");
        compress(&arc, &src, "tar.gz", "5", None);
        let nzx = tmp.path().join("nzx");
        extract(&arc, &nzx);
        assert_same_tree(&src, &nzx);
        assert_links(&nzx);

        let tar = tar_exe();
        if tar.exists() {
            let list = run(Command::new(&tar).arg("-tvf").arg(&arc));
            assert!(list.contains("dir_link -> sub"), "{list}");
            let wtx = tmp.path().join("wtx");
            std::fs::create_dir_all(&wtx).unwrap();
            run(Command::new(&tar).arg("-xf").arg(&arc).arg("-C").arg(&wtx));
            assert_links(&wtx);
            let warc = tmp.path().join("w.tgz");
            run(Command::new(&tar)
                .arg("-czf")
                .arg(&warc)
                .arg("-C")
                .arg(&src)
                .arg("."));
            let nzw = tmp.path().join("nzw");
            extract(&warc, &nzw);
            assert_links(&nzw);
        }
        if ref_tool().is_some() {
            let rtx = tmp.path().join("rtx");
            ref_extract(&arc, &rtx);
            assert_links(&rtx);
        }
    }
}
