//! Developer tool: `nzf <file>...` detects, lists and test-extracts in memory.
//! `nzf --crc <file>...` prints one `file\tmember\tsize\tcrc32` line per file
//! member (the format of `tests/data/manifest.tsv`). ZIP/7z are chosen by
//! extension; `NZF_PASSWORD` supplies a password.
fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let crc = args.first().is_some_and(|a| a == "--crc");
    if crc {
        args.remove(0);
    }
    for a in args {
        let p = std::path::Path::new(&a);
        // ZIP and 7z are routed by nz-archive, not detect(); pick the
        // full-coder readers by extension here.
        let ext = p
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        let by_ext = match ext.as_deref() {
            Some("zip" | "zipx") => Some(nz_formats::Format::ZipFull),
            Some("7z") => Some(nz_formats::Format::SevenZ),
            _ => None,
        };
        let Some(f) = by_ext.or_else(|| nz_formats::detect(p)) else {
            println!("{a}\tUNDETECTED");
            continue;
        };
        let opt = nz_formats::Options {
            password: std::env::var("NZF_PASSWORD").ok(),
        };
        match nz_formats::list(f, p, &opt) {
            Err(e) => println!("{a}\t{f:?}\tLIST-ERR {e:#}"),
            Ok(l) => {
                let mut s = nz_formats::VecSink::default();
                let r = nz_formats::extract(f, p, &opt, &mut s);
                if crc {
                    let file = p.file_name().unwrap().to_string_lossy();
                    for (m, data) in &s.files {
                        println!(
                            "{file}\t{}\t{}\t{:08x}",
                            m,
                            data.len(),
                            crc32fast::hash(data)
                        );
                    }
                    if let Err(e) = r {
                        println!("{file}\t{f:?}\tEXTRACT-ERR {e:#}");
                    }
                    continue;
                }
                let bytes: usize = s.files.iter().map(|x| x.1.len()).sum();
                match r {
                    Ok(()) => println!(
                        "{a}\t{f:?}\tOK {} members, {} files, {bytes} bytes",
                        l.members.len(),
                        s.files.len()
                    ),
                    Err(e) => println!("{a}\t{f:?}\tEXTRACT-ERR {e:#}"),
                }
            }
        }
    }
}
