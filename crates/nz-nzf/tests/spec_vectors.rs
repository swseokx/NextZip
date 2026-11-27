//! The test vectors printed in `docs/nz-format-v1.md` are regenerated here
//! and compared byte for byte, so the document and the implementation
//! cannot drift apart. `NZ_PRINT_VECTORS=1` prints them instead.

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use nz_nzf::{Method, WriteOptions};

fn vector(dir: &Path, rr: u16) -> Vec<u8> {
    let mut srcs: Vec<PathBuf> = Vec::new();
    for name in ["a.txt", "b.txt"] {
        let p = dir.join(name);
        std::fs::write(&p, b"hello, nz\n").unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .unwrap();
        srcs.push(p);
    }
    let out = dir.join(format!("v{rr}.nz"));
    let o = WriteOptions {
        method: Method::for_level(0),
        recovery_bp: rr,
        time_ns: Some(1_700_000_000_000_000_000),
        label: "v1".into(),
        keep_attrs: false,
        ..Default::default()
    };
    nz_nzf::create(&srcs, &out, &o).unwrap();
    std::fs::read(out).unwrap()
}

fn hex(data: &[u8]) -> String {
    let mut s = String::new();
    for (i, line) in data.chunks(16).enumerate() {
        s.push_str(&format!("{:06x} ", i * 16));
        for b in line {
            s.push_str(&format!(" {b:02x}"));
        }
        s.push('\n');
    }
    s
}

/// The hex block between `<!-- vector:NAME -->` and the closing fence.
fn doc_block(doc: &str, name: &str) -> String {
    let start = doc
        .find(&format!("<!-- vector:{name} -->"))
        .unwrap_or_else(|| panic!("vector {name} missing from the document"));
    let rest = &doc[start..];
    let a = rest.find("```text\n").unwrap() + 8;
    let b = rest[a..].find("```").unwrap();
    rest[a..a + b].replace("\r\n", "\n")
}

#[test]
fn document_vectors_match() {
    let t = tempfile::tempdir().unwrap();
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/nz-format-v1.md");
    let print = std::env::var_os("NZ_PRINT_VECTORS").is_some();
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    for (name, rr) in [("plain", 0u16), ("recovery", 300)] {
        let v = vector(t.path(), rr);
        let h = hex(&v);
        let a = nz_nzf::Archive::open(&v, &Default::default()).unwrap();
        let body = hex(&a.index.encode());
        if print {
            println!(
                "<!-- vector:{name} -->
```text
{h}```"
            );
            if rr == 0 {
                println!(
                    "<!-- vector:index-body -->
```text
{body}```"
                );
            }
            continue;
        }
        assert_eq!(
            doc_block(&doc, name),
            h,
            "vector {name} differs from the document"
        );
        if rr == 0 {
            assert_eq!(doc_block(&doc, "index-body"), body);
        }
        let e = &a.index.snapshots[0].entries;
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].chunks, e[1].chunks);
    }
}
