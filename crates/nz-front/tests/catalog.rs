//! Every message the front ends translate has an English entry, and every
//! English entry keeps the template's argument count.

use std::path::Path;

/// Rust string literal body to its value (escapes and `\` line breaks).
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some('\n') | Some('\r') => {
                while it.peek().is_some_and(|c| c.is_whitespace()) {
                    it.next();
                }
            }
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => {}
        }
    }
    out
}

/// The first string literal argument of every `tr(` / `trf(` call.
fn messages(src: &str) -> Vec<String> {
    let mut v = Vec::new();
    let b = src.as_bytes();
    for pat in ["tr(", "trf("] {
        let mut from = 0;
        while let Some(i) = src[from..].find(pat) {
            let at = from + i;
            from = at + pat.len();
            // `tr(` must not be the tail of another name (`attr(`).
            if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
                continue;
            }
            let rest = src[from..].trim_start();
            let Some(body) = rest.strip_prefix('"') else {
                continue;
            };
            let mut end = None;
            let mut esc = false;
            for (k, c) in body.char_indices() {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    end = Some(k);
                    break;
                }
            }
            if let Some(e) = end {
                v.push(unescape(&body[..e]));
            }
        }
    }
    v
}

fn placeholders(s: &str) -> usize {
    s.replace("{{", "").matches('{').count()
}

fn sources() -> Vec<std::path::PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut out = Vec::new();
    for c in [
        "nz-gui",
        "nz-shell",
        "nz-setup",
        "nz-archive",
        "nz-scan",
        "nz-cli",
        "nz-rar",
        "nz-formats",
        "nz-sfx",
        "nz-create",
    ] {
        let mut stack = vec![crates.join(c).join("src")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
    }
    out
}

#[test]
fn every_message_has_an_english_translation() {
    let cat = nz_front::i18n::english_catalog();
    let mut missing = Vec::new();
    let mut seen = 0;
    for p in sources() {
        let src = std::fs::read_to_string(&p).unwrap().replace("\r\n", "\n");
        for m in messages(&src) {
            seen += 1;
            match cat.get(&m) {
                Some(en) if !en.is_empty() => {
                    assert_eq!(
                        placeholders(&m),
                        placeholders(en),
                        "argument count differs: {m:?} -> {en:?}"
                    );
                }
                _ => missing.push(format!("{}: {m:?}", p.display())),
            }
        }
    }
    assert!(seen > 200, "only {seen} messages found");
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "{} untranslated:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

#[test]
fn english_has_no_hangul() {
    for (k, v) in nz_front::i18n::english_catalog() {
        assert!(
            !v.chars().any(|c| ('\u{AC00}'..='\u{D7A3}').contains(&c)),
            "{k:?} -> {v:?}"
        );
    }
}
