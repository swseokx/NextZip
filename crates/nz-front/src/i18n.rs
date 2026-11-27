//! UI translations.
//!
//! The Korean text in the source is the message id (gettext style), so the
//! code stays readable and a missing translation shows Korean instead of a
//! key. Other languages are gettext PO catalogs (`i18n/<lang>.po`),
//! editable with Poedit or Weblate by community translators.
//!
//! Language: `NZ_LANG` (`ko`/`en`), else the `language` preference, else
//! the Windows display language (Korean if it is Korean, English
//! otherwise).
//!
//! Templates use `{}` for arguments in order, `{{` and `}}` for braces;
//! a translation may reorder arguments with `{0}`, `{1}`, ...

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::prefs::{LangPref, Prefs};

/// A UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Korean,
    English,
}

impl Lang {
    /// Short code (`ko`, `en`) for passing to helper processes.
    pub fn code(self) -> &'static str {
        match self {
            Lang::Korean => "ko",
            Lang::English => "en",
        }
    }

    pub fn from_code(c: &str) -> Option<Lang> {
        match c {
            "ko" => Some(Lang::Korean),
            "en" => Some(Lang::English),
            _ => None,
        }
    }

    /// From a Windows LANGID (primary language 0x12 is Korean).
    pub fn from_langid(id: u16) -> Lang {
        if id & 0x3FF == 0x12 {
            Lang::Korean
        } else {
            Lang::English
        }
    }

    /// The language a preference selects on this system.
    pub fn resolve(p: LangPref) -> Lang {
        match p {
            LangPref::Korean => Lang::Korean,
            LangPref::English => Lang::English,
            LangPref::Auto => nz_sys::ui_language().map_or(Lang::English, Lang::from_langid),
        }
    }
}

/// 0: not set (Korean), 1: Korean, 2: English.
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The UI language of this process: Korean (the source language) until a
/// front end calls [`init`] or [`set`], so libraries and tests are
/// language-stable.
pub fn current() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        2 => Lang::English,
        _ => Lang::Korean,
    }
}

/// The language the user asked for: `NZ_LANG`, else the `language`
/// preference, else the Windows display language.
pub fn preferred() -> Lang {
    std::env::var("NZ_LANG")
        .ok()
        .and_then(|v| LangPref::parse(&v))
        .filter(|p| *p != LangPref::Auto)
        .map_or_else(|| Lang::resolve(Prefs::load().language), Lang::resolve)
}

/// Front ends call this once at start: switch to [`preferred`].
pub fn init() -> Lang {
    let l = preferred();
    set(l);
    l
}

/// [`init`] the first time it is called in this process (the shell
/// extension, which has no `main`).
pub fn init_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Keep a language a caller already chose with `set`.
        if CURRENT.load(Ordering::Relaxed) == 0 {
            init();
        }
    });
}

/// Switch the UI language of this process (a language menu, a CLI flag,
/// tests). Text already on screen is not redrawn by this call.
pub fn set(l: Lang) {
    CURRENT.store(
        match l {
            Lang::Korean => 1,
            Lang::English => 2,
        },
        Ordering::Relaxed,
    );
}

const EN_PO: &str = include_str!("../i18n/en.po");

fn english() -> &'static HashMap<String, String> {
    static T: OnceLock<HashMap<String, String>> = OnceLock::new();
    T.get_or_init(|| parse_po(EN_PO))
}

/// The English catalog's entries (tests check coverage against it).
pub fn english_catalog() -> &'static HashMap<String, String> {
    english()
}

/// Translate a message.
pub fn tr(ko: &'static str) -> &'static str {
    tr_in(current(), ko)
}

/// Translate a message for a given language.
pub fn tr_in(lang: Lang, ko: &'static str) -> &'static str {
    match lang {
        Lang::Korean => ko,
        Lang::English => english()
            .get(ko)
            .filter(|s| !s.is_empty())
            .map_or(ko, String::as_str),
    }
}

/// Translate a message that is not a literal (a message computed at run
/// time, e.g. an error coming back from the decoder process).
pub fn tr_dyn(ko: &str) -> String {
    match current() {
        Lang::Korean => ko.to_string(),
        Lang::English => english()
            .get(ko)
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| ko.to_string()),
    }
}

/// Translate a template and fill in `args`.
pub fn trf(ko: &'static str, args: &[&dyn std::fmt::Display]) -> String {
    fill(tr(ko), args)
}

/// Fill a `{}` / `{0}` template.
pub fn fill(t: &str, args: &[&dyn std::fmt::Display]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(t.len() + 16);
    let mut next = 0usize;
    let mut chars = t.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '{' if chars.peek().map(|p| p.1) == Some('{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek().map(|p| p.1) == Some('}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let rest = &t[i + 1..];
                let Some(end) = rest.find('}') else {
                    out.push('{');
                    continue;
                };
                let inner = &rest[..end];
                let idx = if inner.is_empty() {
                    next += 1;
                    Some(next - 1)
                } else {
                    inner.parse::<usize>().ok()
                };
                match idx.and_then(|k| args.get(k)) {
                    Some(a) => {
                        let _ = write!(out, "{a}");
                    }
                    None => {
                        out.push('{');
                        out.push_str(inner);
                        out.push('}');
                    }
                }
                for _ in 0..=inner.chars().count() {
                    chars.next();
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                o => {
                    out.push('\\');
                    out.push(o);
                }
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Parse the subset of gettext PO NextZip uses: `msgid` / `msgstr` with
/// continuation lines, `#` comments. `msgctxt` and plurals are not used.
pub fn parse_po(text: &str) -> HashMap<String, String> {
    #[derive(PartialEq)]
    enum Field {
        None,
        Id,
        Str,
    }
    let mut map = HashMap::new();
    let (mut id, mut st) = (String::new(), String::new());
    let mut field = Field::None;
    let mut flush = |id: &mut String, st: &mut String| {
        if !id.is_empty() {
            map.insert(std::mem::take(id), std::mem::take(st));
        }
        id.clear();
        st.clear();
    };
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l.strip_prefix("msgid ") {
            if field == Field::Str {
                flush(&mut id, &mut st);
            }
            id = unquote(rest).unwrap_or_default();
            field = Field::Id;
        } else if let Some(rest) = l.strip_prefix("msgstr ") {
            st = unquote(rest).unwrap_or_default();
            field = Field::Str;
        } else if l.starts_with('"') {
            let more = unquote(l).unwrap_or_default();
            match field {
                Field::Id => id.push_str(&more),
                Field::Str => st.push_str(&more),
                Field::None => {}
            }
        }
    }
    flush(&mut id, &mut st);
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_positional_and_indexed() {
        assert_eq!(fill("{}개 중 {}", &[&3, &"a"]), "3개 중 a");
        assert_eq!(fill("{1} of {0}", &[&3, &"a"]), "a of 3");
        assert_eq!(fill("{{x}} {}", &[&1]), "{x} 1");
        assert_eq!(fill("{} {}", &[&1]), "1 {}");
        assert_eq!(fill("크기 {}", &[&"1 KB"]), "크기 1 KB");
    }

    #[test]
    fn po_parsing() {
        let m = parse_po(
            "# c\nmsgid \"\"\nmsgstr \"Content-Type: text/plain\\n\"\n\nmsgid \"열기\"\nmsgstr \"Open\"\n\nmsgid \"긴 \"\n\"문장\"\nmsgstr \"\"\n\"Long \\\"text\\\"\"\n",
        );
        assert_eq!(m.get("열기").unwrap(), "Open");
        assert_eq!(m.get("긴 문장").unwrap(), "Long \"text\"");
        assert!(!m.contains_key(""));
    }

    #[test]
    fn langid() {
        assert_eq!(Lang::from_langid(0x0412), Lang::Korean);
        assert_eq!(Lang::from_langid(0x0409), Lang::English);
        assert_eq!(Lang::from_langid(0x0411), Lang::English);
    }

    #[test]
    fn missing_translation_falls_back_to_korean() {
        assert_eq!(
            tr_in(Lang::English, "번역 없는 문장 테스트"),
            "번역 없는 문장 테스트"
        );
        assert_eq!(tr_in(Lang::Korean, "열기"), "열기");
    }
}
