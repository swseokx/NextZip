//! User preferences shared by every NextZip front end.
//!
//! Stored as `key=value` lines in `%LOCALAPPDATA%\NextZip\settings.txt`
//! (next to the GUI's `compress.txt`). Unknown keys are kept on save, so
//! older and newer versions can share the file.

use std::path::PathBuf;

/// UI language choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LangPref {
    /// Follow the Windows display language.
    #[default]
    Auto,
    Korean,
    English,
}

impl LangPref {
    pub fn as_str(self) -> &'static str {
        match self {
            LangPref::Auto => "auto",
            LangPref::Korean => "ko",
            LangPref::English => "en",
        }
    }

    pub fn parse(s: &str) -> Option<LangPref> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => LangPref::Auto,
            "ko" | "ko-kr" | "korean" => LangPref::Korean,
            "en" | "en-us" | "english" => LangPref::English,
            _ => return None,
        })
    }
}

/// Everything the user can set outside the compression dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefs {
    pub language: LangPref,
    /// Scan extracted content with AMSI before it is written (spec 8
    /// "악성코드 검사"). On by default.
    pub malware_scan: bool,
    /// Recreate symbolic links from tar archives as real links (spec 9:
    /// off by default; links become text files holding the target).
    pub symlinks: bool,
    /// Lines with keys this version does not know, written back unchanged.
    other: Vec<String>,
}

impl Default for Prefs {
    fn default() -> Prefs {
        Prefs {
            language: LangPref::Auto,
            malware_scan: true,
            symlinks: false,
            other: Vec::new(),
        }
    }
}

/// `%LOCALAPPDATA%\NextZip\settings.txt` (or `NZ_SETTINGS` for tests).
pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NZ_SETTINGS") {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("NextZip").join("settings.txt"))
}

impl Prefs {
    /// Parse the settings text; bad values fall back to the defaults.
    pub fn parse(text: &str) -> Prefs {
        let mut p = Prefs::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                if !line.trim().is_empty() {
                    p.other.push(line.to_string());
                }
                continue;
            };
            match k.trim() {
                "language" => p.language = LangPref::parse(v).unwrap_or_default(),
                "malware_scan" => p.malware_scan = !matches!(v.trim(), "off" | "0" | "false"),
                "symlinks" => p.symlinks = matches!(v.trim(), "on" | "1" | "true"),
                _ => p.other.push(line.to_string()),
            }
        }
        p
    }

    pub fn to_text(&self) -> String {
        let on = |b: bool| if b { "on" } else { "off" };
        let mut s = format!(
            "language={}\nmalware_scan={}\nsymlinks={}\n",
            self.language.as_str(),
            on(self.malware_scan),
            on(self.symlinks)
        );
        for l in &self.other {
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    /// Read the settings file; defaults when it is missing or unreadable.
    pub fn load() -> Prefs {
        path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| Prefs::parse(&t))
            .unwrap_or_default()
    }

    /// Write the settings file.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(p) = path() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "LOCALAPPDATA is not set",
            ));
        };
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(p, self.to_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_unknown_keys() {
        let p = Prefs::parse("language=en\nmalware_scan=off\nfuture=1\n");
        assert_eq!(p.language, LangPref::English);
        assert!(!p.malware_scan);
        let again = Prefs::parse(&p.to_text());
        assert_eq!(again, p);
        assert!(p.to_text().contains("future=1"));
    }

    #[test]
    fn defaults_on_garbage() {
        let p = Prefs::parse("language=xx\nmalware_scan=maybe\n");
        assert_eq!(p.language, LangPref::Auto);
        assert!(p.malware_scan);
        assert_eq!(Prefs::parse(""), Prefs::default());
    }
}
