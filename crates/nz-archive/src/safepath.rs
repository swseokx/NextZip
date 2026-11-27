//! Archive member name sanitising (zip-slip and Windows name hazards).

use std::path::PathBuf;

/// Map an archive member name to a relative path that cannot leave the
/// output directory, or `None` if the name must be rejected.
///
/// * `..` components, absolute paths, drive letters and NTFS alternate data
///   streams (any `:`) are rejected.
/// * Trailing dots and spaces are trimmed first, because Windows does the
///   same (`".. "` would otherwise become `..`).
/// * Control characters and `<>"|?*` are replaced with `_`.
/// * Reserved device names (`CON`, `NUL`, `COM1`, `LPT1`, ... also with an
///   extension) get a leading `_` instead of opening a device.
pub fn sanitize(name: &str) -> Option<PathBuf> {
    if name.starts_with('/') || name.starts_with('\\') {
        return None;
    }
    let mut p = PathBuf::new();
    for part in name.split(['/', '\\']) {
        // Windows drops trailing dots and spaces, so "..", "...", ".. " all
        // risk naming the parent folder: reject them outright.
        if part.contains("..") && part.chars().all(|c| c == '.' || c == ' ') {
            return None;
        }
        let part = part.trim_end_matches(['.', ' ']);
        if part.is_empty() {
            // "" and "." collapse to nothing; keep going.
            continue;
        }
        if part.contains(':') || part.contains('\0') {
            return None;
        }
        if part.trim_start_matches(' ') == ".." {
            return None;
        }
        let mut clean: String = part
            .chars()
            .map(|c| {
                if (c as u32) < 0x20 || matches!(c, '<' | '>' | '"' | '|' | '?' | '*') {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        if is_reserved(&clean) {
            clean.insert(0, '_');
        }
        p.push(clean);
    }
    if p.as_os_str().is_empty() {
        return None;
    }
    Some(p)
}

/// `Some(new name)` when [`sanitize`] keeps `name` but changes it to fit
/// Windows (reserved device names, trailing dots and spaces, characters
/// Windows does not allow). Separators, empty and `.` components do not
/// count as a change.
pub fn renamed(name: &str) -> Option<String> {
    changed(name, &sanitize(name)?)
}

/// `Some(new name)` when `rel` (the sanitised path of member `name`)
/// differs from `name` other than in separators, empty and `.` parts.
pub fn changed(name: &str, rel: &std::path::Path) -> Option<String> {
    let old: Vec<&str> = name
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let new: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    (old != new).then(|| new.join("/"))
}

/// Does link `target` (relative to the folder of `rel`, `/` or `\\`
/// separated) stay inside the output folder? Absolute targets, drive
/// letters and `..` that climbs above the root do not.
pub fn link_inside(rel: &std::path::Path, target: &str) -> bool {
    if target.starts_with(['/', '\\']) || target.contains(':') {
        return false;
    }
    let mut depth = rel.components().count().saturating_sub(1) as i64;
    for part in target.split(['/', '\\']) {
        match part.trim_end_matches(['.', ' ']) {
            "" if part.is_empty() || part == "." => {}
            "" => {
                // "..", "...", ".. ": the parent (Windows trims the rest).
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

/// The notice front ends show when member names were changed to fit
/// Windows (spec 9: "Windows 규칙에 맞게 이름 변경 후 알림"), or None.
pub fn rename_notice<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut count = 0usize;
    let mut example = None;
    for n in names {
        if let Some(new) = renamed(n) {
            count += 1;
            if example.is_none() {
                example = Some((n.to_string(), new));
            }
        }
    }
    let (old, new) = example?;
    Some(notice(count, &old, &new))
}

/// "N names renamed (e.g. old → new)".
pub fn notice(count: usize, old: &str, new: &str) -> String {
    nz_front::trf(
        "Windows에서 쓸 수 없는 이름이라 바꾼 항목 {}개 (예: {} → {})",
        &[&count, &old.trim_end_matches(['/', '\\']), &new],
    )
}

fn is_reserved(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut ch = stem.chars();
    let prefix: String = ch.by_ref().take(3).collect();
    let rest: String = ch.collect();
    (prefix == "COM" || prefix == "LPT")
        && rest.chars().count() == 1
        && rest
            .chars()
            .all(|c| matches!(c, '1'..='9' | '¹' | '²' | '³'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn link_targets() {
        let p = Path::new;
        assert!(link_inside(p("a/l"), "../b"));
        assert!(link_inside(p("l"), "b/c"));
        assert!(link_inside(p("a/b/l"), "./../../x"));
        assert!(!link_inside(p("l"), "../x"));
        assert!(!link_inside(p("a/l"), "../../x"));
        assert!(!link_inside(p("a/l"), ".. /.. /x"));
        assert!(!link_inside(p("a/l"), "/etc/passwd"));
        assert!(!link_inside(p("a/l"), "C:/x"));
        assert!(!link_inside(p("a/l"), r"\\server\x"));
    }

    #[test]
    fn renamed_names() {
        assert_eq!(renamed("CON").as_deref(), Some("_CON"));
        assert_eq!(renamed("a/nul.txt").as_deref(), Some("a/_nul.txt"));
        assert_eq!(renamed("x. ").as_deref(), Some("x"));
        assert_eq!(renamed("a?b").as_deref(), Some("a_b"));
        assert_eq!(renamed("a/b.txt"), None);
        assert_eq!(renamed(r"a\b/./c/"), None);
        assert_eq!(renamed("../x"), None);
        assert!(rename_notice(["a", "b"]).is_none());
        let n = rename_notice(["a", "CON", "d/aux.c"]).unwrap();
        assert!(n.contains('2') && n.contains("CON"), "{n}");
    }

    #[test]
    fn traversal_is_rejected() {
        for bad in [
            "../x",
            "a/../../x",
            "..\\x",
            "/etc/passwd",
            "\\x",
            "C:/x",
            "C:x",
            "a/b:stream",
            ".. /x",
            "a/.. ./x",
            "../",
            "",
            "./",
        ] {
            assert!(sanitize(bad).is_none(), "{bad:?} accepted");
        }
    }

    #[test]
    fn hazards_are_neutralised() {
        assert_eq!(
            sanitize("a/b/c.txt").unwrap(),
            Path::new("a").join("b").join("c.txt")
        );
        assert_eq!(sanitize("dir./x. ").unwrap(), Path::new("dir").join("x"));
        assert_eq!(sanitize("CON").unwrap(), Path::new("_CON"));
        assert_eq!(
            sanitize("x/nul.txt").unwrap(),
            Path::new("x").join("_nul.txt")
        );
        assert_eq!(sanitize("com1.log").unwrap(), Path::new("_com1.log"));
        assert_eq!(sanitize("com10.log").unwrap(), Path::new("com10.log"));
        assert_eq!(sanitize("a?b*.txt").unwrap(), Path::new("a_b_.txt"));
        assert_eq!(sanitize("tab\there").unwrap(), Path::new("tab_here"));
        assert_eq!(sanitize("a/./b").unwrap(), Path::new("a").join("b"));
    }
}
