//! Deterministic input enumeration.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

/// One item to archive.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Archive path, `/`-separated, no leading slash; directories have no trailing slash.
    pub name: String,
    pub path: PathBuf,
    pub kind: Kind,
    pub size: u64,
    pub mtime: SystemTime,
}

/// Enumerate `sources` in a stable order.
///
/// A directory source contributes its *contents* (like `src\*`), a file source
/// contributes itself under its file name. Symlinks are skipped. Entries are
/// ordered depth-first with siblings sorted by byte-wise file name, so the
/// order never depends on the file system's enumeration order.
pub fn collect(sources: &[PathBuf]) -> Result<Vec<Entry>> {
    Ok(collect_items(sources, false)?
        .into_iter()
        .map(|i| i.entry)
        .collect())
}

/// An enumerated entry; for a symbolic link, `link` holds its target
/// (`/`-separated, as stored in the link) and `entry.kind` is [`Kind::File`]
/// with size 0. Links are never followed.
#[derive(Debug, Clone)]
pub struct Item {
    pub entry: Entry,
    pub link: Option<String>,
}

/// Like [`collect`], but with `links` symbolic links inside directory
/// sources are returned as [`Item`]s with a target instead of being skipped.
/// The order is the same as [`collect`] with the links in their sorted place.
pub fn collect_items(sources: &[PathBuf], links: bool) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for src in sources {
        let meta =
            std::fs::metadata(src).with_context(|| format!("cannot read {}", src.display()))?;
        if meta.is_file() {
            let name = src
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push(Item {
                entry: Entry {
                    name,
                    path: src.clone(),
                    kind: Kind::File,
                    size: meta.len(),
                    mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                },
                link: None,
            });
            continue;
        }
        out.extend(walk_dir(src, src, links)?);
    }
    Ok(out)
}

/// Contents of `dir` (depth-first, siblings sorted by file name), with
/// subdirectories enumerated in parallel on the current Rayon pool. The
/// order is the same as a sequential sorted walk.
fn walk_dir(root: &Path, dir: &Path, links: bool) -> Result<Vec<Item>> {
    use rayon::prelude::*;
    let mut items = Vec::new();
    for item in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let item = item?;
        let ft = item.file_type()?;
        let link = if ft.is_symlink() {
            if !links {
                continue;
            }
            let t = std::fs::read_link(item.path())
                .with_context(|| format!("cannot read link {}", item.path().display()))?;
            Some(t.to_string_lossy().replace('\\', "/"))
        } else {
            None
        };
        // On Windows the directory listing already carries the metadata, but
        // NTFS keeps a *directory's* timestamps in its parent's index stale
        // until that directory itself is enumerated: a directory whose
        // children were just written reports its creation-time mtime on the
        // first walk and the real one afterwards, which made output depend
        // on whether the tree had been listed before. Directories are few, so
        // ask the directory itself.
        let is_dir = ft.is_dir() && link.is_none();
        let meta = if is_dir {
            std::fs::metadata(item.path())
                .with_context(|| format!("cannot read {}", item.path().display()))?
        } else {
            item.metadata()?
        };
        items.push((item.file_name(), item.path(), is_dir, meta, link));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let parts: Vec<Result<Vec<Item>>> = items
        .into_par_iter()
        .map(|(_, path, is_dir, meta, link)| -> Result<Vec<Item>> {
            let mut v = vec![Item {
                entry: Entry {
                    name: archive_name(root, &path),
                    kind: if is_dir { Kind::Dir } else { Kind::File },
                    size: if is_dir || link.is_some() {
                        0
                    } else {
                        meta.len()
                    },
                    mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    path: path.clone(),
                },
                link,
            }];
            if is_dir {
                v.extend(walk_dir(root, &path, links)?);
            }
            Ok(v)
        })
        .collect();
    let mut out = Vec::new();
    for p in parts {
        out.extend(p?);
    }
    Ok(out)
}

fn archive_name(root: &Path, p: &Path) -> String {
    let rel = p.strip_prefix(root).unwrap_or(p);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Windows reserved device names, also with an extension (`nul.txt`).
fn is_reserved_name(part: &str) -> bool {
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
    let b = stem.as_bytes();
    b.len() == 4
        && (b.starts_with(b"COM") || b.starts_with(b"LPT"))
        && (b'1'..=b'9').contains(&b[3])
}

/// Sum of file sizes.
pub fn total_bytes(entries: &[Entry]) -> u64 {
    entries.iter().map(|e| e.size).sum()
}

/// Reject archive member names that could escape the output directory.
///
/// Windows drops trailing dots and spaces from path components, so `.. `
/// or `...` would name the parent folder: such components are rejected,
/// and trailing dots and spaces are trimmed from the rest (M5 security
/// review; same rules as `nz_archive::safepath`). Reserved device names
/// (`CON`, `NUL`, `COM1`, ...) get a leading `_`.
pub fn safe_relative(name: &str) -> Option<PathBuf> {
    let mut p = PathBuf::new();
    for part in name.split(['/', '\\']) {
        if part.contains("..") && part.chars().all(|c| c == '.' || c == ' ') {
            return None;
        }
        let part = part.trim_end_matches(['.', ' ']);
        match part {
            "" => continue,
            _ => {
                if part.contains(':') || part.contains('\0') || part.trim_start() == ".." {
                    return None;
                }
                if is_reserved_name(part) {
                    p.push(format!("_{part}"));
                } else {
                    p.push(part);
                }
            }
        }
    }
    if name.starts_with('/') || name.starts_with('\\') || p.as_os_str().is_empty() {
        return None;
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal() {
        assert!(safe_relative("../x").is_none());
        assert!(safe_relative("a/../../x").is_none());
        assert!(safe_relative("/etc/passwd").is_none());
        assert!(safe_relative("C:/x").is_none());
        assert!(safe_relative("\\x").is_none());
        // Windows trims trailing dots and spaces: these name the parent.
        assert!(safe_relative(".. /x").is_none());
        assert!(safe_relative("a/... /x").is_none());
        assert!(safe_relative("a/.. ./x").is_none());
        assert!(safe_relative("a\\.. \\x").is_none());
        assert_eq!(
            safe_relative("dir./x. ").unwrap(),
            Path::new("dir").join("x")
        );
        assert_eq!(safe_relative("con.txt").unwrap(), Path::new("_con.txt"));
        assert_eq!(
            safe_relative("a/LPT1").unwrap(),
            Path::new("a").join("_LPT1")
        );
        assert_eq!(safe_relative("com10").unwrap(), Path::new("com10"));
        assert_eq!(
            safe_relative("a/b/c.txt").unwrap(),
            Path::new("a").join("b").join("c.txt")
        );
    }

    /// A directory whose children were written after it was created must
    /// report its current mtime on the very first walk (NTFS keeps a stale
    /// copy in the parent's index until the directory is listed).
    #[test]
    fn fresh_directory_mtime_on_first_walk() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(sub.join("f.txt"), b"x").unwrap();
        // Walk first: opening `sub` (as `fs::metadata` does) refreshes the
        // parent's copy.
        let first = collect(&[d.path().to_path_buf()]).unwrap();
        let real = std::fs::metadata(&sub).unwrap().modified().unwrap();
        assert_eq!(first[0].name, "sub");
        assert_eq!(first[0].mtime, real);
    }

    #[test]
    fn order_is_sorted_depth_first() {
        let d = tempfile::tempdir().unwrap();
        for p in ["b/2.txt", "b/1.txt", "a.txt", "c/x/y.txt"] {
            let f = d.path().join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, p).unwrap();
        }
        let names: Vec<_> = collect(&[d.path().to_path_buf()])
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            names,
            ["a.txt", "b", "b/1.txt", "b/2.txt", "c", "c/x", "c/x/y.txt"]
        );
    }
}
