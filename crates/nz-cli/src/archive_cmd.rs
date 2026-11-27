//! `nz x` and `nz l` on top of `nz-archive` (every readable format, code
//! page detection for legacy names, passwords).

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Result, bail};
use nz_archive::{Codepage, Options};

use crate::Args;

fn options(a: &Args) -> Result<Options> {
    let prefs = nz_front::prefs::Prefs::load();
    let codepage = match a.get("cp") {
        Some(s) => Some(Codepage::parse(s).ok_or_else(|| {
            anyhow::anyhow!("unknown code page '{s}' (949, 932, 936, 950, 437, 866, 1252, utf8)")
        })?),
        None => None,
    };
    Ok(Options {
        codepage,
        hint: None,
        password: a.get("p").map(str::to_owned),
        threads: a.num::<usize>("t")?.unwrap_or(0),
        malware_scan: if a.has("noscan") {
            false
        } else {
            a.has("scan") || prefs.malware_scan
        },
        symlinks: a.has("symlinks") || prefs.symlinks,
    })
}

/// Default output folder: the archive name without its archive extension(s).
pub fn default_out(archive: &Path) -> PathBuf {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    let mut stem = name.clone();
    for ext in [
        ".tar.zst", ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.lz4", ".tzst", ".tgz", ".txz", ".tbz2",
        ".tbz", ".tlz4", ".tar", ".zip", ".7z", ".nz", ".alz", ".egg", ".rar", ".zipx",
    ] {
        if lower.ends_with(ext) {
            stem.truncate(name.len() - ext.len());
            break;
        }
    }
    // Any other single extension (x.gz, x.lzh, x.iso, ...).
    if stem == name
        && let Some((b, _)) = name.rsplit_once('.').filter(|(b, _)| !b.is_empty())
    {
        stem = b.to_string();
    }
    // Split volumes: "x.vol1" (EGG) and "x.part01" (RAR).
    for marker in [".vol", ".part"] {
        if let Some(i) = stem.to_ascii_lowercase().rfind(marker)
            && stem[i + marker.len()..].chars().all(|c| c.is_ascii_digit())
            && stem.len() > i + marker.len()
        {
            stem.truncate(i);
        }
    }
    archive.with_file_name(stem)
}

pub fn cmd_extract(a: &Args) -> Result<()> {
    a.check_known(&[
        "o", "t", "q", "cp", "p", "scan", "noscan", "symlinks", "snap", "verify",
    ])?;
    let Some(archive) = a.pos.first() else {
        bail!("usage: nz x [-o:<dir>] [-p:<password>] [-cp:<codepage>] <archive>");
    };
    let archive = Path::new(archive);
    let out = a
        .get("o")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_out(archive));
    if nz_nzf::sniff(archive) {
        return crate::nz_cmd::cmd_extract(a, archive, &out);
    }
    let mut opt = options(a)?;
    let t0 = Instant::now();
    let prog = nz_archive::Progress::default();
    let r = nz_archive::extract(archive, &out, &opt, Some(&prog));
    if let Ok(notes) = prog.notes.lock() {
        for n in notes.iter() {
            eprintln!("nz: {n}");
        }
    }
    opt.forget_password();
    let s = r?;
    if !a.has("q") {
        println!(
            "{} -> {}: {} files, {} dirs, {} bytes, {:.3}s",
            archive.display(),
            out.display(),
            s.files,
            s.dirs,
            s.bytes,
            t0.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

pub fn cmd_list(a: &Args) -> Result<()> {
    a.check_known(&["cp", "p", "json", "snap"])?;
    let Some(archive) = a.pos.first() else {
        bail!("usage: nz l [-cp:<codepage>] [-p:<password>] [-json] <archive>");
    };
    if nz_nzf::sniff(Path::new(archive)) {
        return crate::nz_cmd::cmd_list(a, Path::new(archive));
    }
    let opt = Options {
        malware_scan: false,
        ..options(a)?
    };
    let l = nz_archive::list(Path::new(archive), &opt)?;
    if a.has("json") {
        println!("{}", serde_json::to_string_pretty(&l)?);
        return Ok(());
    }
    println!(
        "{archive}: {}{}{}",
        l.kind.label(),
        if l.solid { ", solid" } else { "" },
        if l.volumes.len() > 1 {
            format!(", {} volumes", l.volumes.len())
        } else {
            String::new()
        }
    );
    if let Some(d) = &l.detection {
        println!("names: {}", d.summary_ko());
    } else if let Some(cp) = l.codepage {
        println!("names: {} (forced)", cp.label());
    }
    println!("{:>14} {:>14}  {:<18} name", "size", "packed", "method");
    for e in &l.entries {
        println!(
            "{:>14} {:>14}  {:<18} {}{}{}",
            e.size,
            e.csize,
            e.method,
            if e.encrypted { "*" } else { "" },
            e.name,
            if e.is_dir { "/" } else { "" }
        );
    }
    println!(
        "{} files, {} bytes, {} packed",
        l.files(),
        l.total_size(),
        l.total_csize()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_folder_names() {
        let d = |s: &str| default_out(Path::new(s)).to_string_lossy().into_owned();
        assert_eq!(d("a.zip"), "a");
        assert_eq!(d("a.tar.zst"), "a");
        assert_eq!(d("자료.ALZ"), "자료");
        assert_eq!(d("big.vol1.egg"), "big");
        assert_eq!(d("x.part01.rar"), "x");
        assert_eq!(d("v.part.rar"), "v.part");
    }
}
