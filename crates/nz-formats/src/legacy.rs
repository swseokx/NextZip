//! Legacy archivers through `unarc-rs` (pure Rust, MIT OR Apache-2.0):
//! ACE, ARC/PAK, ARJ, ZOO, LHA/LZH, HA, UC2, SQ, SQZ, HYP, JAR (ARJ
//! Software), CAB, Amiga LZX/DMS/ADF, Commodore D64/T64/Lynx, Atari ATR,
//! Pack-Ice and FAT floppy images.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use unarc_rs::unified::{ArchiveEntry, ArchiveFormat, UnifiedArchive};
use unarc_rs::{ArchiveEntryKind, ArchiveOptions, VolumeProvider};

use crate::{Format, FormatError, Listing, Member, Options, Sink, limits, util};

fn to_unarc(f: Format) -> Option<ArchiveFormat> {
    Some(match f {
        Format::Ace => ArchiveFormat::Ace,
        Format::Arc => ArchiveFormat::Arc,
        Format::Arj => ArchiveFormat::Arj,
        Format::Zoo => ArchiveFormat::Zoo,
        Format::Lha => ArchiveFormat::Lha,
        Format::Ha => ArchiveFormat::Ha,
        Format::Uc2 => ArchiveFormat::Uc2,
        Format::Sq => ArchiveFormat::Sq,
        Format::Sqz => ArchiveFormat::Sqz,
        Format::Hyp => ArchiveFormat::Hyp,
        Format::Jar32 => ArchiveFormat::Jar,
        Format::Cab => ArchiveFormat::Cab,
        Format::AmigaLzx => ArchiveFormat::Lzx,
        Format::Dms => ArchiveFormat::Dms,
        Format::Adf => ArchiveFormat::Adf,
        Format::Hdf => ArchiveFormat::Hdf,
        Format::D64 => ArchiveFormat::D64,
        Format::T64 => ArchiveFormat::T64,
        Format::Lynx => ArchiveFormat::Lynx,
        Format::Atr => ArchiveFormat::Atr,
        Format::PackIce => ArchiveFormat::PackIce,
        Format::Ice => ArchiveFormat::Ice,
        Format::Fat => ArchiveFormat::Fat,
        Format::ZipFull => ArchiveFormat::Zip,
        Format::SevenZ => ArchiveFormat::SevenZ,
        _ => return None,
    })
}

/// Read through unarc-rs.
pub(crate) fn is_legacy(f: Format) -> bool {
    to_unarc(f).is_some()
}

fn from_unarc(f: ArchiveFormat) -> Option<Format> {
    Some(match f {
        ArchiveFormat::Ace => Format::Ace,
        ArchiveFormat::Arc => Format::Arc,
        ArchiveFormat::Arj => Format::Arj,
        ArchiveFormat::Zoo => Format::Zoo,
        ArchiveFormat::Lha => Format::Lha,
        ArchiveFormat::Ha => Format::Ha,
        ArchiveFormat::Uc2 => Format::Uc2,
        ArchiveFormat::Sq => Format::Sq,
        ArchiveFormat::Sqz => Format::Sqz,
        ArchiveFormat::Hyp => Format::Hyp,
        ArchiveFormat::Jar => Format::Jar32,
        ArchiveFormat::Cab => Format::Cab,
        ArchiveFormat::Lzx => Format::AmigaLzx,
        ArchiveFormat::Dms => Format::Dms,
        ArchiveFormat::Adf => Format::Adf,
        ArchiveFormat::Hdf => Format::Hdf,
        ArchiveFormat::D64 => Format::D64,
        ArchiveFormat::T64 => Format::T64,
        ArchiveFormat::Lynx => Format::Lynx,
        ArchiveFormat::Atr => Format::Atr,
        ArchiveFormat::PackIce => Format::PackIce,
        ArchiveFormat::Ice => Format::Ice,
        ArchiveFormat::Fat => Format::Fat,
        // Formats NextZip reads with its own code (ZIP, 7z, RAR, tar and
        // the single-stream compressors) are not routed here.
        _ => return None,
    })
}

/// Content (and, for magic-less images, name) based detection.
pub(crate) fn detect(path: &Path, _head: &[u8]) -> Option<Format> {
    let mut f = File::open(path).ok()?;
    let found = ArchiveFormat::detect(&mut f, Some(path)).ok().flatten()?;
    // `detect` falls back to the extension when the content has no magic;
    // only accept that for formats whose content check is the extension
    // itself (disk images without a signature).
    from_unarc(found)
}

/// Sibling volumes of split ARJ (`.a01`…) and ACE (`.c00`…) sets.
struct Volumes {
    paths: Vec<PathBuf>,
}

impl VolumeProvider for Volumes {
    fn open_volume(&self, n: u32) -> Option<Box<dyn Read + Send>> {
        let p = self.paths.get(n as usize)?;
        File::open(p)
            .ok()
            .map(|f| Box::new(BufReader::new(f)) as Box<dyn Read + Send>)
    }
}

fn volume_paths(format: Format, path: &Path) -> Vec<PathBuf> {
    let mut v = vec![path.to_path_buf()];
    let name = |i: u32| -> Option<String> {
        match format {
            Format::Arj => Some(format!("a{i:02}")),
            Format::Ace => Some(format!("c{:02}", i - 1)),
            _ => None,
        }
    };
    for i in 1..100 {
        let Some(ext) = name(i) else { break };
        let p = path.with_extension(&ext);
        let upper = path.with_extension(ext.to_ascii_uppercase());
        if p.is_file() {
            v.push(p);
        } else if upper.is_file() {
            v.push(upper);
        } else {
            break;
        }
    }
    v
}

fn open(
    format: Format,
    path: &Path,
    opt: &Options,
) -> Result<(UnifiedArchive<BufReader<util::Concat>>, Vec<PathBuf>)> {
    // Split `.001` ZIP / 7z sets are read as one joined file.
    let split = match format {
        Format::ZipFull | Format::SevenZ => util::split_volumes(path),
        _ => None,
    };
    let volumes = split.clone().unwrap_or_else(|| volume_paths(format, path));
    let mut o = ArchiveOptions::new()
        .with_verify_crc(true)
        .with_max_entry_size(Some(limits::MAX_MEMBER));
    if let Some(pw) = &opt.password {
        o = o.with_password(pw.clone());
    }
    if volumes.len() > 1 && split.is_none() {
        o = o.with_volume_provider_arc(Arc::new(Volumes {
            paths: volumes.clone(),
        }));
    }
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("st"))
    {
        o = o.with_fat_atari_names(true);
    }
    let mut joined = util::Concat::open(split.as_deref().unwrap_or(&[path.to_path_buf()]))?;
    // A 7z self-extractor: the archive starts after the stub.
    if format == Format::SevenZ
        && split.is_none()
        && let Some(util::Embedded::SevenZ(off)) = sfx_7z(path)
    {
        joined = joined.skip_prefix(off);
    }
    let f = BufReader::new(joined);
    let mut a = to_unarc(format)
        .ok_or_else(|| anyhow!("not a legacy format"))?
        .open_with_options(f, o)
        .map_err(map_err)?;
    if matches!(
        format,
        Format::Dms | Format::Sq | Format::PackIce | Format::Ice
    ) && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
    {
        a.set_single_file_name(stem.to_string());
    }
    Ok((a, volumes))
}

/// The 7z payload offset when `path` does not start with a 7z signature.
fn sfx_7z(path: &Path) -> Option<util::Embedded> {
    let mut sig = [0u8; 6];
    File::open(path).ok()?.read_exact(&mut sig).ok()?;
    if &sig == b"7z\xBC\xAF\x27\x1C" {
        return None;
    }
    util::embedded(path)
}

fn map_err(e: unarc_rs::ArchiveError) -> anyhow::Error {
    use unarc_rs::ArchiveError as E;
    match e {
        E::PasswordRequired { .. } | E::EncryptionRequired { .. } => {
            FormatError::PasswordRequired.into()
        }
        E::InvalidPassword { .. } => FormatError::WrongPassword.into(),
        E::UnsupportedMethod { method, format } => {
            FormatError::Unsupported(nz_front::trf("{} 압축 방식 {}", &[&format, &method])).into()
        }
        // sevenz-rust2 / zip errors arrive as text.
        E::ExternalLibrary { message, .. } if message.starts_with("PasswordRequired") => {
            FormatError::PasswordRequired.into()
        }
        E::ExternalLibrary { message, .. }
            if message.starts_with("MaybeBadPassword")
                || message.contains("InvalidPassword")
                || message.contains("invalid password") =>
        {
            FormatError::WrongPassword.into()
        }
        other => anyhow!(other.to_string()),
    }
}

/// delharc (LHA) renders non-ASCII name bytes as lowercase `%xx`; undo
/// that for bytes 0x80..=0xFF so the caller can detect the code page.
/// Control bytes stay escaped.
fn lha_raw_name(name: &str) -> Option<Vec<u8>> {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut any = false;
    let mut lead = false;
    while i < b.len() {
        let hex = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
            && (h << 4 | l) >= 0x80
        {
            let v = h << 4 | l;
            out.push(v);
            any = true;
            // A double-byte lead (CP949 / Shift-JIS / GBK / Big5) whose
            // trail byte was 0x5C: delharc turned that '\' into '_'.
            lead = !lead && v >= 0x81 && v != 0xFF;
            i += 3;
            if lead && b.get(i) == Some(&b'_') {
                out.push(b'\\');
                lead = false;
                i += 1;
            }
            continue;
        }
        lead = false;
        out.push(b[i]);
        i += 1;
    }
    any.then_some(out)
}

fn member(format: Format, e: &ArchiveEntry) -> Member {
    let kind = e.kind();
    let mtime = e.modified_time().and_then(|t| {
        crate::dos_to_unix(
            i64::from(t.year()),
            i64::from(t.month()),
            i64::from(t.day()),
            i64::from(t.hour()),
            i64::from(t.minute()),
            i64::from(t.second()),
        )
    });
    let mut name = e.name().replace('\\', "/");
    let mut link = match kind {
        ArchiveEntryKind::SymbolicLink | ArchiveEntryKind::HardLink => {
            Some(e.link_target().unwrap_or_default().to_string())
        }
        _ => None,
    };
    // LHA stores a symbolic link as "name|target".
    let mut split = false;
    if matches!(format, Format::Lha | Format::Ice)
        && link.as_deref().is_some_and(str::is_empty)
        && let Some((n, t)) = name.split_once('|')
    {
        link = Some(t.to_string());
        name = n.to_string();
        split = true;
    }
    Member {
        name,
        is_dir: e.is_directory() || kind == ArchiveEntryKind::Directory,
        size: e.original_size(),
        csize: e.compressed_size(),
        mtime,
        method: e.compression_method().to_string(),
        crc: u32::try_from(e.crc()).ok().filter(|c| *c != 0),
        encrypted: e.is_encrypted(),
        link,
        raw_name: if matches!(format, Format::Lha | Format::Ice) && !split {
            lha_raw_name(&e.name().replace('\\', "/"))
        } else {
            None
        },
    }
}

pub(crate) fn list(format: Format, path: &Path, opt: &Options) -> Result<Listing> {
    let (mut a, volumes) = open(format, path, opt)?;
    let mut members = Vec::new();
    while let Some(e) = a.next_entry().map_err(map_err)? {
        if members.len() >= limits::MAX_MEMBERS {
            return Err(anyhow!("too many members"));
        }
        members.push(member(format, &e));
        // Sequential readers need the cursor moved past the data.
        a.skip(&e).map_err(map_err)?;
    }
    Ok(Listing {
        members,
        solid: false,
        volumes,
    })
}

pub(crate) fn extract(
    format: Format,
    path: &Path,
    opt: &Options,
    sink: &mut dyn Sink,
) -> Result<()> {
    let (mut a, _) = open(format, path, opt)?;
    let mut i = 0usize;
    while let Some(e) = a.next_entry().map_err(map_err)? {
        let m = member(format, &e);
        let index = i;
        i += 1;
        if m.is_dir || m.link.is_some() || !matches!(e.kind(), ArchiveEntryKind::File) {
            a.skip(&e).map_err(map_err)?;
            continue;
        }
        if !sink.start(index, &m)? {
            a.skip(&e).map_err(map_err)?;
            continue;
        }
        let data = a.read(&e).map_err(map_err)?;
        sink.data(&data)?;
        sink.finish()?;
    }
    Ok(())
}
