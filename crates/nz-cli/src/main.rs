//! `nz` - NextZip command line (M0 prototype).
//!
//! ```text
//! nz c [-fmt:zip|7z|tar|tar.gz|tar.xz|tar.bz2|tar.lz4|tar.zst] [-l:N] [-t:N] <out> <src>...
//! nz x [-o:<dir>] [-t:N] [-p:<pw>] [-cp:<codepage>] [-noscan] <archive>
//! nz l [-cp:<codepage>] [-p:<pw>] [-json] <archive>
//! nz bench <dir> [-runs:5] [-t:N] [-cases:<list>] [-ref:<exe>] [-json:<file>] [-md:<file>]
//! ```

mod archive_cmd;
mod bench;
mod nz_cmd;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use nz_core::lzma::Lzma2Params;
use nz_core::{CompressOptions, Format};

const USAGE: &str = "\
nz - NextZip 1.0

USAGE:
  nz c [options] <out> <src>...     create archive (a directory adds its contents)
  nz x [options] <archive>          extract archive
  nz t [-p:<pw>] <archive.nz>       test a .nz archive (recovery record + every block)
  nz repair [-rr:%] <in.nz> [out]   rewrite a damaged .nz archive from its recovery record
  nz backup [options] <a.nz> <src>  add a deduplicated snapshot (creates the archive)
  nz snapshots <a.nz>               list backup snapshots
  nz restore [-snap:N] [-o:dir] <a.nz>  restore a snapshot (default: latest)
  nz bench <dir> [options]          benchmark compression on <dir>

COMPRESS OPTIONS:
  -fmt:<fmt>         nz, zip, 7z, tar, tar.gz (tgz), tar.xz (txz), tar.bz2 (tbz2),
                     tar.lz4, tar.zst (default: from <out> extension, else zip);
                     zipx, iso, and gz, xz, bz2, zst, lz4 for one file;
                     exe / sfx-x64 / sfx-arm64: self-extracting .exe (7z inside)
  -zm:<method>       zipx member method: zstd (default), lzma, ppmd, xz, bzip2
  -l:N               level 0..9 (default 5)
  .nz (also nz backup):
  -rr:<percent>      recovery record 0..30 % (default 3, 0 = none)
  -p:<password>      encrypt data and names (Argon2id key)
  -em:aes|chacha     AES-256-GCM (default) or ChaCha20-Poly1305
  -block:KiB         block size (default 4096, 16384 at -l:7/8, 32768 at -l:9)
  -label:<text>      snapshot label
  -noads             do not store NTFS alternate data streams (stored by default)
  -t:N               threads (default: all logical CPUs)
  -dl:N              raw libdeflate level 1..12 (zip)
  -dlb:N             libdeflate level for non-text (binary) files (zip, default: as -dl / -l)
  -chunk:KB          parallel Deflate chunk size in KiB (zip, default 128)
  -zl:N              raw zstd level 1..22 (tar.zst)
  -wlog:N            zstd long-distance window log, 0 = off (tar.zst)
  -job:MiB           zstd multithread job size (tar.zst, 0 = level default)
  -ovlog:N           zstd multithread overlap log 1..9 (tar.zst, 0 = level default)
  -nosort            keep walk order instead of grouping by extension (tar.zst)
  -noplan            disable the incompressible-data planner
  7z (every value below overrides the -l preset; sizes in KiB):
  -xl:N              LZMA2 preset 0..9 for text and x86 code
  -xle:N             LZMA2 preset for x86 code only
  -xlo:N  -xlf:N     LZMA2 preset for other data / mostly-compressed files
  -mf:<mf>           match finder and mode: hc4 (fast), bt4 (normal), hc4n (hc4 normal),
                     bt4f (bt4 fast), bt3, bt2 (normal); -omf other data, -emf x86 code
  -nice:N -depth:N   nice length 2..273, match finder depth (-o.. other data, -e.. x86 code)
  -lc:N -lp:N -pb:N  literal context / position bits (-olc.. other data, -elc.. x86 code)
  -dict:KiB          dictionary for text and code; -odict other data, -edict x86 code
  -block:KiB         solid block size (default max(4 MiB, total / 12))
  -seg:KiB           LZMA2 parallel segment size for text (default 2048)
  -pre:KiB           chained-segment preload for text (default 0 = independent)
  -oseg:KiB          segment size for other data (default 1024 at -l:5..8)
  -opre:KiB          chained preload for other data (default 1024 at -l:5+)
  -eblock:KiB -eseg:KiB -epre:KiB  x86 code block, segment, preload (65536, 4096, 4096)
  -fast:lzma2|deflate|copy|zstd  codec for mostly-compressed files (default lzma2)
  -fastl:N           libdeflate level for -fast:deflate (default 6)
  -fastzl:N          zstd level for -fast:zstd (default 18, 19 at -l:9)
  -ppmd:N            PPMd (order N, 2..32) instead of LZMA2 for text
  -ppmdmem:MiB       PPMd model memory (default 64)
  -pblock:KiB        PPMd text block size (default: as -block)
  -nobcj             no BCJ x86 filter on executables
  -noclass           no per-type routing: one LZMA2 class for all data
  -plan              keep the fast / store tiers at levels 6..9 (off there by default)
  -zipc:zstd|lzma2   codec for ZIP-family containers (JAR, ZIP, APK...; default zstd)
  -zipl:N -zipw:N    zstd level (default 3/9/12/19 by -l) and long window log (27, 0 = off)

EXTRACT / LIST (nz x, nz l): ZIP, 7Z, TAR.ZST, ALZ, EGG, RAR
  -o:<dir>           output directory (default: archive name without extension)
  -t:N               threads
  -p:<password>      password for encrypted archives
  -cp:<codepage>     force the code page of legacy names (949, 932, 936, 950,
                     437, 866, 1252, utf8); default: detected statistically
  -json              (nz l) print the listing as JSON
  -noscan            (nz x) do not scan extracted files with Windows AMSI
  -scan              (nz x) scan even if the malware_scan setting is off
                     default: the malware_scan setting (on unless turned off)
  -symlinks          (nz x) recreate tar symbolic links as links (default: a
                     link becomes a text file holding its target path)

GLOBAL OPTIONS:
  -lang:<ko|en|auto> language of messages from the archive library
                     (default: NZ_LANG, else the language setting, else Windows)

ENVIRONMENT:
  NZ_MEM_MIB=N       memory budget in MiB (default: half the free RAM, 256..880);
                     changes scheduling only, never the archive bytes
  NZ_LANG=ko|en      message language (see -lang)
  NZ_SETTINGS=<file> settings file (default %LOCALAPPDATA%\\NextZip\\settings.txt)

BENCH OPTIONS:
  -runs:N            timed runs per case, median reported (default 5)
  -t:N               threads
  -cases:<list>      comma separated, e.g. zip:5,tar.zst:5,tar.zst:5:zl=12
                     case = fmt:level[:key=value...], keys dl chunk zl wlog noplan
  -ref:<exe>         also run an external console archiver as a reference
                     (`<exe> c -fmt:F -l:L -y -r <arc> <dir>\\*`, `<exe> x -y -o:<dir> <arc>`;
                     zip:5 and 7z:5 unless -refcases)
  -refcases:<list>   reference tool cases, e.g. zip:5,7z:5
  -json:<file>       write results as JSON (default: print JSON after the table)
  -md:<file>         write results as a Markdown table
  -tmp:<dir>         scratch directory for archives (default: system temp)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nz: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Split `-key:value` / `-flag` options from positional arguments.
pub(crate) struct Args {
    pub opts: Vec<(String, Option<String>)>,
    pub pos: Vec<String>,
}

impl Args {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = Vec::new();
        let mut pos = Vec::new();
        for a in args {
            if let Some(rest) = a
                .strip_prefix('-')
                .filter(|r| !r.is_empty() && !a.starts_with("--"))
            {
                match rest.split_once(':') {
                    Some((k, v)) => opts.push((k.to_ascii_lowercase(), Some(v.to_string()))),
                    None => opts.push((rest.to_ascii_lowercase(), None)),
                }
            } else if let Some(rest) = a.strip_prefix("--") {
                match rest.split_once('=') {
                    Some((k, v)) => opts.push((k.to_ascii_lowercase(), Some(v.to_string()))),
                    None => opts.push((rest.to_ascii_lowercase(), None)),
                }
            } else {
                pos.push(a.clone());
            }
        }
        Self { opts, pos }
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }
    pub fn has(&self, key: &str) -> bool {
        self.opts.iter().any(|(k, _)| k == key)
    }
    pub fn num<T: std::str::FromStr>(&self, key: &str) -> Result<Option<T>> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| anyhow::anyhow!("invalid value for -{key}: {v}")),
        }
    }
    pub fn check_known(&self, known: &[&str]) -> Result<()> {
        for (k, _) in &self.opts {
            if !known.contains(&k.as_str()) {
                bail!("unknown option -{k}\n\n{USAGE}");
            }
        }
        Ok(())
    }
}

fn run(args: &[String]) -> Result<()> {
    // Global options (-lang) may also come before the command.
    let lead = args
        .iter()
        .take_while(|a| a.to_ascii_lowercase().starts_with("-lang:"))
        .count();
    let (global, args) = args.split_at(lead);
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    let mut all = global.to_vec();
    all.extend_from_slice(&args[1..]);
    let mut rest = Args::parse(&all);
    set_language(&mut rest)?;
    match cmd.as_str() {
        "c" | "a" => cmd_compress(&rest),
        "x" => archive_cmd::cmd_extract(&rest),
        "l" => archive_cmd::cmd_list(&rest),
        "t" => nz_cmd::cmd_test(&rest),
        "repair" => nz_cmd::cmd_repair(&rest),
        "backup" => nz_cmd::cmd_backup(&rest),
        "snapshots" => nz_cmd::cmd_snapshots(&rest),
        "restore" => nz_cmd::cmd_restore(&rest),
        "bench" => bench::run(&rest),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => bail!("unknown command '{other}'\n\n{USAGE}"),
    }
}

/// Apply `-lang:<ko|en|auto>` (removed from `a`), else the preferred
/// language (`NZ_LANG`, the setting, Windows).
fn set_language(a: &mut Args) -> Result<()> {
    use nz_front::i18n::{self, Lang};
    use nz_front::prefs::LangPref;
    let Some(v) = a.get("lang").map(str::to_owned) else {
        i18n::init();
        return Ok(());
    };
    a.opts.retain(|(k, _)| k != "lang");
    match LangPref::parse(&v) {
        Some(p) => i18n::set(Lang::resolve(p)),
        None => bail!("unknown language '{v}' (ko, en, auto)"),
    }
    Ok(())
}

/// Build compression options from `-fmt -l -t -dl -chunk -zl -wlog -noplan`.
pub(crate) fn compress_options(a: &Args, out: &str) -> Result<CompressOptions> {
    let format = match a.get("fmt") {
        Some(f) => Format::parse(f)?,
        None if out.to_ascii_lowercase().ends_with(".zst") => Format::TarZst,
        None => Format::from_name(out).unwrap_or(Format::Zip),
    };
    let level: u8 = a.num("l")?.unwrap_or(5);
    if level > 9 {
        bail!("level must be 0..9");
    }
    let threads = a
        .num::<usize>("t")?
        .unwrap_or_else(nz_core::default_threads);
    let mut o = CompressOptions::new(format, level, threads);
    o.zip.raw_level = a.num("dl")?;
    o.zip.bin_level = a.num("dlb")?;
    if let Some(kb) = a.num::<usize>("chunk")? {
        o.zip.chunk = kb * 1024;
    }
    o.zstd.raw_level = a.num("zl")?;
    o.zstd.window_log = a.num("wlog")?.unwrap_or(0);
    if let Some(j) = a.num("job")? {
        o.zstd.job_mib = j;
    }
    if let Some(v) = a.num("ovlog")? {
        o.zstd.overlap_log = v;
    }
    if a.has("nosort") {
        o.zstd.sort_by_ext = false;
    }
    if a.has("noplan") {
        o.zip.planner = false;
        o.zstd.planner = false;
        o.sevenz.planner = false;
    }
    // 7z: start from the level preset, then apply explicit overrides.
    let s = &mut o.sevenz;
    let tune = |x: &mut Lzma2Params, pre: &str| -> Result<()> {
        if let Some(m) = a.get(&format!("{pre}mf")) {
            x.mf = Some(nz_core::lzma::Mf::parse(m)?);
        }
        if let Some(v) = a.num(&format!("{pre}nice"))? {
            x.nice = Some(v);
        }
        if let Some(v) = a.num(&format!("{pre}depth"))? {
            x.depth = Some(v);
        }
        for (k, slot) in [("lc", &mut x.lc), ("lp", &mut x.lp), ("pb", &mut x.pb)] {
            if let Some(v) = a.num(&format!("{pre}{k}"))? {
                *slot = Some(v);
            }
        }
        if let Some(d) = a.num::<u64>(&format!("{pre}dict"))? {
            x.dict = Some((d * 1024).min(1 << 30) as u32);
        }
        Ok(())
    };
    if let Some(v) = a.num::<u32>("xl")? {
        s.text = Lzma2Params::preset(v.min(9));
        s.exec = s.text;
    }
    if let Some(v) = a.num::<u32>("xle")? {
        s.exec = Lzma2Params::preset(v.min(9));
    }
    if let Some(v) = a.num::<u32>("xlo")? {
        s.other = Lzma2Params::preset(v.min(9));
    }
    if let Some(v) = a.num::<u32>("xlf")? {
        s.fast_lzma = Lzma2Params::preset(v.min(9));
    }
    tune(&mut s.text, "")?;
    tune(&mut s.exec, "")?;
    tune(&mut s.exec, "e")?;
    tune(&mut s.other, "o")?;
    tune(&mut s.fast_lzma, "o")?;
    let kib = |k: &str| -> Result<Option<u64>> { Ok(a.num::<u64>(k)?.map(|v| v * 1024)) };
    if let Some(v) = kib("block")? {
        s.block = Some(v);
    }
    if let Some(v) = kib("seg")? {
        s.segment = Some(v);
    }
    if let Some(v) = kib("pre")? {
        s.preload = Some(v);
    }
    if let Some(v) = kib("oseg")? {
        s.other_seg = Some(v);
    }
    if let Some(v) = kib("opre")? {
        s.other_preload = v;
    }
    if let Some(v) = kib("eblock")? {
        s.exec_block = v;
    }
    if let Some(v) = kib("eseg")? {
        s.exec_seg = v;
    }
    if let Some(v) = kib("epre")? {
        s.exec_preload = v;
    }
    if let Some(f) = a.get("fast") {
        s.fast = nz_core::sevenz::FastCodec::parse(f)?;
    }
    if let Some(l) = a.num("fastl")? {
        s.fast_level = l;
    }
    if let Some(l) = a.num("fastzl")? {
        s.fast_zstd_level = l;
    }
    if let Some(o) = a.num::<u32>("ppmd")? {
        let mem = a.num::<u32>("ppmdmem")?.unwrap_or(64).min(4000) << 20;
        s.text_codec = nz_core::sevenz::TextCodec::Ppmd { order: o, mem };
    }
    if let Some(v) = kib("pblock")? {
        s.ppmd_block = Some(v);
    }
    if a.has("nobcj") {
        s.bcj = false;
    }
    if a.has("noclass") {
        s.classify = false;
    }
    if a.has("plan") {
        s.planner = true;
    }
    if let Some(c) = a.get("zipc") {
        s.zip_codec = nz_core::sevenz::ZipCodec::parse(c)?;
    }
    if let Some(l) = a.num("zipl")? {
        s.zip_level = l;
    }
    if let Some(w) = a.num("zipw")? {
        s.zip_wlog = w;
    }
    Ok(o)
}

/// Formats written by `nz-create` (single-file streams, ZIPX, ISO). A
/// single-file stream is chosen only when the one source is a file; folders
/// and several files keep going to tar.* in `nz-core`.
fn create_kind(a: &Args, out: &str, sources: &[PathBuf]) -> Result<Option<nz_create::Kind>> {
    let kind = match a.get("fmt") {
        Some(f) => nz_create::Kind::parse(f),
        None => nz_create::Kind::from_name(out.as_ref()),
    };
    let kind = match kind {
        Some(nz_create::Kind::Stream(_)) if !nz_create::stream::fits(sources) => None,
        Some(nz_create::Kind::Zipx(_)) => {
            let m = match a.get("zm") {
                Some(m) => nz_create::zipx::Method::parse(m)
                    .ok_or_else(|| anyhow::anyhow!("unknown ZIPX method '{m}'"))?,
                None => nz_create::zipx::Method::Zstd,
            };
            Some(nz_create::Kind::Zipx(m))
        }
        k => k,
    };
    Ok(kind)
}

fn cmd_create(a: &Args, kind: nz_create::Kind, out: &str, sources: &[PathBuf]) -> Result<()> {
    let level: u32 = a.num("l")?.unwrap_or(5);
    if level > 9 {
        bail!("level must be 0..9");
    }
    let opt = nz_create::Options {
        level,
        threads: a.num("t")?.unwrap_or(0),
        volume: None,
        sfx_stub: None,
    };
    let t0 = Instant::now();
    let s = nz_create::create(kind, sources, out.as_ref(), &opt)
        .with_context(|| format!("creating {out}"))?;
    if !a.has("q") {
        println!(
            "{out}: {} {} files, {} dirs, {} -> {} bytes, {:.3}s",
            kind.label(),
            s.files,
            s.dirs,
            s.bytes_in,
            s.bytes_out,
            t0.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

fn cmd_compress(a: &Args) -> Result<()> {
    a.check_known(&[
        "fmt", "l", "t", "dl", "dlb", "chunk", "zl", "wlog", "job", "ovlog", "nosort", "noplan",
        "q", "xl", "xle", "mf", "nice", "depth", "block", "seg", "fast", "fastl", "fastzl", "ppmd",
        "ppmdmem", "pblock", "nobcj", "noclass", "xlo", "xlf", "pre", "dict", "eblock", "eseg",
        "epre", "odict", "oseg", "opre", "lc", "lp", "pb", "olc", "olp", "opb", "omf", "onice",
        "odepth", "plan", "zipc", "zipl", "zipw", "zm", "rr", "p", "em", "noads", "emf", "enice",
        "edepth", "elc", "elp", "epb", "edict",
    ])?;
    if a.pos.len() < 2 {
        bail!("usage: nz c [options] <out> <src>...");
    }
    let out = &a.pos[0];
    let sources: Vec<PathBuf> = a.pos[1..].iter().map(PathBuf::from).collect();
    if nz_cmd::wants_nz(a, out) {
        return nz_cmd::cmd_create(a, out, &sources);
    }
    if a.has("rr") || a.has("p") || a.has("em") {
        bail!("-rr, -p and -em are .nz options (use -fmt:nz)");
    }
    if let Some(kind) = create_kind(a, out, &sources)? {
        return cmd_create(a, kind, out, &sources);
    }
    let opt = compress_options(a, out)?;
    let t0 = Instant::now();
    let s = nz_core::compress(&sources, out.as_ref(), &opt)
        .with_context(|| format!("creating {out}"))?;
    let secs = t0.elapsed().as_secs_f64();
    if !a.has("q") {
        let ratio = if s.input_bytes > 0 {
            100.0 * s.output_bytes as f64 / s.input_bytes as f64
        } else {
            0.0
        };
        println!(
            "{out}: {} files, {} dirs, {} -> {} bytes ({ratio:.2}%), {secs:.3}s, {:.1} MB/s, planner stored {}",
            s.files,
            s.dirs,
            s.input_bytes,
            s.output_bytes,
            s.input_bytes as f64 / 1048576.0 / secs.max(1e-9),
            s.stored_by_planner
        );
    }
    Ok(())
}
