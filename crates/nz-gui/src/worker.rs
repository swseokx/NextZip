//! Long operations run in a child process (`nextzip --worker ...`) so the
//! UI can pause them (suspend the child's threads) and cancel them (kill the
//! child) even though the engine has no cancellation points. The child
//! reports over stdout, one line per event:
//!
//! ```text
//! T <total bytes> <files>      size of the job, once known
//! P <done bytes> <files done>  progress
//! N <kind> <text>              smart-processing note (kind: info|ok|warn)
//! D <files> <in> <out> <stored> finished
//! E <code> <message>           failed (code: PASSWORD|WRONGPASSWORD|UNSUPPORTED|OTHER)
//! ```
//!
//! The password, when any, is the first stdin line (never on the command
//! line, where other processes could read it).

use nz_front::{tr, trf};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HWND, LPARAM, WPARAM};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessIoCounters, GetThreadTimes, IO_COUNTERS, OpenThread, ResumeThread,
    SuspendThread, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};
use windows::Win32::UI::WindowsAndMessaging::PostMessageW;

use crate::ui::WM_APP_WORK;

// ------------------------------------------------------------- child side

fn out(line: &str) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}");
    let _ = o.flush();
    crate::ui::trace(&format!("child {} {line}", std::process::id()));
}

fn fail(e: &anyhow::Error) -> i32 {
    use nz_archive::ArchiveError as A;
    let code = match nz_archive::archive_error(e) {
        Some(A::PasswordRequired) => "PASSWORD",
        Some(A::WrongPassword) => "WRONGPASSWORD",
        Some(A::Unsupported(_)) => "UNSUPPORTED",
        Some(A::MalwareFound(_)) => "MALWARE",
        _ => "OTHER",
    };
    out(&format!("E {code} {}", format!("{e:#}").replace('\n', " ")));
    1
}

fn read_password() -> Option<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    let pw = line.trim_end_matches(['\r', '\n']).to_string();
    zeroize::Zeroize::zeroize(&mut line);
    (!pw.is_empty()).then_some(pw)
}

/// (read, written) bytes of this process so far.
fn io_bytes() -> (u64, u64) {
    let mut c = IO_COUNTERS::default();
    unsafe {
        let _ = GetProcessIoCounters(GetCurrentProcess(), &mut c);
    }
    (c.ReadTransferCount, c.WriteTransferCount)
}

/// Extensions whose content is already compressed (the planner samples
/// them and usually stores them as-is).
const PACKED: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "heic", "avif", "mp3", "aac", "m4a", "ogg", "opus",
    "flac", "mp4", "m4v", "mkv", "webm", "mov", "avi", "zip", "7z", "rar", "gz", "tgz", "bz2",
    "xz", "zst", "lz4", "jar", "apk", "aab", "docx", "xlsx", "pptx", "odt", "epub", "cab", "msi",
    "woff", "woff2",
];
const TEXT: &[&str] = &[
    "txt", "md", "csv", "tsv", "json", "xml", "html", "htm", "css", "js", "ts", "tsx", "jsx", "rs",
    "c", "h", "cpp", "hpp", "cs", "java", "kt", "py", "rb", "go", "php", "sql", "yaml", "yml",
    "toml", "ini", "cfg", "log", "svg", "sh", "ps1", "bat", "lua",
];

fn ext(name: &str) -> String {
    Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn compress_child(args: &[String]) -> i32 {
    // compress <fmt> <level> <out> <src>...
    let (Some(fmt), Some(level), Some(dst)) = (args.first(), args.get(1), args.get(2)) else {
        out("E OTHER bad worker arguments");
        return 2;
    };
    let sources: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();
    // (files, input bytes, output bytes, files stored by the planner)
    let run = || -> anyhow::Result<(usize, u64, u64, usize)> {
        let format = Fmt::parse(fmt)?;
        let level: u8 = level.parse()?;
        let entries = nz_core::walk::collect(&sources)?;
        let total = nz_core::walk::total_bytes(&entries);
        let files: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == nz_core::walk::Kind::File)
            .collect();
        out(&format!("T {total} {}", files.len()));
        let packed: Vec<_> = files
            .iter()
            .filter(|e| PACKED.contains(&ext(&e.name).as_str()))
            .collect();
        if !packed.is_empty() {
            let mut kinds: Vec<String> =
                packed.iter().map(|e| ext(&e.name).to_uppercase()).collect();
            kinds.sort();
            kinds.dedup();
            kinds.truncate(3);
            out(&format!(
                "N warn {}",
                trf(
                    "{}·등 이미 압축된 파일 {}개({})는 표본을 보고 이득이 없으면 그대로 저장합니다",
                    &[
                        &kinds.join("·"),
                        &packed.len(),
                        &crate::ui::size(packed.iter().map(|e| e.size).sum()),
                    ],
                )
            ));
        }
        let text = files
            .iter()
            .filter(|e| TEXT.contains(&ext(&e.name).as_str()))
            .count();
        if text > 0 {
            let how = match format {
                Fmt::Nz => tr("확장자별로 묶고 중복을 제거해 압축합니다"),
                Fmt::Core(f) => match f {
                    nz_core::Format::SevenZ => tr("확장자별로 묶어 솔리드 압축합니다"),
                    nz_core::Format::Tar => tr("하나의 tar 스트림에 그대로 담습니다"),
                    nz_core::Format::TarZst
                    | nz_core::Format::TarGz
                    | nz_core::Format::TarXz
                    | nz_core::Format::TarBz2
                    | nz_core::Format::TarLz4 => tr("하나의 스트림으로 이어 압축합니다"),
                    nz_core::Format::Zip => tr("파일마다 병렬로 압축합니다"),
                },
            };
            out(&format!("N ok {}", trf("텍스트 {}개는 {}", &[&text, &how])));
        }
        let threads = nz_core::default_threads();
        out(&format!(
            "N info {}",
            trf("스레드 {}개 · 수준 {}", &[&threads, &level])
        ));
        let (base_r, base_w) = io_bytes();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d2 = done.clone();
        let ticker = std::thread::spawn(move || {
            while !d2.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                let (r, w) = io_bytes();
                let r = r.saturating_sub(base_r).min(total);
                // stdout lines are tiny next to the archive itself
                let w = w.saturating_sub(base_w);
                out(&format!("P {r} 0 {w}"));
            }
        });
        let r = match format {
            Fmt::Core(f) => {
                let opt = nz_core::CompressOptions::new(f, level, threads);
                nz_core::compress(&sources, Path::new(dst), &opt)
                    .map(|s| (s.files, s.input_bytes, s.output_bytes, s.stored_by_planner))
            }
            Fmt::Nz => {
                let opt = nz_nzf::WriteOptions {
                    method: nz_nzf::Method::for_level(level),
                    ..Default::default()
                };
                nz_core::cpu::pool(threads).and_then(|p| {
                    p.install(|| nz_nzf::create(&sources, Path::new(dst), &opt))
                        .map(|s| (s.files, s.input_bytes, s.output_bytes, 0))
                })
            }
        };
        done.store(true, Ordering::Relaxed);
        let _ = ticker.join();
        r
    };
    match run() {
        Ok((files, input, output, stored)) => {
            out(&format!("D {files} {input} {output} {stored}"));
            0
        }
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            fail(&e)
        }
    }
}

fn extract_child(args: &[String]) -> i32 {
    // extract <archive> <dest> [--cp N] [--test]
    let (Some(archive), Some(dest)) = (args.first(), args.get(1)) else {
        out("E OTHER bad worker arguments");
        return 2;
    };
    let prefs = nz_front::prefs::Prefs::load();
    let mut opt = nz_archive::Options {
        hint: crate::system_codepage(),
        malware_scan: prefs.malware_scan,
        symlinks: prefs.symlinks,
        ..Default::default()
    };
    let test = args.iter().any(|a| a == "--test");
    if let Some(i) = args.iter().position(|a| a == "--cp") {
        opt.codepage = args
            .get(i + 1)
            .and_then(|n| n.parse().ok())
            .and_then(nz_archive::Codepage::from_number);
    }
    opt.password = read_password();
    let archive = PathBuf::from(archive);
    let dest = PathBuf::from(dest);
    let run = || -> anyhow::Result<nz_archive::ExtractStats> {
        let listing = nz_archive::list(&archive, &opt)?;
        out(&format!("T {} {}", listing.total_size(), listing.files()));
        if let Some(d) = &listing.detection {
            let how = if opt.codepage.is_some() {
                tr("직접 지정")
            } else {
                tr("자동 판별")
            };
            out(&format!(
                "N info {}",
                trf("이름 인코딩 {}: {}", &[&how, &d.summary_ko()])
            ));
        }
        if listing.solid {
            out(&format!("N info {}", tr("솔리드 압축이라 순서대로 풉니다")));
        }
        if listing.volumes.len() > 1 {
            out(&format!(
                "N info {}",
                trf("분할 볼륨 {}개를 이어 읽습니다", &[&listing.volumes.len()])
            ));
        }
        let enc = listing.entries.iter().filter(|e| e.encrypted).count();
        if enc > 0 {
            out(&format!("N warn {}", trf("암호화된 항목 {}개", &[&enc])));
        }
        if opt.malware_scan {
            out(&format!(
                "N info {}",
                tr("풀기 전에 Windows 악성코드 검사(AMSI)를 합니다")
            ));
        }
        let threads = nz_core::default_threads();
        out(&format!(
            "N ok {}",
            trf(
                "{} 형식 · 스레드 {}개로 병렬 해제",
                &[&listing.kind.label(), &threads]
            )
        ));
        let prog = Arc::new(nz_archive::Progress::default());
        let p2 = prog.clone();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d2 = done.clone();
        let ticker = std::thread::spawn(move || {
            while !d2.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                out(&format!(
                    "P {} {}",
                    p2.done.load(Ordering::Relaxed),
                    p2.files.load(Ordering::Relaxed)
                ));
            }
        });
        let r = nz_archive::extract(&archive, &dest, &opt, Some(&prog));
        if let Ok(notes) = prog.notes.lock() {
            for n in notes.iter() {
                out(&format!("N warn {}", n.replace('\n', " ")));
            }
        }
        done.store(true, Ordering::Relaxed);
        let _ = ticker.join();
        r
    };
    let r = run();
    opt.forget_password();
    if test {
        let _ = std::fs::remove_dir_all(&dest);
    }
    match r {
        Ok(s) => {
            out(&format!(
                "D {} {} {} 0",
                s.files,
                std::fs::metadata(&archive).map(|m| m.len()).unwrap_or(0),
                s.bytes
            ));
            0
        }
        Err(e) => fail(&e),
    }
}

/// Entry point for `nextzip --worker <op> ...`.
pub fn run_child(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("compress") => compress_child(&args[1..]),
        Some("extract") => extract_child(&args[1..]),
        _ => {
            out("E OTHER unknown worker operation");
            2
        }
    }
}

// ------------------------------------------------------------ parent side

#[derive(Debug, Clone)]
pub enum Event {
    Total {
        bytes: u64,
        files: u64,
    },
    /// `written`: output bytes so far (compression only).
    Progress {
        bytes: u64,
        files: u64,
        written: u64,
    },
    Note {
        kind: NoteKind,
        text: String,
    },
    Done {
        files: u64,
        input: u64,
        output: u64,
        stored: u64,
    },
    Failed {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteKind {
    Info,
    Ok,
    Warn,
}

fn parse(line: &str) -> Option<Event> {
    let (tag, rest) = line.split_once(' ').unwrap_or((line, ""));
    let nums = || -> Vec<u64> { rest.split(' ').filter_map(|x| x.parse().ok()).collect() };
    Some(match tag {
        "T" => {
            let n = nums();
            Event::Total {
                bytes: *n.first()?,
                files: *n.get(1)?,
            }
        }
        "P" => {
            let n = nums();
            Event::Progress {
                bytes: *n.first()?,
                files: *n.get(1)?,
                written: n.get(2).copied().unwrap_or(0),
            }
        }
        "N" => {
            let (k, t) = rest.split_once(' ')?;
            Event::Note {
                kind: match k {
                    "ok" => NoteKind::Ok,
                    "warn" => NoteKind::Warn,
                    _ => NoteKind::Info,
                },
                text: t.to_string(),
            }
        }
        "D" => {
            let n = nums();
            Event::Done {
                files: *n.first()?,
                input: *n.get(1)?,
                output: *n.get(2)?,
                stored: *n.get(3)?,
            }
        }
        "E" => {
            let (c, m) = rest.split_once(' ').unwrap_or((rest, ""));
            Event::Failed {
                code: c.to_string(),
                message: m.to_string(),
            }
        }
        _ => return None,
    })
}

/// Archive format chosen in the compress dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fmt {
    Core(nz_core::Format),
    /// NextZip's own `.nz` container (crate `nz-nzf`).
    Nz,
}

impl Fmt {
    pub fn extension(self) -> &'static str {
        match self {
            Fmt::Core(f) => f.extension(),
            Fmt::Nz => "nz",
        }
    }

    fn parse(s: &str) -> anyhow::Result<Fmt> {
        if s.eq_ignore_ascii_case("nz") {
            Ok(Fmt::Nz)
        } else {
            Ok(Fmt::Core(nz_core::Format::parse(s)?))
        }
    }
}

#[derive(Debug, Clone)]
pub enum Op {
    Compress {
        sources: Vec<PathBuf>,
        out: PathBuf,
        format: Fmt,
        level: u8,
    },
    Extract {
        archive: PathBuf,
        dest: PathBuf,
        codepage: Option<nz_archive::Codepage>,
        password: Option<String>,
        test: bool,
    },
}

impl Op {
    fn args(&self) -> Vec<String> {
        let mut a = vec!["--worker".to_string()];
        match self {
            Op::Compress {
                sources,
                out,
                format,
                level,
            } => {
                a.push("compress".into());
                a.push(format.extension().into());
                a.push(level.to_string());
                a.push(out.to_string_lossy().into_owned());
                a.extend(sources.iter().map(|s| s.to_string_lossy().into_owned()));
            }
            Op::Extract {
                archive,
                dest,
                codepage,
                test,
                ..
            } => {
                a.push("extract".into());
                a.push(archive.to_string_lossy().into_owned());
                a.push(dest.to_string_lossy().into_owned());
                if let Some(cp) = codepage {
                    a.push("--cp".into());
                    a.push(cp.number().to_string());
                }
                if *test {
                    a.push("--test".into());
                }
            }
        }
        a
    }
}

/// A running worker process.
pub struct Job {
    child: Child,
    pub rx: Receiver<Event>,
    paused: bool,
    threads: HashMap<u32, (HANDLE, u64)>,
    last_sample: Instant,
}

impl Job {
    /// Start `op`; each event posts `WM_APP_WORK` to `notify`.
    pub fn start(op: &Op, notify: HWND) -> std::io::Result<Job> {
        let exe = std::env::current_exe()?;
        let mut child = Command::new(exe)
            .args(op.args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let pw = match op {
                Op::Extract { password, .. } => password.clone().unwrap_or_default(),
                _ => String::new(),
            };
            let _ = writeln!(stdin, "{pw}");
        }
        let stdout = child.stdout.take().expect("piped");
        let (tx, rx) = channel();
        let hwnd = notify.0 as isize;
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some(ev) = parse(&line) {
                    if tx.send(ev).is_err() {
                        break;
                    }
                    unsafe {
                        let _ =
                            PostMessageW(Some(HWND(hwnd as _)), WM_APP_WORK, WPARAM(0), LPARAM(0));
                    }
                }
            }
            // EOF: let the window notice a crash without a D/E line.
            unsafe {
                let _ = PostMessageW(Some(HWND(hwnd as _)), WM_APP_WORK, WPARAM(1), LPARAM(0));
            }
        });
        Ok(Job {
            child,
            rx,
            paused: false,
            threads: HashMap::new(),
            last_sample: Instant::now(),
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    pub fn cancel(&mut self) {
        if self.paused {
            self.set_paused(false);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    /// Suspend or resume every thread of the worker.
    pub fn set_paused(&mut self, pause: bool) {
        if pause == self.paused {
            return;
        }
        for tid in thread_ids(self.pid()) {
            unsafe {
                if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME, false, tid) {
                    if pause {
                        SuspendThread(h);
                    } else {
                        ResumeThread(h);
                    }
                    let _ = CloseHandle(h);
                }
            }
        }
        self.paused = pause;
    }

    /// CPU use (0..1) of the worker's busiest threads since the last call,
    /// at most `max` bars, ordered by thread id.
    pub fn thread_usage(&mut self, max: usize) -> Vec<f32> {
        let now = Instant::now();
        let wall = now.duration_since(self.last_sample).as_secs_f64().max(1e-3) * 1e7;
        self.last_sample = now;
        let ids = thread_ids(self.pid());
        let mut usage = Vec::new();
        for tid in &ids {
            let entry = self.threads.entry(*tid).or_insert_with(|| unsafe {
                let h =
                    OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, *tid).unwrap_or_default();
                (h, u64::MAX)
            });
            if entry.0.is_invalid() {
                continue;
            }
            let (mut c, mut e, mut k, mut u) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            let t = unsafe {
                if GetThreadTimes(entry.0, &mut c, &mut e, &mut k, &mut u).is_err() {
                    continue;
                }
                ft(k) + ft(u)
            };
            let prev = std::mem::replace(&mut entry.1, t);
            if prev != u64::MAX {
                usage.push((
                    *tid,
                    ((t.saturating_sub(prev)) as f64 / wall).min(1.0) as f32,
                ));
            }
        }
        // Forget threads that ended.
        self.threads.retain(|tid, (h, _)| {
            let keep = ids.contains(tid);
            if !keep && !h.is_invalid() {
                unsafe {
                    let _ = CloseHandle(*h);
                }
            }
            keep
        });
        usage.sort_by(|a, b| b.1.total_cmp(&a.1));
        usage.truncate(max);
        usage.sort_by_key(|x| x.0);
        usage.into_iter().map(|x| x.1).collect()
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        for (h, _) in self.threads.values() {
            if !h.is_invalid() {
                unsafe {
                    let _ = CloseHandle(*h);
                }
            }
        }
        if !self.exited() {
            self.cancel();
        }
    }
}

fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

fn thread_ids(pid: u32) -> Vec<u32> {
    let mut v = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) else {
            return v;
        };
        let mut te = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        if Thread32First(snap, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    v.push(te.th32ThreadID);
                }
                if Thread32Next(snap, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    v
}

/// Raw process handle (for completeness; std keeps ownership).
#[allow(dead_code)]
pub fn handle(child: &Child) -> HANDLE {
    HANDLE(child.as_raw_handle())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol() {
        assert!(matches!(
            parse("T 100 3"),
            Some(Event::Total {
                bytes: 100,
                files: 3
            })
        ));
        assert!(matches!(
            parse("D 3 100 40 1"),
            Some(Event::Done {
                files: 3,
                input: 100,
                output: 40,
                stored: 1
            })
        ));
        match parse("N warn 암호화된 항목 2개") {
            Some(Event::Note { kind, text }) => {
                assert_eq!(kind, NoteKind::Warn);
                assert_eq!(text, "암호화된 항목 2개");
            }
            other => panic!("{other:?}"),
        }
        match parse("E PASSWORD 암호가 필요합니다") {
            Some(Event::Failed { code, .. }) => assert_eq!(code, "PASSWORD"),
            other => panic!("{other:?}"),
        }
        assert!(parse("garbage").is_none());
    }
}
