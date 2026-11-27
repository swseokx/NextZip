//! The isolated decoder process (spec 5, 9): RAR (C UnRAR) and every
//! legacy or rare format reader (`nz-formats`) run in `nz-decode.exe`.
//!
//! The child locks itself down before it reads the request (low integrity,
//! no privileges, one-process job with a memory cap, mitigations; see
//! `nz-sandbox`), so it cannot write any user file. It never writes files
//! at all: member data comes back over stdout in frames, and this module
//! (in the trusted parent) sanitises names, enforces size limits and writes
//! the output folder. A crash, hang or exploit in a decoder ends with the
//! child; the parent reports an error and removes the partial file.
//!
//! Wire format, child to parent: `tag: u8, len: u32 LE, payload[len]`.
//!
//! | tag | payload |
//! |-----|---------|
//! | `L` | listing, JSON [`nz_formats::Listing`] |
//! | `S` | member start, index as u64 LE |
//! | `D` | member data |
//! | `F` | member finished and verified |
//! | `E` | error, JSON [`WireError`] |
//! | `K` | done |
//!
//! Parent to child: one JSON [`Request`] on stdin.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::{ArchiveError, Progress};

/// Which reader the child runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Backend {
    Formats(nz_formats::Format),
    Rar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Op {
    List,
    Extract,
    /// Report the worker's own confinement (tests and diagnostics): its
    /// integrity level and whether it can create a file in `path`.
    Probe,
}

/// Answer to [`Op::Probe`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeReport {
    /// Token integrity RID (0x1000 = low).
    pub integrity: Option<u32>,
    /// Whether creating a file in the probed folder succeeded.
    pub wrote_file: bool,
    /// Whether starting another process succeeded.
    pub spawned_process: bool,
}

/// What the parent asks for.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Request {
    pub op: Op,
    pub backend: Backend,
    pub path: PathBuf,
    pub password: Option<String>,
    /// Members to extract (indices into the listing); `None` for all.
    pub want: Option<Vec<usize>>,
    /// UI language for messages the child writes (`ko`, `en`).
    #[serde(default)]
    pub lang: Option<String>,
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Some(p) = &mut self.password {
            zeroize::Zeroize::zeroize(p);
        }
    }
}

/// Error carried across the pipe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WireError {
    pub kind: String,
    pub message: String,
}

impl WireError {
    fn from_anyhow(e: &anyhow::Error) -> WireError {
        let kind = if let Some(f) = e
            .chain()
            .find_map(|c| c.downcast_ref::<nz_formats::FormatError>())
        {
            match f {
                nz_formats::FormatError::PasswordRequired => "password",
                nz_formats::FormatError::WrongPassword => "wrongpassword",
                nz_formats::FormatError::Unsupported(_) => "unsupported",
            }
        } else if let Some(a) = crate::archive_error(e) {
            match a {
                ArchiveError::PasswordRequired => "password",
                ArchiveError::WrongPassword => "wrongpassword",
                ArchiveError::Unsupported(_) => "unsupported",
                ArchiveError::Cancelled => "cancelled",
                ArchiveError::MalwareFound(_) => "other",
            }
        } else {
            "other"
        };
        WireError {
            kind: kind.into(),
            message: format!("{e:#}"),
        }
    }

    fn into_anyhow(self) -> anyhow::Error {
        match self.kind.as_str() {
            "password" => ArchiveError::PasswordRequired.into(),
            "wrongpassword" => ArchiveError::WrongPassword.into(),
            "unsupported" => ArchiveError::Unsupported(self.message).into(),
            "cancelled" => ArchiveError::Cancelled.into(),
            _ => anyhow!(self.message),
        }
    }
}

/// Largest frame the parent accepts (data frames are at most 1 MiB).
const MAX_FRAME: u32 = 64 << 20;
/// Data frame size the child writes.
const CHUNK: usize = 1 << 20;
/// Committed memory cap of the child process.
pub const CHILD_MEMORY: usize = 3 << 30;

// ---------------------------------------------------------------- child --

struct FrameWriter<W: Write> {
    w: W,
}

impl<W: Write> FrameWriter<W> {
    fn frame(&mut self, tag: u8, payload: &[u8]) -> std::io::Result<()> {
        self.w.write_all(&[tag])?;
        self.w.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.w.write_all(payload)
    }
}

struct PipeSink<'a, W: Write> {
    out: &'a mut FrameWriter<W>,
    want: Option<&'a [usize]>,
    /// Declared (size, compressed size) of the member being decoded.
    cur: (u64, u64),
}

impl<W: Write> nz_formats::Sink for PipeSink<'_, W> {
    fn start(&mut self, index: usize, m: &nz_formats::Member) -> Result<bool> {
        if self.want.is_some_and(|w| w.binary_search(&index).is_err()) {
            return Ok(false);
        }
        self.out.frame(b'S', &(index as u64).to_le_bytes())?;
        self.cur = (m.size, m.csize);
        // Readers that decode a whole member before handing it over send
        // nothing until it is done: budget that work.
        watchdog::arm(m.size, m.csize);
        Ok(true)
    }
    fn data(&mut self, data: &[u8]) -> Result<()> {
        for c in data.chunks(CHUNK) {
            self.out.frame(b'D', c)?;
        }
        // Streaming readers: a fresh budget for the next chunk.
        watchdog::arm(self.cur.0, self.cur.1);
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        watchdog::disarm();
        self.out.frame(b'F', &[])?;
        Ok(())
    }
}

/// Exit code of a worker stopped by its own [`watchdog`].
pub const RUNAWAY_EXIT: i32 = 0x4E5A;

/// Per-member work budget inside the worker. Third-party legacy decoders
/// can loop on damaged input; with overflow checks off (release builds)
/// the HA decoder, for one, keeps producing output into memory instead of
/// panicking. A worker that spends far more time or memory on a member
/// than its declared sizes justify stops itself with [`RUNAWAY_EXIT`]
/// within seconds, instead of waiting for the parent's stall limit.
///
/// Only `nz-decode.exe` runs the watchdog thread ([`watchdog::start`]);
/// in-process users of [`serve`] (fuzzing, tests) just record budgets.
pub mod watchdog {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Time any member may take, plus 1 s per MiB of declared size.
    pub const BASE_TIME: Duration = Duration::from_secs(30);
    /// Memory any member may add, plus twice its declared size and its
    /// compressed size.
    pub const BASE_MEMORY: u64 = 256 << 20;

    #[derive(Clone, Copy)]
    struct Budget {
        deadline: Instant,
        memory: u64,
    }

    static BUDGET: Mutex<Option<Budget>> = Mutex::new(None);

    /// Budget for decoding `size` bytes from `csize` compressed bytes.
    pub fn arm(size: u64, csize: u64) {
        let size = size.min(nz_formats::limits::MAX_MEMBER);
        let csize = csize.min(nz_formats::limits::MAX_MEMBER);
        let work = size.max(csize);
        let b = Budget {
            deadline: Instant::now() + BASE_TIME + Duration::from_secs(work >> 20),
            memory: nz_sys::current_commit()
                .unwrap_or(0)
                .saturating_add(BASE_MEMORY)
                .saturating_add(size.saturating_mul(2))
                .saturating_add(csize),
        };
        if let Ok(mut g) = BUDGET.lock() {
            *g = Some(b);
        }
    }

    /// Budget for listing an archive of `file_size` bytes (time only).
    pub fn arm_listing(file_size: u64) {
        let b = Budget {
            deadline: Instant::now() + BASE_TIME + Duration::from_secs(file_size >> 20),
            memory: u64::MAX,
        };
        if let Ok(mut g) = BUDGET.lock() {
            *g = Some(b);
        }
    }

    pub fn disarm() {
        if let Ok(mut g) = BUDGET.lock() {
            *g = None;
        }
    }

    /// Why the current budget is exceeded, if it is.
    fn exceeded() -> Option<String> {
        let b = (*BUDGET.lock().ok()?)?;
        if Instant::now() > b.deadline {
            return Some("time budget exceeded".into());
        }
        let used = nz_sys::current_commit()?;
        (used > b.memory).then(|| format!("memory budget exceeded ({} MiB)", used >> 20))
    }

    /// Start the watchdog thread (worker process only).
    pub fn start() {
        std::thread::spawn(|| {
            loop {
                std::thread::sleep(Duration::from_millis(100));
                if let Some(why) = exceeded() {
                    eprintln!("nz-decode: {why}");
                    std::process::exit(super::RUNAWAY_EXIT);
                }
            }
        });
    }
}

fn rar_listing(path: &Path, password: Option<&str>) -> Result<nz_formats::Listing> {
    #[cfg(feature = "rar")]
    {
        let r = nz_rar::list(path, password).map_err(crate::map_rar_err)?;
        Ok(nz_formats::Listing {
            members: r
                .entries
                .into_iter()
                .map(|e| nz_formats::Member {
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    csize: e.csize,
                    mtime: e.mtime.and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs() as i64)
                    }),
                    method: e.method,
                    crc: e.crc,
                    encrypted: e.encrypted,
                    link: e.link.then(String::new),
                    raw_name: None,
                })
                .collect(),
            solid: r.solid,
            volumes: r.volumes,
        })
    }
    #[cfg(not(feature = "rar"))]
    {
        let _ = (path, password);
        Err(ArchiveError::Unsupported(tr("RAR (rar 기능 없이 빌드됨)").into()).into())
    }
}

fn rar_extract<W: Write>(req: &Request, sink: &mut PipeSink<'_, W>) -> Result<()> {
    #[cfg(feature = "rar")]
    {
        use nz_formats::Sink;
        let mut err: Option<anyhow::Error> = None;
        let want: Option<Vec<usize>> = sink.want.map(<[usize]>::to_vec);
        let dummy = nz_formats::Member::default();
        let r = nz_rar::stream(
            &req.path,
            req.password.as_deref(),
            &|i| want.as_ref().is_none_or(|w| w.binary_search(&i).is_ok()),
            &mut |ev| {
                let res = match ev {
                    nz_rar::Event::Start(i, _) => sink.start(i, &dummy).map(|_| ()),
                    nz_rar::Event::Data(d) => sink.data(d),
                    nz_rar::Event::Finish => sink.finish(),
                };
                match res {
                    Ok(()) => true,
                    Err(e) => {
                        err = Some(e);
                        false
                    }
                }
            },
        );
        if let Some(e) = err {
            return Err(e);
        }
        r.map_err(crate::map_rar_err)
    }
    #[cfg(not(feature = "rar"))]
    {
        let _ = (req, sink);
        Err(ArchiveError::Unsupported(tr("RAR (rar 기능 없이 빌드됨)").into()).into())
    }
}

/// Serve one request (the body of `nz-decode.exe` after lockdown; also
/// used in-process by fuzz targets and tests).
pub fn serve<W: Write>(req: &Request, out: W) -> std::io::Result<()> {
    let mut fw = FrameWriter { w: out };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        match (req.op, req.backend) {
            (Op::List, Backend::Formats(f)) => {
                let opt = nz_formats::Options {
                    password: req.password.clone(),
                };
                watchdog::arm_listing(std::fs::metadata(&req.path).map_or(0, |m| m.len()));
                let l = nz_formats::list(f, &req.path, &opt);
                watchdog::disarm();
                let l = l?;
                fw.frame(b'L', &serde_json::to_vec(&l)?)?;
            }
            (Op::Probe, _) => {
                let f = req.path.join("nz-decode-probe.tmp");
                let wrote_file = std::fs::write(&f, b"x").is_ok();
                let _ = std::fs::remove_file(&f);
                let spawned_process = std::process::Command::new("cmd.exe")
                    .args(["/c", "exit", "0"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok();
                let r = ProbeReport {
                    integrity: nz_sandbox::integrity_level(),
                    wrote_file,
                    spawned_process,
                };
                fw.frame(b'L', &serde_json::to_vec(&r)?)?;
            }
            (Op::List, Backend::Rar) => {
                let l = rar_listing(&req.path, req.password.as_deref())?;
                fw.frame(b'L', &serde_json::to_vec(&l)?)?;
            }
            (Op::Extract, backend) => {
                let mut want = req.want.clone();
                if let Some(w) = &mut want {
                    w.sort_unstable();
                }
                let mut sink = PipeSink {
                    out: &mut fw,
                    want: want.as_deref(),
                    cur: (0, 0),
                };
                match backend {
                    Backend::Formats(f) => {
                        let opt = nz_formats::Options {
                            password: req.password.clone(),
                        };
                        nz_formats::extract(f, &req.path, &opt, &mut sink)?;
                    }
                    Backend::Rar => rar_extract(req, &mut sink)?,
                }
            }
        }
        Ok(())
    }));
    match r {
        Ok(Ok(())) => fw.frame(b'K', &[])?,
        Ok(Err(e)) => fw.frame(
            b'E',
            &serde_json::to_vec(&WireError::from_anyhow(&e)).unwrap_or_default(),
        )?,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            let e = WireError {
                kind: "other".into(),
                message: nz_front::trf("디코더 내부 오류(panic): {}", &[&msg]),
            };
            fw.frame(b'E', &serde_json::to_vec(&e).unwrap_or_default())?;
        }
    }
    fw.w.flush()
}

/// `main` of `nz-decode.exe`: lock down, read the request, serve it.
pub fn child_main() -> i32 {
    if let Err(e) = nz_sandbox::lockdown(CHILD_MEMORY) {
        eprintln!("nz-decode: lockdown failed, refusing to run: {e}");
        return 3;
    }
    let mut input = Vec::new();
    if std::io::stdin()
        .take(1 << 20)
        .read_to_end(&mut input)
        .is_err()
    {
        return 4;
    }
    let parsed = serde_json::from_slice::<Request>(&input);
    // The request holds the password.
    zeroize::Zeroize::zeroize(&mut input);
    let req: Request = match parsed {
        Ok(r) => r,
        Err(e) => {
            eprintln!("nz-decode: bad request: {e}");
            return 4;
        }
    };
    // Frames go to a private copy of stdout; anything a decoder prints ends
    // up on stderr instead of corrupting the protocol.
    let out = match nz_sandbox::take_stdout() {
        Ok(f) => BufWriter::with_capacity(CHUNK + 16, f),
        Err(e) => {
            eprintln!("nz-decode: cannot take stdout: {e}");
            return 4;
        }
    };
    if let Some(l) = req.lang.as_deref().and_then(nz_front::Lang::from_code) {
        nz_front::i18n::set(l);
    }
    watchdog::start();
    match serve(&req, out) {
        Ok(()) => 0,
        Err(_) => 5,
    }
}

// --------------------------------------------------------------- parent --

/// Path of `nz-decode.exe`: `NZ_DECODE_EXE`, else next to the current
/// executable, else in a parent folder (test binaries live below
/// `target/<profile>`, where cargo puts the worker).
pub fn worker_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("NZ_DECODE_EXE") {
        return Ok(PathBuf::from(p));
    }
    let name = if cfg!(windows) {
        "nz-decode.exe"
    } else {
        "nz-decode"
    };
    let exe = std::env::current_exe()?;
    let mut dir = exe.parent();
    for _ in 0..6 {
        let Some(d) = dir else { break };
        let p = d.join(name);
        if p.is_file() {
            return Ok(p);
        }
        dir = d.parent();
    }
    bail!(nz_front::trf(
        "격리 디코더 {}를 찾을 수 없습니다 (설치가 손상되었을 수 있습니다)",
        &[&name]
    ))
}

/// Seconds the worker may go without sending a frame before it is treated
/// as hung and killed (a decoder stuck in a loop on damaged input). Every
/// reader sends a frame at least per member, and member data in chunks.
static STALL_SECS: AtomicU64 = AtomicU64::new(300);

/// Change the hang limit (tests use a short one).
pub fn set_stall_timeout(limit: Duration) {
    STALL_SECS.store(limit.as_secs().max(1), Ordering::Relaxed);
}

/// What the stdout reader thread passes on.
enum Msg {
    Frame(u8, Vec<u8>),
    /// The pipe ended (or broke) mid-stream.
    Ended,
    /// A frame longer than [`MAX_FRAME`].
    Bad,
}

struct Child {
    child: std::process::Child,
    _job: nz_sandbox::Contained,
    frames: Receiver<Msg>,
    stderr: std::thread::JoinHandle<String>,
}

impl Child {
    fn spawn(req: &Request) -> Result<Child> {
        let exe = worker_path()?;
        let mut cmd = Command::new(&exe);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("cannot start {}", exe.display()))?;
        let job = match nz_sandbox::Contained::new(&child) {
            Ok(j) => j,
            Err(e) => {
                let _ = child.kill();
                return Err(e).context("cannot contain the decoder process");
            }
        };
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut body = serde_json::to_vec(req)?;
        // The request is small; a write error means the child already died,
        // which the frame reader reports.
        let _ = stdin.write_all(&body);
        zeroize::Zeroize::zeroize(&mut body);
        drop(stdin);
        let mut err = child.stderr.take().expect("piped stderr");
        let stderr = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = (&mut err).take(64 << 10).read_to_string(&mut s);
            s
        });
        let mut out =
            BufReader::with_capacity(CHUNK + 16, child.stdout.take().expect("piped stdout"));
        // Frames are read on their own thread so a silent (hung) worker
        // can be noticed and killed.
        let (tx, frames) = sync_channel(4);
        std::thread::spawn(move || {
            loop {
                let mut head = [0u8; 5];
                if out.read_exact(&mut head).is_err() {
                    let _ = tx.send(Msg::Ended);
                    return;
                }
                let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
                if len > MAX_FRAME {
                    let _ = tx.send(Msg::Bad);
                    return;
                }
                let mut buf = vec![0u8; len as usize];
                if out.read_exact(&mut buf).is_err() {
                    let _ = tx.send(Msg::Ended);
                    return;
                }
                if tx.send(Msg::Frame(head[0], buf)).is_err() {
                    return;
                }
            }
        });
        Ok(Child {
            child,
            _job: job,
            frames,
            stderr,
        })
    }

    /// Next frame, or an error describing how the child ended.
    fn frame(&mut self, buf: &mut Vec<u8>) -> Result<u8> {
        self.frame_or_cancel(buf, None)
    }

    /// [`Child::frame`], also giving up (and killing the worker) when
    /// `cancel` is set while waiting.
    fn frame_or_cancel(
        &mut self,
        buf: &mut Vec<u8>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<u8> {
        let stall = Duration::from_secs(STALL_SECS.load(Ordering::Relaxed));
        let deadline = std::time::Instant::now() + stall;
        let got = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self
                .frames
                .recv_timeout(left.min(Duration::from_millis(200)))
            {
                Err(RecvTimeoutError::Timeout) if !left.is_zero() => {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        return Err(ArchiveError::Cancelled.into());
                    }
                }
                r => break r,
            }
        };
        match got {
            Ok(Msg::Frame(tag, data)) => {
                *buf = data;
                Ok(tag)
            }
            Ok(Msg::Ended) | Err(RecvTimeoutError::Disconnected) => Err(self.died()),
            Ok(Msg::Bad) => {
                let _ = self.child.kill();
                bail!(nz_front::tr("격리 디코더가 잘못된 응답을 보냈습니다"));
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                Err(anyhow!(nz_front::trf(
                    "디코더가 {}초 동안 응답하지 않아 중단했습니다 (손상된 파일일 수 있습니다)",
                    &[&stall.as_secs()]
                )))
            }
        }
    }

    fn died(&mut self) -> anyhow::Error {
        let status = self.child.wait().ok();
        let stderr = std::mem::replace(&mut self.stderr, std::thread::spawn(String::new))
            .join()
            .unwrap_or_default();
        let code = status.and_then(|s| s.code());
        if code == Some(RUNAWAY_EXIT) {
            return anyhow!(nz_front::trf(
                "손상된 압축 파일: 디코더가 시간·메모리 한도를 넘어 중단했습니다 ({})",
                &[&stderr.trim().trim_start_matches("nz-decode: ")]
            ));
        }
        anyhow!(nz_front::trf(
            "격리 디코더가 비정상 종료했습니다 (종료 코드 {}){}",
            &[
                &code
                    .map(|c| format!("{c:#x}"))
                    .unwrap_or_else(|| "?".into()),
                &if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            ]
        ))
    }

    fn finish(mut self) {
        let _ = self.child.wait();
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// List an archive in the isolated process.
pub fn list(backend: Backend, path: &Path, password: Option<&str>) -> Result<nz_formats::Listing> {
    let req = Request {
        op: Op::List,
        backend,
        path: std::path::absolute(path)?,
        password: password.map(str::to_owned),
        want: None,
        lang: Some(nz_front::i18n::current().code().into()),
    };
    let mut c = Child::spawn(&req)?;
    let mut buf = Vec::new();
    let mut listing = None;
    loop {
        match c.frame(&mut buf)? {
            b'L' => listing = Some(serde_json::from_slice(&buf).context("bad listing")?),
            b'E' => {
                let e: WireError = serde_json::from_slice(&buf).context("bad error")?;
                return Err(e.into_anyhow());
            }
            b'K' => break,
            t => bail!("unexpected frame {t:#x} from decoder"),
        }
    }
    c.finish();
    listing.ok_or_else(|| anyhow!("decoder sent no listing"))
}

/// Ask a fresh worker how confined it is, probing writes into `dir`.
pub fn probe(dir: &Path) -> Result<ProbeReport> {
    let req = Request {
        op: Op::Probe,
        backend: Backend::Rar,
        path: std::path::absolute(dir)?,
        password: None,
        want: None,
        lang: None,
    };
    let mut c = Child::spawn(&req)?;
    let mut buf = Vec::new();
    let mut report = None;
    loop {
        match c.frame(&mut buf)? {
            b'L' => report = Some(serde_json::from_slice(&buf).context("bad probe")?),
            b'E' => {
                let e: WireError = serde_json::from_slice(&buf).context("bad error")?;
                return Err(e.into_anyhow());
            }
            b'K' => break,
            t => bail!("unexpected frame {t:#x} from decoder"),
        }
    }
    c.finish();
    report.ok_or_else(|| anyhow!("decoder sent no probe report"))
}

/// Limits the parent enforces on what the child sends.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest single member written.
    pub member: u64,
    /// Largest total written for one archive.
    pub total: u64,
}

impl Limits {
    /// Default limits for an archive of `archive_size` bytes: 64 GiB per
    /// member and in total, but never more than 4096 times the archive
    /// size plus 1 GiB (zip-bomb guard, spec 9).
    pub fn for_archive(archive_size: u64) -> Limits {
        let cap = archive_size.saturating_mul(4096).saturating_add(1 << 30);
        Limits {
            member: cap.min(64 << 30),
            total: cap.min(64 << 30),
        }
    }
}

/// Largest member held in memory while it is being scanned; a larger one
/// is written under a temporary name and renamed when clean.
const SCAN_HOLD: usize = 64 << 20;

enum Out {
    Mem(Vec<u8>),
    File(BufWriter<File>),
}

/// The member being received from the decoder.
struct Member<'a> {
    index: usize,
    /// Final path.
    dest: PathBuf,
    /// Where the data goes now: `dest`, or a temporary name while scanning.
    target: PathBuf,
    out: Out,
    size: u64,
    scan: Option<nz_scan::Scan<'a>>,
}

impl Member<'_> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        if let Out::Mem(v) = &mut self.out {
            if v.len() + data.len() <= SCAN_HOLD {
                v.extend_from_slice(data);
                return Ok(());
            }
            let f = File::create(&self.target)
                .with_context(|| format!("cannot create {}", self.target.display()))?;
            let mut w = BufWriter::with_capacity(1 << 20, f);
            w.write_all(v)?;
            self.out = Out::File(w);
        }
        if let Out::File(w) = &mut self.out {
            w.write_all(data)?;
        }
        Ok(())
    }

    /// Give the member its final name (it is complete and clean).
    fn commit(self, mtime: Option<std::time::SystemTime>) -> Result<()> {
        let f = match self.out {
            Out::Mem(v) => {
                let mut f = File::create(&self.dest)
                    .with_context(|| format!("cannot create {}", self.dest.display()))?;
                f.write_all(&v)?;
                f
            }
            Out::File(w) => w.into_inner().map_err(|e| e.into_error())?,
        };
        if let Some(t) = mtime {
            let _ = f.set_modified(t);
        }
        drop(f);
        if self.target != self.dest && self.target.exists() {
            std::fs::rename(&self.target, &self.dest)
                .with_context(|| format!("cannot create {}", self.dest.display()))?;
        }
        Ok(())
    }

    /// Drop the member and anything written for it.
    fn discard(self) {
        let written = matches!(self.out, Out::File(_));
        drop(self.scan);
        drop(self.out);
        if written {
            let _ = std::fs::remove_file(&self.target);
        }
    }
}

/// Extract `jobs` (listing index → sanitised relative path) into `out_dir`
/// through the isolated process. Returns (files, bytes).
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract(
    backend: Backend,
    path: &Path,
    password: Option<&str>,
    out_dir: &Path,
    jobs: &[(usize, PathBuf)],
    mtimes: &dyn Fn(usize) -> Option<std::time::SystemTime>,
    names: &dyn Fn(usize) -> String,
    prog: &Progress,
    limits: Limits,
    guard: &crate::scan::Guard,
) -> Result<(usize, u64)> {
    let want: Vec<usize> = jobs.iter().map(|j| j.0).collect();
    let map: std::collections::HashMap<usize, &PathBuf> =
        jobs.iter().map(|(i, p)| (*i, p)).collect();
    let req = Request {
        op: Op::Extract,
        backend,
        path: std::path::absolute(path)?,
        password: password.map(str::to_owned),
        want: Some(want),
        lang: Some(nz_front::i18n::current().code().into()),
    };
    let mut c = Child::spawn(&req)?;
    let mut buf = Vec::with_capacity(CHUNK);
    let mut cur: Option<Member<'_>> = None;
    let mut files = 0usize;
    let mut total = 0u64;
    let mut seen = std::collections::HashSet::new();
    let result = (|| -> Result<()> {
        loop {
            if prog.cancel.load(Ordering::Relaxed) {
                return Err(ArchiveError::Cancelled.into());
            }
            match c.frame_or_cancel(&mut buf, Some(&prog.cancel))? {
                b'S' => {
                    if cur.is_some() || buf.len() != 8 {
                        bail!("decoder protocol error (start)");
                    }
                    let i = u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize;
                    let Some(rel) = map.get(&i) else {
                        bail!("decoder sent a member that was not requested");
                    };
                    if !seen.insert(i) {
                        bail!("decoder sent a member twice");
                    }
                    let dest = out_dir.join(rel);
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)
                            .with_context(|| format!("cannot create {}", parent.display()))?;
                    }
                    // A scanned member is held in memory (or, when large,
                    // under a temporary name) until its verdict is in.
                    let scan = guard.begin(&names(i))?;
                    let (target, out) = if scan.is_some() {
                        (crate::scan::pending_name(&dest), Out::Mem(Vec::new()))
                    } else {
                        let f = File::create(&dest)
                            .with_context(|| format!("cannot create {}", dest.display()))?;
                        (
                            dest.clone(),
                            Out::File(BufWriter::with_capacity(1 << 20, f)),
                        )
                    };
                    cur = Some(Member {
                        index: i,
                        dest,
                        target,
                        out,
                        size: 0,
                        scan,
                    });
                }
                b'D' => {
                    let Some(m) = &mut cur else {
                        bail!("decoder protocol error (data)");
                    };
                    m.size += buf.len() as u64;
                    total += buf.len() as u64;
                    if m.size > limits.member || total > limits.total {
                        bail!(nz_front::tr("압축 폭탄 의심: 출력이 한도를 넘었습니다"));
                    }
                    if let Some(s) = &mut m.scan {
                        s.data(&buf)?;
                    }
                    m.write(&buf)?;
                    prog.done.fetch_add(buf.len() as u64, Ordering::Relaxed);
                }
                b'F' => {
                    let Some(mut m) = cur.take() else {
                        bail!("decoder protocol error (finish)");
                    };
                    let scan = m.scan.take();
                    let clean = match guard.end(&names(m.index), scan) {
                        Ok(c) => c,
                        Err(e) => {
                            m.discard();
                            return Err(e);
                        }
                    };
                    if !clean {
                        m.discard();
                        continue;
                    }
                    let i = m.index;
                    m.commit(mtimes(i))?;
                    files += 1;
                    prog.files.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut s) = prog.current.lock() {
                        *s = names(i);
                    }
                }
                b'E' => {
                    let e: WireError = serde_json::from_slice(&buf).context("bad error")?;
                    return Err(e.into_anyhow());
                }
                b'K' => return Ok(()),
                t => bail!("unexpected frame {t:#x} from decoder"),
            }
        }
    })();
    if let Some(m) = cur.take() {
        // Incomplete member: never leave a truncated file behind.
        m.discard();
    }
    match result {
        Ok(()) => {
            c.finish();
            Ok((files, total))
        }
        Err(e) => Err(e),
    }
}
