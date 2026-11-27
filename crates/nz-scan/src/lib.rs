//! Malware scanning of extracted content through AMSI (spec 8 "악성코드
//! 검사", spec 9).
//!
//! AMSI runs in a separate scanner process, `nz-scan.exe`: providers load
//! into whoever calls `AmsiInitialize`, and a provider crash, hang or slow
//! start must not take the front end with it. The front end streams each
//! member's bytes to the scanner *before* they are written to disk, so a
//! detected file never lands in the output folder.
//!
//! Wire format (both directions): `tag: u8, len: u32 LE, payload[len]`.
//!
//! | dir | tag | payload |
//! |-----|-----|---------|
//! | child → parent | `H` | hello: i32 LE, 0 = AMSI ready, else the `AmsiInitialize` HRESULT |
//! | parent → child | `B` | begin an item, UTF-8 content name |
//! | parent → child | `C` | item data (any size up to [`MAX_FRAME`]) |
//! | parent → child | `E` | end of item |
//! | child → parent | `R` | verdict for the item: raw `AMSI_RESULT` i32 LE, then HRESULT i32 LE (0 = ok) |
//!
//! The child scans an item in windows of [`WINDOW`] bytes that overlap by
//! [`OVERLAP`] bytes, all in one AMSI session, so a signature that crosses
//! a window boundary is still seen whole.

mod amsi;

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Condvar, Mutex};

use anyhow::{Context, Result, anyhow, bail};

/// Largest frame either side accepts.
pub const MAX_FRAME: u32 = 16 << 20;
/// Bytes handed to one `AmsiScanBuffer` call.
pub const WINDOW: usize = 8 << 20;
/// Bytes repeated at the start of the next window.
pub const OVERLAP: usize = 64 << 10;
/// Scanner processes kept for parallel extraction.
const MAX_PROCS: usize = 4;

/// What AMSI said about one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// A provider reports malware (`AMSI_RESULT_DETECTED` or above).
    Detected,
    /// Blocked by administrator policy (`AMSI_RESULT_BLOCKED_BY_ADMIN_*`).
    Blocked,
}

impl Verdict {
    fn from_raw(r: i32) -> Verdict {
        match r {
            32768.. => Verdict::Detected,
            16384..=20479 => Verdict::Blocked,
            _ => Verdict::Clean,
        }
    }

    /// The worse of two verdicts.
    fn max(self, o: Verdict) -> Verdict {
        let rank = |v| match v {
            Verdict::Clean => 0,
            Verdict::Blocked => 1,
            Verdict::Detected => 2,
        };
        if rank(o) > rank(self) { o } else { self }
    }

    /// Not clean: the item must not be written.
    pub fn is_threat(self) -> bool {
        self != Verdict::Clean
    }
}

fn frame(w: &mut impl Write, tag: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[tag])?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)
}

fn read_frame(r: &mut impl Read, buf: &mut Vec<u8>) -> Result<u8> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head)?;
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    if len > MAX_FRAME {
        bail!("scanner frame too long ({len} bytes)");
    }
    buf.clear();
    buf.resize(len as usize, 0);
    r.read_exact(buf)?;
    Ok(head[0])
}

// ---------------------------------------------------------------- child --

/// One item being scanned in the child.
struct Item<'a> {
    session: amsi::Session<'a>,
    name: String,
    buf: Vec<u8>,
    /// Bytes at the start of `buf` that were already scanned (overlap).
    seen: usize,
    worst: i32,
    hr: i32,
}

impl Item<'_> {
    fn scan_window(&mut self) {
        if self.buf.len() <= self.seen {
            return;
        }
        match self.session.scan(&self.name, &self.buf) {
            Ok(r) => self.worst = self.worst.max(r),
            Err(hr) => self.hr = hr,
        }
        let keep = self.buf.len().min(OVERLAP);
        self.buf.drain(..self.buf.len() - keep);
        self.seen = keep;
    }

    fn push(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let room = WINDOW - self.buf.len();
            let n = room.min(data.len());
            self.buf.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.buf.len() == WINDOW {
                self.scan_window();
            }
        }
    }
}

/// `main` of `nz-scan.exe`: initialise AMSI, then answer items on
/// stdin/stdout until stdin closes. Returns the exit code.
pub fn child_main() -> i32 {
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    serve(
        BufReader::with_capacity(1 << 20, stdin),
        BufWriter::new(stdout),
    )
}

/// The scanner loop over any pipe pair (tests drive it in-process).
pub fn serve(mut r: impl Read, mut w: impl Write) -> i32 {
    let amsi = match amsi::Amsi::new("NextZip") {
        Ok(a) => a,
        Err(hr) => {
            let _ = frame(&mut w, b'H', &hr.to_le_bytes()).and_then(|()| w.flush());
            return 2;
        }
    };
    if frame(&mut w, b'H', &0i32.to_le_bytes())
        .and_then(|()| w.flush())
        .is_err()
    {
        return 3;
    }
    let mut buf = Vec::new();
    let mut item: Option<Item<'_>> = None;
    loop {
        let tag = match read_frame(&mut r, &mut buf) {
            Ok(t) => t,
            // Parent closed the pipe: normal end.
            Err(_) => return 0,
        };
        match tag {
            b'B' => {
                item = Some(Item {
                    session: amsi.session(),
                    name: String::from_utf8_lossy(&buf).into_owned(),
                    buf: Vec::new(),
                    seen: 0,
                    worst: 0,
                    hr: 0,
                });
            }
            b'C' => match &mut item {
                Some(it) => it.push(&buf),
                None => return 4,
            },
            b'E' => {
                let Some(mut it) = item.take() else { return 4 };
                it.scan_window();
                let mut reply = [0u8; 8];
                reply[..4].copy_from_slice(&it.worst.to_le_bytes());
                reply[4..].copy_from_slice(&it.hr.to_le_bytes());
                drop(it);
                if frame(&mut w, b'R', &reply)
                    .and_then(|()| w.flush())
                    .is_err()
                {
                    return 3;
                }
            }
            _ => return 4,
        }
    }
}

// --------------------------------------------------------------- parent --

/// Path of `nz-scan.exe`: `NZ_SCAN_EXE`, else next to the current
/// executable, else in a parent folder (test binaries live below
/// `target/<profile>`, where cargo puts the scanner).
pub fn scanner_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("NZ_SCAN_EXE") {
        return Ok(PathBuf::from(p));
    }
    let name = if cfg!(windows) {
        "nz-scan.exe"
    } else {
        "nz-scan"
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
        "악성코드 검사기 {}를 찾을 수 없습니다 (설치가 손상되었을 수 있습니다)",
        &[&name]
    ))
}

struct Proc {
    child: Child,
    tx: BufWriter<ChildStdin>,
    rx: BufReader<ChildStdout>,
}

impl Proc {
    fn spawn(exe: &Path, args: &[String]) -> Result<Proc> {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("cannot start {}", exe.display()))?;
        let tx = BufWriter::with_capacity(1 << 20, child.stdin.take().expect("piped"));
        let rx = BufReader::new(child.stdout.take().expect("piped"));
        let mut p = Proc { child, tx, rx };
        let mut buf = Vec::new();
        let tag = read_frame(&mut p.rx, &mut buf).context("scanner did not start")?;
        if tag != b'H' || buf.len() != 4 {
            bail!("scanner protocol error (hello)");
        }
        let hr = i32::from_le_bytes(buf[..4].try_into().unwrap());
        if hr != 0 {
            return Err(anyhow!(Unavailable(hr)));
        }
        Ok(p)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // Closing stdin ends the child's loop; kill it if it is stuck.
        let _ = self.tx.flush();
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// AMSI could not be initialised (no antimalware provider, or AMSI turned
/// off by policy). Front ends show a notice and extract without scanning.
#[derive(Debug, Clone, Copy)]
pub struct Unavailable(pub i32);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&nz_front::trf(
            "Windows 악성코드 검사(AMSI)를 사용할 수 없습니다 (HRESULT {})",
            &[&format!("{:#010x}", self.0)],
        ))
    }
}

impl std::error::Error for Unavailable {}

/// Is `e` (or its cause) [`Unavailable`]?
pub fn is_unavailable(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<Unavailable>().is_some())
}

/// A pool of scanner processes. Cheap to share across threads; each
/// [`Scanner::begin`] borrows one process for one item.
pub struct Scanner {
    idle: Mutex<(Vec<Proc>, usize)>,
    freed: Condvar,
    exe: PathBuf,
    args: Vec<String>,
}

impl Scanner {
    /// Start one scanner process (more start on demand, up to 4). Fails
    /// with [`Unavailable`] when AMSI has no provider.
    pub fn start() -> Result<Scanner> {
        Scanner::start_with(scanner_path()?, Vec::new())
    }

    /// Like [`Scanner::start`], with another executable that serves the
    /// scanner protocol when run with `args` (`nz-decode --scan`).
    pub fn start_with(exe: PathBuf, args: Vec<String>) -> Result<Scanner> {
        let p = Proc::spawn(&exe, &args)?;
        Ok(Scanner {
            idle: Mutex::new((vec![p], 1)),
            freed: Condvar::new(),
            exe,
            args,
        })
    }

    fn take(&self) -> Result<Proc> {
        let mut g = self
            .idle
            .lock()
            .map_err(|_| anyhow!("scanner pool poisoned"))?;
        loop {
            if let Some(p) = g.0.pop() {
                return Ok(p);
            }
            if g.1 < MAX_PROCS {
                g.1 += 1;
                drop(g);
                let p = Proc::spawn(&self.exe, &self.args);
                if p.is_err()
                    && let Ok(mut g) = self.idle.lock()
                {
                    g.1 -= 1;
                }
                return p;
            }
            g = self
                .freed
                .wait(g)
                .map_err(|_| anyhow!("scanner pool poisoned"))?;
        }
    }

    fn give_back(&self, p: Option<Proc>) {
        if let Ok(mut g) = self.idle.lock() {
            match p {
                Some(p) => g.0.push(p),
                // A broken process is dropped; a new one may start later.
                None => g.1 -= 1,
            }
        }
        self.freed.notify_one();
    }

    /// Start scanning one item named `name` (shown by some providers).
    pub fn begin(&self, name: &str) -> Result<Scan<'_>> {
        let mut p = self.take()?;
        if let Err(e) = frame(&mut p.tx, b'B', name.as_bytes()) {
            self.give_back(None);
            return Err(e).context("scanner stopped");
        }
        Ok(Scan {
            pool: self,
            proc: Some(p),
        })
    }

    /// Scan a whole buffer.
    pub fn scan(&self, name: &str, data: &[u8]) -> Result<Verdict> {
        let mut s = self.begin(name)?;
        s.data(data)?;
        s.end()
    }

    /// Scan everything `r` yields.
    pub fn scan_reader(&self, name: &str, mut r: impl Read) -> Result<Verdict> {
        let mut s = self.begin(name)?;
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            s.data(&buf[..n])?;
        }
        s.end()
    }
}

/// One item in progress; feed it with [`Scan::data`], finish with
/// [`Scan::end`]. Dropping it unfinished discards the scanner process.
pub struct Scan<'a> {
    pool: &'a Scanner,
    proc: Option<Proc>,
}

impl Scan<'_> {
    pub fn data(&mut self, data: &[u8]) -> Result<()> {
        let p = self.proc.as_mut().expect("scan in progress");
        for c in data.chunks(MAX_FRAME as usize) {
            if let Err(e) = frame(&mut p.tx, b'C', c) {
                return Err(e).context("scanner stopped");
            }
        }
        Ok(())
    }

    /// Finish the item and get its verdict.
    pub fn end(mut self) -> Result<Verdict> {
        let mut p = self.proc.take().expect("scan in progress");
        let r = (|| -> Result<Verdict> {
            frame(&mut p.tx, b'E', &[])?;
            p.tx.flush()?;
            let mut buf = Vec::new();
            let tag = read_frame(&mut p.rx, &mut buf)?;
            if tag != b'R' || buf.len() != 8 {
                bail!("scanner protocol error (verdict)");
            }
            let raw = i32::from_le_bytes(buf[..4].try_into().unwrap());
            let hr = i32::from_le_bytes(buf[4..].try_into().unwrap());
            if hr != 0 {
                bail!(nz_front::trf(
                    "AMSI 검사 실패 (HRESULT {})",
                    &[&format!("{hr:#010x}")]
                ));
            }
            Ok(Verdict::from_raw(raw))
        })();
        self.pool.give_back(r.is_ok().then_some(p));
        r.context(nz_front::tr("악성코드 검사기가 응답하지 않습니다"))
    }
}

impl Drop for Scan<'_> {
    fn drop(&mut self) {
        if self.proc.take().is_some() {
            // Mid-item: the process state is unknown, start fresh later.
            self.pool.give_back(None);
        }
    }
}

/// Worse of two verdicts (for callers combining several items).
pub fn worst(a: Verdict, b: Verdict) -> Verdict {
    a.max(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_ranges() {
        assert_eq!(Verdict::from_raw(0), Verdict::Clean);
        assert_eq!(Verdict::from_raw(1), Verdict::Clean);
        assert_eq!(Verdict::from_raw(16384), Verdict::Blocked);
        assert_eq!(Verdict::from_raw(20479), Verdict::Blocked);
        assert_eq!(Verdict::from_raw(32768), Verdict::Detected);
        assert_eq!(
            worst(Verdict::Blocked, Verdict::Detected),
            Verdict::Detected
        );
        assert_eq!(worst(Verdict::Clean, Verdict::Blocked), Verdict::Blocked);
    }

    #[test]
    fn oversized_frame_is_refused() {
        let mut bad = vec![b'C'];
        bad.extend_from_slice(&(MAX_FRAME + 1).to_le_bytes());
        let mut buf = Vec::new();
        assert!(read_frame(&mut &bad[..], &mut buf).is_err());
    }
}
