//! Progress window: percentage, throughput, elapsed / remaining time,
//! smart-processing notes, per-thread CPU bars, pause / cancel /
//! background, and the completion summary.

use nz_front::{tr, trf};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{BeginPaint, EndPaint, HDC, PAINTSTRUCT};
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{HSTRING, PCWSTR, w};

use crate::gfx::{self, Align, Type, icon, rect};
use crate::theme::{self, Mode};
use crate::ui::{self, Btn, WM_APP_PAINT, WM_APP_WORK};
use crate::worker::{Event, Job, NoteKind, Op};

pub const CLASS: PCWSTR = w!("NextZipProgress");

const W: f32 = 540.0;
const H: f32 = 500.0;

const ID_BAR: isize = 10;
const ID_NOTES: isize = 11;
const ID_THREADS: isize = 12;
const ID_RESULT: isize = 13;
const ID_BG: isize = 20;
const ID_PAUSE: isize = 21;
const ID_CANCEL: isize = 2;
const ID_OPEN: isize = 23;
const ID_CLOSE: isize = 24;

const TIMER: usize = 1;

#[derive(Debug, Clone, PartialEq)]
enum State {
    Running,
    Done {
        files: u64,
        input: u64,
        output: u64,
        stored: u64,
    },
    Failed(String),
    Cancelled,
}

pub struct Progress {
    hwnd: HWND,
    op: Op,
    job: Option<Job>,
    state: State,
    total: u64,
    total_files: u64,
    done: u64,
    written: u64,
    files: u64,
    shown: f32,
    notes: Vec<(NoteKind, String)>,
    history: VecDeque<(Instant, u64)>,
    started: Instant,
    paused_for: Duration,
    paused_at: Option<Instant>,
    finished_at: Option<Instant>,
    threads: Vec<f32>,
    last_threads: Instant,
    bar: HWND,
    notes_panel: HWND,
    threads_panel: HWND,
    result: HWND,
    b_bg: HWND,
    b_pause: HWND,
    b_cancel: HWND,
    b_open: HWND,
    b_close: HWND,
}

/// Open a progress window running `op`.
pub fn start(owner: Option<HWND>, op: Op) -> HWND {
    let st = Progress {
        hwnd: HWND::default(),
        op,
        job: None,
        state: State::Running,
        total: 0,
        total_files: 0,
        done: 0,
        written: 0,
        files: 0,
        shown: 0.0,
        notes: Vec::new(),
        history: VecDeque::new(),
        started: Instant::now(),
        paused_for: Duration::ZERO,
        paused_at: None,
        finished_at: None,
        threads: Vec::new(),
        last_threads: Instant::now(),
        bar: HWND::default(),
        notes_panel: HWND::default(),
        threads_panel: HWND::default(),
        result: HWND::default(),
        b_bg: HWND::default(),
        b_pause: HWND::default(),
        b_cancel: HWND::default(),
        b_open: HWND::default(),
        b_close: HWND::default(),
    };
    let style = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
    let ex = WS_EX_APPWINDOW;
    let (w, h) = ui::outer_size(style, ex, W, H, ui::system_dpi());
    // Unowned: it has its own taskbar button and outlives the main window.
    let hwnd = ui::create(
        CLASS,
        "NextZip",
        style,
        ex,
        (CW_USEDEFAULT, CW_USEDEFAULT, w, h),
        None,
        0,
        st,
    );
    ui::center(hwnd, owner);
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
    hwnd
}

impl Progress {
    fn is_compress(&self) -> bool {
        matches!(self.op, Op::Compress { .. })
    }

    fn is_test(&self) -> bool {
        matches!(self.op, Op::Extract { test: true, .. })
    }

    fn archive_name(&self) -> String {
        let p = match &self.op {
            Op::Compress { out, .. } => out,
            Op::Extract { archive, .. } => archive,
        };
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn title(&self) -> String {
        let name = self.archive_name();
        let paused = self.job.as_ref().is_some_and(Job::paused);
        match (&self.state, self.is_compress(), self.is_test()) {
            (State::Running, true, _) => trf(
                "{} 압축 중{}",
                &[&name, &if paused { tr(" (일시정지됨)") } else { "" }],
            ),
            (State::Running, false, true) => trf(
                "{} 검사 중{}",
                &[&name, &if paused { tr(" (일시정지됨)") } else { "" }],
            ),
            (State::Running, false, false) => trf(
                "{} 푸는 중{}",
                &[&name, &if paused { tr(" (일시정지됨)") } else { "" }],
            ),
            (State::Done { .. }, true, _) => tr("압축 완료").into(),
            (State::Done { .. }, false, true) => tr("검사 통과").into(),
            (State::Done { .. }, false, false) => tr("풀기 완료").into(),
            (State::Failed(_), true, _) => tr("압축하지 못했습니다").into(),
            (State::Failed(_), false, true) => tr("검사 실패").into(),
            (State::Failed(_), false, false) => tr("풀지 못했습니다").into(),
            (State::Cancelled, _, _) => tr("취소했습니다").into(),
        }
    }

    fn init(&mut self, hwnd: HWND) {
        self.hwnd = hwnd;
        ui::top_opened();
        ui::style_frame(hwnd, false);
        self.bar = ui::panel(
            hwnd,
            ID_BAR,
            tr("전체 진행률"),
            48, /* ROLE_SYSTEM_PROGRESSBAR */
        );
        self.notes_panel = ui::panel(
            hwnd,
            ID_NOTES,
            tr("스마트 처리 내역"),
            33, /* ROLE_SYSTEM_LIST */
        );
        self.threads_panel = ui::panel(
            hwnd,
            ID_THREADS,
            tr("스레드 사용률"),
            51, /* ROLE_SYSTEM_CHART */
        );
        self.result = ui::panel(hwnd, ID_RESULT, tr("결과"), 8 /* ROLE_SYSTEM_ALERT */);
        ui::show(self.result, false);
        self.b_bg = ui::button(
            hwnd,
            ID_BG,
            tr("백그라운드로"),
            Btn::Secondary(tr("백그라운드로").into()),
            true,
        );
        self.b_pause = ui::button(
            hwnd,
            ID_PAUSE,
            tr("일시정지"),
            Btn::Secondary(tr("일시정지").into()),
            false,
        );
        self.b_cancel = ui::button(
            hwnd,
            ID_CANCEL,
            tr("취소"),
            Btn::Secondary(tr("취소").into()),
            false,
        );
        self.b_open = ui::button(
            hwnd,
            ID_OPEN,
            tr("폴더 열기"),
            Btn::Primary(tr("폴더 열기(&O)").into()),
            true,
        );
        self.b_close = ui::button(
            hwnd,
            ID_CLOSE,
            tr("닫기"),
            Btn::Secondary(tr("닫기").into()),
            false,
        );
        ui::show(self.b_open, false);
        ui::show(self.b_close, false);
        self.layout();
        self.launch();
        unsafe {
            SetTimer(Some(hwnd), TIMER, 100, None);
        }
    }

    fn launch(&mut self) {
        self.state = State::Running;
        self.started = Instant::now();
        self.paused_for = Duration::ZERO;
        self.history.clear();
        self.notes.clear();
        self.done = 0;
        self.files = 0;
        self.shown = 0.0;
        match Job::start(&self.op, self.hwnd) {
            Ok(j) => self.job = Some(j),
            Err(e) => self.finish(State::Failed(trf(
                "작업 프로세스를 시작하지 못했습니다: {}",
                &[&e],
            ))),
        }
        self.refresh_title();
    }

    fn layout(&self) {
        let h = self.hwnd;
        ui::place(h, self.bar, 24.0, 116.0, W - 48.0, 8.0);
        ui::place(h, self.notes_panel, 24.0, 212.0, W - 48.0, 120.0);
        ui::place(h, self.threads_panel, 24.0, 340.0, W - 48.0, 72.0);
        ui::place(h, self.result, 24.0, 340.0, W - 48.0, 72.0);
        let y = H - 56.0;
        ui::place(h, self.b_cancel, W - 24.0 - 88.0, y, 88.0, 32.0);
        ui::place(
            h,
            self.b_pause,
            W - 24.0 - 88.0 - 8.0 - 104.0,
            y,
            104.0,
            32.0,
        );
        ui::place(
            h,
            self.b_bg,
            W - 24.0 - 88.0 - 16.0 - 104.0 - 120.0,
            y,
            120.0,
            32.0,
        );
        ui::place(h, self.b_close, W - 24.0 - 88.0, y, 88.0, 32.0);
        ui::place(
            h,
            self.b_open,
            W - 24.0 - 88.0 - 8.0 - 112.0,
            y,
            112.0,
            32.0,
        );
    }

    fn refresh_title(&self) {
        ui::set_text(self.hwnd, &format!("{} — NextZip", self.title()));
        ui::invalidate(self.hwnd);
    }

    fn elapsed(&self) -> Duration {
        let end = self.finished_at.unwrap_or_else(Instant::now);
        let paused = self.paused_for
            + self
                .paused_at
                .map(|p| end.duration_since(p))
                .unwrap_or_default();
        end.duration_since(self.started).saturating_sub(paused)
    }

    fn fraction(&self) -> f32 {
        match self.state {
            State::Done { .. } => 1.0,
            _ if self.total == 0 => 0.0,
            // Never show 100% before the worker says it is done.
            _ => (self.done as f64 / self.total as f64).min(0.99) as f32,
        }
    }

    fn rate(&self) -> f64 {
        let (Some(a), Some(b)) = (self.history.front(), self.history.back()) else {
            return 0.0;
        };
        let dt = b.0.duration_since(a.0).as_secs_f64();
        if dt < 0.2 {
            let e = self.elapsed().as_secs_f64();
            return if e > 0.0 { self.done as f64 / e } else { 0.0 };
        }
        let recent = (b.1.saturating_sub(a.1)) as f64 / dt;
        if recent > 0.0 {
            return recent;
        }
        // Input fully read, still compressing: show the average.
        let e = self.elapsed().as_secs_f64();
        if e > 0.0 { self.done as f64 / e } else { 0.0 }
    }

    fn drain(&mut self) {
        dbg_log("drain");
        let mut events = Vec::new();
        if let Some(j) = &self.job {
            while let Ok(ev) = j.rx.try_recv() {
                events.push(ev);
            }
        }
        for ev in events {
            match ev {
                Event::Total { bytes, files } => {
                    self.total = bytes;
                    self.total_files = files;
                }
                Event::Progress {
                    bytes,
                    files,
                    written,
                } => {
                    self.done = bytes;
                    self.written = written;
                    if files > 0 {
                        self.files = files;
                    }
                    let now = Instant::now();
                    self.history.push_back((now, bytes));
                    while self
                        .history
                        .front()
                        .is_some_and(|f| now.duration_since(f.0) > Duration::from_secs(2))
                    {
                        self.history.pop_front();
                    }
                }
                Event::Note { kind, text } => {
                    self.notes.push((kind, text));
                    let all: Vec<&str> = self.notes.iter().map(|n| n.1.as_str()).collect();
                    ui::acc_value(self.notes_panel, &all.join(". "));
                    ui::invalidate(self.notes_panel);
                }
                Event::Done {
                    files,
                    input,
                    output,
                    stored,
                } => self.finish(State::Done {
                    files,
                    input,
                    output,
                    stored,
                }),
                Event::Failed { code, message } => {
                    if !self.is_compress() && (code == "PASSWORD" || code == "WRONGPASSWORD") {
                        self.job = None;
                        let archive = match &self.op {
                            Op::Extract { archive, .. } => archive.clone(),
                            _ => PathBuf::new(),
                        };
                        match crate::password::ask(self.hwnd, &archive, code == "WRONGPASSWORD") {
                            Some(pw) => {
                                if let Op::Extract { password, .. } = &mut self.op {
                                    *password = Some(pw);
                                }
                                self.launch();
                            }
                            None => self.finish(State::Cancelled),
                        }
                        return;
                    }
                    if code == "MALWARE" {
                        // Spec 9: a clear, blocking warning on detection.
                        crate::ui::warning(
                            self.hwnd,
                            tr("NextZip - 악성코드 발견"),
                            &format!(
                                "{message}\n\n{}",
                                tr(
                                    "발견된 파일은 풀지 않았습니다. Windows 보안에서 자세한 내용을 확인하세요."
                                )
                            ),
                        );
                    }
                    let msg = if code == "UNSUPPORTED" {
                        format!(
                            "{message}\n{}",
                            tr("이 형식의 해당 기능은 아직 지원하지 않습니다.")
                        )
                    } else {
                        message
                    };
                    self.finish(State::Failed(msg));
                }
            }
        }
    }

    fn finish(&mut self, st: State) {
        if self.state != State::Running {
            return;
        }
        self.finished_at = Some(Instant::now());
        if let Some(p) = self.paused_at.take() {
            self.paused_for += p.elapsed();
        }
        self.state = st;
        if let Some(mut j) = self.job.take()
            && !j.exited()
        {
            j.cancel();
        }
        unsafe {
            let _ = KillTimer(Some(self.hwnd), TIMER);
        }
        for h in [self.b_bg, self.b_pause, self.b_cancel, self.threads_panel] {
            ui::show(h, false);
        }
        let ok = matches!(self.state, State::Done { .. });
        ui::show(self.b_open, ok && !self.is_test());
        ui::show(self.b_close, true);
        ui::show(self.result, true);
        let summary = self.result_text();
        ui::acc_name(
            self.result,
            &format!("{} {}", self.title(), summary.join(" ")),
        );
        unsafe {
            windows::Win32::UI::Accessibility::NotifyWinEvent(
                0x0002, /* EVENT_SYSTEM_ALERT */
                self.result,
                -4,
                0,
            );
            let focus = if ok && !self.is_test() {
                self.b_open
            } else {
                self.b_close
            };
            let _ = windows::Win32::UI::Input::KeyboardAndMouse::SetFocus(Some(focus));
            if IsIconic(self.hwnd).as_bool() {
                let fi = FLASHWINFO {
                    cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
                    hwnd: self.hwnd,
                    dwFlags: FLASHW_TRAY | FLASHW_TIMERNOFG,
                    uCount: 3,
                    dwTimeout: 0,
                };
                let _ = FlashWindowEx(&fi);
            }
        }
        ui::acc_value(self.bar, &format!("{:.0}%", self.fraction() * 100.0));
        self.refresh_title();
    }

    fn result_text(&self) -> Vec<String> {
        let secs = self.elapsed().as_secs_f64();
        match &self.state {
            State::Done {
                files,
                input,
                output,
                stored,
            } => {
                let name = self.archive_name();
                let mut v = Vec::new();
                if self.is_compress() {
                    let ratio = if *input > 0 {
                        *output as f64 * 100.0 / *input as f64
                    } else {
                        0.0
                    };
                    v.push(trf(
                        "{} · {} → {} ({}%) · {}초",
                        &[
                            &name,
                            &ui::size(*input),
                            &ui::size(*output),
                            &format!("{ratio:.1}"),
                            &format!("{secs:.1}"),
                        ],
                    ));
                    let mut s = trf("파일 {}개", &[&ui::count(*files)]);
                    if *stored > 0 {
                        s.push_str(&trf(
                            " · 압축 이득이 없어 그대로 저장한 파일 {}개",
                            &[&ui::count(*stored)],
                        ));
                    }
                    v.push(s);
                } else {
                    v.push(trf(
                        "{} · 파일 {}개 · {} · {}초",
                        &[
                            &name,
                            &ui::count(*files),
                            &ui::size(*output),
                            &format!("{secs:.1}"),
                        ],
                    ));
                    if self.is_test() {
                        v.push(
                            tr("모든 항목을 풀어 CRC를 확인했습니다 (임시 폴더는 지웠습니다)")
                                .into(),
                        );
                    } else if let Op::Extract { dest, .. } = &self.op {
                        v.push(dest.display().to_string());
                    }
                }
                v
            }
            State::Failed(m) => m.lines().map(str::to_string).collect(),
            State::Cancelled => vec![if self.is_compress() {
                tr("만들던 압축 파일은 지웠습니다.").into()
            } else if self.is_test() {
                tr("검사를 멈췄습니다.").into()
            } else {
                tr("이미 푼 파일은 그대로 남아 있습니다.").into()
            }],
            State::Running => Vec::new(),
        }
    }

    fn tick(&mut self) {
        dbg_log("tick");
        self.drain();
        if let Some(j) = &mut self.job
            && j.exited()
            && self.state == State::Running
        {
            // Give the reader thread a moment to deliver the last lines.
            std::thread::sleep(Duration::from_millis(30));
            self.drain();
            if self.state == State::Running {
                self.finish(State::Failed(
                    tr("작업 프로세스가 예기치 않게 끝났습니다.").into(),
                ));
            }
            return;
        }
        let target = self.fraction();
        self.shown = if theme::animate() {
            // ~200 ms ease towards the target at 100 ms ticks
            self.shown + (target - self.shown) * 0.6
        } else {
            target
        };
        if self.last_threads.elapsed() >= Duration::from_millis(500) {
            self.last_threads = Instant::now();
            let max = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .min(32);
            if let Some(j) = &mut self.job
                && !j.paused()
            {
                self.threads = j.thread_usage(max);
            }
            ui::invalidate(self.threads_panel);
            ui::acc_value(self.bar, &format!("{:.0}%", target * 100.0));
        }
        ui::invalidate(self.hwnd);
        ui::invalidate(self.bar);
    }

    fn metrics(&self) -> [(&'static str, String); 4] {
        let rate = self.rate();
        let elapsed = self.elapsed().as_secs_f64();
        let remain = if rate > 1.0 && self.total > self.done {
            let s = (self.total - self.done) as f64 / rate;
            if s < 1.5 {
                tr("약 1초").to_string()
            } else if s < 60.0 {
                trf("약 {}초", &[&format!("{s:.0}")])
            } else {
                trf("약 {}분", &[&(s / 60.0).ceil()])
            }
        } else if matches!(self.state, State::Done { .. }) {
            tr("0초").into()
        } else {
            tr("계산 중").into()
        };
        let fourth = if self.is_compress() {
            match &self.state {
                State::Done { input, output, .. } if *input > 0 => (
                    tr("압축률"),
                    format!("{:.1}%", *output as f64 * 100.0 / *input as f64),
                ),
                // Below 64 KiB the counter is only our own progress lines.
                _ if self.written < 64 * 1024 => (tr("출력"), "—".into()),
                _ => (tr("출력"), ui::size(self.written)),
            }
        } else {
            (
                tr("파일"),
                format!(
                    "{} / {}",
                    ui::count(self.files),
                    ui::count(self.total_files)
                ),
            )
        };
        [
            (tr("처리량"), format!("{}/s", ui::size(rate as u64))),
            (tr("경과"), ui::duration(elapsed)),
            (tr("남은 시간"), remain),
            fourth,
        ]
    }

    fn paint(&self, hdc: HDC) {
        let p = theme::pal();
        let title = self.title();
        let frac = self.fraction();
        let big = format!("{:.0}%", frac * 100.0);
        let sub = if self.total > 0 {
            trf(
                "{} 중 {}",
                &[&ui::size(self.total), &ui::size(self.done.min(self.total))],
            )
        } else if self.state == State::Running {
            tr("파일 목록 확인 중…").to_string()
        } else {
            String::new()
        };
        let metrics = self.metrics();
        let running = self.state == State::Running;
        gfx::paint(self.hwnd, hdc, |c| {
            c.clear(p.surface);
            c.text(
                &title,
                rect(24.0, 20.0, W - 48.0, 28.0),
                Type::Title,
                Align::Left,
                p.text,
            );
            c.text(
                &big,
                rect(24.0, 60.0, 120.0, 44.0),
                Type::Display,
                Align::Left,
                p.text,
            );
            let bw = c.measure(&big, Type::Display);
            c.text(
                &sub,
                rect(36.0 + bw, 72.0, W - 60.0 - bw, 28.0),
                Type::Body,
                Align::Left,
                p.muted,
            );
            let cw = (W - 48.0 - 24.0) / 4.0;
            for (i, (k, v)) in metrics.iter().enumerate() {
                let x = 24.0 + i as f32 * (cw + 8.0);
                c.round(rect(x, 140.0, cw, 56.0), 4.0, p.surface2);
                c.text(
                    k,
                    rect(x + 10.0, 146.0, cw - 20.0, 16.0),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                );
                c.text(
                    v,
                    rect(x + 10.0, 166.0, cw - 20.0, 22.0),
                    Type::Subtitle,
                    Align::Left,
                    p.text,
                );
            }
            if running {
                c.hline(0.0, c.w, H - 72.0, p.divider);
            }
        });
    }

    fn paint_bar(&self, hdc: HDC) {
        let p = theme::pal();
        let v = self.shown.max(if self.state == State::Running {
            0.0
        } else {
            self.fraction()
        });
        gfx::paint(self.bar, hdc, |c| {
            c.clear(p.surface);
            c.round(rect(0.0, 0.0, c.w, c.h), 4.0, p.divider);
            if v > 0.0 {
                c.round(rect(0.0, 0.0, (c.w * v).max(c.h), c.h), 4.0, p.primary);
            }
            if p.mode == Mode::HighContrast {
                c.stroke_round(rect(0.0, 0.0, c.w, c.h), 4.0, p.text, 1.0);
            }
        });
    }

    fn paint_notes(&self, hdc: HDC) {
        let p = theme::pal();
        let notes = self.notes.clone();
        gfx::paint(self.notes_panel, hdc, |c| {
            c.clear(p.surface);
            let mut y = 0.0;
            for (kind, text) in notes.iter().take(5) {
                let (g, col) = match kind {
                    NoteKind::Warn => (icon::INFO, p.attention),
                    NoteKind::Ok => (icon::CHECK_CIRCLE, p.success),
                    NoteKind::Info => (icon::INFO, p.muted),
                };
                c.icon(g, rect(0.0, y + 2.0, 16.0, 16.0), Type::IconSmall, col);
                c.text(
                    text,
                    rect(24.0, y, c.w - 24.0, 20.0),
                    Type::Body,
                    Align::Left,
                    p.text,
                );
                y += 24.0;
            }
        });
    }

    fn paint_threads(&self, hdc: HDC) {
        let p = theme::pal();
        let bars = self.threads.clone();
        gfx::paint(self.threads_panel, hdc, |c| {
            c.clear(p.surface);
            let label = if bars.is_empty() {
                tr("스레드 사용률").to_string()
            } else {
                let avg = bars.iter().sum::<f32>() / bars.len() as f32;
                trf(
                    "스레드 사용률 ({}개 · 평균 {}%)",
                    &[&bars.len(), &format!("{:.0}", avg * 100.0)],
                )
            };
            c.text(
                &label,
                rect(0.0, 0.0, c.w, 16.0),
                Type::Caption,
                Align::Left,
                p.muted,
            );
            let n = bars.len().max(1) as f32;
            let gap = 4.0;
            let bw = ((c.w - gap * (n - 1.0)) / n).max(2.0);
            let top = 24.0;
            let hh = c.h - top - 4.0;
            for (i, u) in bars.iter().enumerate() {
                let x = i as f32 * (bw + gap);
                c.fill(rect(x, top + hh - 1.0, bw, 1.0), p.divider);
                let bh = (hh * u).max(1.0);
                c.round(rect(x, top + hh - bh, bw, bh), 2.0, p.primary);
            }
        });
    }

    fn paint_result(&self, hdc: HDC) {
        let p = theme::pal();
        let lines = self.result_text();
        let (accent, g, head) = match &self.state {
            State::Done { .. } => (p.success, icon::CHECK_CIRCLE, self.title()),
            State::Failed(_) => (p.danger, icon::WARNING, self.title()),
            _ => (p.muted, icon::INFO, self.title()),
        };
        gfx::paint(self.result, hdc, |c| {
            c.clear(p.surface);
            c.stroke_round(rect(0.0, 0.0, c.w, c.h), 8.0, p.divider, 1.0);
            c.round(rect(0.0, 0.0, 4.0, c.h), 2.0, accent);
            c.icon(g, rect(16.0, 10.0, 16.0, 20.0), Type::IconSmall, accent);
            c.text(
                &head,
                rect(40.0, 10.0, c.w - 56.0, 20.0),
                Type::BodyStrong,
                Align::Left,
                p.text,
            );
            let mut y = 32.0;
            for l in lines.iter().take(2) {
                c.text(
                    l,
                    rect(40.0, y, c.w - 56.0, 16.0),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                );
                y += 17.0;
            }
        });
    }

    fn toggle_pause(&mut self) {
        let Some(j) = &mut self.job else { return };
        let pause = !j.paused();
        j.set_paused(pause);
        if pause {
            self.paused_at = Some(Instant::now());
        } else if let Some(p) = self.paused_at.take() {
            self.paused_for += p.elapsed();
            self.history.clear();
        }
        let label = if pause {
            tr("계속")
        } else {
            tr("일시정지")
        };
        ui::acc_name(self.b_pause, label);
        ui::set_btn(self.b_pause, Btn::Secondary(label.into()));
        self.refresh_title();
    }

    fn cancel(&mut self) {
        if self.state != State::Running {
            return;
        }
        if let Some(mut j) = self.job.take() {
            j.cancel();
        }
        match &self.op {
            Op::Compress { out, .. } => {
                let _ = std::fs::remove_file(out);
            }
            Op::Extract {
                dest, test: true, ..
            } => {
                let _ = std::fs::remove_dir_all(dest);
            }
            _ => {}
        }
        self.finish(State::Cancelled);
    }

    fn open_folder(&self) {
        let target = match &self.op {
            Op::Compress { out, .. } => out.parent().map(|p| p.to_path_buf()),
            Op::Extract { dest, .. } => Some(dest.clone()),
        };
        if let Some(t) = target {
            unsafe {
                ShellExecuteW(
                    Some(self.hwnd),
                    &HSTRING::from("open"),
                    &HSTRING::from(t.as_os_str()),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    SW_SHOWNORMAL,
                );
            }
        }
    }
}

impl ui::WindowState for Progress {
    fn handle(&mut self, hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
        match msg {
            WM_CREATE => {
                self.init(hwnd);
                Some(LRESULT(0))
            }
            WM_ERASEBKGND => Some(LRESULT(1)),
            WM_PAINT => {
                dbg_log("paint");
                let mut ps = PAINTSTRUCT::default();
                let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
                self.paint(hdc);
                unsafe {
                    let _ = EndPaint(hwnd, &ps);
                }
                crate::first_paint();
                Some(LRESULT(0))
            }
            WM_APP_PAINT => {
                let hdc = HDC(lp.0 as _);
                match wp.0 as isize {
                    ID_BAR => self.paint_bar(hdc),
                    ID_NOTES => self.paint_notes(hdc),
                    ID_THREADS => self.paint_threads(hdc),
                    ID_RESULT => self.paint_result(hdc),
                    _ => {}
                }
                Some(LRESULT(0))
            }
            WM_DRAWITEM => {
                let dis = unsafe { &*(lp.0 as *const DRAWITEMSTRUCT) };
                ui::draw_button(dis, theme::pal().surface);
                Some(LRESULT(1))
            }
            WM_TIMER => {
                self.tick();
                Some(LRESULT(0))
            }
            WM_APP_WORK => {
                self.drain();
                Some(LRESULT(0))
            }
            WM_COMMAND => {
                let id = ui::loword(wp.0) as isize;
                // Owner-drawn buttons have BS_NOTIFY: act on clicks only,
                // not on focus notifications.
                if lp.0 != 0 && ui::hiword(wp.0) as u32 != BN_CLICKED {
                    return Some(LRESULT(0));
                }
                match id {
                    ID_BG => unsafe {
                        let _ = ShowWindow(hwnd, SW_MINIMIZE);
                    },
                    ID_PAUSE => self.toggle_pause(),
                    ID_CANCEL => {
                        if self.state == State::Running {
                            self.cancel()
                        } else {
                            unsafe {
                                let _ = DestroyWindow(hwnd);
                            }
                        }
                    }
                    ID_OPEN => {
                        self.open_folder();
                        unsafe {
                            let _ = DestroyWindow(hwnd);
                        }
                    }
                    ID_CLOSE | 1 if self.state != State::Running => unsafe {
                        let _ = DestroyWindow(hwnd);
                    },
                    _ => {}
                }
                Some(LRESULT(0))
            }
            WM_CLOSE => {
                if self.state == State::Running {
                    let r = unsafe {
                        MessageBoxW(
                            Some(hwnd),
                            &HSTRING::from(tr("작업을 취소할까요?")),
                            &HSTRING::from("NextZip"),
                            MB_YESNO | MB_ICONQUESTION,
                        )
                    };
                    if r != IDYES {
                        return Some(LRESULT(0));
                    }
                    self.cancel();
                }
                unsafe {
                    let _ = DestroyWindow(hwnd);
                }
                Some(LRESULT(0))
            }
            WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
                theme::refresh();
                ui::style_frame(hwnd, false);
                unsafe {
                    let _ = windows::Win32::Graphics::Gdi::RedrawWindow(
                        Some(hwnd),
                        None,
                        None,
                        windows::Win32::Graphics::Gdi::RDW_INVALIDATE
                            | windows::Win32::Graphics::Gdi::RDW_ALLCHILDREN,
                    );
                }
                None
            }
            WM_DPICHANGED => {
                ui::apply_dpi_rect(hwnd, lp);
                self.layout();
                ui::invalidate(hwnd);
                Some(LRESULT(0))
            }
            WM_DESTROY => {
                if self.state == State::Running {
                    self.cancel();
                }
                if let Some(mut j) = self.job.take() {
                    j.cancel();
                }
                ui::top_closed();
                Some(LRESULT(0))
            }
            _ => None,
        }
    }
}

fn dbg_log(m: &str) {
    ui::trace(m);
}
