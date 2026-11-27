//! Compress dialog: file name, format segment, profile cards; encryption /
//! split / recovery behind a collapsed expander (M3).

use nz_front::{tr, trf};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{BeginPaint, EndPaint, HDC, PAINTSTRUCT};
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCWSTR, w};

use crate::gfx::{self, Align, Type, rect};
use crate::theme;
use crate::ui::{self, Btn};

pub const CLASS: PCWSTR = w!("NextZipCompress");

const ID_NAME: isize = 10;
const ID_LOCATION: isize = 11;
const ID_FMT: isize = 20; // 20..23
const ID_PROF: isize = 30; // 30..33
const ID_MORE: isize = 40;
const ID_OK: isize = 1; // IDOK
const ID_CANCEL: isize = 2; // IDCANCEL

const W: f32 = 520.0;

use crate::worker::Fmt;

const FORMATS: [(&str, Fmt, &str); 4] = [
    (
        "ZIP",
        Fmt::Core(nz_core::Format::Zip),
        "ZIP: 모든 PC에서 열립니다.",
    ),
    (
        "7Z",
        Fmt::Core(nz_core::Format::SevenZ),
        "7Z: 높은 압축률. 7-Zip·NextZip 등에서 열립니다.",
    ),
    (
        "NZ",
        Fmt::Nz,
        "NZ: 복구 정보 3% 포함, 중복 제거. NextZip에서 열립니다.",
    ),
    (
        "TAR.ZST",
        Fmt::Core(nz_core::Format::TarZst),
        "TAR.ZST: 매우 빠릅니다. 7-Zip 23 이상·NextZip·Linux에서 열립니다.",
    ),
];

/// (label, level, speed meter, ratio meter)
const PROFILES: [(&str, u8, f32, f32); 4] = [
    ("초고속", 1, 1.0, 0.30),
    ("균형", 5, 0.75, 0.65),
    ("고압축", 7, 0.35, 0.85),
    ("최대", 9, 0.15, 0.95),
];

fn settings_file() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("NextZip").join("compress.txt"))
}

fn load_settings() -> (usize, usize) {
    let s = settings_file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .unwrap_or_default();
    let mut fmt = 1;
    let mut prof = 1;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("format=") {
            fmt = v.parse().unwrap_or(1);
        }
        if let Some(v) = line.strip_prefix("profile=") {
            prof = v.parse().unwrap_or(1);
        }
    }
    if fmt >= FORMATS.len() {
        fmt = 1;
    }
    (fmt, prof.min(PROFILES.len() - 1))
}

fn save_settings(fmt: usize, prof: usize) {
    if let Some(f) = settings_file() {
        if let Some(d) = f.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(f, format!("format={fmt}\nprofile={prof}\n"));
    }
}

/// Default archive name and folder for `sources`.
pub fn default_target(sources: &[PathBuf]) -> (String, PathBuf) {
    let first = &sources[0];
    let dir = first
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let name = if sources.len() == 1 {
        if first.is_dir() {
            first.file_name()
        } else {
            first.file_stem()
        }
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into())
    } else {
        dir.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "archive".into())
    };
    (name, dir)
}

/// `dir/name.ext`, adding " (2)", " (3)" … when it exists.
pub fn unique_path(dir: &Path, name: &str, ext: &str) -> PathBuf {
    let mut p = dir.join(format!("{name}.{ext}"));
    let mut n = 2;
    while p.exists() {
        p = dir.join(format!("{name} ({n}).{ext}"));
        n += 1;
    }
    p
}

fn valid_name(s: &str) -> Result<(), &'static str> {
    let t = s.trim();
    if t.is_empty() {
        return Err(tr("파일 이름을 입력하세요."));
    }
    if t.chars().any(|c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (c as u32) < 32
    }) {
        return Err(tr("이름에 < > : \" / \\ | ? * 는 쓸 수 없습니다."));
    }
    if t.ends_with('.') {
        return Err(tr("이름은 마침표로 끝날 수 없습니다."));
    }
    Ok(())
}

pub struct Compress {
    hwnd: HWND,
    sources: Vec<PathBuf>,
    dir: PathBuf,
    name: HWND,
    location: HWND,
    fmts: Vec<HWND>,
    profs: Vec<HWND>,
    more: HWND,
    ok: HWND,
    cancel: HWND,
    fmt: usize,
    prof: usize,
    expanded: bool,
    error: Option<&'static str>,
    start_now: bool,
}

pub fn show(owner: Option<HWND>, sources: Vec<PathBuf>, start_now: bool) -> HWND {
    let (name, dir) = default_target(&sources);
    let (fmt, prof) = load_settings();
    let st = Compress {
        hwnd: HWND::default(),
        sources,
        dir,
        name: HWND::default(),
        location: HWND::default(),
        fmts: Vec::new(),
        profs: Vec::new(),
        more: HWND::default(),
        ok: HWND::default(),
        cancel: HWND::default(),
        fmt,
        prof,
        expanded: false,
        error: None,
        start_now,
    };
    let style = WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    let ex = if owner.is_some() {
        WS_EX_DLGMODALFRAME
    } else {
        WS_EX_DLGMODALFRAME | WS_EX_APPWINDOW
    };
    let (w, h) = ui::outer_size(style, ex, W, height(false), ui::system_dpi());
    let hwnd = ui::create(
        CLASS,
        tr("압축하기 — NextZip"),
        style,
        ex,
        (CW_USEDEFAULT, CW_USEDEFAULT, w, h),
        owner,
        0,
        st,
    );
    ui::set_text(ui::get_child(hwnd, ID_NAME), &name);
    ui::center(hwnd, owner);
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
    }
    if let Some(o) = owner {
        ui::enable(o, false);
    }
    hwnd
}

fn height(expanded: bool) -> f32 {
    if expanded { 616.0 } else { 576.0 }
}

impl Compress {
    fn init(&mut self, hwnd: HWND) {
        self.hwnd = hwnd;
        ui::top_opened();
        ui::style_frame(hwnd, false);
        self.name = ui::edit(hwnd, ID_NAME, tr("파일 이름"), false);
        self.location = ui::button(
            hwnd,
            ID_LOCATION,
            tr("저장 위치 변경"),
            Btn::Link {
                label: tr("위치 변경…").into(),
                strong: false,
            },
            true,
        );
        for (i, (label, _, _)) in FORMATS.iter().enumerate() {
            let b = ui::button(
                hwnd,
                ID_FMT + i as isize,
                &trf("포맷 {}", &[&label]),
                Btn::Segment {
                    label: label.to_string(),
                    checked: i == self.fmt,
                },
                i == 0,
            );
            self.fmts.push(b);
        }
        for (i, (label, level, speed, ratio)) in PROFILES.iter().enumerate() {
            let label = tr(label);
            let b = ui::button(
                hwnd,
                ID_PROF + i as isize,
                &trf("압축 프로필 {}, 수준 {}", &[&label, &level]),
                Btn::Profile {
                    label: label.to_string(),
                    speed: *speed,
                    ratio: *ratio,
                    checked: i == self.prof,
                },
                i == 0,
            );
            self.profs.push(b);
        }
        self.more = ui::button(
            hwnd,
            ID_MORE,
            tr("암호화 · 분할 · 복구 레코드 (M3에서 제공)"),
            Btn::Expander {
                label: tr("암호화 · 분할 · 복구 레코드").into(),
                note: tr("— M3에서 제공").into(),
                open: false,
            },
            true,
        );
        self.cancel = ui::button(
            hwnd,
            ID_CANCEL,
            tr("취소"),
            Btn::Secondary(tr("취소").into()),
            true,
        );
        self.ok = ui::button(
            hwnd,
            ID_OK,
            tr("압축 시작"),
            Btn::Primary(tr("압축 시작(&S)").into()),
            false,
        );
        self.sync_radio();
        self.layout();
        unsafe {
            let _ = SetFocus(Some(self.name));
        }
        ui::send(self.name, windows::Win32::UI::Controls::EM_SETSEL, 0, -1);
        if self.start_now {
            unsafe {
                let _ = PostMessageW(Some(hwnd), WM_COMMAND, WPARAM(ID_OK as usize), LPARAM(0));
            }
        }
    }

    /// Radio convention: only the checked item of a group is a tab stop.
    fn sync_radio(&self) {
        for (i, b) in self.fmts.iter().enumerate() {
            ui::set_btn(
                *b,
                Btn::Segment {
                    label: FORMATS[i].0.into(),
                    checked: i == self.fmt,
                },
            );
            set_tabstop(*b, i == self.fmt);
        }
        for (i, b) in self.profs.iter().enumerate() {
            let (label, _, speed, ratio) = PROFILES[i];
            let label = tr(label);
            ui::set_btn(
                *b,
                Btn::Profile {
                    label: label.into(),
                    speed,
                    ratio,
                    checked: i == self.prof,
                },
            );
            set_tabstop(*b, i == self.prof);
        }
        ui::invalidate(self.hwnd);
    }

    fn layout(&self) {
        let h = self.hwnd;
        ui::place(h, self.name, 33.0, 96.0, W - 66.0, 22.0);
        ui::place(h, self.location, W - 24.0 - 92.0, 126.0, 92.0, 24.0);
        let sw = 96.0;
        for (i, b) in self.fmts.iter().enumerate() {
            ui::place(h, *b, 24.0 + i as f32 * sw, 184.0, sw + 1.0, 32.0);
        }
        for (i, b) in self.profs.iter().enumerate() {
            ui::place(h, *b, 24.0, 274.0 + i as f32 * 52.0, W - 48.0, 44.0);
        }
        ui::place(h, self.more, 20.0, 486.0, W - 40.0, 32.0);
        let fy = height(self.expanded) - 56.0;
        ui::place(
            h,
            self.cancel,
            W - 24.0 - 112.0 - 8.0 - 88.0,
            fy,
            88.0,
            32.0,
        );
        ui::place(h, self.ok, W - 24.0 - 112.0, fy, 112.0, 32.0);
    }

    fn paint(&self, hdc: HDC) {
        let p = theme::pal();
        let name_rc = ui::child_rect(self.hwnd, self.name);
        let edit_focus =
            unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetFocus() } == self.name;
        let dir = self.dir.display().to_string();
        let fmt_hint = tr(FORMATS[self.fmt].2);
        let expanded = self.expanded;
        let error = self.error;
        gfx::paint(self.hwnd, hdc, |c| {
            c.clear(p.surface);
            c.text(
                tr("압축하기"),
                rect(24.0, 20.0, W - 48.0, 28.0),
                Type::Title,
                Align::Left,
                p.text,
            );
            c.text(
                tr("파일 이름"),
                rect(24.0, 64.0, 200.0, 20.0),
                Type::BodyStrong,
                Align::Left,
                p.text,
            );
            let frame = rect(24.0, 88.0, W - 48.0, 36.0 - 2.0);
            let _ = name_rc;
            c.round(frame, 4.0, p.surface);
            let border = if error.is_some() {
                p.danger
            } else if edit_focus {
                p.focus
            } else {
                p.border
            };
            c.stroke_round(
                frame,
                4.0,
                border,
                if edit_focus || error.is_some() {
                    2.0
                } else {
                    1.0
                },
            );
            match error {
                Some(e) => c.text(
                    e,
                    rect(24.0, 128.0, W - 140.0, 18.0),
                    Type::Caption,
                    Align::Left,
                    p.danger,
                ),
                None => c.text(
                    &trf("저장 위치: {}", &[&dir]),
                    rect(24.0, 128.0, W - 148.0, 18.0),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                ),
            }
            c.text(
                tr("포맷"),
                rect(24.0, 160.0, 200.0, 20.0),
                Type::BodyStrong,
                Align::Left,
                p.text,
            );
            c.text(
                fmt_hint,
                rect(24.0, 222.0, W - 48.0, 18.0),
                Type::Caption,
                Align::Left,
                p.muted,
            );
            c.text(
                tr("압축 프로필"),
                rect(24.0, 250.0, 200.0, 20.0),
                Type::BodyStrong,
                Align::Left,
                p.text,
            );
            if expanded {
                c.text_wrap(
                    tr("암호(AES-256), 분할 크기, 복구 레코드 비율, 스레드 수는 M3에서 추가됩니다. 지금은 모든 논리 프로세서를 씁니다."),
                    rect(44.0, 522.0, W - 68.0, 36.0),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                );
            }
            c.hline(0.0, c.w, height(expanded) - 72.0, p.divider);
        });
    }

    fn select_fmt(&mut self, i: usize) {
        if self.fmt != i {
            self.fmt = i;
            self.sync_radio();
        }
    }

    fn select_prof(&mut self, i: usize) {
        if self.prof != i {
            self.prof = i;
            self.sync_radio();
        }
    }

    fn start(&mut self) {
        let name = ui::get_text(self.name);
        if let Err(e) = valid_name(&name) {
            self.error = Some(e);
            ui::invalidate(self.hwnd);
            unsafe {
                let _ = SetFocus(Some(self.name));
            }
            return;
        }
        let format = FORMATS[self.fmt].1;
        save_settings(self.fmt, self.prof);
        let out = unique_path(&self.dir, name.trim(), format.extension());
        let op = crate::worker::Op::Compress {
            sources: self.sources.clone(),
            out,
            format,
            level: PROFILES[self.prof].1,
        };
        let owner = unsafe { GetWindow(self.hwnd, GW_OWNER).ok() };
        crate::progress::start(owner, op);
        self.close();
    }

    fn close(&self) {
        if let Ok(o) = unsafe { GetWindow(self.hwnd, GW_OWNER) } {
            ui::enable(o, true);
            unsafe {
                let _ = SetForegroundWindow(o);
            }
        }
        unsafe {
            let _ = DestroyWindow(self.hwnd);
        }
    }
}

fn set_tabstop(h: HWND, on: bool) {
    unsafe {
        let s = GetWindowLongW(h, GWL_STYLE) as u32;
        let s = if on {
            s | WS_TABSTOP.0
        } else {
            s & !WS_TABSTOP.0
        };
        SetWindowLongW(h, GWL_STYLE, s as i32);
    }
}

impl ui::WindowState for Compress {
    fn handle(&mut self, hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
        match msg {
            WM_CREATE => {
                self.init(hwnd);
                Some(LRESULT(0))
            }
            WM_ERASEBKGND => Some(LRESULT(1)),
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
                self.paint(hdc);
                unsafe {
                    let _ = EndPaint(hwnd, &ps);
                }
                crate::first_paint();
                Some(LRESULT(0))
            }
            WM_CTLCOLOREDIT => Some(ui::ctl_color(wp)),
            WM_DRAWITEM => {
                let dis = unsafe { &*(lp.0 as *const DRAWITEMSTRUCT) };
                ui::draw_button(dis, theme::pal().surface);
                Some(LRESULT(1))
            }
            WM_COMMAND => {
                let id = ui::loword(wp.0) as isize;
                let code = ui::hiword(wp.0) as u32;
                match (id, code) {
                    (ID_NAME, c) if c == EN_SETFOCUS || c == EN_KILLFOCUS => ui::invalidate(hwnd),
                    (ID_NAME, c) if c == EN_CHANGE => {
                        if self.error.is_some() {
                            self.error = None;
                            ui::invalidate(hwnd);
                        }
                    }
                    (x, c)
                        if (ID_FMT..ID_FMT + 4).contains(&x)
                            && (c == BN_CLICKED || c == BN_SETFOCUS) =>
                    {
                        self.select_fmt((x - ID_FMT) as usize)
                    }
                    (x, c)
                        if (ID_PROF..ID_PROF + 4).contains(&x)
                            && (c == BN_CLICKED || c == BN_SETFOCUS) =>
                    {
                        self.select_prof((x - ID_PROF) as usize)
                    }
                    (ID_MORE, c) if c == BN_CLICKED => {
                        self.expanded = !self.expanded;
                        ui::set_btn(
                            self.more,
                            Btn::Expander {
                                label: tr("암호화 · 분할 · 복구 레코드").into(),
                                note: tr("— M3에서 제공").into(),
                                open: self.expanded,
                            },
                        );
                        let (w, h) = ui::outer_size(
                            WS_CAPTION | WS_SYSMENU,
                            WS_EX_DLGMODALFRAME,
                            W,
                            height(self.expanded),
                            unsafe { windows::Win32::UI::HiDpi::GetDpiForWindow(hwnd) },
                        );
                        unsafe {
                            let _ = SetWindowPos(hwnd, None, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
                        }
                        self.layout();
                        ui::invalidate(hwnd);
                    }
                    (ID_LOCATION, c) if c == BN_CLICKED => {
                        if let Some(d) =
                            ui::pick_folder(hwnd, tr("저장 위치 고르기"), Some(&self.dir))
                        {
                            self.dir = d;
                            ui::invalidate(hwnd);
                        }
                    }
                    (ID_OK, c) if c == BN_CLICKED => self.start(),
                    (ID_CANCEL, c) if c == BN_CLICKED => self.close(),
                    _ => {}
                }
                Some(LRESULT(0))
            }
            WM_CLOSE => {
                self.close();
                Some(LRESULT(0))
            }
            WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
                theme::refresh();
                ui::style_frame(hwnd, false);
                ui::theme_control(self.name, "edit");
                ui::invalidate(hwnd);
                None
            }
            WM_DPICHANGED => {
                ui::apply_dpi_rect(hwnd, lp);
                ui::set_font(self.name, ui::body_font(hwnd));
                self.layout();
                ui::invalidate(hwnd);
                Some(LRESULT(0))
            }
            WM_DESTROY => {
                ui::top_closed();
                Some(LRESULT(0))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("project").is_ok());
        assert!(valid_name(" ").is_err());
        assert!(valid_name("a/b").is_err());
        assert!(valid_name("a.").is_err());
        let (n, _) = default_target(&[PathBuf::from("C:\\w\\report.docx")]);
        assert_eq!(n, "report");
    }
}
