//! NextZip Windows GUI: Win32 + Direct2D/DirectWrite, no WinUI or web view.
//!
//! ```text
//! nextzip [archive]                    main window (start screen without a file)
//! nextzip --compress <path>...         compress dialog (Explorer "압축…")
//! nextzip --extract-here <archive>     extract next to the archive (Explorer "여기에 풀기")
//! nextzip --extract-folder <archive>   extract into <stem>\ (Explorer "폴더로 풀기")
//! nextzip --worker ...                 internal: background job process
//!
//! --theme light|dark       fixed theme instead of the Windows app mode
//! --start                  with --compress: start immediately with saved settings
//! --screenshot <png> [--delay <ms>]  save the active window and exit
//! --probe-startup <file>   write "startup_ms=<n>" at the first paint and exit
//! ```

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod compress;
mod gfx;
mod mainwin;
mod password;
mod progress;
mod theme;
mod ui;
mod worker;

use nz_front::tr;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{FILETIME, HWND, LPARAM, RECT};
use windows::Win32::Globalization::GetACP;
use windows::Win32::Graphics::Dwm::{DWMWA_EXTENDED_FRAME_BOUNDS, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, ReleaseDC,
    SRCCOPY, SelectObject,
};
use windows::Win32::Graphics::Imaging::{
    CLSID_WICImagingFactory, GUID_ContainerFormatPng, IWICImagingFactory, WICBitmapEncoderNoCache,
    WICBitmapIgnoreAlpha,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId, GetProcessTimes};
use windows::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_LISTVIEW_CLASSES, ICC_STANDARD_CLASSES, ICC_TREEVIEW_CLASSES,
    INITCOMMONCONTROLSEX, InitCommonControlsEx,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{VK_D, VK_E, VK_N, VK_O, VK_R, VK_UP};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{BOOL, HSTRING};

/// System ANSI code page as a detection hint (949 on Korean Windows).
pub fn system_codepage() -> Option<nz_archive::Codepage> {
    nz_archive::Codepage::from_number(unsafe { GetACP() })
}

/// Folder name for "폴더로 풀기": the archive name without archive suffixes.
pub fn archive_stem(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into());
    let lower = name.to_lowercase();
    for suf in [
        ".tar.zst", ".tzst", ".zip", ".7z", ".nz", ".alz", ".egg", ".rar", ".zst", ".a00",
    ] {
        if lower.ends_with(suf) && name.len() > suf.len() {
            let mut stem = name[..name.len() - suf.len()].to_string();
            // name.part1.rar -> name
            if suf == ".rar" {
                let l = stem.to_lowercase();
                if let Some(i) = l.rfind(".part")
                    && l[i + 5..].chars().all(|c| c.is_ascii_digit())
                    && i + 5 < l.len()
                {
                    stem.truncate(i);
                }
            }
            return stem;
        }
    }
    name
}

fn unique_dir(p: PathBuf) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let base = p.to_string_lossy().into_owned();
    (2..)
        .map(|n| PathBuf::from(format!("{base} ({n})")))
        .find(|c| !c.exists())
        .unwrap_or(p)
}

thread_local! {
    static PROBE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static PROBED: Cell<bool> = const { Cell::new(false) };
}

fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

/// Milliseconds since process creation (startup tracing).
pub fn since_start() -> f64 {
    let (mut c, mut e, mut k, mut u) = Default::default();
    unsafe {
        let _ = GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u);
        (ft(GetSystemTimePreciseAsFileTime()).saturating_sub(ft(c))) as f64 / 10_000.0
    }
}

pub fn stage(name: &str) {
    ui::trace(&format!("stage {:.1} {name}", since_start()));
}

/// Called after each top-level first paint; with `--probe-startup`, records
/// the time from process creation and quits.
pub fn first_paint() {
    if PROBED.with(Cell::get) {
        return;
    }
    stage("first paint");
    PROBED.with(|p| p.set(true));
    let Some(out) = PROBE.with(|p| p.borrow().clone()) else {
        return;
    };
    let (mut c, mut e, mut k, mut u) = Default::default();
    unsafe {
        let _ = GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u);
        let now = GetSystemTimePreciseAsFileTime();
        let ms = (ft(now).saturating_sub(ft(c))) as f64 / 10_000.0;
        let cpu = (ft(k) + ft(u)) as f64 / 10_000.0;
        let _ = std::fs::write(out, format!("startup_ms={ms:.1}\ncpu_ms={cpu:.1}\n"));
        PostQuitMessage(0);
    }
}

/// Save the visible pixels of `hwnd` (with its frame) as a PNG.
fn screenshot(hwnd: HWND, out: &Path) -> windows::core::Result<()> {
    unsafe {
        let mut r = RECT::default();
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut r as *mut _ as *mut _,
            std::mem::size_of::<RECT>() as u32,
        )?;
        let (w, h) = (r.right - r.left, r.bottom - r.top);
        // Render the window itself (works while other windows cover it),
        // then crop the invisible resize borders off.
        let mut wr = RECT::default();
        GetWindowRect(hwnd, &mut wr)?;
        let (ww, wh) = (wr.right - wr.left, wr.bottom - wr.top);
        let screen = GetDC(None);
        let full_dc = CreateCompatibleDC(Some(screen));
        let full = CreateCompatibleBitmap(screen, ww, wh);
        let old_full = SelectObject(full_dc, full.into());
        let _ = windows::Win32::Storage::Xps::PrintWindow(
            hwnd,
            full_dc,
            windows::Win32::Storage::Xps::PRINT_WINDOW_FLAGS(2), // PW_RENDERFULLCONTENT
        );
        let mem = CreateCompatibleDC(Some(screen));
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bmp.into());
        let _ = BitBlt(
            mem,
            0,
            0,
            w,
            h,
            Some(full_dc),
            r.left - wr.left,
            r.top - wr.top,
            SRCCOPY,
        );
        SelectObject(mem, old);
        SelectObject(full_dc, old_full);
        let _ = DeleteObject(full.into());
        let _ = DeleteDC(full_dc);
        let wic: IWICImagingFactory =
            CoCreateInstance(&CLSID_WICImagingFactory, None, CLSCTX_INPROC_SERVER)?;
        let bitmap = wic.CreateBitmapFromHBITMAP(bmp, Default::default(), WICBitmapIgnoreAlpha)?;
        let stream = wic.CreateStream()?;
        stream.InitializeFromFilename(
            &HSTRING::from(out.as_os_str()),
            0x4000_0000, /* GENERIC_WRITE */
        )?;
        let enc = wic.CreateEncoder(&GUID_ContainerFormatPng, std::ptr::null())?;
        enc.Initialize(&stream, WICBitmapEncoderNoCache)?;
        let mut frame = None;
        enc.CreateNewFrame(&mut frame, std::ptr::null_mut())?;
        let frame = frame.ok_or_else(windows::core::Error::empty)?;
        frame.Initialize(None)?;
        frame.WriteSource(&bitmap, std::ptr::null())?;
        frame.Commit()?;
        enc.Commit()?;
        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem);
        ReleaseDC(None, screen);
    }
    Ok(())
}

unsafe extern "system" fn collect_window(h: HWND, lp: LPARAM) -> BOOL {
    unsafe {
        let v = &mut *(lp.0 as *mut Vec<HWND>);
        v.push(h);
    }
    BOOL(1)
}

fn thread_windows() -> Vec<HWND> {
    let mut v: Vec<HWND> = Vec::new();
    unsafe {
        let _ = EnumThreadWindows(
            GetCurrentThreadId(),
            Some(collect_window),
            LPARAM(&mut v as *mut _ as isize),
        );
    }
    v
}

/// The active top-level window of this thread (for screenshots).
fn active_window() -> Option<HWND> {
    let fg = unsafe { GetForegroundWindow() };
    let mine = thread_windows();
    if mine.contains(&fg) {
        return Some(fg);
    }
    mine.into_iter()
        .find(|h| unsafe { IsWindowVisible(*h).as_bool() && GetWindow(*h, GW_OWNER).is_err() })
}

struct Args {
    files: Vec<PathBuf>,
    mode: Mode,
    start: bool,
    theme: theme::Pref,
    screenshot: Option<PathBuf>,
    delay: u32,
    probe: Option<PathBuf>,
}

#[derive(PartialEq)]
enum Mode {
    Open,
    Compress,
    ExtractHere,
    ExtractFolder,
}

fn parse(args: &[String]) -> Args {
    let mut a = Args {
        files: Vec::new(),
        mode: Mode::Open,
        start: false,
        theme: theme::Pref::System,
        screenshot: None,
        delay: 1200,
        probe: None,
    };
    let mut it = args.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--compress" => a.mode = Mode::Compress,
            "--extract-here" => a.mode = Mode::ExtractHere,
            "--extract-folder" => a.mode = Mode::ExtractFolder,
            "--start" => a.start = true,
            "--theme" => {
                a.theme = match it.next().map(String::as_str) {
                    Some("light") => theme::Pref::Light,
                    Some("dark") => theme::Pref::Dark,
                    _ => theme::Pref::System,
                }
            }
            "--screenshot" => a.screenshot = it.next().map(PathBuf::from),
            "--delay" => a.delay = it.next().and_then(|d| d.parse().ok()).unwrap_or(1200),
            "--probe-startup" => a.probe = it.next().map(PathBuf::from),
            _ => a.files.push(PathBuf::from(x)),
        }
    }
    a
}

fn accelerators() -> HACCEL {
    let ctrl = FVIRTKEY | FCONTROL;
    let alt = FVIRTKEY | FALT;
    let table = [
        ACCEL {
            fVirt: ctrl,
            key: VK_O.0,
            cmd: mainwin::CMD_OPEN,
        },
        ACCEL {
            fVirt: ctrl,
            key: VK_N.0,
            cmd: mainwin::CMD_NEW,
        },
        ACCEL {
            fVirt: ctrl,
            key: VK_R.0,
            cmd: mainwin::CMD_RECENT,
        },
        ACCEL {
            fVirt: ctrl,
            key: VK_E.0,
            cmd: mainwin::CMD_EXTRACT,
        },
        ACCEL {
            fVirt: alt,
            key: VK_UP.0,
            cmd: mainwin::CMD_UP,
        },
        ACCEL {
            fVirt: alt,
            key: VK_D.0,
            cmd: mainwin::CMD_FOCUS_PATH,
        },
    ];
    unsafe { CreateAcceleratorTableW(&table).unwrap_or_default() }
}

fn main() {
    nz_front::i18n::init();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--worker") {
        std::process::exit(worker::run_child(&argv[1..]));
    }
    let args = parse(&argv);
    stage("main");
    // Direct2D/DirectWrite start-up runs in parallel with everything up to
    // the first measure or paint.
    gfx::start();
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES
                | ICC_TREEVIEW_CLASSES
                | ICC_BAR_CLASSES
                | ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);
    }
    stage("com+comctl");
    PROBE.with(|p| *p.borrow_mut() = args.probe.clone());
    theme::set_pref(args.theme);
    theme::refresh();
    ui::register_panel();
    ui::register::<mainwin::Main>(mainwin::CLASS);
    ui::register::<compress::Compress>(compress::CLASS);
    ui::register::<progress::Progress>(progress::CLASS);
    ui::register::<password::Password>(password::CLASS);

    let mut main_hwnd = None;
    match args.mode {
        Mode::Open => {
            let h = mainwin::Main::create(args.files.first().cloned());
            stage("main window");
            unsafe {
                let _ = ShowWindow(h, SW_SHOWDEFAULT);
            }
            main_hwnd = Some(h);
        }
        Mode::Compress if !args.files.is_empty() => {
            compress::show(None, args.files.clone(), args.start);
        }
        Mode::ExtractHere | Mode::ExtractFolder if !args.files.is_empty() => {
            for a in &args.files {
                let parent = a.parent().map(Path::to_path_buf).unwrap_or_default();
                let dest = if args.mode == Mode::ExtractHere {
                    parent
                } else {
                    unique_dir(parent.join(archive_stem(a)))
                };
                progress::start(
                    None,
                    worker::Op::Extract {
                        archive: a.clone(),
                        dest,
                        codepage: None,
                        password: None,
                        test: false,
                    },
                );
            }
        }
        _ => {
            ui::message(
                HWND::default(),
                "NextZip",
                tr("처리할 파일이 없습니다."),
                true,
            );
            return;
        }
    }

    let shot_timer = if args.screenshot.is_some() {
        unsafe { SetTimer(None, 0, args.delay, None) }
    } else {
        0
    };
    let accel = accelerators();
    unsafe {
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if msg.hwnd.is_invalid()
                && msg.message == WM_TIMER
                && shot_timer != 0
                && msg.wParam.0 == shot_timer
            {
                if let (Some(out), Some(w)) = (&args.screenshot, active_window()) {
                    let _ = KillTimer(None, msg.wParam.0);
                    if let Err(e) = screenshot(w, out) {
                        let _ = std::fs::write(out.with_extension("err.txt"), e.to_string());
                    }
                    PostQuitMessage(0);
                }
                continue;
            }
            let root = GetAncestor(msg.hwnd, GA_ROOT);
            if Some(root) == main_hwnd && TranslateAcceleratorW(root, accel, &msg) != 0 {
                continue;
            }
            if !root.is_invalid() && IsDialogMessageW(root, &msg).as_bool() {
                ui::flush_deferred();
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
            ui::flush_deferred();
        }
        // Tear down remaining windows so running jobs are cancelled.
        for h in thread_windows() {
            let _ = DestroyWindow(h);
        }
        ui::flush_deferred();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stems() {
        assert_eq!(archive_stem(Path::new("C:\\a\\photos.zip")), "photos");
        assert_eq!(archive_stem(Path::new("x.tar.zst")), "x");
        assert_eq!(archive_stem(Path::new("backup.nz")), "backup");
        assert_eq!(archive_stem(Path::new("movie.part1.rar")), "movie");
        assert_eq!(archive_stem(Path::new("a.part.rar")), "a.part");
        assert_eq!(archive_stem(Path::new("noext")), "noext");
    }
}
