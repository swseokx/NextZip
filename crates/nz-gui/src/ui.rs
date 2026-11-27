//! Shared Win32 plumbing: window classes with boxed state, owner-drawn
//! buttons painted with Direct2D, accessibility annotations, native control
//! fonts and dark-mode theming, DPI helpers, small dialogs.

use nz_front::tr;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{
    DWMSBT_MAINWINDOW, DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DwmSetWindowAttribute,
};
use windows::Win32::Graphics::Gdi::{
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, CreateFontW, DEFAULT_CHARSET, DeleteObject, FW_NORMAL,
    HFONT, HGDIOBJ, InvalidateRect, OUT_DEFAULT_PRECIS,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Variant::{VARIANT, VT_I4};
use windows::Win32::UI::Accessibility::{
    CLSID_AccPropServices, IAccPropServices, NotifyWinEvent, PROPID_ACC_ROLE, PROPID_ACC_STATE,
    PROPID_ACC_VALUE,
};
use windows::Win32::UI::Controls::WM_MOUSELEAVE;
use windows::Win32::UI::Controls::{
    DRAWITEMSTRUCT, ODS_DISABLED, ODS_FLAGS, ODS_FOCUS, ODS_NOFOCUSRECT, ODS_SELECTED,
    TOOLTIPS_CLASSW, TTF_IDISHWND, TTF_SUBCLASS, TTM_ADDTOOLW, TTM_SETMAXTIPWIDTH, TTS_ALWAYSTIP,
    TTS_NOPREFIX, TTTOOLINFOW,
};
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    DefSubclassProc, FOS_ALLOWMULTISELECT, FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS, FileOpenDialog,
    FileSaveDialog, IFileOpenDialog, IFileSaveDialog, IShellItem, SHCreateItemFromParsingName,
    SIGDN_FILESYSPATH, SetWindowSubclass,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{HSTRING, PCWSTR, w};

use crate::gfx::{self, Align, Type, rect};
use crate::theme::{self, Mode};

pub const WM_APP_WORK: u32 = WM_APP + 1;

// ---------------------------------------------------------------- windows

/// A window procedure on boxed state: `S` lives in GWLP_USERDATA from
/// WM_NCCREATE until WM_NCDESTROY.
pub trait WindowState: Sized + 'static {
    fn handle(&mut self, hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT>;
}

unsafe extern "system" fn proc_for<S: WindowState>(
    hwnd: HWND,
    msg: u32,
    wp: WPARAM,
    lp: LPARAM,
) -> LRESULT {
    unsafe {
        if msg == WM_NCCREATE {
            let cs = &*(lp.0 as *const CREATESTRUCTW);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, cs.lpCreateParams as isize);
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut RefCell<S>;
        if p.is_null() {
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        if msg == WM_NCDESTROY {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            // The window may be destroyed from inside its own handler (the
            // state is borrowed further up the stack): free it later, from
            // the top-level message loop.
            let b: Box<dyn std::any::Any> = Box::from_raw(p);
            DEFERRED.with(|d| d.borrow_mut().push(b));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        // Re-entrant messages (a SendMessage from inside a handler) go to
        // DefWindowProc instead of panicking on the RefCell.
        let r = match (*p).try_borrow_mut() {
            Ok(mut s) => {
                trace(&format!("enter {:x} {msg:#x}", hwnd.0 as usize));
                let r = s.handle(hwnd, msg, wp, lp);
                trace(&format!("leave {:x} {msg:#x}", hwnd.0 as usize));
                r
            }
            Err(_) if msg == WM_MEASUREITEM => {
                // Owner-drawn list created from inside a handler: answer the
                // row height here (32 DIP rows).
                let mi = &mut *(lp.0 as *mut windows::Win32::UI::Controls::MEASUREITEMSTRUCT);
                mi.itemHeight = (32.0 * dpi(hwnd)).round() as u32;
                Some(LRESULT(1))
            }
            Err(_) => {
                trace(&format!("busy {:x} {msg:#x}", hwnd.0 as usize));
                None
            }
        };
        r.unwrap_or_else(|| DefWindowProcW(hwnd, msg, wp, lp))
    }
}

thread_local! {
    static DEFERRED: RefCell<Vec<Box<dyn std::any::Any>>> = const { RefCell::new(Vec::new()) };
}

/// Free the state of destroyed windows (call from the top-level loop only).
pub fn flush_deferred() {
    let v = DEFERRED.with(|d| std::mem::take(&mut *d.borrow_mut()));
    drop(v);
}

pub fn register<S: WindowState>(class: PCWSTR) {
    unsafe {
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS,
            lpfnWndProc: Some(proc_for::<S>),
            hInstance: GetModuleHandleW(None).unwrap_or_default().into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hIcon: LoadIconW(
                Some(GetModuleHandleW(None).unwrap_or_default().into()),
                PCWSTR(1 as _),
            )
            .unwrap_or_default(),
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassExW(&wc);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create<S: WindowState>(
    class: PCWSTR,
    title: &str,
    style: WINDOW_STYLE,
    ex: WINDOW_EX_STYLE,
    rc: (i32, i32, i32, i32),
    parent: Option<HWND>,
    id: isize,
    state: S,
) -> HWND {
    let boxed = Box::into_raw(Box::new(RefCell::new(state)));
    unsafe {
        CreateWindowExW(
            ex,
            class,
            &HSTRING::from(title),
            style,
            rc.0,
            rc.1,
            rc.2,
            rc.3,
            parent,
            if id != 0 { Some(HMENU(id as _)) } else { None },
            Some(GetModuleHandleW(None).unwrap_or_default().into()),
            Some(boxed as *const _),
        )
        .unwrap_or_default()
    }
}

/// Create a native child control.
pub fn control(
    class: PCWSTR,
    text: &str,
    style: WINDOW_STYLE,
    ex: WINDOW_EX_STYLE,
    parent: HWND,
    id: isize,
) -> HWND {
    unsafe {
        CreateWindowExW(
            ex,
            class,
            &HSTRING::from(text),
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            0,
            0,
            Some(parent),
            Some(HMENU(id as _)),
            Some(GetModuleHandleW(None).unwrap_or_default().into()),
            None,
        )
        .unwrap_or_default()
    }
}

pub fn dpi(hwnd: HWND) -> f32 {
    unsafe { GetDpiForWindow(hwnd) }.max(96) as f32 / 96.0
}

/// DIPs to pixels for `hwnd`.
pub fn px(hwnd: HWND, dip: f32) -> i32 {
    (dip * dpi(hwnd)).round() as i32
}

pub fn client(hwnd: HWND) -> RECT {
    let mut rc = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut rc);
    }
    rc
}

/// Move a child; coordinates in DIPs.
pub fn place(parent: HWND, child: HWND, x: f32, y: f32, w: f32, h: f32) {
    let s = dpi(parent);
    unsafe {
        let _ = MoveWindow(
            child,
            (x * s).round() as i32,
            (y * s).round() as i32,
            (w * s).round().max(0.0) as i32,
            (h * s).round().max(0.0) as i32,
            true,
        );
    }
}

pub fn show(hwnd: HWND, visible: bool) {
    unsafe {
        let _ = ShowWindow(hwnd, if visible { SW_SHOW } else { SW_HIDE });
    }
}

pub fn enable(hwnd: HWND, on: bool) {
    unsafe {
        let _ = EnableWindow(hwnd, on);
    }
}

pub fn invalidate(hwnd: HWND) {
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

pub fn set_text(hwnd: HWND, s: &str) {
    unsafe {
        let _ = SetWindowTextW(hwnd, &HSTRING::from(s));
    }
}

pub fn get_text(hwnd: HWND) -> String {
    unsafe {
        let n = GetWindowTextLengthW(hwnd).max(0) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(hwnd, &mut buf).max(0) as usize;
        String::from_utf16_lossy(&buf[..got])
    }
}

pub fn send(hwnd: HWND, msg: u32, wp: usize, lp: isize) -> isize {
    unsafe { SendMessageW(hwnd, msg, Some(WPARAM(wp)), Some(LPARAM(lp))).0 }
}

pub fn loword(v: usize) -> u16 {
    (v & 0xFFFF) as u16
}

pub fn hiword(v: usize) -> u16 {
    ((v >> 16) & 0xFFFF) as u16
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Title bar follows the theme; the main window gets Mica.
pub fn style_frame(hwnd: HWND, mica: bool) {
    let dark: i32 = (theme::pal().mode == Mode::Dark) as i32;
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const i32 as *const _,
            4,
        );
        if mica {
            let v = DWMSBT_MAINWINDOW.0;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_SYSTEMBACKDROP_TYPE,
                &v as *const i32 as *const _,
                4,
            );
        }
    }
}

/// Dark or light visual style for a native control (list, tree, edit).
pub fn theme_control(hwnd: HWND, kind: &str) {
    let dark = theme::pal().mode == Mode::Dark;
    let sub = match (dark, kind) {
        (true, "edit") => "DarkMode_CFD",
        (true, "header") => "DarkMode_ItemsView",
        (true, _) => "DarkMode_Explorer",
        (false, _) => "Explorer",
    };
    unsafe {
        let _ =
            windows::Win32::UI::Controls::SetWindowTheme(hwnd, &HSTRING::from(sub), PCWSTR::null());
    }
}

// ------------------------------------------------------------------ fonts

thread_local! {
    static FONTS: RefCell<HashMap<(i32, i32), HFONT>> = RefCell::new(HashMap::new());
}

/// GDI font for native controls: Segoe UI 14px (body) at `hwnd`'s DPI.
pub fn font(hwnd: HWND, size_dip: f32, weight: i32) -> HFONT {
    let h = -(size_dip * dpi(hwnd)).round() as i32;
    FONTS.with(|f| {
        *f.borrow_mut().entry((h, weight)).or_insert_with(|| unsafe {
            CreateFontW(
                h,
                0,
                0,
                0,
                weight,
                0,
                0,
                0,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                0,
                w!("Segoe UI"),
            )
        })
    })
}

pub fn set_font(ctrl: HWND, f: HFONT) {
    send(ctrl, WM_SETFONT, f.0 as usize, 1);
}

pub fn body_font(hwnd: HWND) -> HFONT {
    font(hwnd, 14.0, FW_NORMAL.0 as i32)
}

#[allow(dead_code)]
pub fn drop_fonts() {
    FONTS.with(|f| {
        for (_, h) in f.borrow_mut().drain() {
            unsafe {
                let _ = DeleteObject(HGDIOBJ(h.0));
            }
        }
    });
}

// ----------------------------------------------------------- accessibility

thread_local! {
    static ACC: RefCell<Option<IAccPropServices>> = const { RefCell::new(None) };
}

fn acc() -> Option<IAccPropServices> {
    ACC.with(|a| {
        let mut a = a.borrow_mut();
        if a.is_none() {
            *a = unsafe {
                CoCreateInstance(&CLSID_AccPropServices, None, CLSCTX_INPROC_SERVER).ok()
            };
        }
        a.clone()
    })
}

fn variant_i4(v: i32) -> VARIANT {
    let mut var = VARIANT::default();
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_I4;
        inner.Anonymous.lVal = v;
    }
    var
}

const OBJID_CLIENT: u32 = 0xFFFF_FFFC;

/// Override the MSAA/UIA role of a window (e.g. a painted panel exposed as
/// a status bar, an owner-drawn button exposed as a radio button).
pub fn acc_role(hwnd: HWND, role: u32) {
    if let Some(a) = acc() {
        unsafe {
            let _ = a.SetHwndProp(
                hwnd,
                OBJID_CLIENT,
                0,
                PROPID_ACC_ROLE,
                &variant_i4(role as i32),
            );
        }
    }
}

pub fn acc_state(hwnd: HWND, state: u32) {
    if let Some(a) = acc() {
        unsafe {
            let _ = a.SetHwndProp(
                hwnd,
                OBJID_CLIENT,
                0,
                PROPID_ACC_STATE,
                &variant_i4(state as i32),
            );
            NotifyWinEvent(0x800A, hwnd, OBJID_CLIENT as i32, 0); // EVENT_OBJECT_STATECHANGE
        }
    }
}

pub fn acc_value(hwnd: HWND, value: &str) {
    if let Some(a) = acc() {
        unsafe {
            let _ = a.SetHwndPropStr(
                hwnd,
                OBJID_CLIENT,
                0,
                PROPID_ACC_VALUE,
                &HSTRING::from(value),
            );
            NotifyWinEvent(0x800E, hwnd, OBJID_CLIENT as i32, 0); // EVENT_OBJECT_VALUECHANGE
        }
    }
}

/// Accessible name = window text (MSAA's default proxy reads it); changing it
/// raises a name-change event.
pub fn acc_name(hwnd: HWND, name: &str) {
    set_text(hwnd, name);
    unsafe { NotifyWinEvent(0x800C, hwnd, OBJID_CLIENT as i32, 0) }; // EVENT_OBJECT_NAMECHANGE
}

// ---------------------------------------------------------------- tooltips

pub fn tooltip(owner: HWND, tool: HWND, text: &str) {
    thread_local! {
        static TIPS: RefCell<HashMap<isize, HWND>> = RefCell::new(HashMap::new());
    }
    let root = unsafe { GetAncestor(owner, GA_ROOT) };
    let tip = TIPS.with(|t| {
        *t.borrow_mut()
            .entry(root.0 as isize)
            .or_insert_with(|| unsafe {
                let tip = CreateWindowExW(
                    WS_EX_TOPMOST,
                    TOOLTIPS_CLASSW,
                    PCWSTR::null(),
                    WS_POPUP | WINDOW_STYLE(TTS_ALWAYSTIP | TTS_NOPREFIX),
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    Some(root),
                    None,
                    Some(GetModuleHandleW(None).unwrap_or_default().into()),
                    None,
                )
                .unwrap_or_default();
                send(tip, TTM_SETMAXTIPWIDTH, 0, 400);
                tip
            })
    });
    let mut buf = wide(text);
    let ti = TTTOOLINFOW {
        cbSize: std::mem::size_of::<TTTOOLINFOW>() as u32,
        uFlags: TTF_IDISHWND | TTF_SUBCLASS,
        hwnd: owner,
        uId: tool.0 as usize,
        lpszText: windows::core::PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    send(tip, TTM_ADDTOOLW, 0, &ti as *const _ as isize);
}

// ------------------------------------------------------- owner-drawn buttons

#[derive(Clone, Debug, PartialEq)]
pub enum Btn {
    /// Toolbar: icon + optional label (`main` = accent colour icon).
    Tool {
        icon: char,
        label: String,
        main: bool,
    },
    /// Filled accent button (one per dialog).
    Primary(String),
    /// Bordered button.
    Secondary(String),
    /// Segmented control item.
    Segment { label: String, checked: bool },
    /// Compression profile card with speed / ratio meters (0..1).
    Profile {
        label: String,
        speed: f32,
        ratio: f32,
        checked: bool,
    },
    /// Text link / breadcrumb segment (`strong` = current).
    Link { label: String, strong: bool },
    /// Recent file row on the start screen.
    Recent { name: String, dir: String },
    /// Expander header ("암호화 · 분할 …") with a chevron.
    Expander {
        label: String,
        note: String,
        open: bool,
    },
    /// Small inline button with a trailing chevron (code page picker).
    Drop { label: String },
}

thread_local! {
    static BTNS: RefCell<HashMap<isize, Btn>> = RefCell::new(HashMap::new());
    static HOT: Cell<isize> = const { Cell::new(0) };
}

unsafe extern "system" fn btn_subclass(
    hwnd: HWND,
    msg: u32,
    wp: WPARAM,
    lp: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    unsafe {
        match msg {
            WM_MOUSEMOVE => {
                if HOT.with(Cell::get) != hwnd.0 as isize {
                    let old = HOT.with(|h| h.replace(hwnd.0 as isize));
                    if old != 0 {
                        invalidate(HWND(old as _));
                    }
                    invalidate(hwnd);
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    let _ = TrackMouseEvent(&mut tme);
                }
            }
            WM_MOUSELEAVE => {
                if HOT.with(Cell::get) == hwnd.0 as isize {
                    HOT.with(|h| h.set(0));
                }
                invalidate(hwnd);
            }
            WM_NCDESTROY => {
                BTNS.with(|b| b.borrow_mut().remove(&(hwnd.0 as isize)));
            }
            // Arrow keys move between radio-like buttons of a group.
            WM_GETDLGCODE => {
                let r = DefSubclassProc(hwnd, msg, wp, lp);
                let is_radio = BTNS.with(|b| {
                    matches!(
                        b.borrow().get(&(hwnd.0 as isize)),
                        Some(Btn::Segment { .. } | Btn::Profile { .. })
                    )
                });
                if is_radio {
                    return LRESULT(r.0 | DLGC_RADIOBUTTON as isize);
                }
                return r;
            }
            _ => {}
        }
        DefSubclassProc(hwnd, msg, wp, lp)
    }
}

const ROLE_SYSTEM_RADIOBUTTON: u32 = 45;
const STATE_SYSTEM_CHECKED: u32 = 0x10;

/// Create an owner-drawn button. Its window text is the accessible name.
pub fn button(parent: HWND, id: isize, name: &str, kind: Btn, group_start: bool) -> HWND {
    let mut style = WINDOW_STYLE((BS_OWNERDRAW | BS_NOTIFY) as u32) | WS_TABSTOP;
    if group_start {
        style |= WS_GROUP;
    }
    let h = control(w!("BUTTON"), name, style, WINDOW_EX_STYLE(0), parent, id);
    unsafe {
        let _ = SetWindowSubclass(h, Some(btn_subclass), 1, 0);
    }
    set_btn(h, kind);
    h
}

pub fn set_btn(h: HWND, kind: Btn) {
    let radio = match &kind {
        Btn::Segment { checked, .. } | Btn::Profile { checked, .. } => Some(*checked),
        _ => None,
    };
    BTNS.with(|b| b.borrow_mut().insert(h.0 as isize, kind));
    if let Some(checked) = radio {
        acc_role(h, ROLE_SYSTEM_RADIOBUTTON);
        acc_state(
            h,
            if checked {
                STATE_SYSTEM_CHECKED | 0x0010_0000 // focusable
            } else {
                0x0010_0000
            },
        );
    }
    invalidate(h);
}

pub fn btn(h: HWND) -> Option<Btn> {
    BTNS.with(|b| b.borrow().get(&(h.0 as isize)).cloned())
}

/// Paint an owner-drawn button (WM_DRAWITEM). `bg` is the parent's
/// background behind the button.
pub fn draw_button(dis: &DRAWITEMSTRUCT, bg: crate::theme::Rgb) {
    let Some(kind) = btn(dis.hwndItem) else {
        return;
    };
    let p = theme::pal();
    let hc = p.mode == Mode::HighContrast;
    let hot = HOT.with(Cell::get) == dis.hwndItem.0 as isize;
    let pressed = has(dis.itemState, ODS_SELECTED);
    let disabled = has(dis.itemState, ODS_DISABLED);
    let focus = has(dis.itemState, ODS_FOCUS) && !has(dis.itemState, ODS_NOFOCUSRECT);
    gfx::paint_rect(dis.hwndItem, dis.hDC, dis.rcItem, |c| {
        let (w, h) = (c.w, c.h);
        c.clear(bg);
        let fg = if disabled { p.muted } else { p.text };
        match &kind {
            Btn::Tool { icon, label, main } => {
                if (hot || pressed) && !disabled {
                    c.round(
                        rect(0.0, 0.0, w, h),
                        4.0,
                        if hc { p.selected } else { p.hover },
                    );
                }
                let ic = if disabled {
                    p.muted
                } else if *main {
                    p.primary
                } else {
                    p.text
                };
                if label.is_empty() {
                    c.icon(*icon, rect(0.0, 0.0, w, h), Type::Icon, ic);
                } else {
                    c.icon(*icon, rect(8.0, 0.0, 20.0, h), Type::Icon, ic);
                    let t = if *main { Type::BodyStrong } else { Type::Body };
                    c.text(label, rect(32.0, 0.0, w - 36.0, h), t, Align::Left, fg);
                }
            }
            Btn::Primary(label) => {
                let fill = if disabled {
                    p.divider
                } else if hot || pressed {
                    p.primary_hover
                } else {
                    p.primary
                };
                c.round(rect(0.0, 0.0, w, h), 4.0, fill);
                let tc = if disabled { p.muted } else { p.on_primary };
                c.text(
                    &strip_amp(label),
                    rect(0.0, 0.0, w, h),
                    Type::BodyStrong,
                    Align::Center,
                    tc,
                );
            }
            Btn::Secondary(label) => {
                c.round(
                    rect(0.0, 0.0, w, h),
                    4.0,
                    if (hot || pressed) && !disabled {
                        p.hover
                    } else {
                        p.surface
                    },
                );
                c.stroke_round(
                    rect(0.0, 0.0, w, h),
                    4.0,
                    if disabled { p.divider } else { p.border },
                    1.0,
                );
                c.text(
                    &strip_amp(label),
                    rect(0.0, 0.0, w, h),
                    Type::Body,
                    Align::Center,
                    fg,
                );
            }
            Btn::Segment { label, checked } => {
                let fill = if *checked {
                    p.selected
                } else if hot && !disabled {
                    p.hover
                } else {
                    p.surface
                };
                c.fill(rect(0.0, 0.0, w, h), fill);
                c.stroke_round(rect(0.0, 0.0, w, h), 0.0, p.border, 1.0);
                let t = if *checked {
                    Type::BodyStrong
                } else {
                    Type::Body
                };
                let col = if *checked && !hc { p.primary } else { fg };
                c.text(label, rect(0.0, 0.0, w, h), t, Align::Center, col);
                if *checked {
                    c.fill(rect(1.0, h - 3.0, w - 2.0, 2.0), p.primary);
                }
            }
            Btn::Profile {
                label,
                speed,
                ratio,
                checked,
            } => {
                let fill = if *checked {
                    p.selected
                } else if hot {
                    p.hover
                } else {
                    p.surface
                };
                c.round(rect(0.0, 0.0, w, h), 4.0, fill);
                c.stroke_round(
                    rect(0.0, 0.0, w, h),
                    4.0,
                    if *checked { p.primary } else { p.divider },
                    if *checked { 2.0 } else { 1.0 },
                );
                // radio dot
                let cy = h / 2.0;
                c.stroke_round(rect(12.0, cy - 8.0, 16.0, 16.0), 8.0, p.border, 1.0);
                if *checked {
                    c.round(rect(16.0, cy - 4.0, 8.0, 8.0), 4.0, p.primary);
                }
                c.text(
                    label,
                    rect(36.0, 0.0, 70.0, h),
                    Type::BodyStrong,
                    Align::Left,
                    fg,
                );
                let mw = ((w - 120.0) / 2.0 - 12.0).max(40.0);
                for (i, (name, v)) in [(tr("속도"), *speed), (tr("압축률"), *ratio)]
                    .iter()
                    .enumerate()
                {
                    let x = 112.0 + i as f32 * (mw + 12.0);
                    c.text(
                        name,
                        rect(x, 0.0, 44.0, h),
                        Type::Caption,
                        Align::Left,
                        p.muted,
                    );
                    let bx = x + 44.0;
                    let bw = (mw - 44.0).max(10.0);
                    c.round(rect(bx, cy - 3.0, bw, 6.0), 3.0, p.divider);
                    c.round(rect(bx, cy - 3.0, bw * v, 6.0), 3.0, p.primary);
                }
            }
            Btn::Link { label, strong } => {
                if hot {
                    c.round(rect(0.0, 0.0, w, h), 4.0, p.hover);
                }
                let t = if *strong {
                    Type::BodyStrong
                } else {
                    Type::Body
                };
                c.text(label, rect(4.0, 0.0, w - 8.0, h), t, Align::Center, fg);
            }
            Btn::Recent { name, dir } => {
                if hot {
                    c.round(rect(0.0, 0.0, w, h), 4.0, p.hover);
                }
                c.icon(
                    gfx::icon::ARCHIVE,
                    rect(8.0, 0.0, 24.0, h),
                    Type::Icon,
                    p.muted,
                );
                c.text(
                    name,
                    rect(40.0, 0.0, w * 0.45, h),
                    Type::Body,
                    Align::Left,
                    fg,
                );
                c.text(
                    dir,
                    rect(40.0 + w * 0.45, 0.0, w * 0.55 - 48.0, h),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                );
            }
            Btn::Expander { label, note, open } => {
                if hot {
                    c.round(rect(0.0, 0.0, w, h), 4.0, p.hover);
                }
                let g = if *open {
                    gfx::icon::CHEVRON_DOWN
                } else {
                    gfx::icon::CHEVRON_RIGHT
                };
                c.icon(g, rect(0.0, 0.0, 20.0, h), Type::IconSmall, fg);
                let lw = c.measure(label, Type::Body);
                c.text(
                    label,
                    rect(24.0, 0.0, lw + 4.0, h),
                    Type::Body,
                    Align::Left,
                    fg,
                );
                c.text(
                    note,
                    rect(32.0 + lw, 0.0, w - lw - 32.0, h),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                );
            }
            Btn::Drop { label } => {
                if hot || pressed {
                    c.round(rect(0.0, 0.0, w, h), 4.0, p.hover);
                }
                c.text(
                    label,
                    rect(6.0, 0.0, w - 26.0, h),
                    Type::Caption,
                    Align::Left,
                    fg,
                );
                c.icon(
                    gfx::icon::CHEVRON_DOWN,
                    rect(w - 20.0, 0.0, 16.0, h),
                    Type::IconSmall,
                    fg,
                );
            }
        }
        if focus {
            c.stroke_round(rect(0.0, 0.0, w, h), 4.0, p.focus, 2.0);
        }
    });
}

pub fn has(state: ODS_FLAGS, f: ODS_FLAGS) -> bool {
    state.0 & f.0 != 0
}

fn strip_amp(s: &str) -> String {
    s.replace('&', "")
}

// --------------------------------------------------------------- dialogs

fn item_path(it: &IShellItem) -> Option<PathBuf> {
    unsafe {
        let p = it.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let s = p.to_string().ok();
        CoTaskMemFree(Some(p.0 as *const _));
        s.map(PathBuf::from)
    }
}

pub fn pick_files(owner: HWND, title: &str, archives_only: bool) -> Vec<PathBuf> {
    unsafe {
        let Ok(d): windows::core::Result<IFileOpenDialog> =
            CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)
        else {
            return Vec::new();
        };
        let mut opts = d.GetOptions().unwrap_or_default() | FOS_FORCEFILESYSTEM;
        if !archives_only {
            opts |= FOS_ALLOWMULTISELECT;
        }
        let _ = d.SetOptions(opts);
        let _ = d.SetTitle(&HSTRING::from(title));
        let n1 = wide(tr("압축 파일"));
        let s1 = wide("*.zip;*.7z;*.nz;*.tzst;*.zst;*.alz;*.egg;*.rar;*.a00;*.part1.rar");
        let n2 = wide(tr("모든 파일"));
        let s2 = wide("*.*");
        let specs = [
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(n1.as_ptr()),
                pszSpec: PCWSTR(s1.as_ptr()),
            },
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(n2.as_ptr()),
                pszSpec: PCWSTR(s2.as_ptr()),
            },
        ];
        if archives_only {
            let _ = d.SetFileTypes(&specs);
        }
        if d.Show(Some(owner)).is_err() {
            return Vec::new();
        }
        let Ok(items) = d.GetResults() else {
            return Vec::new();
        };
        let n = items.GetCount().unwrap_or(0);
        (0..n)
            .filter_map(|i| items.GetItemAt(i).ok())
            .filter_map(|it| item_path(&it))
            .collect()
    }
}

pub fn pick_folder(owner: HWND, title: &str, start: Option<&std::path::Path>) -> Option<PathBuf> {
    unsafe {
        let d: IFileOpenDialog =
            CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let opts = d.GetOptions().unwrap_or_default() | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM;
        let _ = d.SetOptions(opts);
        let _ = d.SetTitle(&HSTRING::from(title));
        if let Some(s) = start
            && let Ok(it) =
                SHCreateItemFromParsingName::<_, _, IShellItem>(&HSTRING::from(s.as_os_str()), None)
        {
            let _ = d.SetFolder(&it);
        }
        d.Show(Some(owner)).ok()?;
        item_path(&d.GetResult().ok()?)
    }
}

#[allow(dead_code)]
pub fn pick_save(owner: HWND, title: &str, name: &str) -> Option<PathBuf> {
    unsafe {
        let d: IFileSaveDialog =
            CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let _ = d.SetTitle(&HSTRING::from(title));
        let _ = d.SetFileName(&HSTRING::from(name));
        d.Show(Some(owner)).ok()?;
        item_path(&d.GetResult().ok()?)
    }
}

pub fn warning(owner: HWND, title: &str, text: &str) {
    unsafe {
        MessageBoxW(
            Some(owner),
            &HSTRING::from(text),
            &HSTRING::from(title),
            MB_ICONWARNING,
        );
    }
}

pub fn message(owner: HWND, title: &str, text: &str, error: bool) {
    unsafe {
        MessageBoxW(
            Some(owner),
            &HSTRING::from(text),
            &HSTRING::from(title),
            if error {
                MB_ICONERROR
            } else {
                MB_ICONINFORMATION
            },
        );
    }
}

/// Disable `owner` and pump messages until `done()` (modal helper for our
/// own popup windows).
pub fn modal_loop(owner: HWND, dlg: HWND, done: impl Fn() -> bool) {
    enable(owner, false);
    unsafe {
        let mut msg = MSG::default();
        while !done() && IsWindow(Some(dlg)).as_bool() {
            if !GetMessageW(&mut msg, None, 0, 0).as_bool() {
                PostQuitMessage(msg.wParam.0 as i32);
                break;
            }
            if IsDialogMessageW(dlg, &msg).as_bool() {
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        enable(owner, true);
        let _ = SetForegroundWindow(owner);
        if IsWindow(Some(dlg)).as_bool() {
            let _ = DestroyWindow(dlg);
        }
    }
}

/// Centre `hwnd` over `owner` (or the work area).
pub fn center(hwnd: HWND, owner: Option<HWND>) {
    unsafe {
        let mut r = RECT::default();
        let _ = GetWindowRect(hwnd, &mut r);
        let mut o = RECT::default();
        match owner {
            Some(ow) if IsWindowVisible(ow).as_bool() => {
                let _ = GetWindowRect(ow, &mut o);
            }
            _ => {
                let _ = SystemParametersInfoW(
                    SPI_GETWORKAREA,
                    0,
                    Some(&mut o as *mut _ as *mut _),
                    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
                );
            }
        }
        let w = r.right - r.left;
        let h = r.bottom - r.top;
        let x = o.left + ((o.right - o.left) - w) / 2;
        let y = o.top + ((o.bottom - o.top) - h) / 2;
        let _ = SetWindowPos(hwnd, None, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
}

/// Outer window size for a client size in DIPs at the DPI of `near`.
pub fn outer_size(
    style: WINDOW_STYLE,
    ex: WINDOW_EX_STYLE,
    w: f32,
    h: f32,
    dpi: u32,
) -> (i32, i32) {
    let s = dpi as f32 / 96.0;
    let mut r = RECT {
        left: 0,
        top: 0,
        right: (w * s) as i32,
        bottom: (h * s) as i32,
    };
    unsafe {
        let _ = windows::Win32::UI::HiDpi::AdjustWindowRectExForDpi(&mut r, style, false, ex, dpi);
    }
    (r.right - r.left, r.bottom - r.top)
}

/// DPI of the monitor the cursor is on (for windows not yet created).
pub fn system_dpi() -> u32 {
    unsafe {
        let mut pt = Default::default();
        let _ = GetCursorPos(&mut pt);
        let mon = windows::Win32::Graphics::Gdi::MonitorFromPoint(
            pt,
            windows::Win32::Graphics::Gdi::MONITOR_DEFAULTTONEAREST,
        );
        let (mut x, mut y) = (96u32, 96u32);
        let _ = windows::Win32::UI::HiDpi::GetDpiForMonitor(
            mon,
            windows::Win32::UI::HiDpi::MDT_EFFECTIVE_DPI,
            &mut x,
            &mut y,
        );
        x.max(96)
    }
}

/// Apply WM_DPICHANGED's suggested rectangle.
pub fn apply_dpi_rect(hwnd: HWND, lp: LPARAM) {
    unsafe {
        let r = &*(lp.0 as *const RECT);
        let _ = SetWindowPos(
            hwnd,
            None,
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

// --------------------------------------------------------------- formatting

pub fn size(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", U[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}", U[i])
    } else {
        format!("{v:.2} {}", U[i])
    }
}

pub fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("0:{:04.1}", secs)
    } else {
        let s = secs as u64;
        if s >= 3600 {
            format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
        } else {
            format!("{}:{:02}", s / 60, s % 60)
        }
    }
}

pub fn local_time(t: std::time::SystemTime) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) else {
        return String::new();
    };
    let ft100 = d.as_nanos() / 100 + 116_444_736_000_000_000;
    let ft = FILETIME {
        dwLowDateTime: ft100 as u32,
        dwHighDateTime: (ft100 >> 32) as u32,
    };
    let mut st = SYSTEMTIME::default();
    let mut lt = SYSTEMTIME::default();
    unsafe {
        if FileTimeToSystemTime(&ft, &mut st).is_err()
            || SystemTimeToTzSpecificLocalTime(None, &st, &mut lt).is_err()
        {
            return String::new();
        }
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(size(512), "512 B");
        assert_eq!(size(2_528_000), "2.41 MB");
        assert_eq!(count(1204), "1,204");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(duration(1.25), "0:01.2");
        assert_eq!(duration(75.0), "1:15");
    }
}

// ------------------------------------------------------------------ panels

/// Sent by a panel to its parent to paint it: wParam = panel id, lParam =
/// HDC. The parent paints with `gfx::paint(panel, hdc, ..)`.
pub const WM_APP_PAINT: u32 = WM_APP + 2;

pub const PANEL_CLASS: PCWSTR = w!("NzPanel");

unsafe extern "system" fn panel_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                let mut ps = windows::Win32::Graphics::Gdi::PAINTSTRUCT::default();
                let hdc = windows::Win32::Graphics::Gdi::BeginPaint(hwnd, &mut ps);
                if let Ok(parent) = GetParent(hwnd) {
                    let id = GetDlgCtrlID(hwnd) as usize;
                    SendMessageW(
                        parent,
                        WM_APP_PAINT,
                        Some(WPARAM(id)),
                        Some(LPARAM(hdc.0 as isize)),
                    );
                }
                let _ = windows::Win32::Graphics::Gdi::EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_ERASEBKGND => LRESULT(1),
            WM_COMMAND | WM_DRAWITEM | WM_NOTIFY | WM_MEASUREITEM => match GetParent(hwnd) {
                Ok(parent) => SendMessageW(parent, msg, Some(wp), Some(lp)),
                Err(_) => LRESULT(0),
            },
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

pub fn register_panel() {
    unsafe {
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(panel_proc),
            hInstance: GetModuleHandleW(None).unwrap_or_default().into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            lpszClassName: PANEL_CLASS,
            ..Default::default()
        };
        RegisterClassExW(&wc);
    }
}

/// A painted child region with an accessible name and role.
pub fn panel(parent: HWND, id: isize, name: &str, role: u32) -> HWND {
    let h = control(
        PANEL_CLASS,
        name,
        WS_CLIPCHILDREN,
        WINDOW_EX_STYLE(0),
        parent,
        id,
    );
    if role != 0 {
        acc_role(h, role);
    }
    h
}

// ------------------------------------------------------------ edit colours

thread_local! {
    static BRUSHES: RefCell<HashMap<u32, windows::Win32::Graphics::Gdi::HBRUSH>> =
        RefCell::new(HashMap::new());
}

/// WM_CTLCOLOREDIT / WM_CTLCOLORSTATIC answer in the current palette.
pub fn ctl_color(wp: WPARAM) -> LRESULT {
    use windows::Win32::Graphics::Gdi::{CreateSolidBrush, SetBkColor, SetTextColor};
    let p = theme::pal();
    let hdc = windows::Win32::Graphics::Gdi::HDC(wp.0 as _);
    unsafe {
        SetTextColor(hdc, p.text.colorref());
        SetBkColor(hdc, p.surface.colorref());
    }
    let b = BRUSHES.with(|b| {
        *b.borrow_mut()
            .entry(p.surface.0)
            .or_insert_with(|| unsafe { CreateSolidBrush(p.surface.colorref()) })
    });
    LRESULT(b.0 as isize)
}

/// A bordered single-line edit box (the border is painted by the parent
/// around the control rectangle, see `edit_frame`).
pub fn edit(parent: HWND, id: isize, name: &str, password: bool) -> HWND {
    let mut style = WINDOW_STYLE((ES_AUTOHSCROLL | ES_LEFT) as u32) | WS_TABSTOP;
    if password {
        style |= WINDOW_STYLE(ES_PASSWORD as u32);
    }
    let h = control(w!("EDIT"), "", style, WINDOW_EX_STYLE(0), parent, id);
    // Accessible name comes from the preceding label; set it explicitly.
    if let Some(a) = acc() {
        unsafe {
            let _ = a.SetHwndPropStr(
                h,
                OBJID_CLIENT,
                0,
                windows::Win32::UI::Accessibility::PROPID_ACC_NAME,
                &HSTRING::from(name),
            );
        }
    }
    set_font(h, body_font(parent));
    theme_control(h, "edit");
    h
}

/// Child window rectangle in the parent's DIPs.
pub fn child_rect(
    parent: HWND,
    child: HWND,
) -> windows::Win32::Graphics::Direct2D::Common::D2D_RECT_F {
    let mut r = RECT::default();
    unsafe {
        let _ = GetWindowRect(child, &mut r);
        let mut pts = [
            windows::Win32::Foundation::POINT {
                x: r.left,
                y: r.top,
            },
            windows::Win32::Foundation::POINT {
                x: r.right,
                y: r.bottom,
            },
        ];
        windows::Win32::Graphics::Gdi::MapWindowPoints(None, Some(parent), &mut pts);
        let s = dpi(parent);
        windows::Win32::Graphics::Direct2D::Common::D2D_RECT_F {
            left: pts[0].x as f32 / s,
            top: pts[0].y as f32 / s,
            right: pts[1].x as f32 / s,
            bottom: pts[1].y as f32 / s,
        }
    }
}

// ------------------------------------------------------- top-level counting

thread_local! {
    static TOP: Cell<usize> = const { Cell::new(0) };
}

/// Count a top-level window; the app quits when the last one closes.
pub fn top_opened() {
    TOP.with(|t| t.set(t.get() + 1));
}

pub fn top_closed() {
    let left = TOP.with(|t| {
        let n = t.get().saturating_sub(1);
        t.set(n);
        n
    });
    if left == 0 {
        unsafe { PostQuitMessage(0) };
    }
}

pub fn get_child(parent: HWND, id: isize) -> HWND {
    unsafe { GetDlgItem(Some(parent), id as i32).unwrap_or_default() }
}

/// Debug trace to the file named by `NZ_GUI_LOG` (off by default).
pub fn trace(m: &str) {
    static LOG: std::sync::OnceLock<Option<std::ffi::OsString>> = std::sync::OnceLock::new();
    if let Some(p) = LOG.get_or_init(|| std::env::var_os("NZ_GUI_LOG")) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
            let _ = writeln!(f, "{:?} {m}", std::time::SystemTime::now());
        }
    }
}
