//! Direct2D / DirectWrite painting on window DCs.
//!
//! Every custom-drawn window paints through one shared `ID2D1DCRenderTarget`
//! bound to the window's DC inside WM_PAINT. Coordinates are DIPs (CSS px of
//! the design tokens); the target's DPI is set to the window's DPI, so Per-
//! Monitor DPI v2 scaling is automatic.

use std::cell::RefCell;
use std::collections::HashMap;

use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::Graphics::Direct2D::Common::{
    D2D_RECT_F, D2D1_ALPHA_MODE_PREMULTIPLIED, D2D1_COLOR_F, D2D1_PIXEL_FORMAT,
};
use windows::Win32::Graphics::Direct2D::{
    D2D1_ANTIALIAS_MODE_PER_PRIMITIVE, D2D1_DASH_STYLE_DASH, D2D1_DRAW_TEXT_OPTIONS_CLIP,
    D2D1_FACTORY_TYPE_SINGLE_THREADED, D2D1_FEATURE_LEVEL_DEFAULT, D2D1_RENDER_TARGET_PROPERTIES,
    D2D1_RENDER_TARGET_TYPE_DEFAULT, D2D1_RENDER_TARGET_USAGE_GDI_COMPATIBLE, D2D1_ROUNDED_RECT,
    D2D1_STROKE_STYLE_PROPERTIES, D2D1CreateFactory, ID2D1DCRenderTarget, ID2D1Factory,
    ID2D1SolidColorBrush, ID2D1StrokeStyle,
};
use windows::Win32::Graphics::DirectWrite::{
    DWRITE_FACTORY_TYPE_SHARED, DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL,
    DWRITE_FONT_WEIGHT, DWRITE_MEASURING_MODE_NATURAL, DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
    DWRITE_PARAGRAPH_ALIGNMENT_NEAR, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_TEXT_ALIGNMENT_LEADING,
    DWRITE_TEXT_ALIGNMENT_TRAILING, DWRITE_TRIMMING, DWRITE_TRIMMING_GRANULARITY_CHARACTER,
    DWRITE_WORD_WRAPPING_NO_WRAP, DWRITE_WORD_WRAPPING_WRAP, DWriteCreateFactory, IDWriteFactory,
    IDWriteTextFormat,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Gdi::HDC;
use windows::core::{HSTRING, Result};
use windows_numerics::Vector2;

use crate::theme::Rgb;

/// The design's type ramp (MASTER.md section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    Title,
    Subtitle,
    Body,
    BodyStrong,
    Caption,
    Mono,
    Display,
    Icon,
    IconSmall,
    IconLarge,
}

impl Type {
    fn spec(self) -> (&'static str, f32, i32) {
        match self {
            Type::Title => (UI_FONT, 20.0, 600),
            Type::Subtitle => (UI_FONT, 16.0, 600),
            Type::Body => (UI_FONT, 14.0, 400),
            Type::BodyStrong => (UI_FONT, 14.0, 600),
            Type::Caption => (UI_FONT, 12.0, 400),
            Type::Mono => ("Cascadia Mono", 12.0, 400),
            Type::Display => (UI_FONT, 32.0, 600),
            Type::Icon => (ICON_FONT, 16.0, 400),
            Type::IconSmall => (ICON_FONT, 12.0, 400),
            Type::IconLarge => (ICON_FONT, 32.0, 400),
        }
    }
}

pub const UI_FONT: &str = "Segoe UI Variable Text";
const ICON_FONT: &str = "Segoe Fluent Icons";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Align {
    Left,
    Center,
    Right,
}

struct Gfx {
    d2d: ID2D1Factory,
    dw: IDWriteFactory,
    rt: ID2D1DCRenderTarget,
    formats: HashMap<(Type, Align, bool, bool), IDWriteTextFormat>,
    dash: ID2D1StrokeStyle,
    icon_font: &'static str,
}

thread_local! {
    static G: RefCell<Option<Gfx>> = const { RefCell::new(None) };
}

fn rt_props() -> D2D1_RENDER_TARGET_PROPERTIES {
    D2D1_RENDER_TARGET_PROPERTIES {
        r#type: D2D1_RENDER_TARGET_TYPE_DEFAULT,
        pixelFormat: D2D1_PIXEL_FORMAT {
            format: DXGI_FORMAT_B8G8R8A8_UNORM,
            alphaMode: D2D1_ALPHA_MODE_PREMULTIPLIED,
        },
        dpiX: 0.0,
        dpiY: 0.0,
        usage: D2D1_RENDER_TARGET_USAGE_GDI_COMPATIBLE,
        minLevel: D2D1_FEATURE_LEVEL_DEFAULT,
    }
}

/// A built [`Gfx`] crossing from the start-up thread to the UI thread.
/// The D2D factory is single-threaded: it and everything made from it are
/// only ever used by one thread at a time (the builder, then the UI thread
/// after the hand-over), which is what that factory type requires. The
/// DirectWrite factory is the thread-safe shared one.
struct Built(Result<Gfx>);
// SAFETY: see above; the value is moved, never shared.
unsafe impl Send for Built {}

thread_local! {
    static PENDING: RefCell<Option<std::sync::mpsc::Receiver<Built>>> = const { RefCell::new(None) };
}

/// Start creating the factories on a background thread. Loading d2d1 /
/// DirectWrite and the font fallback for Hangul take ~50-70 ms; this
/// overlaps them with COM, common controls and window creation. The first
/// drawing or measuring call waits for the result (see [`ready`]).
pub fn start() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(Built(build()));
    });
    PENDING.with(|p| *p.borrow_mut() = Some(rx));
}

/// Finish initialisation on this thread (waits for [`start`] if it ran).
pub fn init() -> Result<()> {
    if G.with(|g| g.borrow().is_some()) {
        return Ok(());
    }
    let pending = PENDING.with(|p| p.borrow_mut().take());
    let built = match pending.and_then(|rx| rx.recv().ok()) {
        Some(Built(r)) => r,
        None => build(),
    }?;
    G.with(|g| *g.borrow_mut() = Some(built));
    Ok(())
}

/// Make sure the factories exist before drawing; a failure is fatal.
fn ready() {
    if let Err(e) = init() {
        crate::ui::message(
            HWND::default(),
            "NextZip",
            &nz_front::trf("Direct2D를 시작하지 못했습니다: {}", &[&e]),
            true,
        );
        std::process::exit(1);
    }
}

fn build() -> Result<Gfx> {
    unsafe {
        let d2d: ID2D1Factory = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)?;
        let dw: IDWriteFactory = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)?;
        let rt = d2d.CreateDCRenderTarget(&rt_props())?;
        let dash = d2d.CreateStrokeStyle(
            &D2D1_STROKE_STYLE_PROPERTIES {
                dashStyle: D2D1_DASH_STYLE_DASH,
                ..Default::default()
            },
            None,
        )?;
        // Windows 10 has Segoe MDL2 Assets with the same code points.
        // Probing the system font collection costs ~20 ms at start-up;
        // the font file's presence answers the same question.
        let windir = std::env::var_os("WINDIR").unwrap_or_else(|| r"C:\Windows".into());
        let icon_font = if std::path::Path::new(&windir)
            .join("Fonts")
            .join("SegoeIcons.ttf")
            .exists()
        {
            ICON_FONT
        } else {
            "Segoe MDL2 Assets"
        };
        let mut g = Gfx {
            d2d,
            dw,
            rt,
            formats: HashMap::new(),
            dash,
            icon_font,
        };
        // Warm the formats the first frame uses and the Hangul font
        // fallback while the UI thread is still creating windows.
        for (t, a) in [
            (Type::Body, Align::Left),
            (Type::BodyStrong, Align::Left),
            (Type::Caption, Align::Left),
            (Type::Icon, Align::Center),
        ] {
            let f = make_format(&mut g, t, a, true, false);
            let w: Vec<u16> = "열기 풀기 압축 테스트 상태".encode_utf16().collect();
            if let Ok(l) = g.dw.CreateTextLayout(&w, &f, 1000.0, 100.0) {
                let mut m = Default::default();
                let _ = l.GetMetrics(&mut m);
            }
        }
        Ok(g)
    }
}

fn format(t: Type, align: Align, vcenter: bool, wrap: bool) -> IDWriteTextFormat {
    ready();
    G.with(|g| {
        let mut g = g.borrow_mut();
        let g = g.as_mut().expect("gfx::init");
        make_format(g, t, align, vcenter, wrap)
    })
}

fn make_format(g: &mut Gfx, t: Type, align: Align, vcenter: bool, wrap: bool) -> IDWriteTextFormat {
    {
        if let Some(f) = g.formats.get(&(t, align, vcenter, wrap)) {
            return f.clone();
        }
        let (mut family, size, weight) = t.spec();
        if family == ICON_FONT {
            family = g.icon_font;
        }
        unsafe {
            let f =
                g.dw.CreateTextFormat(
                    &HSTRING::from(family),
                    None,
                    DWRITE_FONT_WEIGHT(weight),
                    DWRITE_FONT_STYLE_NORMAL,
                    DWRITE_FONT_STRETCH_NORMAL,
                    size,
                    &HSTRING::from("ko-kr"),
                )
                .expect("text format");
            let _ = f.SetTextAlignment(match align {
                Align::Left => DWRITE_TEXT_ALIGNMENT_LEADING,
                Align::Center => DWRITE_TEXT_ALIGNMENT_CENTER,
                Align::Right => DWRITE_TEXT_ALIGNMENT_TRAILING,
            });
            let _ = f.SetParagraphAlignment(if vcenter {
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER
            } else {
                DWRITE_PARAGRAPH_ALIGNMENT_NEAR
            });
            let _ = f.SetWordWrapping(if wrap {
                DWRITE_WORD_WRAPPING_WRAP
            } else {
                DWRITE_WORD_WRAPPING_NO_WRAP
            });
            if !wrap {
                let trim = DWRITE_TRIMMING {
                    granularity: DWRITE_TRIMMING_GRANULARITY_CHARACTER,
                    delimiter: 0,
                    delimiterCount: 0,
                };
                if let Ok(sign) = g.dw.CreateEllipsisTrimmingSign(&f) {
                    let _ = f.SetTrimming(&trim, &sign);
                }
            }
            g.formats.insert((t, align, vcenter, wrap), f.clone());
            f
        }
    }
}

pub fn rect(x: f32, y: f32, w: f32, h: f32) -> D2D_RECT_F {
    D2D_RECT_F {
        left: x,
        top: y,
        right: x + w,
        bottom: y + h,
    }
}

/// Paint context for one WM_PAINT.
pub struct Ctx {
    rt: ID2D1DCRenderTarget,
    brush: ID2D1SolidColorBrush,
    dash: ID2D1StrokeStyle,
    pub w: f32,
    pub h: f32,
}

impl Ctx {
    fn set(&self, c: D2D1_COLOR_F) -> &ID2D1SolidColorBrush {
        unsafe { self.brush.SetColor(&c) };
        &self.brush
    }
    pub fn clear(&self, c: Rgb) {
        unsafe { self.rt.Clear(Some(&c.d2d())) };
    }
    pub fn fill(&self, r: D2D_RECT_F, c: Rgb) {
        unsafe { self.rt.FillRectangle(&r, self.set(c.d2d())) };
    }
    pub fn round(&self, r: D2D_RECT_F, radius: f32, c: Rgb) {
        let rr = D2D1_ROUNDED_RECT {
            rect: r,
            radiusX: radius,
            radiusY: radius,
        };
        unsafe { self.rt.FillRoundedRectangle(&rr, self.set(c.d2d())) };
    }
    /// Stroke a rounded rectangle inset by half the stroke width, so a 1px
    /// border stays inside `r`.
    pub fn stroke_round(&self, r: D2D_RECT_F, radius: f32, c: Rgb, width: f32) {
        let i = width / 2.0;
        let rr = D2D1_ROUNDED_RECT {
            rect: D2D_RECT_F {
                left: r.left + i,
                top: r.top + i,
                right: r.right - i,
                bottom: r.bottom - i,
            },
            radiusX: radius,
            radiusY: radius,
        };
        unsafe {
            self.rt
                .DrawRoundedRectangle(&rr, self.set(c.d2d()), width, None)
        };
    }
    pub fn dashed_round(&self, r: D2D_RECT_F, radius: f32, c: Rgb, width: f32) {
        let rr = D2D1_ROUNDED_RECT {
            rect: r,
            radiusX: radius,
            radiusY: radius,
        };
        unsafe {
            self.rt
                .DrawRoundedRectangle(&rr, self.set(c.d2d()), width, &self.dash)
        };
    }
    pub fn hline(&self, x0: f32, x1: f32, y: f32, c: Rgb) {
        unsafe {
            self.rt.DrawLine(
                Vector2 { X: x0, Y: y + 0.5 },
                Vector2 { X: x1, Y: y + 0.5 },
                self.set(c.d2d()),
                1.0,
                None,
            )
        };
    }
    pub fn vline(&self, x: f32, y0: f32, y1: f32, c: Rgb) {
        unsafe {
            self.rt.DrawLine(
                Vector2 { X: x + 0.5, Y: y0 },
                Vector2 { X: x + 0.5, Y: y1 },
                self.set(c.d2d()),
                1.0,
                None,
            )
        };
    }
    pub fn text(&self, s: &str, r: D2D_RECT_F, t: Type, align: Align, c: Rgb) {
        self.text_ex(s, r, t, align, true, false, c);
    }
    pub fn text_wrap(&self, s: &str, r: D2D_RECT_F, t: Type, align: Align, c: Rgb) {
        self.text_ex(s, r, t, align, false, true, c);
    }
    #[allow(clippy::too_many_arguments)]
    pub fn text_ex(
        &self,
        s: &str,
        r: D2D_RECT_F,
        t: Type,
        align: Align,
        vcenter: bool,
        wrap: bool,
        c: Rgb,
    ) {
        let f = format(t, align, vcenter, wrap);
        let w: Vec<u16> = s.encode_utf16().collect();
        unsafe {
            self.rt.DrawText(
                &w,
                &f,
                &r,
                self.set(c.d2d()),
                D2D1_DRAW_TEXT_OPTIONS_CLIP,
                DWRITE_MEASURING_MODE_NATURAL,
            )
        };
    }
    /// Draw one Fluent icon glyph centred in `r`.
    pub fn icon(&self, glyph: char, r: D2D_RECT_F, t: Type, c: Rgb) {
        self.text(&glyph.to_string(), r, t, Align::Center, c);
    }
    /// Width of `s` in DIPs.
    pub fn measure(&self, s: &str, t: Type) -> f32 {
        measure(s, t)
    }
}

pub fn measure(s: &str, t: Type) -> f32 {
    let f = format(t, Align::Left, true, false);
    let w: Vec<u16> = s.encode_utf16().collect();
    G.with(|g| {
        let g = g.borrow();
        let g = g.as_ref().expect("gfx::init");
        unsafe {
            g.dw.CreateTextLayout(&w, &f, 10_000.0, 100.0)
                .and_then(|l| {
                    let mut m = Default::default();
                    l.GetMetrics(&mut m)
                        .map(|_| m.widthIncludingTrailingWhitespace)
                })
                .unwrap_or(s.len() as f32 * 7.0)
        }
    })
}

/// Paint `hwnd`'s client area (`hdc` from BeginPaint / WM_PRINTCLIENT).
pub fn paint(hwnd: HWND, hdc: HDC, f: impl FnOnce(&Ctx)) {
    let mut rc = RECT::default();
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
    }
    paint_rect(hwnd, hdc, rc, f);
}

pub fn paint_rect(hwnd: HWND, hdc: HDC, rc: RECT, f: impl FnOnce(&Ctx)) {
    let dpi = unsafe { windows::Win32::UI::HiDpi::GetDpiForWindow(hwnd) }.max(96) as f32;
    let scale = dpi / 96.0;
    ready();
    let (rt, brush, dash) = G.with(|g| {
        let g = g.borrow();
        let g = g.as_ref().expect("gfx::init");
        let brush = unsafe {
            g.rt.CreateSolidColorBrush(&Rgb(0).d2d(), None)
                .expect("brush")
        };
        (g.rt.clone(), brush, g.dash.clone())
    });
    unsafe {
        if rt.BindDC(hdc, &rc).is_err() {
            return;
        }
        rt.SetDpi(dpi, dpi);
        rt.SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        rt.BeginDraw();
    }
    let ctx = Ctx {
        rt: rt.clone(),
        brush,
        dash,
        w: (rc.right - rc.left) as f32 / scale,
        h: (rc.bottom - rc.top) as f32 / scale,
    };
    f(&ctx);
    unsafe {
        if rt.EndDraw(None, None).is_err() {
            // Device loss: recreate the target for the next paint.
            G.with(|g| {
                if let Some(g) = g.borrow_mut().as_mut()
                    && let Ok(rt) = g.d2d.CreateDCRenderTarget(&rt_props())
                {
                    g.rt = rt;
                }
            });
        }
    }
}

/// Fluent UI icon code points (Segoe Fluent Icons / MDL2 Assets).
#[allow(dead_code)]
pub mod icon {
    pub const EXTRACT: char = '\u{E896}';
    pub const ARCHIVE: char = '\u{F012}';
    pub const SHIELD: char = '\u{EA18}';
    pub const ADD: char = '\u{E710}';
    pub const DELETE: char = '\u{E74D}';
    pub const VIEW: char = '\u{F0E2}';
    pub const OPEN: char = '\u{E8E5}';
    pub const CHEVRON_RIGHT: char = '\u{E76C}';
    pub const CHEVRON_DOWN: char = '\u{E70D}';
    pub const LOCK: char = '\u{E72E}';
    pub const PAUSE: char = '\u{E769}';
    pub const CHECK: char = '\u{E73E}';
    pub const CHECK_CIRCLE: char = '\u{E930}';
    pub const INFO: char = '\u{E946}';
    pub const WARNING: char = '\u{E7BA}';
    pub const UP: char = '\u{E74A}';
    pub const LANGUAGE: char = '\u{F2B7}';
    pub const SETTINGS: char = '\u{E713}';
}
