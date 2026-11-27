//! Design tokens from `design-system/nextzip/tokens.css`, light / dark /
//! high contrast, following the Windows app mode and contrast settings.

use std::cell::Cell;

use windows::Win32::Foundation::COLORREF;
use windows::Win32::Graphics::Direct2D::Common::D2D1_COLOR_F;
use windows::Win32::Graphics::Gdi::{
    COLOR_BTNFACE, COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT, COLOR_HOTLIGHT,
    COLOR_WINDOW, COLOR_WINDOWTEXT, GetSysColor, SYS_COLOR_INDEX,
};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows::Win32::UI::WindowsAndMessaging::{
    SPI_GETCLIENTAREAANIMATION, SPI_GETHIGHCONTRAST, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    SystemParametersInfoW,
};
use windows::core::w;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rgb(pub u32);

impl Rgb {
    pub fn d2d(self) -> D2D1_COLOR_F {
        self.alpha(1.0)
    }
    pub fn alpha(self, a: f32) -> D2D1_COLOR_F {
        D2D1_COLOR_F {
            r: ((self.0 >> 16) & 0xFF) as f32 / 255.0,
            g: ((self.0 >> 8) & 0xFF) as f32 / 255.0,
            b: (self.0 & 0xFF) as f32 / 255.0,
            a,
        }
    }
    /// GDI COLORREF (0x00BBGGRR).
    pub fn colorref(self) -> COLORREF {
        let r = (self.0 >> 16) & 0xFF;
        let g = (self.0 >> 8) & 0xFF;
        let b = self.0 & 0xFF;
        COLORREF(r | (g << 8) | (b << 16))
    }
    fn from_sys(i: SYS_COLOR_INDEX) -> Rgb {
        let c = unsafe { GetSysColor(i) };
        Rgb(((c & 0xFF) << 16) | (c & 0xFF00) | ((c >> 16) & 0xFF))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Light,
    Dark,
    HighContrast,
}

#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub mode: Mode,
    pub bg: Rgb,
    pub surface: Rgb,
    pub surface2: Rgb,
    pub text: Rgb,
    pub muted: Rgb,
    pub divider: Rgb,
    pub border: Rgb,
    pub primary: Rgb,
    pub primary_hover: Rgb,
    pub on_primary: Rgb,
    pub selected: Rgb,
    pub hover: Rgb,
    pub focus: Rgb,
    pub attention: Rgb,
    pub success: Rgb,
    pub danger: Rgb,
}

pub const LIGHT: Palette = Palette {
    mode: Mode::Light,
    bg: Rgb(0xF7F8F8),
    surface: Rgb(0xFFFFFF),
    surface2: Rgb(0xF1F3F3),
    text: Rgb(0x1A2321),
    muted: Rgb(0x5A6866),
    divider: Rgb(0xDDE2E2),
    border: Rgb(0x8A9694),
    primary: Rgb(0x0F766E),
    primary_hover: Rgb(0x115E59),
    on_primary: Rgb(0xFFFFFF),
    selected: Rgb(0xE6F4F2),
    hover: Rgb(0xEEF1F1),
    focus: Rgb(0x0F766E),
    attention: Rgb(0xC2410C),
    success: Rgb(0x15803D),
    danger: Rgb(0xB91C1C),
};

pub const DARK: Palette = Palette {
    mode: Mode::Dark,
    bg: Rgb(0x151A19),
    surface: Rgb(0x1C2221),
    surface2: Rgb(0x232A29),
    text: Rgb(0xE6ECEB),
    muted: Rgb(0xA3B0AE),
    divider: Rgb(0x323B3A),
    border: Rgb(0x6E7A78),
    primary: Rgb(0x2DD4BF),
    primary_hover: Rgb(0x5EEAD4),
    on_primary: Rgb(0x04201D),
    selected: Rgb(0x12302C),
    hover: Rgb(0x262E2D),
    focus: Rgb(0x5EEAD4),
    attention: Rgb(0xFB923C),
    success: Rgb(0x4ADE80),
    danger: Rgb(0xF87171),
};

fn high_contrast() -> Palette {
    let window = Rgb::from_sys(COLOR_WINDOW);
    let text = Rgb::from_sys(COLOR_WINDOWTEXT);
    let hl = Rgb::from_sys(COLOR_HIGHLIGHT);
    let hl_text = Rgb::from_sys(COLOR_HIGHLIGHTTEXT);
    Palette {
        mode: Mode::HighContrast,
        bg: window,
        surface: window,
        surface2: Rgb::from_sys(COLOR_BTNFACE),
        text,
        muted: Rgb::from_sys(COLOR_GRAYTEXT),
        divider: text,
        border: text,
        primary: hl,
        primary_hover: hl,
        on_primary: hl_text,
        selected: hl,
        hover: window,
        focus: Rgb::from_sys(COLOR_HOTLIGHT),
        attention: text,
        success: text,
        danger: text,
    }
}

/// Theme override from the command line (`--theme light|dark`), for
/// screenshots and for users who want a fixed theme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pref {
    System,
    Light,
    Dark,
}

thread_local! {
    static PREF: Cell<Pref> = const { Cell::new(Pref::System) };
    static CURRENT: Cell<Palette> = const { Cell::new(LIGHT) };
    static ANIMATE: Cell<bool> = const { Cell::new(true) };
}

pub fn set_pref(p: Pref) {
    PREF.with(|c| c.set(p));
}

fn system_is_light() -> bool {
    let mut v: u32 = 1;
    let mut n = 4u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"),
            w!("AppsUseLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut v as *mut u32 as *mut _),
            Some(&mut n),
        )
    };
    r.is_err() || v != 0
}

fn is_high_contrast() -> bool {
    let mut hc = HIGHCONTRASTW {
        cbSize: std::mem::size_of::<HIGHCONTRASTW>() as u32,
        ..Default::default()
    };
    unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            hc.cbSize,
            Some(&mut hc as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .is_ok()
            && hc.dwFlags.contains(HCF_HIGHCONTRASTON)
    }
}

/// Re-read system settings (call at start and on WM_SETTINGCHANGE).
pub fn refresh() -> Palette {
    let p = if is_high_contrast() {
        high_contrast()
    } else {
        match PREF.with(Cell::get) {
            Pref::Light => LIGHT,
            Pref::Dark => DARK,
            Pref::System if system_is_light() => LIGHT,
            Pref::System => DARK,
        }
    };
    let mut anim = windows::core::BOOL(1);
    unsafe {
        let _ = SystemParametersInfoW(
            SPI_GETCLIENTAREAANIMATION,
            0,
            Some(&mut anim as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        );
    }
    ANIMATE.with(|c| c.set(anim.as_bool()));
    CURRENT.with(|c| c.set(p));
    p
}

pub fn pal() -> Palette {
    CURRENT.with(Cell::get)
}

/// False when Windows "animation effects" are off (prefers-reduced-motion).
pub fn animate() -> bool {
    ANIMATE.with(Cell::get)
}
