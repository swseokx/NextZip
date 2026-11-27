//! Password prompt (modal).

use nz_front::{tr, trf};
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{BeginPaint, EndPaint, PAINTSTRUCT};
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCWSTR, w};

use crate::gfx::{self, Align, Type, rect};
use crate::theme;
use crate::ui::{self, Btn};

pub const CLASS: PCWSTR = w!("NextZipPassword");

const W: f32 = 420.0;
const H: f32 = 236.0;
const ID_EDIT: isize = 10;
const ID_SHOW: isize = 11;

type Answer = Rc<RefCell<Option<Option<String>>>>;

pub struct Password {
    hwnd: HWND,
    name: String,
    again: bool,
    edit: HWND,
    show: HWND,
    visible: bool,
    answer: Answer,
}

/// Ask for the password of `archive`; `None` when the user cancels.
pub fn ask(owner: HWND, archive: &Path, again: bool) -> Option<String> {
    let answer: Answer = Rc::new(RefCell::new(None));
    let st = Password {
        hwnd: HWND::default(),
        name: archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        again,
        edit: HWND::default(),
        show: HWND::default(),
        visible: false,
        answer: answer.clone(),
    };
    let style = WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    let ex = WS_EX_DLGMODALFRAME;
    let (w, h) = ui::outer_size(style, ex, W, H, ui::system_dpi());
    let hwnd = ui::create(
        CLASS,
        tr("암호 입력 — NextZip"),
        style,
        ex,
        (CW_USEDEFAULT, CW_USEDEFAULT, w, h),
        Some(owner),
        0,
        st,
    );
    ui::center(hwnd, Some(owner));
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
    }
    let a2 = answer.clone();
    ui::modal_loop(owner, hwnd, move || a2.borrow().is_some());
    answer.borrow_mut().take().flatten()
}

impl Password {
    fn layout(&self) {
        ui::place(self.hwnd, self.edit, 33.0, 104.0, W - 66.0 - 88.0, 22.0);
        ui::place(self.hwnd, self.show, W - 24.0 - 80.0, 98.0, 80.0, 34.0);
        let y = H - 56.0;
        ui::place(
            self.hwnd,
            ui::get_child(self.hwnd, 2),
            W - 24.0 - 88.0 - 8.0 - 88.0,
            y,
            88.0,
            32.0,
        );
        ui::place(
            self.hwnd,
            ui::get_child(self.hwnd, 1),
            W - 24.0 - 88.0,
            y,
            88.0,
            32.0,
        );
    }

    fn done(&self, v: Option<String>) {
        *self.answer.borrow_mut() = Some(v);
        unsafe {
            let _ = DestroyWindow(self.hwnd);
        }
    }
}

impl ui::WindowState for Password {
    fn handle(&mut self, hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
        match msg {
            WM_CREATE => {
                self.hwnd = hwnd;
                ui::style_frame(hwnd, false);
                self.edit = ui::edit(hwnd, ID_EDIT, tr("암호"), true);
                self.show = ui::button(
                    hwnd,
                    ID_SHOW,
                    tr("암호 표시"),
                    Btn::Secondary(tr("표시").into()),
                    true,
                );
                ui::button(hwnd, 2, tr("취소"), Btn::Secondary(tr("취소").into()), true);
                ui::button(hwnd, 1, tr("확인"), Btn::Primary(tr("확인").into()), false);
                self.layout();
                unsafe {
                    let _ = SetFocus(Some(self.edit));
                }
                Some(LRESULT(0))
            }
            WM_ERASEBKGND => Some(LRESULT(1)),
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
                let p = theme::pal();
                let focus =
                    unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetFocus() } == self.edit;
                let line = if self.again {
                    tr("암호가 틀렸습니다. 다시 입력하세요.").to_string()
                } else {
                    trf("{}은(는) 암호로 보호되어 있습니다.", &[&self.name])
                };
                let again = self.again;
                gfx::paint(hwnd, hdc, |c| {
                    c.clear(p.surface);
                    c.text(
                        tr("암호 입력"),
                        rect(24.0, 20.0, W - 48.0, 28.0),
                        Type::Title,
                        Align::Left,
                        p.text,
                    );
                    c.text(
                        &line,
                        rect(24.0, 56.0, W - 48.0, 18.0),
                        Type::Body,
                        Align::Left,
                        if again { p.danger } else { p.muted },
                    );
                    let frame = rect(24.0, 96.0, W - 48.0 - 88.0, 34.0);
                    c.stroke_round(
                        frame,
                        4.0,
                        if focus { p.focus } else { p.border },
                        if focus { 2.0 } else { 1.0 },
                    );
                    c.text(
                        tr("암호는 이 작업에만 쓰고 저장하지 않습니다."),
                        rect(24.0, 138.0, W - 48.0, 16.0),
                        Type::Caption,
                        Align::Left,
                        p.muted,
                    );
                    c.hline(0.0, c.w, H - 72.0, p.divider);
                });
                unsafe {
                    let _ = EndPaint(hwnd, &ps);
                }
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
                if lp.0 != 0 && id != ID_EDIT && code != BN_CLICKED {
                    return Some(LRESULT(0));
                }
                match id {
                    1 => self.done(Some(ui::get_text(self.edit))),
                    2 => self.done(None),
                    ID_SHOW if code == BN_CLICKED => {
                        self.visible = !self.visible;
                        let ch = if self.visible { 0 } else { 0x25CF };
                        ui::send(
                            self.edit,
                            windows::Win32::UI::Controls::EM_SETPASSWORDCHAR,
                            ch,
                            0,
                        );
                        let label = if self.visible {
                            tr("숨김")
                        } else {
                            tr("표시")
                        };
                        ui::acc_name(
                            self.show,
                            if self.visible {
                                tr("암호 숨기기")
                            } else {
                                tr("암호 표시")
                            },
                        );
                        ui::set_btn(self.show, Btn::Secondary(label.into()));
                        ui::invalidate(self.edit);
                    }
                    ID_EDIT if code == EN_SETFOCUS || code == EN_KILLFOCUS => ui::invalidate(hwnd),
                    _ => {}
                }
                Some(LRESULT(0))
            }
            WM_CLOSE => {
                self.done(None);
                Some(LRESULT(0))
            }
            WM_DPICHANGED => {
                ui::apply_dpi_rect(hwnd, lp);
                ui::set_font(self.edit, ui::body_font(hwnd));
                self.layout();
                Some(LRESULT(0))
            }
            _ => None,
        }
    }
}
