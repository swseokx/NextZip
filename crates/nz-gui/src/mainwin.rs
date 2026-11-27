//! Main window: toolbar, path bar, folder tree, virtual file list, preview
//! pane, status bar; the start screen when no archive is open.

use nz_front::{tr, trf};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};

use nz_archive::{Codepage, Listing};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, HDC, PAINTSTRUCT, RDW_ALLCHILDREN, RDW_ERASE, RDW_INVALIDATE,
    RedrawWindow,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::Input::KeyboardAndMouse::{SetFocus, VK_BACK};
use windows::Win32::UI::Shell::{
    DragAcceptFiles, DragFinish, DragQueryFileW, HDROP, SHFILEINFOW, SHGFI_SMALLICON,
    SHGFI_SYSICONINDEX, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{HSTRING, PCWSTR, w};

use crate::gfx::{self, Align, Type, icon, rect};
use crate::theme::{self, Mode};
use crate::ui::{self, Btn, WM_APP_PAINT, WM_APP_WORK};

pub const CLASS: PCWSTR = w!("NextZipMain");

const TB_H: f32 = 48.0;
const PATH_H: f32 = 40.0;
const STATUS_H: f32 = 28.0;
const TREE_W: f32 = 220.0;
const PREVIEW_W: f32 = 260.0;
const ROW_H: f32 = 32.0;

// control ids
const ID_OPEN: isize = 100;
const ID_EXTRACT: isize = 101;
const ID_COMPRESS: isize = 102;
const ID_TEST: isize = 103;
const ID_ADD: isize = 104;
const ID_DELETE: isize = 105;
const ID_VIEW: isize = 106;
const ID_SETTINGS: isize = 107;
const ID_UP: isize = 110;
const ID_CRUMB: isize = 120; // .. 199
const ID_TREE: isize = 200;
const ID_LIST: isize = 201;
const ID_PREVIEW: isize = 300;
const ID_PREVIEW_CP: isize = 301;
const ID_STATUS: isize = 310;
const ID_STATUS_CP: isize = 311;
const ID_EMPTY_OPEN: isize = 400;
const ID_EMPTY_NEW: isize = 401;
const ID_RECENT: isize = 410; // .. 419
// accelerators
pub const CMD_OPEN: u16 = 500;
pub const CMD_NEW: u16 = 501;
pub const CMD_RECENT: u16 = 502;
pub const CMD_EXTRACT: u16 = 503;
pub const CMD_UP: u16 = 504;
pub const CMD_FOCUS_PATH: u16 = 505;
// code page menu
const MENU_CP_AUTO: usize = 1000;
const MENU_CP: usize = 1001;
const MENU_LANG: usize = 1100; // .. 1102: auto, Korean, English
const MENU_SCAN: usize = 1110;
const MENU_LINKS: usize = 1111;

const COLS: [(&str, f32, bool); 7] = [
    ("이름", 260.0, false),
    ("크기", 90.0, true),
    ("압축 크기", 90.0, true),
    ("압축률", 70.0, true),
    ("방법", 110.0, false),
    ("수정한 날짜", 130.0, false),
    ("CRC", 84.0, false),
];

struct Dir {
    name: String,
    parent: Option<usize>,
    dirs: Vec<usize>,
    files: Vec<usize>,
    tree: isize,
}

struct Opened {
    path: PathBuf,
    listing: Listing,
    dirs: Vec<Dir>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Row {
    Dir(usize),
    File(usize),
}

type LoadResult = Result<(PathBuf, Listing), String>;

pub struct Main {
    hwnd: HWND,
    tools: Vec<HWND>,
    tool_seps: Vec<f32>,
    up: HWND,
    crumbs: Vec<HWND>,
    crumb_x: Vec<f32>,
    tree: HWND,
    list: HWND,
    preview: HWND,
    preview_cp: HWND,
    status: HWND,
    status_cp: HWND,
    empty_open: HWND,
    empty_new: HWND,
    recents: Vec<(HWND, PathBuf)>,
    arc: Option<Opened>,
    cur: usize,
    rows: Vec<Row>,
    sort: (usize, bool),
    show_preview: bool,
    loading: Option<(PathBuf, Receiver<LoadResult>)>,
    codepage: Option<Codepage>,
    password: Option<String>,
    icons: HashMap<String, i32>,
    sysimg: HIMAGELIST,
    tree_sync: bool,
    painted: bool,
}

fn sys_icon(name: &str, dir: bool) -> (i32, HIMAGELIST) {
    let mut fi = SHFILEINFOW::default();
    let attr = if dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let h = unsafe {
        SHGetFileInfoW(
            &HSTRING::from(name),
            attr,
            Some(&mut fi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES,
        )
    };
    (fi.iIcon, HIMAGELIST(h as _))
}

fn recent_file() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("NextZip").join("recent.txt"))
}

pub fn recent() -> Vec<PathBuf> {
    recent_file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .map(|s| {
            s.lines()
                .map(PathBuf::from)
                .filter(|p| p.is_file())
                .take(5)
                .collect()
        })
        .unwrap_or_default()
}

fn add_recent(p: &Path) {
    let Some(f) = recent_file() else { return };
    let mut v: Vec<PathBuf> = std::fs::read_to_string(&f)
        .map(|s| s.lines().map(PathBuf::from).collect())
        .unwrap_or_default();
    v.retain(|x| x != p);
    v.insert(0, p.to_path_buf());
    v.truncate(10);
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let text: Vec<String> = v.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    let _ = std::fs::write(f, text.join("\n"));
}

fn build_dirs(listing: &Listing, root_name: &str) -> Vec<Dir> {
    let mut dirs = vec![Dir {
        name: root_name.to_string(),

        parent: None,
        dirs: Vec::new(),
        files: Vec::new(),
        tree: 0,
    }];
    let mut index: HashMap<String, usize> = HashMap::new();
    fn ensure(dirs: &mut Vec<Dir>, index: &mut HashMap<String, usize>, path: &str) -> usize {
        if path.is_empty() {
            return 0;
        }
        if let Some(&i) = index.get(path) {
            return i;
        }
        let (parent, name) = match path.rfind('/') {
            Some(p) => (&path[..p], &path[p + 1..]),
            None => ("", path),
        };
        let pi = ensure(dirs, index, parent);
        let i = dirs.len();
        dirs.push(Dir {
            name: name.to_string(),

            parent: Some(pi),
            dirs: Vec::new(),
            files: Vec::new(),
            tree: 0,
        });
        dirs[pi].dirs.push(i);
        index.insert(path.to_string(), i);
        i
    }
    for (i, e) in listing.entries.iter().enumerate() {
        let name = e.name.trim_matches('/');
        if name.is_empty() {
            continue;
        }
        if e.is_dir {
            ensure(&mut dirs, &mut index, name);
        } else {
            let parent = name.rfind('/').map(|p| &name[..p]).unwrap_or("");
            let d = ensure(&mut dirs, &mut index, parent);
            dirs[d].files.push(i);
        }
    }
    // Sort sub-folders by name for the tree.
    let names: Vec<String> = dirs.iter().map(|d| d.name.to_lowercase()).collect();
    for d in &mut dirs {
        d.dirs.sort_by(|a, b| names[*a].cmp(&names[*b]));
    }
    dirs
}

impl Main {
    pub fn create(open: Option<PathBuf>) -> HWND {
        let state = Main {
            hwnd: HWND::default(),
            tools: Vec::new(),
            tool_seps: Vec::new(),
            up: HWND::default(),
            crumbs: Vec::new(),
            crumb_x: Vec::new(),
            tree: HWND::default(),
            list: HWND::default(),
            preview: HWND::default(),
            preview_cp: HWND::default(),
            status: HWND::default(),
            status_cp: HWND::default(),
            empty_open: HWND::default(),
            empty_new: HWND::default(),
            recents: Vec::new(),
            arc: None,
            cur: 0,
            rows: Vec::new(),
            sort: (0, true),
            show_preview: true,
            loading: None,
            codepage: None,
            password: None,
            icons: HashMap::new(),
            sysimg: HIMAGELIST::default(),
            tree_sync: false,
            painted: false,
        };
        let dpi = ui::system_dpi();
        let style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
        let (w, h) = ui::outer_size(style, WINDOW_EX_STYLE(0), 1080.0, 680.0, dpi);
        let hwnd = ui::create(
            CLASS,
            "NextZip",
            style,
            WINDOW_EX_STYLE(0),
            (CW_USEDEFAULT, CW_USEDEFAULT, w, h),
            None,
            0,
            state,
        );
        if let Some(p) = open {
            unsafe {
                let b = Box::new(p);
                let _ = PostMessageW(
                    Some(hwnd),
                    WM_APP + 10,
                    WPARAM(0),
                    LPARAM(Box::into_raw(b) as isize),
                );
            }
        }
        hwnd
    }

    fn init(&mut self, hwnd: HWND) {
        self.hwnd = hwnd;
        ui::style_frame(hwnd, true);
        let tools: [(isize, char, &str, &str, bool); 8] = [
            (
                ID_OPEN,
                icon::OPEN,
                tr("열기"),
                tr("압축 파일 열기 (Ctrl+O)"),
                false,
            ),
            (
                ID_EXTRACT,
                icon::EXTRACT,
                tr("풀기"),
                tr("풀기 (Ctrl+E)"),
                true,
            ),
            (
                ID_COMPRESS,
                icon::ARCHIVE,
                tr("압축"),
                tr("새로 압축 (Ctrl+N)"),
                false,
            ),
            (
                ID_TEST,
                icon::SHIELD,
                tr("테스트"),
                tr("압축 파일 검사"),
                false,
            ),
            (
                ID_ADD,
                icon::ADD,
                tr("추가"),
                tr("파일 추가 (M3에서 지원)"),
                false,
            ),
            (
                ID_DELETE,
                icon::DELETE,
                tr("삭제"),
                tr("항목 삭제 (M3에서 지원)"),
                false,
            ),
            (
                ID_VIEW,
                icon::VIEW,
                "",
                tr("미리보기 패널 보이기/숨기기"),
                false,
            ),
            (
                ID_SETTINGS,
                icon::SETTINGS,
                "",
                tr("설정: 언어, 악성코드 검사"),
                false,
            ),
        ];
        for (i, (id, ic, label, tip, main)) in tools.iter().enumerate() {
            let name = if !label.is_empty() {
                label
            } else if *id == ID_SETTINGS {
                tr("설정")
            } else {
                tr("미리보기 패널")
            };
            let b = ui::button(
                hwnd,
                *id,
                name,
                Btn::Tool {
                    icon: *ic,
                    label: label.to_string(),
                    main: *main,
                },
                i == 0,
            );
            ui::tooltip(hwnd, b, tip);
            self.tools.push(b);
        }
        ui::enable(self.tools[4], false);
        ui::enable(self.tools[5], false);
        self.up = ui::button(
            hwnd,
            ID_UP,
            tr("상위 폴더"),
            Btn::Tool {
                icon: icon::UP,
                label: String::new(),
                main: false,
            },
            true,
        );
        ui::tooltip(hwnd, self.up, tr("상위 폴더 (Backspace, Alt+↑)"));
        self.tree = ui::control(
            WC_TREEVIEWW,
            tr("폴더"),
            WINDOW_STYLE(TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT | TVS_TRACKSELECT)
                | WS_TABSTOP
                | WS_GROUP,
            WINDOW_EX_STYLE(0),
            hwnd,
            ID_TREE,
        );
        ui::send(
            self.tree,
            TVM_SETEXTENDEDSTYLE,
            TVS_EX_DOUBLEBUFFER as usize,
            TVS_EX_DOUBLEBUFFER as isize,
        );
        stage_("toolbar");
        self.create_list();
        stage_("list");
        self.preview = ui::panel(
            hwnd,
            ID_PREVIEW,
            tr("미리보기"),
            16, /* ROLE_SYSTEM_PANE */
        );
        self.preview_cp = ui::button(
            self.preview,
            ID_PREVIEW_CP,
            tr("이름 인코딩 변경"),
            Btn::Secondary(tr("인코딩 변경…").into()),
            true,
        );
        self.status = ui::panel(
            hwnd,
            ID_STATUS,
            tr("상태"),
            23, /* ROLE_SYSTEM_STATUSBAR */
        );
        self.status_cp = ui::button(
            self.status,
            ID_STATUS_CP,
            tr("이름 인코딩"),
            Btn::Drop {
                label: String::new(),
            },
            true,
        );
        ui::tooltip(
            self.status,
            self.status_cp,
            tr("파일 이름 코드페이지 바꾸기"),
        );
        self.empty_open = ui::button(
            hwnd,
            ID_EMPTY_OPEN,
            tr("열기…"),
            Btn::Secondary(tr("열기…").into()),
            true,
        );
        self.empty_new = ui::button(
            hwnd,
            ID_EMPTY_NEW,
            tr("새로 압축…"),
            Btn::Secondary(tr("새로 압축…").into()),
            false,
        );
        for (i, p) in recent().into_iter().enumerate() {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let dir = p
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default();
            let b = ui::button(
                hwnd,
                ID_RECENT + i as isize,
                &trf("최근 파일: {}", &[&name]),
                Btn::Recent { name, dir },
                i == 0,
            );
            self.recents.push((b, p));
        }
        stage_("panels");
        unsafe { DragAcceptFiles(hwnd, true) };
        self.apply_theme();
        self.apply_fonts();
        self.update_mode();
    }

    fn create_list(&mut self) {
        if !self.list.is_invalid() {
            unsafe {
                let _ = DestroyWindow(self.list);
            }
        }
        let style = WINDOW_STYLE(
            LVS_REPORT
                | LVS_OWNERDATA
                | LVS_OWNERDRAWFIXED
                | LVS_SHOWSELALWAYS
                | LVS_SHAREIMAGELISTS,
        ) | WS_TABSTOP
            | WS_GROUP;
        self.list = ui::control(
            WC_LISTVIEWW,
            tr("파일 목록"),
            style,
            WINDOW_EX_STYLE(0),
            self.hwnd,
            ID_LIST,
        );
        ui::send(
            self.list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            0,
            (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as isize,
        );
        // The shell image list loads shell32's icon cache (~40 ms): attach
        // it after the first paint (see WM_APP + 11).
        if !self.sysimg.is_invalid() {
            self.attach_images();
        }
        let s = ui::dpi(self.hwnd);
        for (i, (name, w, right)) in COLS.iter().enumerate() {
            let name = tr(name);
            let text = ui::wide(name);
            let col = LVCOLUMNW {
                mask: LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM,
                fmt: if *right { LVCFMT_RIGHT } else { LVCFMT_LEFT },
                cx: (w * s) as i32,
                pszText: windows::core::PWSTR(text.as_ptr() as *mut _),
                iSubItem: i as i32,
                ..Default::default()
            };
            ui::send(self.list, LVM_INSERTCOLUMNW, i, &col as *const _ as isize);
        }
        self.apply_fonts();
        self.apply_theme();
        self.update_sort_arrow();
        ui::send(self.list, LVM_SETITEMCOUNT, self.rows.len(), 0);
        self.layout();
    }

    fn attach_images(&mut self) {
        if self.sysimg.is_invalid() {
            self.sysimg = sys_icon("x.txt", false).1;
        }
        let img = self.sysimg;
        // The list draws icons itself from `sysimg`: giving it the image list
        // (LVM_SETIMAGELIST) would shrink the owner-drawn 32 DIP rows to the
        // 16 px icon height.
        ui::send(self.tree, TVM_SETIMAGELIST, TVSIL_NORMAL as usize, img.0);
        ui::invalidate(self.list);
    }

    fn apply_fonts(&self) {
        let f = ui::body_font(self.hwnd);
        for h in [self.tree, self.list] {
            if !h.is_invalid() {
                ui::set_font(h, f);
            }
        }
        if !self.tree.is_invalid() {
            ui::send(
                self.tree,
                TVM_SETITEMHEIGHT,
                ui::px(self.hwnd, 28.0) as usize,
                0,
            );
        }
        if !self.list.is_invalid() {
            let hdr = HWND(ui::send(self.list, LVM_GETHEADER, 0, 0) as _);
            ui::set_font(hdr, ui::font(self.hwnd, 12.0, 400));
        }
    }

    fn apply_theme(&self) {
        let p = theme::pal();
        ui::style_frame(self.hwnd, true);
        if !self.list.is_invalid() {
            ui::theme_control(self.list, "list");
            let hdr = HWND(ui::send(self.list, LVM_GETHEADER, 0, 0) as _);
            ui::theme_control(hdr, "header");
            ui::send(
                self.list,
                LVM_SETBKCOLOR,
                0,
                p.surface.colorref().0 as isize,
            );
            ui::send(
                self.list,
                LVM_SETTEXTBKCOLOR,
                0,
                p.surface.colorref().0 as isize,
            );
            ui::send(self.list, LVM_SETTEXTCOLOR, 0, p.text.colorref().0 as isize);
        }
        if !self.tree.is_invalid() {
            ui::theme_control(self.tree, "tree");
            ui::send(
                self.tree,
                TVM_SETBKCOLOR,
                0,
                p.surface2.colorref().0 as isize,
            );
            ui::send(self.tree, TVM_SETTEXTCOLOR, 0, p.text.colorref().0 as isize);
        }
        unsafe {
            let _ = RedrawWindow(
                Some(self.hwnd),
                None,
                None,
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN,
            );
        }
    }

    // ------------------------------------------------------------ layout

    fn has_archive(&self) -> bool {
        self.arc.is_some() || self.loading.is_some()
    }

    fn update_mode(&mut self) {
        let a = self.has_archive();
        for h in [self.tree, self.list, self.status, self.up] {
            ui::show(h, a);
        }
        ui::show(self.preview, a && self.show_preview);
        for h in [self.empty_open, self.empty_new] {
            ui::show(h, !a);
        }
        for (h, _) in &self.recents {
            ui::show(*h, !a);
        }
        for h in &self.crumbs {
            ui::show(*h, a);
        }
        for (i, h) in self.tools.iter().enumerate() {
            let on = match i {
                1 | 3 => self.arc.is_some(),
                4 | 5 => false,
                6 => a,
                _ => true,
            };
            ui::enable(*h, on);
        }
        let title = match &self.arc {
            Some(o) => format!(
                "{} — NextZip",
                o.path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default()
            ),
            None => "NextZip".into(),
        };
        ui::set_text(self.hwnd, &title);
        self.layout();
        ui::invalidate(self.hwnd);
    }

    fn layout(&mut self) {
        let hwnd = self.hwnd;
        if hwnd.is_invalid() {
            return;
        }
        let rc = ui::client(hwnd);
        let s = ui::dpi(hwnd);
        let (w, h) = (rc.right as f32 / s, rc.bottom as f32 / s);
        // toolbar
        let mut x = 8.0;
        let mut rx = w - 8.0;
        self.tool_seps.clear();
        for (i, b) in self.tools.iter().enumerate() {
            let Some(Btn::Tool { label, .. }) = ui::btn(*b) else {
                continue;
            };
            let bw = if label.is_empty() {
                36.0
            } else {
                40.0 + gfx::measure(&label, Type::BodyStrong)
            };
            if i >= 6 {
                // View and settings sit at the right end.
                rx -= bw;
                ui::place(hwnd, *b, rx, 6.0, bw, 36.0);
                rx -= 4.0;
                continue;
            }
            if i == 1 || i == 4 {
                self.tool_seps.push(x + 4.0);
                x += 9.0;
            }
            ui::place(hwnd, *b, x, 6.0, bw, 36.0);
            x += bw + 4.0;
        }
        // path bar
        ui::place(hwnd, self.up, 8.0, TB_H + 4.0, 32.0, 32.0);
        let mut cx = 48.0;
        self.crumb_x.clear();
        for (i, b) in self.crumbs.iter().enumerate() {
            if i > 0 {
                self.crumb_x.push(cx);
                cx += 16.0;
            }
            let Some(Btn::Link { label, strong }) = ui::btn(*b) else {
                continue;
            };
            let t = if strong { Type::BodyStrong } else { Type::Body };
            let bw = (gfx::measure(&label, t) + 12.0).min(260.0);
            ui::place(hwnd, *b, cx, TB_H + 4.0, bw, 32.0);
            cx += bw;
        }
        // body
        let top = TB_H + PATH_H;
        let bh = (h - top - STATUS_H).max(0.0);
        let pw = if self.show_preview { PREVIEW_W } else { 0.0 };
        let tw = if w > 720.0 { TREE_W } else { 0.0 };
        ui::place(hwnd, self.tree, 0.0, top, tw, bh);
        ui::place(
            hwnd,
            self.list,
            tw + 1.0,
            top,
            (w - tw - pw - 2.0).max(0.0),
            bh,
        );
        ui::place(hwnd, self.preview, w - pw, top, pw, bh);
        ui::place(
            self.preview,
            self.preview_cp,
            16.0,
            (bh - 48.0).max(0.0),
            140.0,
            32.0,
        );
        ui::place(hwnd, self.status, 0.0, h - STATUS_H, w, STATUS_H);
        let cpw = 200.0;
        ui::place(
            self.status,
            self.status_cp,
            w - cpw - 8.0,
            2.0,
            cpw,
            STATUS_H - 4.0,
        );
        // start screen
        let dz = self.drop_zone(w, h);
        let cy = dz.top + 170.0;
        ui::place(hwnd, self.empty_open, w / 2.0 - 124.0, cy, 120.0, 32.0);
        ui::place(hwnd, self.empty_new, w / 2.0 + 4.0, cy, 120.0, 32.0);
        let ry = dz.bottom + 44.0;
        for (i, (b, _)) in self.recents.iter().enumerate() {
            ui::place(hwnd, *b, 24.0, ry + i as f32 * 36.0, w - 48.0, 32.0);
        }
    }

    fn drop_zone(&self, w: f32, h: f32) -> windows::Win32::Graphics::Direct2D::Common::D2D_RECT_F {
        let recent_h = if self.recents.is_empty() {
            0.0
        } else {
            44.0 + self.recents.len() as f32 * 36.0
        };
        let zh = (h - TB_H - 48.0 - recent_h).clamp(240.0, 360.0);
        rect(24.0, TB_H + 24.0, w - 48.0, zh)
    }

    // ------------------------------------------------------------ painting

    fn paint(&mut self, hdc: HDC) {
        let p = theme::pal();
        let has = self.has_archive();
        let seps = self.tool_seps.clone();
        let chevs = self.crumb_x.clone();
        let rc = ui::client(self.hwnd);
        let s = ui::dpi(self.hwnd);
        let dz = self.drop_zone(rc.right as f32 / s, rc.bottom as f32 / s);
        gfx::paint(self.hwnd, hdc, |c| {
            c.clear(p.bg);
            c.fill(rect(0.0, 0.0, c.w, TB_H), p.surface2);
            c.hline(0.0, c.w, TB_H - 1.0, p.divider);
            for x in &seps {
                c.vline(*x, 12.0, TB_H - 12.0, p.divider);
            }
            if has {
                c.fill(rect(0.0, TB_H, c.w, PATH_H), p.surface);
                c.hline(0.0, c.w, TB_H + PATH_H - 1.0, p.divider);
                for x in &chevs {
                    c.icon(
                        icon::CHEVRON_RIGHT,
                        rect(*x, TB_H + 4.0, 16.0, 32.0),
                        Type::IconSmall,
                        p.muted,
                    );
                }
                // splitter lines
                let tw = if c.w > 720.0 { TREE_W } else { 0.0 };
                if tw > 0.0 {
                    c.vline(tw, TB_H + PATH_H, c.h - STATUS_H, p.divider);
                }
                if self.show_preview {
                    c.vline(
                        c.w - PREVIEW_W - 1.0,
                        TB_H + PATH_H,
                        c.h - STATUS_H,
                        p.divider,
                    );
                }
            } else {
                c.round(dz, 8.0, p.surface);
                c.dashed_round(dz, 8.0, p.border, 2.0);
                let cx = dz.left;
                let w = dz.right - dz.left;
                c.icon(
                    icon::ARCHIVE,
                    rect(cx, dz.top + 32.0, w, 40.0),
                    Type::IconLarge,
                    p.muted,
                );
                c.text(
                    tr("파일이나 폴더를 여기로 끌어다 놓으세요"),
                    rect(cx, dz.top + 80.0, w, 24.0),
                    Type::Subtitle,
                    Align::Center,
                    p.text,
                );
                c.text(
                    tr("압축 파일은 열고, 일반 파일은 압축합니다."),
                    rect(cx, dz.top + 108.0, w, 20.0),
                    Type::Body,
                    Align::Center,
                    p.muted,
                );
                c.text(
                    tr("열기 Ctrl+O  ·  새로 압축 Ctrl+N  ·  최근 파일 Ctrl+R"),
                    rect(cx, dz.top + 136.0, w, 20.0),
                    Type::Caption,
                    Align::Center,
                    p.muted,
                );
                if !self.recents.is_empty() {
                    c.text(
                        tr("최근 파일"),
                        rect(24.0, dz.bottom + 16.0, 200.0, 24.0),
                        Type::BodyStrong,
                        Align::Left,
                        p.text,
                    );
                }
            }
        });
    }

    fn paint_status(&self, hdc: HDC) {
        let p = theme::pal();
        let text = self.status_text();
        gfx::paint(self.status, hdc, |c| {
            c.clear(p.surface2);
            c.hline(0.0, c.w, 0.0, p.divider);
            c.text(
                &text,
                rect(12.0, 0.0, c.w - 230.0, c.h),
                Type::Caption,
                Align::Left,
                p.muted,
            );
        });
    }

    fn status_text(&self) -> String {
        if let Some((p, _)) = &self.loading {
            return trf(
                "{} 목록을 읽는 중…",
                &[&p.file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default()],
            );
        }
        let Some(o) = &self.arc else {
            return String::new();
        };
        let l = &o.listing;
        let total = l.total_size();
        let packed = std::fs::metadata(&o.path).map(|m| m.len()).unwrap_or(0)
            + l.volumes
                .iter()
                .skip(1)
                .filter_map(|v| std::fs::metadata(v).ok())
                .map(|m| m.len())
                .sum::<u64>();
        let ratio = if total > 0 {
            format!(" ({:.1}%)", packed as f64 * 100.0 / total as f64)
        } else {
            String::new()
        };
        let mut parts = vec![
            trf("{}개 파일", &[&ui::count(l.files() as u64)]),
            trf("원본 {}", &[&ui::size(total)]),
            trf("압축 {}{}", &[&ui::size(packed), &ratio]),
            l.kind.label().to_string(),
        ];
        if l.solid {
            parts.push(tr("솔리드").into());
        }
        if l.volumes.len() > 1 {
            parts.push(trf("분할 {}개", &[&l.volumes.len()]));
        }
        parts.push(if l.any_encrypted() {
            tr("암호화됨").into()
        } else {
            tr("암호화 없음").into()
        });
        parts.join("  ·  ")
    }

    fn selected(&self) -> Vec<usize> {
        let mut v = Vec::new();
        let mut i = -1isize;
        loop {
            i = ui::send(
                self.list,
                LVM_GETNEXTITEM,
                i as usize,
                LVNI_SELECTED as isize,
            );
            if i < 0 {
                break;
            }
            v.push(i as usize);
        }
        v
    }

    fn preview_lines(&self) -> (String, Vec<(String, String)>, bool) {
        let Some(o) = &self.arc else {
            return (String::new(), Vec::new(), false);
        };
        let sel = self.selected();
        if sel.len() == 1
            && let Some(Row::File(i)) = self.rows.get(sel[0])
        {
            let e = &o.listing.entries[*i];
            let name = e.name.rsplit('/').next().unwrap_or(&e.name).to_string();
            let mut v = vec![
                (
                    tr("크기").to_string(),
                    if e.csize > 0 {
                        format!("{} → {}", ui::size(e.size), ui::size(e.csize))
                    } else {
                        ui::size(e.size)
                    },
                ),
                (tr("방법").to_string(), e.method.clone()),
            ];
            if let Some(crc) = e.crc {
                v.push(("CRC32".to_string(), format!("{crc:08X}")));
            }
            if let Some(t) = e.mtime {
                v.push((tr("수정").to_string(), ui::local_time(t)));
            }
            if e.encrypted {
                v.push((tr("암호").to_string(), tr("암호화됨").to_string()));
            }
            v.push((tr("경로").to_string(), e.name.clone()));
            return (name, v, false);
        }
        let l = &o.listing;
        let mut v = vec![
            (tr("형식").to_string(), l.kind.label().to_string()),
            (
                tr("파일").to_string(),
                trf("{}개", &[&ui::count(l.files() as u64)]),
            ),
            (tr("원본 크기").to_string(), ui::size(l.total_size())),
        ];
        if l.solid {
            v.push((tr("솔리드").to_string(), tr("예").to_string()));
        }
        if l.volumes.len() > 1 {
            v.push((
                tr("분할 볼륨").to_string(),
                trf("{}개", &[&l.volumes.len()]),
            ));
        }
        let mut show_cp = false;
        if let Some(cp) = l.codepage {
            show_cp = true;
            let basis = match (&self.codepage, &l.detection) {
                (Some(_), _) => trf("{} · 직접 지정", &[&cp.label()]),
                (None, Some(d)) => d.summary_ko(),
                (None, None) => cp.label().to_string(),
            };
            v.push((tr("이름 인코딩").to_string(), basis));
            if let (None, Some(d)) = (&self.codepage, &l.detection) {
                let scripts: Vec<String> = d
                    .scripts
                    .iter()
                    .filter(|(_, f)| *f > 0.0)
                    .map(|(n, f)| format!("{n} {:.0}%", f * 100.0))
                    .collect();
                if !scripts.is_empty() {
                    v.push((tr("판별 근거").to_string(), scripts.join(", ")));
                }
                let others: Vec<String> = d
                    .scores
                    .iter()
                    .skip(1)
                    .take(2)
                    .map(|s| format!("{} {:.2}", s.codepage.label(), s.score))
                    .collect();
                if !others.is_empty() {
                    v.push((tr("다른 후보").to_string(), others.join(", ")));
                }
            }
        }
        let name = o
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        (name, v, show_cp)
    }

    fn paint_preview(&self, hdc: HDC) {
        let p = theme::pal();
        let (title, lines, _) = self.preview_lines();
        gfx::paint(self.preview, hdc, |c| {
            c.clear(p.surface);
            c.text(
                &title,
                rect(16.0, 12.0, c.w - 32.0, 24.0),
                Type::Subtitle,
                Align::Left,
                p.text,
            );
            let mut y = 48.0;
            for (k, v) in &lines {
                c.text(
                    k,
                    rect(16.0, y, c.w - 32.0, 16.0),
                    Type::Caption,
                    Align::Left,
                    p.muted,
                );
                y += 18.0;
                let lines = (gfx::measure(v, Type::Body) / (c.w - 32.0))
                    .ceil()
                    .clamp(1.0, 4.0);
                let hh = 20.0 * lines;
                c.text_ex(
                    v,
                    rect(16.0, y, c.w - 32.0, hh),
                    Type::Body,
                    Align::Left,
                    false,
                    true,
                    p.text,
                );
                y += hh + 10.0;
            }
        });
    }

    fn refresh_preview(&self) {
        let (title, lines, show_cp) = self.preview_lines();
        let mut text = title;
        for (k, v) in &lines {
            text.push_str(&format!(", {k}: {v}"));
        }
        ui::acc_value(self.preview, &text);
        ui::show(self.preview_cp, show_cp);
        ui::invalidate(self.preview);
        let cp_label = self
            .arc
            .as_ref()
            .and_then(|o| o.listing.codepage)
            .map(|cp| {
                let how = if self.codepage.is_some() {
                    tr("지정")
                } else {
                    tr("자동")
                };
                trf("이름 인코딩: {} ({})", &[&cp.label(), &how])
            });
        ui::show(self.status_cp, cp_label.is_some() && self.arc.is_some());
        if let Some(l) = cp_label {
            ui::acc_name(self.status_cp, &l);
            ui::set_btn(self.status_cp, Btn::Drop { label: l });
        }
        let st = self.status_text();
        ui::acc_name(self.status, &st);
        ui::invalidate(self.status);
    }

    // --------------------------------------------------------- archive

    pub fn open(&mut self, path: PathBuf) {
        let path = std::path::absolute(&path).unwrap_or(path);
        let (tx, rx) = channel();
        let opt = nz_archive::Options {
            codepage: self.codepage,
            hint: crate::system_codepage(),
            password: self.password.clone(),
            threads: 0,
            malware_scan: false,
            symlinks: false,
        };
        let hwnd = self.hwnd.0 as isize;
        let p2 = path.clone();
        std::thread::spawn(move || {
            let r = nz_archive::list(&p2, &opt)
                .map(|l| (p2.clone(), l))
                .map_err(|e| match nz_archive::archive_error(&e) {
                    Some(nz_archive::ArchiveError::PasswordRequired) => "PASSWORD".to_string(),
                    Some(nz_archive::ArchiveError::WrongPassword) => "WRONGPASSWORD".to_string(),
                    _ => format!("{e:#}"),
                });
            let _ = tx.send(r);
            unsafe {
                let _ = PostMessageW(Some(HWND(hwnd as _)), WM_APP_WORK, WPARAM(2), LPARAM(0));
            }
        });
        self.loading = Some((path, rx));
        self.arc = None;
        self.rows.clear();
        ui::send(self.list, LVM_SETITEMCOUNT, 0, 0);
        ui::send(self.tree, TVM_DELETEITEM, 0, TVI_ROOT.0);
        self.update_mode();
        self.refresh_preview();
    }

    fn loaded(&mut self) {
        let Some((path, rx)) = self.loading.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok((p, listing))) => {
                add_recent(&p);
                let root = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let dirs = build_dirs(&listing, &root);
                self.arc = Some(Opened {
                    path: p,
                    listing,
                    dirs,
                });
                self.fill_tree();
                self.navigate(0);
                self.update_mode();
                unsafe {
                    let _ = SetFocus(Some(self.list));
                }
            }
            Ok(Err(code)) if code == "PASSWORD" || code == "WRONGPASSWORD" => {
                let again = code == "WRONGPASSWORD";
                match crate::password::ask(self.hwnd, &path, again) {
                    Some(pw) => {
                        self.password = Some(pw);
                        self.open(path);
                    }
                    None => self.update_mode(),
                }
            }
            Ok(Err(msg)) => {
                self.update_mode();
                ui::message(self.hwnd, tr("열 수 없음"), &msg, true);
            }
            Err(_) => {
                // Not ready (spurious notification): keep waiting.
                self.loading = Some((path, rx));
            }
        }
        self.refresh_preview();
    }

    fn fill_tree(&mut self) {
        let Some(o) = &mut self.arc else { return };
        ui::send(self.tree, TVM_DELETEITEM, 0, TVI_ROOT.0);
        let (folder, _) = sys_icon("folder", true);
        let order: Vec<usize> = {
            // parents before children
            let mut v = vec![0];
            let mut i = 0;
            while i < v.len() {
                let d = v[i];
                v.extend(o.dirs[d].dirs.iter().copied());
                i += 1;
            }
            v
        };
        for d in order {
            let parent = o.dirs[d]
                .parent
                .map(|p| o.dirs[p].tree)
                .unwrap_or(TVI_ROOT.0);
            let text = ui::wide(&o.dirs[d].name);
            let ins = TVINSERTSTRUCTW {
                hParent: HTREEITEM(parent),
                hInsertAfter: TVI_LAST,
                Anonymous: TVINSERTSTRUCTW_0 {
                    itemex: TVITEMEXW {
                        mask: TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE,
                        pszText: windows::core::PWSTR(text.as_ptr() as *mut _),
                        lParam: LPARAM(d as isize),
                        iImage: folder,
                        iSelectedImage: folder,
                        ..Default::default()
                    },
                },
            };
            o.dirs[d].tree = ui::send(self.tree, TVM_INSERTITEMW, 0, &ins as *const _ as isize);
        }
        let root = o.dirs[0].tree;
        ui::send(self.tree, TVM_EXPAND, TVE_EXPAND.0 as usize, root);
    }

    fn navigate(&mut self, dir: usize) {
        let Some(o) = &self.arc else { return };
        if dir >= o.dirs.len() {
            return;
        }
        self.cur = dir;
        // breadcrumbs
        for b in self.crumbs.drain(..) {
            unsafe {
                let _ = DestroyWindow(b);
            }
        }
        let mut chain = vec![dir];
        while let Some(p) = o.dirs[*chain.last().unwrap()].parent {
            chain.push(p);
        }
        chain.reverse();
        let last = chain.len() - 1;
        for (i, d) in chain.iter().enumerate() {
            let b = ui::button(
                self.hwnd,
                ID_CRUMB + (i as isize).min(79),
                &o.dirs[*d].name,
                Btn::Link {
                    label: o.dirs[*d].name.clone(),
                    strong: i == last,
                },
                false,
            );
            unsafe {
                // Keep the crumbs between the up button and the tree in tab order.
                let _ = SetWindowPos(
                    b,
                    Some(self.up),
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                );
            }
            self.crumbs.push(b);
        }
        let d = &o.dirs[dir];
        self.rows = d
            .dirs
            .iter()
            .map(|i| Row::Dir(*i))
            .chain(d.files.iter().map(|i| Row::File(*i)))
            .collect();
        let item = d.tree;
        self.sort_rows();
        ui::send(self.list, LVM_SETITEMCOUNT, self.rows.len(), 0);
        ui::send(self.list, LVM_ENSUREVISIBLE, 0, 0);
        // focus first row
        let mut it = LVITEMW {
            stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_FOCUSED.0 | LVIS_SELECTED.0),
            state: LVIS_FOCUSED,
            ..Default::default()
        };
        ui::send(self.list, LVM_SETITEMSTATE, usize::MAX, {
            let mut clear = LVITEMW {
                stateMask: LVIS_SELECTED,
                ..Default::default()
            };
            &mut clear as *mut _ as isize
        });
        if !self.rows.is_empty() {
            ui::send(self.list, LVM_SETITEMSTATE, 0, &mut it as *mut _ as isize);
        }
        ui::invalidate(self.list);
        ui::enable(self.up, dir != 0);
        self.tree_sync = true;
        ui::send(self.tree, TVM_SELECTITEM, TVGN_CARET as usize, item);
        self.tree_sync = false;
        self.layout();
        ui::invalidate(self.hwnd);
        self.refresh_preview();
    }

    fn sort_rows(&mut self) {
        let Some(o) = &self.arc else { return };
        let (col, asc) = self.sort;
        let e = &o.listing.entries;
        let dirs = &o.dirs;
        let key_name = |r: &Row| match r {
            Row::Dir(d) => dirs[*d].name.to_lowercase(),
            Row::File(i) => e[*i].name.rsplit('/').next().unwrap_or("").to_lowercase(),
        };
        self.rows.sort_by(|a, b| {
            let da = matches!(a, Row::Dir(_));
            let db = matches!(b, Row::Dir(_));
            if da != db {
                return db.cmp(&da);
            }
            let ord = match (col, a, b) {
                (1, Row::File(x), Row::File(y)) => e[*x].size.cmp(&e[*y].size),
                (2, Row::File(x), Row::File(y)) => e[*x].csize.cmp(&e[*y].csize),
                (3, Row::File(x), Row::File(y)) => {
                    let r = |i: usize| {
                        if e[i].size == 0 {
                            0.0
                        } else {
                            e[i].csize as f64 / e[i].size as f64
                        }
                    };
                    r(*x).total_cmp(&r(*y))
                }
                (4, Row::File(x), Row::File(y)) => e[*x].method.cmp(&e[*y].method),
                (5, Row::File(x), Row::File(y)) => e[*x].mtime.cmp(&e[*y].mtime),
                (6, Row::File(x), Row::File(y)) => e[*x].crc.cmp(&e[*y].crc),
                _ => std::cmp::Ordering::Equal,
            }
            .then_with(|| key_name(a).cmp(&key_name(b)));
            if asc { ord } else { ord.reverse() }
        });
    }

    fn update_sort_arrow(&self) {
        let hdr = HWND(ui::send(self.list, LVM_GETHEADER, 0, 0) as _);
        for i in 0..COLS.len() {
            let mut it = HDITEMW {
                mask: HDI_FORMAT,
                ..Default::default()
            };
            ui::send(hdr, HDM_GETITEMW, i, &mut it as *mut _ as isize);
            it.fmt = HEADER_CONTROL_FORMAT_FLAGS(it.fmt.0 & !(HDF_SORTUP.0 | HDF_SORTDOWN.0));
            if i == self.sort.0 {
                it.fmt = HEADER_CONTROL_FORMAT_FLAGS(
                    it.fmt.0
                        | if self.sort.1 {
                            HDF_SORTUP.0
                        } else {
                            HDF_SORTDOWN.0
                        },
                );
            }
            ui::send(hdr, HDM_SETITEMW, i, &it as *const _ as isize);
        }
    }

    fn cell(&self, row: usize, col: usize) -> String {
        let Some(o) = &self.arc else {
            return String::new();
        };
        let Some(r) = self.rows.get(row) else {
            return String::new();
        };
        match r {
            Row::Dir(d) => match col {
                0 => o.dirs[*d].name.clone(),
                4 => tr("폴더").into(),
                _ => String::new(),
            },
            Row::File(i) => {
                let e = &o.listing.entries[*i];
                match col {
                    0 => e.name.rsplit('/').next().unwrap_or(&e.name).to_string(),
                    1 => ui::size(e.size),
                    2 => {
                        if e.csize > 0 || e.size == 0 {
                            ui::size(e.csize)
                        } else {
                            "—".into()
                        }
                    }
                    3 => {
                        if e.size > 0 && e.csize > 0 {
                            format!("{:.1}%", e.csize as f64 * 100.0 / e.size as f64)
                        } else {
                            "—".into()
                        }
                    }
                    4 => {
                        if e.encrypted {
                            trf("{} · 암호", &[&e.method])
                        } else {
                            e.method.clone()
                        }
                    }
                    5 => e.mtime.map(ui::local_time).unwrap_or_default(),
                    6 => e.crc.map(|c| format!("{c:08X}")).unwrap_or_default(),
                    _ => String::new(),
                }
            }
        }
    }

    fn icon_for(&mut self, row: usize) -> i32 {
        match self.rows.get(row) {
            Some(Row::Dir(_)) => *self
                .icons
                .entry("/".into())
                .or_insert_with(|| sys_icon("folder", true).0),
            Some(Row::File(i)) => {
                let name = self
                    .arc
                    .as_ref()
                    .map(|o| o.listing.entries[*i].name.clone())
                    .unwrap_or_default();
                let ext = Path::new(&name)
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                *self
                    .icons
                    .entry(ext.clone())
                    .or_insert_with(|| sys_icon(&format!("x.{ext}"), false).0)
            }
            None => 0,
        }
    }

    fn draw_row(&mut self, dis: &DRAWITEMSTRUCT) {
        let row = dis.itemID as usize;
        let p = theme::pal();
        let selected = ui::has(dis.itemState, ODS_SELECTED);
        let focused = ui::has(dis.itemState, ODS_FOCUS)
            && unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetFocus() } == self.list;
        let s = ui::dpi(self.hwnd);
        let widths: Vec<f32> = (0..COLS.len())
            .map(|i| ui::send(self.list, LVM_GETCOLUMNWIDTH, i, 0) as f32 / s)
            .collect();
        let cells: Vec<String> = (0..COLS.len()).map(|c| self.cell(row, c)).collect();
        let is_store =
            matches!(self.rows.get(row), Some(Row::File(_))) && cells[4].starts_with("Store");
        let icon_idx = self.icon_for(row);
        let hc = p.mode == Mode::HighContrast;
        gfx::paint_rect(self.list, dis.hDC, dis.rcItem, |c| {
            let bg = if selected { p.selected } else { p.surface };
            c.clear(bg);
            let fg = if selected && hc { p.on_primary } else { p.text };
            let muted = if selected && hc {
                p.on_primary
            } else {
                p.muted
            };
            let mut x = 0.0;
            for (i, w) in widths.iter().enumerate() {
                let (_, _, right) = COLS[i];
                let pad = 12.0;
                let r = if i == 0 {
                    rect(x + pad + 24.0, 0.0, w - pad * 2.0 - 24.0, c.h)
                } else {
                    rect(x + pad, 0.0, (w - pad * 2.0).max(0.0), c.h)
                };
                let align = if right { Align::Right } else { Align::Left };
                match i {
                    4 if !cells[4].is_empty() && cells[4] != tr("폴더") => {
                        let tw = (c.measure(&cells[4], Type::Caption) + 12.0).min(w - pad * 2.0);
                        let chip = rect(x + pad, (c.h - 20.0) / 2.0, tw.max(0.0), 20.0);
                        c.round(chip, 4.0, if selected { p.surface } else { p.surface2 });
                        let col = if is_store && !hc { p.attention } else { fg };
                        c.text(&cells[4], chip, Type::Caption, Align::Center, col);
                    }
                    5 | 6 => c.text(
                        &cells[i],
                        r,
                        if i == 6 { Type::Mono } else { Type::Body },
                        align,
                        muted,
                    ),
                    _ => c.text(&cells[i], r, Type::Body, align, fg),
                }
                x += w;
            }
            if focused {
                c.stroke_round(rect(1.0, 1.0, c.w - 2.0, c.h - 2.0), 4.0, p.focus, 2.0);
            }
        });
        // System icon on top (GDI).
        let y =
            dis.rcItem.top + ((dis.rcItem.bottom - dis.rcItem.top) - ui::px(self.hwnd, 16.0)) / 2;
        unsafe {
            let _ = ImageList_Draw(
                self.sysimg,
                icon_idx,
                dis.hDC,
                dis.rcItem.left + (12.0 * s) as i32,
                y,
                ILD_TRANSPARENT,
            );
        }
    }

    // ---------------------------------------------------------- actions

    fn archive_path(&self) -> Option<PathBuf> {
        self.arc.as_ref().map(|o| o.path.clone())
    }

    fn do_open_dialog(&mut self) {
        if let Some(p) = ui::pick_files(self.hwnd, tr("압축 파일 열기"), true)
            .into_iter()
            .next()
        {
            self.codepage = None;
            self.password = None;
            self.open(p);
        }
    }

    fn do_compress(&mut self, sources: Vec<PathBuf>) {
        let sources = if sources.is_empty() {
            ui::pick_files(self.hwnd, tr("압축할 파일 고르기"), false)
        } else {
            sources
        };
        if !sources.is_empty() {
            crate::compress::show(Some(self.hwnd), sources, false);
        }
    }

    fn do_extract(&mut self) {
        let Some(path) = self.archive_path() else {
            return;
        };
        let stem = crate::archive_stem(&path);
        let start = path.parent().map(Path::to_path_buf);
        let Some(dir) = ui::pick_folder(
            self.hwnd,
            &trf("풀 위치 고르기 — 그 안에 '{}' 폴더를 만듭니다", &[&stem]),
            start.as_deref(),
        ) else {
            return;
        };
        crate::progress::start(
            Some(self.hwnd),
            crate::worker::Op::Extract {
                archive: path,
                dest: dir.join(&stem),
                codepage: self.codepage,
                password: self.password.clone(),
                test: false,
            },
        );
    }

    fn do_test(&mut self) {
        let Some(path) = self.archive_path() else {
            return;
        };
        let dest = std::env::temp_dir().join(format!("nextzip-test-{}", std::process::id()));
        crate::progress::start(
            Some(self.hwnd),
            crate::worker::Op::Extract {
                archive: path,
                dest,
                codepage: self.codepage,
                password: self.password.clone(),
                test: true,
            },
        );
    }

    fn codepage_menu(&mut self, anchor: HWND) {
        let Some(o) = &self.arc else { return };
        let current = o.listing.codepage;
        unsafe {
            let Ok(m) = CreatePopupMenu() else { return };
            let flags = |on: bool| {
                if on {
                    MF_STRING | MF_CHECKED
                } else {
                    MF_STRING
                }
            };
            let _ = AppendMenuW(
                m,
                flags(self.codepage.is_none()),
                MENU_CP_AUTO,
                &HSTRING::from(tr("자동 판별")),
            );
            let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
            for (i, cp) in Codepage::ALL.iter().enumerate() {
                let on =
                    self.codepage == Some(*cp) || (self.codepage.is_none() && current == Some(*cp));
                let label = if self.codepage.is_none() && current == Some(*cp) {
                    trf("{} (판별됨)", &[&cp.label()])
                } else {
                    cp.label().to_string()
                };
                let _ = AppendMenuW(
                    m,
                    if on && self.codepage.is_some() {
                        flags(true)
                    } else {
                        MF_STRING
                    },
                    MENU_CP + i,
                    &HSTRING::from(label),
                );
            }
            let mut r = RECT::default();
            let _ = GetWindowRect(anchor, &mut r);
            let cmd = TrackPopupMenu(
                m,
                TPM_RETURNCMD | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
                r.left,
                r.top,
                None,
                self.hwnd,
                None,
            );
            let _ = DestroyMenu(m);
            let cmd = cmd.0 as usize;
            let new = if cmd == MENU_CP_AUTO {
                None
            } else if (MENU_CP..MENU_CP + Codepage::ALL.len()).contains(&cmd) {
                Some(Codepage::ALL[cmd - MENU_CP])
            } else {
                return;
            };
            if new != self.codepage {
                self.codepage = new;
                if let Some(p) = self.archive_path() {
                    self.open(p);
                }
            }
        }
    }

    /// Language and malware-scan settings (saved to the shared settings
    /// file, read by the GUI, the shell extension and `nz`).
    fn settings_menu(&mut self) {
        use nz_front::prefs::{LangPref, Prefs};
        let mut prefs = Prefs::load();
        let Some(anchor) = self.tools.get(7).copied() else {
            return;
        };
        unsafe {
            let Ok(m) = CreatePopupMenu() else { return };
            let flags = |on: bool| {
                if on {
                    MF_STRING | MF_CHECKED
                } else {
                    MF_STRING
                }
            };
            let langs = [
                (LangPref::Auto, tr("언어: Windows 설정 따르기")),
                (LangPref::Korean, "한국어"),
                (LangPref::English, "English"),
            ];
            for (i, (l, label)) in langs.iter().enumerate() {
                let _ = AppendMenuW(
                    m,
                    flags(prefs.language == *l),
                    MENU_LANG + i,
                    &HSTRING::from(*label),
                );
            }
            let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
            let _ = AppendMenuW(
                m,
                flags(prefs.malware_scan),
                MENU_SCAN,
                &HSTRING::from(tr("풀기 전에 악성코드 검사 (Windows AMSI)")),
            );
            let _ = AppendMenuW(
                m,
                flags(prefs.symlinks),
                MENU_LINKS,
                &HSTRING::from(tr("tar의 심볼릭 링크를 실제 링크로 풀기")),
            );
            let mut r = RECT::default();
            let _ = GetWindowRect(anchor, &mut r);
            let cmd = TrackPopupMenu(
                m,
                TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_TOPALIGN,
                r.right,
                r.bottom,
                None,
                self.hwnd,
                None,
            );
            let _ = DestroyMenu(m);
            let cmd = cmd.0 as usize;
            if (MENU_LANG..MENU_LANG + langs.len()).contains(&cmd) {
                let l = langs[cmd - MENU_LANG].0;
                if l == prefs.language {
                    return;
                }
                prefs.language = l;
                nz_front::i18n::set(nz_front::i18n::Lang::resolve(l));
                let saved = prefs.save();
                ui::message(
                    self.hwnd,
                    "NextZip",
                    &match saved {
                        Ok(()) => {
                            tr("언어를 바꿨습니다. NextZip을 다시 시작하면 모든 화면에 적용됩니다.")
                                .to_string()
                        }
                        Err(e) => trf("설정을 저장하지 못했습니다: {}", &[&e]),
                    },
                    false,
                );
            } else if cmd == MENU_LINKS {
                prefs.symlinks = !prefs.symlinks;
                if let Err(e) = prefs.save() {
                    ui::message(
                        self.hwnd,
                        "NextZip",
                        &trf("설정을 저장하지 못했습니다: {}", &[&e]),
                        true,
                    );
                }
            } else if cmd == MENU_SCAN {
                prefs.malware_scan = !prefs.malware_scan;
                if let Err(e) = prefs.save() {
                    ui::message(
                        self.hwnd,
                        "NextZip",
                        &trf("설정을 저장하지 못했습니다: {}", &[&e]),
                        true,
                    );
                } else if !prefs.malware_scan {
                    ui::message(
                        self.hwnd,
                        "NextZip",
                        tr(
                            "악성코드 검사를 껐습니다. 믿을 수 있는 압축 파일만 푸세요. Windows 보안의 실시간 보호는 계속 동작합니다.",
                        ),
                        false,
                    );
                }
            }
        }
    }

    fn command(&mut self, id: isize) {
        match id {
            ID_OPEN => self.do_open_dialog(),
            ID_EXTRACT => self.do_extract(),
            ID_COMPRESS | ID_EMPTY_NEW => self.do_compress(Vec::new()),
            ID_TEST => self.do_test(),
            ID_VIEW => {
                self.show_preview = !self.show_preview;
                self.update_mode();
            }
            ID_SETTINGS => self.settings_menu(),
            ID_UP => self.go_up(),
            ID_EMPTY_OPEN => self.do_open_dialog(),
            ID_PREVIEW_CP => self.codepage_menu(self.preview_cp),
            ID_STATUS_CP => self.codepage_menu(self.status_cp),
            x if (ID_CRUMB..ID_CRUMB + 80).contains(&x) => {
                let depth = (x - ID_CRUMB) as usize;
                let Some(o) = &self.arc else { return };
                let mut chain = vec![self.cur];
                while let Some(p) = o.dirs[*chain.last().unwrap()].parent {
                    chain.push(p);
                }
                chain.reverse();
                if let Some(d) = chain.get(depth) {
                    self.navigate(*d);
                }
            }
            x if (ID_RECENT..ID_RECENT + 10).contains(&x) => {
                if let Some((_, p)) = self.recents.get((x - ID_RECENT) as usize) {
                    let p = p.clone();
                    self.open(p);
                }
            }
            _ => {}
        }
    }

    fn accel(&mut self, cmd: u16) {
        match cmd {
            CMD_OPEN => self.do_open_dialog(),
            CMD_NEW => self.do_compress(Vec::new()),
            CMD_RECENT => {
                if let Some((b, _)) = self.recents.first()
                    && !self.has_archive()
                {
                    unsafe {
                        let _ = SetFocus(Some(*b));
                    }
                }
            }
            CMD_EXTRACT => {
                if self.arc.is_some() {
                    self.do_extract()
                }
            }
            CMD_UP => self.go_up(),
            CMD_FOCUS_PATH => {
                if let Some(b) = self.crumbs.last() {
                    unsafe {
                        let _ = SetFocus(Some(*b));
                    }
                }
            }
            _ => {}
        }
    }

    fn go_up(&mut self) {
        let parent = self.arc.as_ref().and_then(|o| o.dirs[self.cur].parent);
        if let Some(p) = parent {
            let from = self.cur;
            self.navigate(p);
            // keep the folder we came from selected
            if let Some(i) = self.rows.iter().position(|r| *r == Row::Dir(from)) {
                let mut it = LVITEMW {
                    stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_FOCUSED.0 | LVIS_SELECTED.0),
                    state: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_FOCUSED.0 | LVIS_SELECTED.0),
                    ..Default::default()
                };
                ui::send(self.list, LVM_SETITEMSTATE, i, &mut it as *mut _ as isize);
                ui::send(self.list, LVM_ENSUREVISIBLE, i, 0);
            }
        }
    }

    fn activate(&mut self, row: usize) {
        match self.rows.get(row) {
            Some(Row::Dir(d)) => {
                let d = *d;
                self.navigate(d);
            }
            Some(Row::File(_)) => self.refresh_preview(),
            None => {}
        }
    }

    fn notify(&mut self, lp: LPARAM) -> Option<LRESULT> {
        let hdr = unsafe { &*(lp.0 as *const NMHDR) };
        if hdr.idFrom == ID_LIST as usize {
            match hdr.code {
                LVN_GETDISPINFOW => {
                    let di = unsafe { &mut *(lp.0 as *mut NMLVDISPINFOW) };
                    let row = di.item.iItem as usize;
                    if di.item.mask.contains(LVIF_TEXT) && !di.item.pszText.is_null() {
                        let t = self.cell(row, di.item.iSubItem as usize);
                        let cap = di.item.cchTextMax.max(1) as usize;
                        let w: Vec<u16> = t
                            .encode_utf16()
                            .take(cap - 1)
                            .chain(std::iter::once(0))
                            .collect();
                        unsafe {
                            std::ptr::copy_nonoverlapping(w.as_ptr(), di.item.pszText.0, w.len());
                        }
                    }
                    if di.item.mask.contains(LVIF_IMAGE) {
                        di.item.iImage = self.icon_for(row);
                    }
                    return Some(LRESULT(0));
                }
                LVN_ODFINDITEMW => {
                    let fi = unsafe { &*(lp.0 as *const NMLVFINDITEMW) };
                    if fi.lvfi.flags.contains(LVFI_STRING) || fi.lvfi.flags.contains(LVFI_PARTIAL) {
                        let needle =
                            unsafe { fi.lvfi.psz.to_string().unwrap_or_default() }.to_lowercase();
                        let n = self.rows.len();
                        let start = fi.iStart.max(0) as usize;
                        for k in 0..n {
                            let i = (start + k) % n;
                            if self.cell(i, 0).to_lowercase().starts_with(&needle) {
                                return Some(LRESULT(i as isize));
                            }
                        }
                    }
                    return Some(LRESULT(-1));
                }
                LVN_COLUMNCLICK => {
                    let nm = unsafe { &*(lp.0 as *const NMLISTVIEW) };
                    let col = nm.iSubItem as usize;
                    self.sort = if self.sort.0 == col {
                        (col, !self.sort.1)
                    } else {
                        (col, true)
                    };
                    self.sort_rows();
                    self.update_sort_arrow();
                    ui::invalidate(self.list);
                    return Some(LRESULT(0));
                }
                LVN_ITEMACTIVATE => {
                    let nm = unsafe { &*(lp.0 as *const NMITEMACTIVATE) };
                    let row = if nm.iItem >= 0 {
                        nm.iItem as usize
                    } else {
                        ui::send(
                            self.list,
                            LVM_GETNEXTITEM,
                            usize::MAX,
                            LVNI_FOCUSED as isize,
                        ) as usize
                    };
                    self.activate(row);
                    return Some(LRESULT(0));
                }
                LVN_KEYDOWN => {
                    let kd = unsafe { &*(lp.0 as *const NMLVKEYDOWN) };
                    if kd.wVKey == VK_BACK.0 {
                        self.go_up();
                    }
                    return Some(LRESULT(0));
                }
                LVN_ITEMCHANGED | LVN_ODSTATECHANGED => {
                    self.refresh_preview();
                    return Some(LRESULT(0));
                }
                _ => {}
            }
        }
        if hdr.idFrom == ID_TREE as usize && hdr.code == TVN_SELCHANGEDW && !self.tree_sync {
            let nm = unsafe { &*(lp.0 as *const NMTREEVIEWW) };
            let d = nm.itemNew.lParam.0 as usize;
            if d != self.cur {
                self.navigate(d);
            }
            return Some(LRESULT(0));
        }
        None
    }

    fn dropped(&mut self, hdrop: HDROP) {
        let mut paths = Vec::new();
        unsafe {
            let n = DragQueryFileW(hdrop, u32::MAX, None);
            for i in 0..n {
                let len = DragQueryFileW(hdrop, i, None) as usize;
                let mut buf = vec![0u16; len + 1];
                DragQueryFileW(hdrop, i, Some(&mut buf));
                paths.push(PathBuf::from(String::from_utf16_lossy(&buf[..len])));
            }
            DragFinish(hdrop);
        }
        if paths.len() == 1 && paths[0].is_file() && nz_archive::Kind::sniff(&paths[0]).is_ok() {
            self.codepage = None;
            self.password = None;
            let p = paths.remove(0);
            self.open(p);
        } else if !paths.is_empty() {
            self.do_compress(paths);
        }
    }

    fn btn_bg(&self, ctl: HWND) -> theme::Rgb {
        let p = theme::pal();
        let id = unsafe { GetDlgCtrlID(ctl) } as isize;
        match id {
            ID_OPEN..=ID_SETTINGS => p.surface2,
            ID_STATUS_CP => p.surface2,
            ID_UP | ID_PREVIEW_CP => p.surface,
            x if (ID_CRUMB..ID_CRUMB + 80).contains(&x) => p.surface,
            _ => p.bg,
        }
    }
}

impl ui::WindowState for Main {
    fn handle(&mut self, hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
        match msg {
            WM_CREATE => {
                ui::top_opened();
                self.init(hwnd);
                Some(LRESULT(0))
            }
            WM_SIZE => {
                self.layout();
                ui::invalidate(hwnd);
                Some(LRESULT(0))
            }
            WM_GETMINMAXINFO => {
                let mm = unsafe { &mut *(lp.0 as *mut MINMAXINFO) };
                mm.ptMinTrackSize = POINT {
                    x: ui::px(hwnd, 480.0),
                    y: ui::px(hwnd, 360.0),
                };
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
                if !self.painted {
                    self.painted = true;
                    crate::first_paint();
                    unsafe {
                        let _ = PostMessageW(Some(hwnd), WM_APP + 11, WPARAM(0), LPARAM(0));
                    }
                }
                Some(LRESULT(0))
            }
            WM_APP_PAINT => {
                let hdc = HDC(lp.0 as _);
                match wp.0 as isize {
                    ID_PREVIEW => self.paint_preview(hdc),
                    ID_STATUS => self.paint_status(hdc),
                    _ => {}
                }
                Some(LRESULT(0))
            }
            WM_MEASUREITEM => {
                let mi = unsafe { &mut *(lp.0 as *mut MEASUREITEMSTRUCT) };
                if mi.CtlType == ODT_LISTVIEW {
                    mi.itemHeight = ui::px(hwnd, ROW_H) as u32;
                }
                Some(LRESULT(1))
            }
            WM_DRAWITEM => {
                let dis = unsafe { &*(lp.0 as *const DRAWITEMSTRUCT) };
                if dis.CtlType == ODT_LISTVIEW {
                    self.draw_row(dis);
                } else {
                    ui::draw_button(dis, self.btn_bg(dis.hwndItem));
                }
                Some(LRESULT(1))
            }
            WM_COMMAND => {
                let id = ui::loword(wp.0);
                if lp.0 == 0 {
                    // accelerator or IDOK from the dialog manager
                    if id == IDOK.0 as u16 {
                        let focus =
                            unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetFocus() };
                        if focus == self.list {
                            let row = ui::send(
                                self.list,
                                LVM_GETNEXTITEM,
                                usize::MAX,
                                LVNI_FOCUSED as isize,
                            );
                            if row >= 0 {
                                self.activate(row as usize);
                            }
                        } else if !focus.is_invalid() {
                            ui::send(focus, BM_CLICK, 0, 0);
                        }
                    } else {
                        self.accel(id);
                    }
                } else if ui::hiword(wp.0) as u32 == BN_CLICKED {
                    self.command(id as isize);
                }
                Some(LRESULT(0))
            }
            WM_NOTIFY => self.notify(lp),
            WM_DROPFILES => {
                self.dropped(HDROP(wp.0 as _));
                Some(LRESULT(0))
            }
            WM_APP_WORK => {
                if wp.0 == 2 {
                    self.loaded();
                }
                Some(LRESULT(0))
            }
            x if x == WM_APP + 11 => {
                self.attach_images();
                Some(LRESULT(0))
            }
            x if x == WM_APP + 10 => {
                let p = unsafe { Box::from_raw(lp.0 as *mut PathBuf) };
                self.open(*p);
                Some(LRESULT(0))
            }
            WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
                theme::refresh();
                self.apply_theme();
                None
            }
            WM_DPICHANGED => {
                ui::apply_dpi_rect(hwnd, lp);
                self.apply_fonts();
                self.create_list();
                // re-run sizing of the column widths at the new DPI happens in create_list
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

fn stage_(n: &str) {
    crate::stage(n);
}
