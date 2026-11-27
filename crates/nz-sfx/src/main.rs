//! NextZip self-extractor stub. Run as `<name>.exe` with a 7z archive and
//! trailer appended (see the library docs).
//!
//! ```text
//! <name>.exe                 ask, then extract to <exe folder>\<name>
//! <name>.exe -o:<folder>     extract there
//! <name>.exe -y              no questions; replace existing files
//! ```
//!
//! Exit code 0 on success, 1 on error, 2 when the user cancelled.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;

use nz_front::{tr, trf};

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    // The recipient may not have NextZip: NZ_LANG, else the Windows
    // display language.
    nz_front::i18n::init();
    let mut dest: Option<PathBuf> = None;
    let mut quiet = false;
    for a in std::env::args_os().skip(1) {
        let s = a.to_string_lossy();
        if s.eq_ignore_ascii_case("-y") || s.eq_ignore_ascii_case("/y") {
            quiet = true;
        } else if let Some(d) = s.strip_prefix("-o:").or_else(|| s.strip_prefix("/o:")) {
            dest = Some(PathBuf::from(d));
        }
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return fail(quiet, &format!("{e}")),
    };
    let dest = dest.unwrap_or_else(|| {
        let stem = exe.file_stem().map(|s| s.to_owned()).unwrap_or_default();
        exe.with_file_name(stem)
    });
    let mut overwrite = quiet;
    if !quiet {
        let msg = trf("다음 폴더에 압축을 풉니다.\n\n{}", &[&dest.display()]);
        if !ui::confirm(&msg) {
            return 2;
        }
        let non_empty = std::fs::read_dir(&dest).is_ok_and(|mut d| d.next().is_some());
        if non_empty {
            if !ui::confirm(tr(
                "폴더가 비어 있지 않습니다. 같은 이름의 파일을 덮어쓸까요?",
            )) {
                return 2;
            }
            overwrite = true;
        }
    }
    match nz_sfx::extract_sfx(&exe, &dest, overwrite) {
        Ok(s) => {
            if !quiet {
                ui::info(&trf(
                    "압축을 풀었습니다: 파일 {}개, {} 바이트\n\n{}",
                    &[&s.files, &s.bytes, &dest.display()],
                ));
            }
            0
        }
        Err(e) => fail(quiet, &format!("{e:#}")),
    }
}

fn fail(quiet: bool, msg: &str) -> i32 {
    if quiet {
        eprintln!("nz-sfx: {msg}");
    } else {
        ui::error(msg);
    }
    1
}

#[cfg(windows)]
mod ui {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDOK, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_OKCANCEL,
        MESSAGEBOX_STYLE, MessageBoxW,
    };

    fn show(text: &str, style: MESSAGEBOX_STYLE) -> i32 {
        let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (t, c) = (w(text), w(nz_front::tr("NextZip 자동 압축 풀기")));
        // SAFETY: both strings are NUL-terminated UTF-16 buffers that live
        // across the call; a null owner window is allowed.
        unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), style) }
    }

    pub fn confirm(text: &str) -> bool {
        show(text, MB_OKCANCEL | MB_ICONQUESTION) == IDOK
    }

    pub fn info(text: &str) {
        show(text, MB_OK | MB_ICONINFORMATION);
    }

    pub fn error(text: &str) {
        show(text, MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
mod ui {
    pub fn confirm(text: &str) -> bool {
        eprintln!("{text}");
        true
    }

    pub fn info(text: &str) {
        eprintln!("{text}");
    }

    pub fn error(text: &str) {
        eprintln!("{text}");
    }
}
