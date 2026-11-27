//! `nextzip-setup.exe` — per-user installer; installed as `uninstall.exe`.
//!
//! ```text
//! nextzip-setup.exe [/quiet]            install (asks first unless /quiet)
//! uninstall.exe /uninstall [/quiet]     remove (asks first unless /quiet)
//! ```
//! Exit code 0 = done, 1 = failed, 2 = cancelled by the user.
#![windows_subsystem = "windows"]

use nz_front::{tr, trf};
use std::path::Path;
use std::process::Command;

use nz_setup::{Layout, VERSION};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;
use windows::Win32::UI::WindowsAndMessaging::{
    IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MESSAGEBOX_STYLE,
    MessageBoxW,
};
use windows::core::HSTRING;

const TITLE: &str = "NextZip 설치";

fn message(text: &str, style: MESSAGEBOX_STYLE) -> bool {
    unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from(tr(TITLE)), style) == IDYES }
}

fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .map(|a| a.to_ascii_lowercase())
        .collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    let quiet = has("/quiet") || has("/s");
    let layout = match Layout::user() {
        Ok(l) => l,
        Err(e) => {
            if !quiet {
                message(&format!("{e:#}"), MB_OK | MB_ICONERROR);
            }
            std::process::exit(1);
        }
    };
    let code = if has("/uninstall") {
        uninstall(&layout, quiet, has("/stage2"))
    } else {
        install(&layout, quiet)
    };
    std::process::exit(code);
}

fn install(layout: &Layout, quiet: bool) -> i32 {
    let payload = match nz_setup::embedded() {
        Ok(p) => p,
        Err(e) => {
            return fail(
                quiet,
                &trf("설치 데이터가 손상되었습니다: {}", &[&format!("{e:#}")]),
            );
        }
    };
    if !quiet
        && !message(
            &trf(
                "NextZip {}을(를) 설치할까요?\n\n\
                 위치: {}\n\
                 - 현재 사용자에게만 설치합니다(관리자 권한 없음).\n\
                 - 탐색기 우클릭 메뉴와 시작 메뉴 바로 가기를 추가합니다.\n\
                 - 파일 연결(기본 앱)은 바꾸지 않습니다.",
                &[&VERSION, &layout.dir.display()],
            ),
            MB_YESNO | MB_ICONQUESTION,
        )
    {
        return 2;
    }
    let me = match std::env::current_exe().and_then(std::fs::read) {
        Ok(b) => b,
        Err(e) => return fail(quiet, &trf("설치 파일을 읽지 못했습니다: {}", &[&e])),
    };
    match nz_setup::install(layout, &payload, &me) {
        Ok(notes) => {
            if !quiet {
                let mut t = trf(
                    "NextZip {} 설치를 마쳤습니다.\n\n\
                     Windows 11에서는 우클릭 메뉴의 \"추가 옵션 표시\" 아래에 NextZip이 나타납니다. \
                     바로 보이지 않으면 탐색기를 다시 시작하거나 로그아웃 후 다시 로그인하세요.",
                    &[&VERSION],
                );
                for n in notes {
                    t.push_str("\n\n");
                    t.push_str(&n);
                }
                message(&t, MB_OK | MB_ICONINFORMATION);
            }
            0
        }
        Err(e) => fail(quiet, &trf("설치하지 못했습니다: {}", &[&format!("{e:#}")])),
    }
}

fn uninstall(layout: &Layout, quiet: bool, stage2: bool) -> i32 {
    let me = std::env::current_exe().unwrap_or_default();
    // Running from the install folder: this file would be locked while we
    // delete it. Continue from a copy in %TEMP% instead.
    if !stage2 && me.parent() == Some(layout.dir.as_path()) {
        if !quiet && !confirm_uninstall() {
            return 2;
        }
        let tmp =
            std::env::temp_dir().join(format!("nextzip-uninstall-{}.exe", std::process::id()));
        if std::fs::copy(&me, &tmp).is_ok() {
            let mut c = Command::new(&tmp);
            c.args(["/uninstall", "/stage2"]);
            if quiet {
                c.arg("/quiet");
            }
            if c.spawn().is_ok() {
                return 0;
            }
        }
        // Fall through: uninstall in place, leaving uninstall.exe behind.
        return run_uninstall(layout, quiet, None);
    }
    if !stage2 && !quiet && !confirm_uninstall() {
        return 2;
    }
    run_uninstall(layout, quiet, stage2.then_some(me.as_path()))
}

fn confirm_uninstall() -> bool {
    message(
        tr(
            "NextZip을 제거할까요?\n\n탐색기 우클릭 메뉴, 시작 메뉴 바로 가기, 설치 폴더의 NextZip 파일을 지웁니다.",
        ),
        MB_YESNO | MB_ICONQUESTION,
    )
}

fn run_uninstall(layout: &Layout, quiet: bool, temp_copy: Option<&Path>) -> i32 {
    // The first process (uninstall.exe in the install folder) may still be
    // exiting: give its file a moment to unlock.
    for _ in 0..25 {
        let p = layout.dir.join(nz_setup::UNINSTALLER);
        if !p.exists() || std::fs::OpenOptions::new().write(true).open(&p).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let r = nz_setup::uninstall(layout);
    if let Some(tmp) = temp_copy {
        // Delete this temporary copy once the process has exited.
        use std::os::windows::process::CommandExt;
        let _ = Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 3 127.0.0.1 >nul & del /f /q"])
            .arg(tmp)
            .creation_flags(CREATE_NO_WINDOW.0)
            .spawn();
    }
    match r {
        Ok(notes) => {
            if !quiet {
                let mut t = String::from(tr("NextZip을 제거했습니다."));
                for n in notes {
                    t.push_str("\n\n");
                    t.push_str(&n);
                }
                message(&t, MB_OK | MB_ICONINFORMATION);
            }
            0
        }
        Err(e) => fail(quiet, &trf("제거하지 못했습니다: {}", &[&format!("{e:#}")])),
    }
}

fn fail(quiet: bool, text: &str) -> i32 {
    if !quiet {
        message(text, MB_OK | MB_ICONERROR);
    }
    1
}
