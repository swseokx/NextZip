//! The locked-down process must not be able to write user files, start
//! processes or raise its memory use past the cap. The test re-runs this
//! test binary as a child (env `NZ_SANDBOX_PROBE`) so the lockdown never
//! touches the test runner itself.

#![cfg(windows)]

use std::process::Command;

fn probe_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("NZ_SANDBOX_PROBE").map(Into::into)
}

#[test]
fn child_probe() {
    let Some(dir) = probe_dir() else {
        return; // only meaningful when started by `lockdown_blocks_writes`
    };
    // Before lockdown the folder is writable.
    std::fs::write(dir.join("before.txt"), b"ok").expect("write before lockdown");
    let l = nz_sandbox::lockdown(512 << 20).expect("lockdown");
    assert!(l.complete(), "{l:?}");
    assert_eq!(nz_sandbox::integrity_level(), Some(0x1000));
    // Writing into a medium-integrity folder is denied.
    let w = std::fs::write(dir.join("after.txt"), b"bad");
    assert!(w.is_err(), "write after lockdown succeeded");
    // Starting another process is denied by the job.
    let c = Command::new("cmd.exe").args(["/c", "exit", "0"]).status();
    assert!(c.is_err(), "child process started: {c:?}");
    // Allocating past the cap fails instead of succeeding.
    let big: Result<Vec<u8>, _> = std::panic::catch_unwind(|| {
        let mut v = Vec::new();
        v.try_reserve_exact(1 << 30).map(|_| v)
    })
    .unwrap_or(Ok(Vec::new()));
    assert!(
        big.is_err(),
        "1 GiB allocation succeeded under a 512 MiB cap"
    );
    println!("PROBE-OK");
}

#[test]
fn lockdown_blocks_writes() {
    if probe_dir().is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_probe", "--nocapture", "--test-threads=1"])
        .env("NZ_SANDBOX_PROBE", dir.path())
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("PROBE-OK"), "{text}");
    assert!(dir.path().join("before.txt").exists());
    assert!(!dir.path().join("after.txt").exists());
}
