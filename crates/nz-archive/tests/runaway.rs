//! Damaged input that makes a third-party decoder run away fails fast in
//! debug and release builds. Own test binary: `tests/hang.rs` shortens the
//! process-wide stall limit, which must not be what ends this case.

use std::path::Path;
use std::time::{Duration, Instant};

/// Found by `fmt_detect` fuzzing: the third-party HA decoder hits an
/// arithmetic overflow. With overflow checks (debug builds) unarc-rs 0.8.1
/// panics; without them (release builds) it kept producing output into
/// memory (tens of GB) until the parent's 5-minute stall limit. Extraction
/// must fail quickly and cleanly in both builds (the stall limit is not
/// shortened here).
#[test]
fn damaged_ha_fails_fast_in_debug_and_release() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fuzz_ha_overflow.ha");
    let out = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let e = nz_archive::extract(&p, out.path(), &nz_archive::Options::default(), None)
        .expect_err("damaged archive must fail");
    let msg = format!("{e:#}");
    // The patched decoder (third_party/unarc-rs) reports the overrun
    // itself; the panic guard (overflow checks on) and the worker's budget
    // (release) are the backstops if a future decoder version regresses.
    assert!(
        msg.contains("Corrupted HA")
            || msg.contains("decoder fault")
            || msg.contains("한도를 넘어"),
        "{msg}"
    );
    assert!(t.elapsed() < Duration::from_secs(60), "{:?}", t.elapsed());
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
