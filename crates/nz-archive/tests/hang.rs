//! A decoder that stops making progress (an infinite loop on damaged
//! input) is killed by the parent's stall limit instead of hanging the
//! extraction. Own test binary: the limit is process-wide.

use std::path::Path;
use std::time::{Duration, Instant};

/// Found by `fmt_detect` fuzzing: a damaged HA archive on which the
/// third-party HA (HSC) decoder never finishes.
#[test]
fn hung_decoder_is_killed() {
    nz_archive::isolated::set_stall_timeout(Duration::from_secs(5));
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fuzz_ha_hang.ha");
    let out = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let r = nz_archive::list(&p, &nz_archive::Options::default())
        .and_then(|_| nz_archive::extract(&p, out.path(), &nz_archive::Options::default(), None));
    let e = r.expect_err("damaged archive must fail");
    assert!(t.elapsed() < Duration::from_secs(60), "{:?}", t.elapsed());
    let msg = format!("{e:#}");
    // The patched decoder (third_party/unarc-rs) now stops this input
    // itself; the worker budget and the stall limit stay as backstops.
    assert!(
        msg.contains("Corrupted HA") || msg.contains("응답하지") || msg.contains("한도를 넘어"),
        "{msg}"
    );
}
