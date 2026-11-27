//! Entry points for the cargo-fuzz targets in `fuzz/` (and their smoke
//! test): write the input to a per-process temp file, then detect, list and
//! extract it in memory. Errors are expected; panics are turned into errors
//! by the public API's guard, so libFuzzer reports aborts, stack overflows,
//! out-of-memory and hangs.

use std::path::PathBuf;

use crate::{Format, Options, Sink};

/// Discards data but caps the total, like the parent's size limits.
struct Discard(u64);

impl Sink for Discard {
    fn start(&mut self, _: usize, _: &crate::Member) -> anyhow::Result<bool> {
        Ok(true)
    }
    fn data(&mut self, d: &[u8]) -> anyhow::Result<()> {
        self.0 += d.len() as u64;
        if self.0 > 256 << 20 {
            anyhow::bail!("output limit");
        }
        Ok(())
    }
    fn finish(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

fn scratch(ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!("nzfuzz-{}.{ext}", std::process::id()))
}

/// Run `data` as `format` (or as whatever [`crate::detect`] finds when
/// `format` is `None`). `ext` names the temp file, for extension sniffing.
pub fn run(format: Option<Format>, ext: &str, data: &[u8]) {
    let p = scratch(ext);
    if std::fs::write(&p, data).is_err() {
        return;
    }
    let Some(f) = format.or_else(|| crate::detect(&p)) else {
        return;
    };
    // The unarc-rs HA decoder has known bugs (overflow panics, endless
    // loops on damaged input; see bench/results/1.0-formats-*.md). The
    // product contains them (panic guard, worker stall limit), but under
    // libFuzzer on Windows a panic unwind is itself reported as a crash
    // and a hang as a timeout, so HA would stop every run. Skip it.
    if f == Format::Ha {
        return;
    }
    // Auto-detected input that lands in unarc-rs: upstream decoders panic
    // on many damaged inputs (contained in the product by the guard, but a
    // crash to libFuzzer). `fmt_legacy`, built like the product (`-O`),
    // covers them; `fmt_detect` stays on detection and NextZip's readers.
    if format.is_none() && crate::legacy::is_legacy(f) {
        return;
    }
    let opt = Options::default();
    if crate::list(f, &p, &opt).is_ok() {
        let _ = crate::extract(f, &p, &opt, &mut Discard(0));
    }
}

/// Pick one of `formats` with the first byte and run the rest.
pub fn run_selected(formats: &[Format], data: &[u8]) {
    let Some((&k, rest)) = data.split_first() else {
        return;
    };
    let f = formats[k as usize % formats.len()];
    run(
        Some(f),
        f.extensions().first().copied().unwrap_or("bin"),
        rest,
    );
}
