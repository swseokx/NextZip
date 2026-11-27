#![no_main]

// Full-coder ZIP (zip crate) and 7z (sevenz-rust2) fallbacks.
use nz_formats::Format as F;

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_formats::fuzzing::run_selected(&[F::ZipFull, F::SevenZ], data));
