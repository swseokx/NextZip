#![no_main]

// Package containers: cpio, ar, deb, rpm, asar, xar, uue, xxe.
use nz_formats::Format as F;

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_formats::fuzzing::run_selected(&[F::Cpio, F::Ar, F::Deb, F::Rpm, F::Asar, F::Xar, F::Uue, F::Xxe], data));
