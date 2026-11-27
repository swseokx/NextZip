#![no_main]

// Whatever nz-formats detects in the input (all readers).
libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_formats::fuzzing::run(None, "bin", data));
