#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_archive::fuzzing::core_7z(data));
