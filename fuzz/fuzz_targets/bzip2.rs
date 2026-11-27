#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_archive::fuzzing::bzip2(data));
