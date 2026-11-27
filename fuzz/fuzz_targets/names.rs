#![no_main]

// Code page detection + zip-slip guard on newline-separated raw names.
libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_archive::fuzzing::names(data));
