#![no_main]

// List + extract with the content sniffed; the file name is x.alz.
libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_archive::fuzzing::archive("x.alz", data));
