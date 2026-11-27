#![no_main]

// .nz reader: open (header, trailer, crypto descriptor, index), automatic
// repair on failure, then decode every block and compare chunk hashes.
libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_nzf::fuzzing::open_and_test(data, false));
