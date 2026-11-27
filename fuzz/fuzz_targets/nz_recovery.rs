#![no_main]

// .nz recovery path: scan for the recovery record, verify every sector and
// rebuild damaged ones; then open with full verification.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    nz_nzf::fuzzing::recovery(data);
    nz_nzf::fuzzing::open_and_test(data, true);
});
