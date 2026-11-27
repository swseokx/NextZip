#![no_main]

// Single-file streams: gzip, bzip2, xz, lzma, lzip, zstd, lz4, brotli, compress (.Z).
use nz_formats::Format as F;

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_formats::fuzzing::run_selected(&[F::Gz, F::Bz2, F::Xz, F::Lzma, F::Lzip, F::Zst, F::Lz4, F::Br, F::Z], data));
