# Patched third-party crates

Crates here replace their crates.io release through `[patch.crates-io]` in the
workspace `Cargo.toml`. Each keeps its upstream licence files; drop the copy
once upstream ships the fix.

| Crate | Version | Licence | Change |
|---|---|---|---|
| lzxd | 0.2.7 | MIT OR Apache-2.0 | E8 translation: treat an absolute target of 0 as non-negative (`abs_val >= 0` instead of `is_positive()`). Without it, LZX data with an E8 call to offset 0 decodes wrong (libarchive `test_read_format_cab_lzx_e8.cab`). |
| sevenz-rust2 | 0.24.2 | Apache-2.0 | Used by `fuzz/` only: `crate-type = ["rlib"]` (upstream also builds a cdylib, which fails to link under cargo-fuzz on Windows). Code unchanged. |
| unarc-rs | 0.8.1 | MIT OR Apache-2.0 | HA decoders (`src/ha/hsc.rs`, `src/ha/asc.rs`, `src/ha/ha_archive.rs`): stop with a "corrupted entry" error once the output passes the size recorded in the header, and when an HSC symbol needs more escapes than there are context orders (cyclic context chain). Without it, damaged HA input decodes forever into memory in release builds (overflow checks off): `crates/nz-archive/tests/data/fuzz_ha_overflow.ha` took tens of GB. `[[test]]` targets are dropped from `Cargo.toml` because the 15 MB test data is not copied. See `docs/upstream-bugs.md` #2, #3. |
