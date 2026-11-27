# Test inputs in this folder

| File | Source | Licence |
|---|---|---|
| `alz_split_real.alz`, `.a00`, `.a01` | Made on 2026-11-22 with ALZip 12.38 (`ALZipCon.exe` 26.11.11.19, `-a -v64KB src 분할.alz`, files renamed) from generated input: `src/readme.txt` (text) and `src/한글/데이터.bin` (seeded random bytes). ALZip was removed afterwards. Used by `tests/legacy.rs` (`alz_split_made_by_alzip`). | Generated input, no licence |
| `fuzz_ha_hang.ha` | Found by the `fmt_detect` fuzz target (2026-11-22): a damaged HA archive on which the unarc-rs HSC decoder never finishes. Used by `tests/hang.rs`. | Generated input, no licence |
| `fuzz_ha_overflow.ha` | Found by `fmt_detect` fuzzing (2026-11-22): makes the unarc-rs HSC decoder panic (add overflow, `ha/hsc.rs:827`). Used by `tests/hang.rs`. | Generated input, no licence |
| `la_zip_junk_prefix.zip` | libarchive 3.8.11 `test/test_compat_zip_4.zip.uu`, decoded (zeros before a ZIP) | BSD-2-Clause |
| `la_zstd_skippable.tar.zst` | libarchive 3.8.11 `test/test_compat_zstd_3.tar.zst.uu`, decoded (skippable frames before the data) | BSD-2-Clause |

`rar/` and `fuzz-regressions/` have their own notes / commit history.
