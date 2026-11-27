# nz-formats regression fixtures

`manifest.tsv` lists, per fixture, every file member as
`fixture<TAB>member<TAB>size<TAB>crc32`. It was produced by
`cargo run -p nz-formats --example nzf -- --crc <files>` (with
`NZF_PASSWORD=pass` for `*_aes.*`) and cross-checked against 7-Zip 26.06
extraction wherever 7-Zip reads the format (see
`bench/results/1.0-formats-*.md`). `tests/fixtures.rs` re-checks it.

| Files | Made with | Licence |
|---|---|---|
| `hello.*`, `t.*` (cpio, ar, deb, xar, tar.Z/.lz/.lzma/.zst/.bz2, single streams, uu) | Windows `tar.exe` (bsdtar 3.8) from a generated tree | ours |
| `hello.txt.xxe` | small Python xxencoder | ours |
| `t.lzh` | an external LZH archiver (lh5) from a generated tree | ours |
| `hello.*.cab` | Windows `makecab` (MSZIP, LZX) | ours |
| `zip_*.zip`, `7z_*.7z` | 7-Zip 26.06 (Deflate64, BZip2, LZMA, PPMd, AES-256; Deflate, Delta, ARM64, header encryption) | ours |
| `la_*` | libarchive 3.8.11 test suite (`libarchive/test/*.uu`, decoded) | BSD-2-Clause |
| `unarc_*` | unarc-rs test data (`crates/unarc-rs/tests`) | MIT OR Apache-2.0 |
