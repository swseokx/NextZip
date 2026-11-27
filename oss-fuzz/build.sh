#!/bin/bash -eu
# OSS-Fuzz build script for NextZip: builds every cargo-fuzz target in fuzz/
# and copies it, with its seed corpus when there is one, to $OUT.

cd "$SRC/nextzip"

# The fuzz crate is its own workspace (fuzz/Cargo.toml) with the same
# [patch.crates-io] entries as the main workspace.
cargo fuzz build -O --fuzz-dir fuzz

# Every [[bin]] in fuzz/Cargo.toml, so new targets are picked up automatically.
TARGETS="$(cargo fuzz list --fuzz-dir fuzz)"
BIN_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"

for t in $TARGETS; do
    cp "$BIN_DIR/$t" "$OUT/"
    if [ -d "fuzz/corpus/$t" ] && [ -n "$(ls -A "fuzz/corpus/$t")" ]; then
        (cd "fuzz/corpus/$t" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
    fi
    # Archive inputs can be large; give libFuzzer room for them.
    printf '[libfuzzer]\nmax_len = 1048576\n' > "$OUT/$t.options"
done
