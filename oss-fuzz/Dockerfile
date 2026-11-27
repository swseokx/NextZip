# OSS-Fuzz build image for NextZip. NOT SUBMITTED (see README.md).
FROM gcr.io/oss-fuzz-base/base-builder-rust
# base-builder already ships zip (seed corpora) and cmake 3.29; the C/C++
# codecs (UnRAR, zstd, liblzma, libdeflate, bzip2, lz4) are built from vendored
# sources by their -sys crates with the image's clang, so no apt packages.
# The base image pins an older nightly (nightly-2025-09-05 = rustc 1.91 as of
# 2026-11), below the workspace MSRV 1.95. Pin a newer nightly; rust-src is
# needed by cargo-fuzz's sanitizer builds.
ENV RUSTUP_TOOLCHAIN=nightly-2026-11-19
RUN rustup toolchain install $RUSTUP_TOOLCHAIN --no-self-update --profile minimal --component rust-src
# TODO: replace with the public repository URL before submitting.
RUN git clone --depth 1 https://example.invalid/nextzip.git nextzip
WORKDIR $SRC/nextzip
COPY build.sh $SRC/
