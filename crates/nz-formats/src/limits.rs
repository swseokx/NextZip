//! Resource limits for readers of untrusted input.

/// Bytes read from the start of a file for format detection.
pub const SNIFF: usize = 64 * 1024;

/// Largest member a reader decodes into memory at once.
pub const MAX_MEMBER: u64 = 1 << 30;

/// Most that is allocated up front from a size taken from a header.
pub const PREALLOC: usize = 16 << 20;

/// Most members a listing may hold (more is treated as a malformed archive).
pub const MAX_MEMBERS: usize = 1_000_000;

/// A `Vec` with capacity for `size` bytes, capped at [`PREALLOC`].
pub fn vec_for(size: u64) -> Vec<u8> {
    Vec::with_capacity(size.min(PREALLOC as u64) as usize)
}

/// Memory limit for LZMA-family decoders (dictionary allocation).
pub const DICT_MEMORY: u64 = 1536 << 20;

/// Largest output of one single-stream member (the parent applies its own
/// zip-bomb ratio limit on top).
pub const MAX_STREAM: u64 = 1 << 42;
