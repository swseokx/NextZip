# The `.nz` archive format, version 1.0

Status: **stable** (v1.0, 2026-11-22). Reference implementation: crate
`nz-nzf` in the NextZip repository, MIT licensed. Anyone may implement this
format without restriction.

> 한국어 요약: `.nz`는 NextZip의 네이티브 컨테이너입니다. 내용 기반 청크(FastCDC)
> 단위 중복 제거, 독립 해제 가능한 블록(zstd·LZ4·LZMA2·저장), 스냅샷(증분 백업),
> 파일명까지 포함하는 암호화(Argon2id + AES-256-GCM/ChaCha20-Poly1305), 그리고
> 섹터 단위 Reed-Solomon 복구 레코드를 담습니다. 이 문서의 테스트 벡터(17장)는
> 테스트(`crates/nz-nzf/tests/spec_vectors.rs`)가 매번 다시 만들어 바이트 단위로
> 비교하므로, 문서와 구현이 어긋나면 빌드가 실패합니다.

The keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conventions

* All integers are **little-endian**. `u8/u16/u32/u64` are unsigned.
* `varint` is unsigned LEB128: 7 bits per byte, least significant group
  first, high bit set on every byte except the last. At most 10 bytes; the
  10th byte MUST be 0 or 1. A multi-byte varint MUST NOT end in a `0x00`
  byte (no redundant groups). Readers MUST reject violations.
* `zigzag(v) = (v << 1) ^ (v >> 63)` maps signed `i64` to `u64`
  (0, -1, 1, -2 … → 0, 1, 2, 3 …).
* `string` is `varint length` followed by that many bytes of UTF-8. Length
  MUST be at most 65535 and the bytes MUST be valid UTF-8.
* `BLAKE3(x)` is the 32-byte BLAKE3 hash. `H8(x)` and `H4(x)` are its first
  8 and 4 bytes. `BLAKE3_keyed(k, x)` is BLAKE3 in keyed mode;
  `BLAKE3_derive(ctx, k)` is BLAKE3 key derivation with the context string
  `ctx` (both as in the BLAKE3 specification).
* "Reserved" bytes MUST be written as zero; where noted, readers MUST
  reject non-zero values.
* Times are nanoseconds since 1970-01-01T00:00:00Z (`i64`, may be negative).

## 2. File layout

```text
offset 0     Main header                              64 bytes
offset 64    Crypto descriptor (encrypted only)       64 bytes
             Block frame 0 .. Block frame n-1         64 + stored_len each
             Primary index frame                      72 + stored_len
             ---- end of the covered area (= recovery_offset when present)
             Recovery record (optional)               rr_len
             Index copy frame                         identical bytes to the primary
end - 64     Trailer                                  64 bytes
```

A writer that cannot seek MAY leave the main header's offsets at zero and
rely on the trailer. The reference writer always writes the final main
header. Readers MUST NOT assume blocks are contiguous or in index order;
they are located only through the index. Bytes between structures that the
index does not reference (for example a superseded index after a backup
run, §12) MUST be ignored.

## 3. Main header and trailer (64 bytes)

| off | size | field |
|---:|---:|---|
| 0 | 4 | magic: `4E 5A 1A 01` (`"NZ"`, 0x1A, 0x01); trailer: `4E 5A 1A FE` |
| 4 | 1 | version major = 1 (readers MUST reject other values) |
| 5 | 1 | version minor = 0 (readers MUST accept any minor) |
| 6 | 2 | flags: bit 0 `ENCRYPTED`, bit 1 `RECOVERY`; other bits MUST be 0 (reject) |
| 8 | 8 | `index_offset`: offset of the primary index frame |
| 16 | 8 | `index_copy_offset`: offset of the index copy frame, 0 = none |
| 24 | 8 | `recovery_offset`: offset of the recovery record, 0 = none |
| 32 | 8 | `archive_size`: total file length including the trailer |
| 40 | 4 | `rr_sector_size` (0 without a recovery record) |
| 44 | 2 | `rr_basis_points`: parity per data, in 1/10000 (300 = 3 %) |
| 46 | 2 | reserved (reject non-zero) |
| 48 | 4 | `rr_group_sectors`: data sectors per recovery group |
| 52 | 4 | reserved (reject non-zero) |
| 56 | 8 | `H8(bytes 0..56)` |

The trailer is the same structure with the trailer magic; its check value is
computed over its own bytes 0..56. In a finished archive the header and the
trailer carry identical fields. When `RECOVERY` is set, the recovery record
covers exactly bytes `[0, recovery_offset)`, so the main header itself is
protected; its geometry (`rr_*` fields) is repeated in the header and the
trailer so that the record can be used even if both of its own headers are
damaged.

## 4. Encryption

### 4.1 Crypto descriptor (64 bytes at offset 64, only when `ENCRYPTED`)

| off | size | field |
|---:|---:|---|
| 0 | 4 | magic `NZCK` |
| 4 | 1 | AEAD: 1 = AES-256-GCM, 2 = ChaCha20-Poly1305 (RFC 8439) |
| 5 | 1 | KDF: 1 = Argon2id version 0x13 (RFC 9106) |
| 6 | 2 | reserved (reject non-zero) |
| 8 | 4 | Argon2 memory `m` in KiB |
| 12 | 4 | Argon2 passes `t` |
| 16 | 4 | Argon2 lanes `p` |
| 20 | 16 | salt |
| 36 | 16 | key check value |
| 52 | 4 | reserved (reject non-zero) |
| 56 | 8 | `H8(bytes 0..56)` |

Readers MUST reject `m > 1048576` (1 GiB), `t > 64`, `p > 16`, `m < 8·p`,
`t = 0` or `p = 0` before running the KDF. The reference writer uses
`m = 65536, t = 3, p = 1` and a random salt.

### 4.2 Keys

```text
master    = Argon2id(password as UTF-8, salt, m, t, p, output 32 bytes)
block_key = BLAKE3_derive("NextZip .nz v1 block key", master)
index_key = BLAKE3_derive("NextZip .nz v1 index key", master)
hash_key  = BLAKE3_derive("NextZip .nz v1 hash key",  master)
check     = first 16 bytes of BLAKE3_derive("NextZip .nz v1 key check", master)
```

A password is wrong exactly when `check` differs from the stored value.
Implementations SHOULD wipe keys from memory after use.

### 4.3 Content hash

`ContentHash(x)` is `BLAKE3(x)` for unencrypted archives and
`BLAKE3_keyed(hash_key, x)` for encrypted ones (an unkeyed hash of plaintext
would let anyone confirm guesses about the contents). It is used for block
hashes, chunk hashes and the index hash.

## 5. Codecs

| id | name | payload |
|---:|---|---|
| 0 | store | the raw bytes |
| 1 | zstd | exactly one Zstandard frame (RFC 8878) whose content is `raw_len` bytes; readers MAY refuse windows above 2^27 |
| 2 | lz4 | one LZ4 *block* (no frame, no size prefix) decoding to `raw_len` bytes |
| 3 | lzma2 | 1 property byte `d` (< 40) followed by a raw LZMA2 stream; dictionary size is `(2 \| (d & 1)) << (d / 2 + 11)`; readers MUST reject a dictionary larger than the one for `max(raw_len, 4096)` |

Decoding MUST produce exactly `raw_len` bytes; anything else is an error.
The index frame uses only codecs 0 and 1.

### 5.1 Block filters

A block frame names a filter (§6 byte 6) that the writer applied to the
raw block bytes before the codec; readers decode, then undo the filter, then
check `ContentHash` (which is always over the unfiltered raw bytes).

| id | name | definition |
|---:|---|---|
| 0 | none | — |
| 1 | x86 | the x86 BCJ filter (7-Zip method `03030103`, xz filter id `0x04`) applied once to the whole raw block as one stream with start offset 0: `E8`/`E9` rel32 operands become absolute addresses; the last 4 bytes are never converted. Output is identical to liblzma's x86 filter with start offset 0. |

Readers MUST reject unknown filter ids. A filter MAY be combined with any
codec, including store.

## 6. Block frame

A block is an independently decodable unit of chunk data.

| off | size | field |
|---:|---:|---|
| 0 | 4 | magic `NZBK` |
| 4 | 1 | codec id (§5) |
| 5 | 1 | flags: 0 = plain, 1 = encrypted; other values rejected |
| 6 | 1 | filter id (§5.1); unknown values rejected |
| 7 | 1 | reserved (reject non-zero) |
| 8 | 4 | `raw_len` (≤ 268435456; reject larger) |
| 12 | 4 | `stored_len`: bytes following this 64-byte header |
| 16 | 32 | `ContentHash(raw bytes)` |
| 48 | 12 | nonce (zero when plain) |
| 60 | 4 | `H4(bytes 0..60)` |
| 64 | `stored_len` | payload |

Plain: payload = codec output. Encrypted: payload =
`AEAD_encrypt(block_key, nonce, plaintext = codec output, aad = header bytes 0..48)`,
i.e. the codec output followed by the 16-byte tag. Readers decrypt, decode,
then MUST compare `ContentHash` and reject a mismatch.

Nonces MUST never repeat under one key. The reference writer draws a random
8-byte prefix per write session and appends the block number of that
session as `u32` (bytes 8..12, little-endian).

## 7. Index frame

| off | size | field |
|---:|---:|---|
| 0 | 4 | magic `NZIX` |
| 4 | 1 | codec id: 0 or 1 only |
| 5 | 1 | flags: 0 = plain, 1 = encrypted |
| 6 | 2 | reserved (reject non-zero) |
| 8 | 8 | `raw_len` (≤ 2^30; reject larger) |
| 16 | 8 | `stored_len` |
| 24 | 32 | `ContentHash(raw index body)` |
| 56 | 12 | nonce (random per index when encrypted, else zero) |
| 68 | 4 | `H4(bytes 0..68)` |
| 72 | `stored_len` | payload |

Encrypted payload = `AEAD_encrypt(index_key, nonce, codec output, aad = header bytes 0..56)`.
The index copy is a byte-identical copy of the primary index frame.

## 8. Index body

```text
IndexBody  := u8 version (= 1)
              varint nblocks   Block[nblocks]
              varint nchunks   Chunk[nchunks]
              varint nsnaps    Snapshot[nsnaps]
              (no trailing bytes)
Block      := varint offset          absolute offset of the block frame
              varint raw_len         MUST equal the frame's raw_len
Chunk      := varint block           index into Block[], < nblocks
              varint offset          byte offset inside the block's raw data
              varint len             offset + len <= block raw_len
              32 bytes hash          ContentHash(chunk bytes)
Snapshot   := varint zigzag(time_ns)
              string label
              varint nentries  Entry[nentries]
Entry      := string path
              u8 kind                0 file, 1 directory, 2 symbolic link
              varint attrs           Windows file attributes (0 = unknown)
              varint mode            Unix mode bits (0 = unknown)
              varint zigzag(mtime_ns)
              kind 0: varint size  ChunkList     (sum of chunk lengths == size)
              kind 2: string target              ('/'-separated, as stored)
              varint nstreams  Stream[nstreams]
Stream     := u8 kind                0 NTFS alternate data stream, 1 extended attribute
              string name
              varint size  ChunkList
ChunkList  := varint n, then n values zigzag(id_k - (id_{k-1} + 1)) with id_{-1} = -1
```

* Chunks are global to the archive: any entry of any snapshot may reference
  any chunk, any number of times. This is the deduplication mechanism.
* A file's content is the concatenation of its chunks in order; an empty
  file has no chunks.
* `path` is relative, `/`-separated, and MUST NOT be empty. Readers MUST
  reject (or refuse to extract) paths that are absolute, contain a drive or
  stream designator (`:`), or contain a `..` component; the reference
  reader rejects the whole archive (same policy as its other formats).
* Streams of kind 0 are NTFS alternate (named `$DATA`) data streams; the
  content of a stream is the concatenation of its chunks, like a file's.
  Their names MUST be 1–255 UTF-16 code units long and MUST NOT contain
  `:` (which would select a stream type such as `$INDEX_ALLOCATION`),
  `/`, `\`, `<`, `>`, `"`, `|`, `?`, `*` or characters below U+0020.
  Readers MUST reject (or refuse to extract) an archive with a kind-0 name
  that breaks this rule, like an unsafe path. Kind 1 (extended attribute)
  is reserved: the reference writer never stores it and the reference
  extractor ignores it, as it ignores streams of directories and links.
* Snapshots are ordered oldest first; a plain archive has one snapshot.
* Every count is bounded by the remaining body bytes before allocation
  (reference: `count × minimum item size ≤ remaining`).

## 9. Recovery record

### 9.1 Geometry

Inputs: `covered_len` (= `recovery_offset`), sector size `S` (a power of two,
64 ≤ S ≤ 2^20), group size `D` (1 ≤ D ≤ 32768 data sectors), basis points
`bp` (1 ≤ bp ≤ 10000).

```text
N        = ceil(covered_len / S)             data sectors; sector i = bytes [i·S, (i+1)·S)
                                             the last one is zero-padded to S
G        = ceil(N / D)                       groups; group g = sectors [g·D, min((g+1)·D, N))
D_g      = sectors in group g
P(d)     = max(1, ceil(d · bp / 10000))      parity sectors of a group with d data sectors
P_g      = P(D_g);   P_total = (G-1)·P(D) + P(D_{G-1})
first parity sector of group g = g · P(D)
rr_len   = 64 + 8·(N + P_total) + S·P_total + 8·(N + P_total) + 64
```

### 9.2 Layout (starting at `recovery_offset`)

| relative offset | size | content |
|---|---:|---|
| 0 | 64 | record header A |
| 64 | 8·(N+P_total) | hash table A: `H8` of every data sector (zero-padded), then of every parity sector |
| 64 + 8·(N+P_total) | S·P_total | parity sectors, group 0 first |
| … | 8·(N+P_total) | hash table B (identical to A) |
| rr_len − 64 | 64 | record header B (identical to A) |

Record header:

| off | size | field |
|---:|---:|---|
| 0 | 4 | magic `NZRR` |
| 4 | 1 | record version = 1 |
| 5 | 1 | reserved |
| 6 | 2 | `bp` |
| 8 | 4 | `S` |
| 12 | 4 | `D` |
| 16 | 8 | `covered_len` |
| 24 | 4 | `G` |
| 28 | 4 | `P_total` |
| 32 | 8 | `rr_len` |
| 40 | 16 | reserved |
| 56 | 8 | `H8(bytes 0..56)` |

Readers MUST recompute G, P_total and rr_len from (covered_len, S, D, bp)
and reject a header that disagrees.

### 9.3 Parity code

The parity sectors of group g are the **recovery shards of the Leopard-RS
high-rate code over GF(2^16)** (Lin, Chung and Han, "Novel polynomial basis
and its application to Reed-Solomon erasure codes", FOCS 2014; the
construction of C. A. Taylor's *leopard* library) with
`original_count = D_g`, `recovery_count = P_g`, `shard_bytes = S` and the
`D_g` data sectors of the group, in order, as original shards. Shard bytes
use leopard's layout: each 64-byte block holds the low bytes of 32 GF(2^16)
elements followed by their high bytes. The reference implementation uses
`reed_solomon_simd::rate::HighRateEncoder` 3.1. Because the code works on
each 64-byte column independently, encoders MAY split sectors into column
stripes (multiples of 64 bytes) and code them in parallel; the bytes are the
same. Note `P_g.next_power_of_two() + D_g ≤ 65536` always holds for
`D ≤ 32768, bp ≤ 10000`.

### 9.4 Repair and the recovery budget

A data or parity sector is **intact** when its `H8` equals the entry in
hash table A or the entry in hash table B (entries that cannot be read are
ignored). Everything else — including a sector beyond a truncated end — is
damaged. For each group with damaged data sectors, if the number of damaged
data sectors is at most the number of intact parity sectors, the damaged
data sectors are restored by Leopard-RS decoding from the intact shards.

**Guarantee.** A group is restored byte-exact when its damaged data sectors
plus its damaged parity sectors number at most `P_g`. This holds for any
pattern (bit flips, zeroed runs, contiguous runs, truncation of the
recovery record's tail) and includes damage to the main header, crypto
descriptor, blocks and the primary index, all of which lie in the covered
area. A sector whose two hash entries are *both* damaged counts as damaged.
Damage outside the covered area other than parity sectors (record headers,
hash tables, index copy, trailer) does not consume the budget as long as one
copy of each survives. A contiguous damaged run of `L` bytes inside one
group touches at most `ceil(L / S) + 1` sectors.

When a group exceeds its budget, readers SHOULD report the byte ranges of
its damaged data sectors and continue: blocks outside those ranges still
decode and every entry whose chunks avoid them can still be extracted.

### 9.5 Locating structures

Readers SHOULD try, in order: the main header; the trailer (last 64 bytes);
and, if both fail, a backwards scan for a valid record header (`NZRR` with a
correct `H8`) whose position is either `covered_len` (header A) or
`covered_len + rr_len − 64` (header B). After repairing the covered area the
main header is readable again. The index is read from `index_offset`, and
from `index_copy_offset` if that fails. The reference reader first reads
without verification and applies the recovery record only when a check
fails (a header, an index or a block), so undamaged archives pay nothing.

## 10. Reading

1. Locate the header (§9.5); verify `H8`, version and flags.
2. If `ENCRYPTED`: read the crypto descriptor at offset 64, derive keys
   (§4.2) and check the password.
3. Read the index frame, decrypt, decode, verify `ContentHash`, parse.
4. For an entry, for each chunk id: decode the chunk's block (verifying its
   `ContentHash`) and copy `len` bytes from `offset`. Blocks are independent
   and MAY be decoded in parallel; a block shared by several entries need be
   decoded once.

## 11. Writing (reference writer, informative)

* **Chunking:** FastCDC with normalized chunking level 2: minimum 16 KiB,
  average 64 KiB, maximum 256 KiB. Gear table: `gear[i]` = first 8 bytes
  (little-endian `u64`) of `BLAKE3("nz fastcdc gear" ‖ byte i)`. Rolling
  hash `h = (h << 1) + gear[byte]` starting at offset 16384; before 65536 a
  cut is made after the byte where `h & MASK_S == 0`, from there up to
  262144 where `h & MASK_L == 0`; otherwise at 262144. `MASK_S` has bits 63,
  60, 57, … (18 bits, every third from the top), `MASK_L` the first 14 of
  them. Readers never need this; it only decides what deduplicates.
* **Deduplication:** a chunk whose `ContentHash` is already in the chunk
  table is referenced instead of stored.
* **Blocks:** every file is classified by content with the NextZip planner
  (LZ4 on up to three sample windows, PE/ELF x86 headers, a text
  heuristic). At levels 1–9 new chunks go to one of up to four open blocks:
  *code* (x86 / x86-64 executables), *packed* (levels 6–8: mostly
  compressed or incompressible files), *stored* (levels 1–8 without a
  packed block: incompressible files) and *normal* (everything else, all
  alternate data streams, and every file at level 0). A block is sealed,
  and only then numbered, once it holds at least its target size: 4 MiB at
  levels 0–6, 16 MiB at 7–8, 64 MiB at 9; code blocks 8 MiB at levels 2–6
  (4 MiB at 1, as the others at 7–9). At the end the open blocks are sealed
  in the order normal, code, packed, stored. Files are fed grouped by
  extension for a better ratio (`create`) or in walk order (`backup`).
* **Codec per level:** 0 store, 1 LZ4, 2–6 zstd 1/3/5/7/9, 7–8 zstd 15/19,
  9 LZMA2 preset 9 (one LZMA2 stream per block, encoded as 4 MiB segments
  in parallel, each with the preceding 8 MiB as preset dictionary, so the
  decoder sees a single ordinary stream). zstd frames use a window of
  `next_power_of_two(raw_len)` (at most 2^27). Code blocks use filter 1
  (x86 BCJ). Packed blocks use LZMA2 preset 1 with `lc=0`, `pb=0` in
  independent 1 MiB segments. Stored blocks are not compressed; any other
  block whose compressed form is not smaller is stored without a filter.
* **Alternate data streams:** on Windows the named `$DATA` streams of every
  regular file (`FindFirstStreamW`) are stored as kind-0 streams, in name
  order, their chunks added right after the file's content. Names failing
  the §8 rule are not stored. Directories' streams are not stored. The
  reference extractor writes kind-0 streams of file entries as
  `<file>:<name>` after the content and before the modification time and
  read-only attribute; a stream that cannot be written (e.g. on FAT) is
  reported and the file kept. Other systems skip streams on extraction.
* **Recovery record:** default 3 % (`bp = 300`), at most 30 %;
  `S = clamp(next_power_of_two(ceil(covered_len / 32768)), 1024, 4096)`,
  `D = 32768` (one group up to 32 MiB at 1 KiB sectors, 128 MiB groups at
  4 KiB sectors).
* **Determinism:** with the same input and options, the bytes do not depend
  on the number of threads (chunk boundaries, block contents and numbers,
  nonce counters and the recovery record are all functions of the input).
  Encrypted archives differ between runs only by salt and nonces.
* **Order of writing:** header (provisional), crypto descriptor, blocks,
  primary index, final header at offset 0, recovery record computed over
  `[0, recovery_offset)`, index copy, trailer.

## 12. Appending a snapshot (backup)

1. Open and, if needed, repair the archive (a run on an archive damaged
   beyond its record MUST be refused). Repaired sectors are written back.
2. Let `start` = end of the primary index frame. Write an interim main
   header: same flags without `RECOVERY`, same `index_offset`, the other
   offsets 0, `archive_size = start`; truncate the file to `start`. The
   archive stays valid (old snapshots) if the run is interrupted from here on.
3. Hash new data; reuse chunks already present; write new blocks from
   `start` (with a fresh nonce prefix when encrypted).
4. Write a new index containing all blocks, all chunks and all snapshots
   plus the new one. The old primary index remains as unreferenced bytes.
5. Write the final header, a new recovery record over the whole covered
   area, the index copy and the trailer, as in §11.

An encrypted archive keeps its crypto descriptor; the same password is
required to append.

## 13. Reader limits (MUST)

Readers MUST bound every allocation by a header field already validated
against the limits in this document (block ≤ 256 MiB, index ≤ 1 GiB,
Argon2 ≤ 1 GiB, counts ≤ remaining bytes, strings ≤ 65535 bytes, frame
lengths ≤ archive length, recovery tables ≤ archive length) and MUST treat
every inconsistency as damage, never as a reason to read out of bounds.

## 14. Security notes

* Encryption covers block contents and the whole index (names, sizes,
  times, the chunk table). Block sizes, their number and the archive size
  remain visible. Recovery data is computed over ciphertext.
* AEAD authenticates each block and the index; the check value only
  distinguishes a wrong password from damage.
* Symbolic links are stored as links; the reference extractor writes them
  as regular files containing the target (links are never created by
  default).

## 15. Versioning

A change that old readers would misread increments the major version.
Minor versions only add things old readers can ignore (new codec ids and
flag bits are major changes because readers reject unknown ones).

History: the block filter byte (§5.1, §6 byte 6, formerly reserved) was
added to v1.0 on 2026-11-23, before any release that wrote `.nz` files;
readers built from earlier development snapshots reject blocks with a
non-zero filter. Kind-0 stream name rules (§8) were made explicit at the
same time; the index encoding is unchanged.

## 16. Reference implementation map

| section | source |
|---|---|
| §3–§7 | `crates/nz-nzf/src/fmt.rs` |
| §4 | `crates/nz-nzf/src/crypto.rs` |
| §5 | `crates/nz-nzf/src/codec.rs` |
| §8 | `crates/nz-nzf/src/index.rs` |
| §9 | `crates/nz-nzf/src/rr.rs` |
| §10 | `crates/nz-nzf/src/read.rs` |
| §11–§12 | `crates/nz-nzf/src/write.rs`, `cdc.rs` |

## 17. Test vectors

Inputs: two files `a.txt` and `b.txt`, each containing the 10 bytes
`hello, nz\n`, modification time 1 700 000 000 s, attributes not stored,
level 0 (store), snapshot time 1 700 000 000 000 000 000 ns, label `v1`.

### 17.1 Without recovery record (`-rr:0`)

<!-- vector:plain -->
```text
000000  4e 5a 1a 01 01 00 00 00 8a 00 00 00 00 00 00 00
000010  28 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000020  06 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000030  00 00 00 00 00 00 00 00 90 e7 62 01 61 12 af 10
000040  4e 5a 42 4b 00 00 00 00 0a 00 00 00 0a 00 00 00
000050  d9 3e d3 47 fd 79 a4 8f 62 f2 3b 3b 90 53 b8 31
000060  94 b6 f8 b9 fc 54 22 d3 05 7a ed 94 a8 ae 69 a3
000070  00 00 00 00 00 00 00 00 00 00 00 00 1c 7c 41 9b
000080  68 65 6c 6c 6f 2c 20 6e 7a 0a 4e 5a 49 58 01 00
000090  00 00 62 00 00 00 00 00 00 00 56 00 00 00 00 00
0000a0  00 00 20 18 28 90 b0 fa f5 86 e6 d7 78 5d 5a 1b
0000b0  40 2e b3 9d 34 40 b3 4a f5 5b 3b 63 de de 26 ff
0000c0  1e 5a 00 00 00 00 00 00 00 00 00 00 00 00 98 57
0000d0  f4 d7 28 b5 2f fd 20 62 6d 02 00 14 04 01 01 40
0000e0  0a 01 00 00 0a d9 3e d3 47 fd 79 a4 8f 62 f2 3b
0000f0  3b 90 53 b8 31 94 b6 f8 b9 fc 54 22 d3 05 7a ed
000100  94 a8 ae 69 a3 01 80 80 d0 e2 c6 bf ce 97 2f 02
000110  76 31 02 05 61 2e 74 78 74 00 00 00 05 62 03 00
000120  39 84 08 66 e1 53 9b 50 4e 5a 49 58 01 00 00 00
000130  62 00 00 00 00 00 00 00 56 00 00 00 00 00 00 00
000140  20 18 28 90 b0 fa f5 86 e6 d7 78 5d 5a 1b 40 2e
000150  b3 9d 34 40 b3 4a f5 5b 3b 63 de de 26 ff 1e 5a
000160  00 00 00 00 00 00 00 00 00 00 00 00 98 57 f4 d7
000170  28 b5 2f fd 20 62 6d 02 00 14 04 01 01 40 0a 01
000180  00 00 0a d9 3e d3 47 fd 79 a4 8f 62 f2 3b 3b 90
000190  53 b8 31 94 b6 f8 b9 fc 54 22 d3 05 7a ed 94 a8
0001a0  ae 69 a3 01 80 80 d0 e2 c6 bf ce 97 2f 02 76 31
0001b0  02 05 61 2e 74 78 74 00 00 00 05 62 03 00 39 84
0001c0  08 66 e1 53 9b 50 4e 5a 1a fe 01 00 00 00 8a 00
0001d0  00 00 00 00 00 00 28 01 00 00 00 00 00 00 00 00
0001e0  00 00 00 00 00 00 06 02 00 00 00 00 00 00 00 00
0001f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 0e a6
000200  83 d4 28 0f 55 30
```

Walk-through: header (0x000–0x03f) with `index_offset = 0x8a`,
`index_copy_offset = 0x128`, `archive_size = 0x206`; one block frame at
0x40 (codec 0, raw 10, stored 10, hash `BLAKE3("hello, nz\n")`) and its 10
payload bytes; the primary index frame at 0x8a (zstd, raw 0x62, stored
0x56); the index copy at 0x128; the trailer at 0x1c6.

The decoded index body:

<!-- vector:index-body -->
```text
000000  01 01 40 0a 01 00 00 0a d9 3e d3 47 fd 79 a4 8f
000010  62 f2 3b 3b 90 53 b8 31 94 b6 f8 b9 fc 54 22 d3
000020  05 7a ed 94 a8 ae 69 a3 01 80 80 d0 e2 c6 bf ce
000030  97 2f 02 76 31 02 05 61 2e 74 78 74 00 00 00 80
000040  80 d0 e2 c6 bf ce 97 2f 0a 01 00 00 05 62 2e 74
000050  78 74 00 00 00 80 80 d0 e2 c6 bf ce 97 2f 0a 01
000060  00 00
```

`01` version · `01` one block: `40` offset 64, `0a` raw 10 · `01` one
chunk: block `00`, offset `00`, length `0a`, 32-byte hash · `01` one
snapshot: time `80 80 d0 e2 c6 bf ce 97 2f` (zigzag), label `02 "v1"` ·
`02` two entries: `05 "a.txt"`, kind `00`, attrs `00`, mode `00`, mtime
(zigzag varint), size `0a`, chunk list `01 00` (one chunk, id 0), streams
`00`; then `b.txt` with the same chunk — deduplicated.

### 17.2 With a 3 % recovery record (default)

`covered_len = 0x128` (296), so `S = 1024`, `D = 32768`, `N = 1`, `G = 1`,
`P = 1`, `rr_len = 64 + 16 + 1024 + 16 + 64 = 1184`.

<!-- vector:recovery -->
```text
000000  4e 5a 1a 01 01 00 02 00 8a 00 00 00 00 00 00 00
000010  c8 05 00 00 00 00 00 00 28 01 00 00 00 00 00 00
000020  a6 06 00 00 00 00 00 00 00 04 00 00 2c 01 00 00
000030  00 80 00 00 00 00 00 00 2d 18 95 f3 b1 8c 7f b5
000040  4e 5a 42 4b 00 00 00 00 0a 00 00 00 0a 00 00 00
000050  d9 3e d3 47 fd 79 a4 8f 62 f2 3b 3b 90 53 b8 31
000060  94 b6 f8 b9 fc 54 22 d3 05 7a ed 94 a8 ae 69 a3
000070  00 00 00 00 00 00 00 00 00 00 00 00 1c 7c 41 9b
000080  68 65 6c 6c 6f 2c 20 6e 7a 0a 4e 5a 49 58 01 00
000090  00 00 62 00 00 00 00 00 00 00 56 00 00 00 00 00
0000a0  00 00 20 18 28 90 b0 fa f5 86 e6 d7 78 5d 5a 1b
0000b0  40 2e b3 9d 34 40 b3 4a f5 5b 3b 63 de de 26 ff
0000c0  1e 5a 00 00 00 00 00 00 00 00 00 00 00 00 98 57
0000d0  f4 d7 28 b5 2f fd 20 62 6d 02 00 14 04 01 01 40
0000e0  0a 01 00 00 0a d9 3e d3 47 fd 79 a4 8f 62 f2 3b
0000f0  3b 90 53 b8 31 94 b6 f8 b9 fc 54 22 d3 05 7a ed
000100  94 a8 ae 69 a3 01 80 80 d0 e2 c6 bf ce 97 2f 02
000110  76 31 02 05 61 2e 74 78 74 00 00 00 05 62 03 00
000120  39 84 08 66 e1 53 9b 50 4e 5a 52 52 01 00 2c 01
000130  00 04 00 00 00 80 00 00 28 01 00 00 00 00 00 00
000140  01 00 00 00 01 00 00 00 a0 04 00 00 00 00 00 00
000150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000160  76 37 91 4f cd 3a c4 e1 34 2a fa 95 44 1e 43 03
000170  34 2a fa 95 44 1e 43 03 4e 5a 1a 01 01 00 02 00
000180  8a 00 00 00 00 00 00 00 c8 05 00 00 00 00 00 00
000190  28 01 00 00 00 00 00 00 a6 06 00 00 00 00 00 00
0001a0  00 04 00 00 2c 01 00 00 00 80 00 00 00 00 00 00
0001b0  2d 18 95 f3 b1 8c 7f b5 4e 5a 42 4b 00 00 00 00
0001c0  0a 00 00 00 0a 00 00 00 d9 3e d3 47 fd 79 a4 8f
0001d0  62 f2 3b 3b 90 53 b8 31 94 b6 f8 b9 fc 54 22 d3
0001e0  05 7a ed 94 a8 ae 69 a3 00 00 00 00 00 00 00 00
0001f0  00 00 00 00 1c 7c 41 9b 68 65 6c 6c 6f 2c 20 6e
000200  7a 0a 4e 5a 49 58 01 00 00 00 62 00 00 00 00 00
000210  00 00 56 00 00 00 00 00 00 00 20 18 28 90 b0 fa
000220  f5 86 e6 d7 78 5d 5a 1b 40 2e b3 9d 34 40 b3 4a
000230  f5 5b 3b 63 de de 26 ff 1e 5a 00 00 00 00 00 00
000240  00 00 00 00 00 00 98 57 f4 d7 28 b5 2f fd 20 62
000250  6d 02 00 14 04 01 01 40 0a 01 00 00 0a d9 3e d3
000260  47 fd 79 a4 8f 62 f2 3b 3b 90 53 b8 31 94 b6 f8
000270  b9 fc 54 22 d3 05 7a ed 94 a8 ae 69 a3 01 80 80
000280  d0 e2 c6 bf ce 97 2f 02 76 31 02 05 61 2e 74 78
000290  74 00 00 00 05 62 03 00 39 84 08 66 e1 53 9b 50
0002a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0002b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0002c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0002d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0002e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0002f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000300  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000310  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000320  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000330  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000340  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000350  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000360  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000370  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000380  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000390  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000400  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000420  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000430  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000440  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000450  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000460  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000470  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000480  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000490  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0004a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0004b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0004c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0004d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0004e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0004f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000500  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000510  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000520  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000530  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000540  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000550  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000560  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000570  00 00 00 00 00 00 00 00 34 2a fa 95 44 1e 43 03
000580  34 2a fa 95 44 1e 43 03 4e 5a 52 52 01 00 2c 01
000590  00 04 00 00 00 80 00 00 28 01 00 00 00 00 00 00
0005a0  01 00 00 00 01 00 00 00 a0 04 00 00 00 00 00 00
0005b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0005c0  76 37 91 4f cd 3a c4 e1 4e 5a 49 58 01 00 00 00
0005d0  62 00 00 00 00 00 00 00 56 00 00 00 00 00 00 00
0005e0  20 18 28 90 b0 fa f5 86 e6 d7 78 5d 5a 1b 40 2e
0005f0  b3 9d 34 40 b3 4a f5 5b 3b 63 de de 26 ff 1e 5a
000600  00 00 00 00 00 00 00 00 00 00 00 00 98 57 f4 d7
000610  28 b5 2f fd 20 62 6d 02 00 14 04 01 01 40 0a 01
000620  00 00 0a d9 3e d3 47 fd 79 a4 8f 62 f2 3b 3b 90
000630  53 b8 31 94 b6 f8 b9 fc 54 22 d3 05 7a ed 94 a8
000640  ae 69 a3 01 80 80 d0 e2 c6 bf ce 97 2f 02 76 31
000650  02 05 61 2e 74 78 74 00 00 00 05 62 03 00 39 84
000660  08 66 e1 53 9b 50 4e 5a 1a fe 01 00 02 00 8a 00
000670  00 00 00 00 00 00 c8 05 00 00 00 00 00 00 28 01
000680  00 00 00 00 00 00 a6 06 00 00 00 00 00 00 00 04
000690  00 00 2c 01 00 00 00 80 00 00 00 00 00 00 41 cd
0006a0  bd 40 81 8d 69 7a
```
