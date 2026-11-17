//! Unreal IoStore container reader (R5 census, extended by the
//! IoStore rung, D-1638).
//!
//! Parses the full table of contents of a version 8 `.utoc`
//! (UE 5.x) and extracts chunk payloads from the paired
//! `.ucas`. The layout below was measured byte-exactly against
//! two held containers (a 3,871-chunk game container and the
//! 1-chunk `global` container of the Detailed Cowgirl
//! Simulator build, UE 5.5); both files' section arithmetic
//! closes exactly to the file size.
//!
//! TOC layout (all header fields little-endian u32 unless
//! noted):
//!
//! - Header, 144 bytes: the 16-byte magic
//!   `-==--==--==--==-`, then version (@16), header size
//!   (@20), chunk entry count (@24), compressed block entry
//!   count (@28), compressed block entry size (@32, 12),
//!   compression method name count (@36), compression method
//!   name length (@40, 32), compression block size (@44),
//!   directory index size (@48), partition count (@52),
//!   container id (@56, 8 bytes), encryption key GUID (@64,
//!   16 bytes), container flags (@80; 1 = Compressed,
//!   2 = Encrypted, 4 = Signed, 8 = Indexed), and the
//!   hash-lookup entry count (@84).
//! - Chunk ids: 12 bytes per chunk (an 8-byte hash, three
//!   bytes, and a chunk-type byte).
//! - Chunk records: 10 bytes per chunk — two big-endian
//!   40-bit fields: the chunk's offset and length in the
//!   container's *uncompressed* space, where each chunk is
//!   aligned to the compression block size. The records are
//!   parallel to the chunk id array (same index = same
//!   chunk); the pairing is proven by the chunk hash check
//!   below on every extracted chunk.
//! - Hash-lookup table: `count` u32 words (@84). Contents
//!   (a perfect-hash directory lookup) are recorded, not
//!   interpreted.
//! - Compressed block entries: 12 bytes each — serialized
//!   offset (5 bytes LE), compressed size (3 bytes LE),
//!   uncompressed size (3 bytes LE), compression method
//!   index (1 byte). Method index 0 is stored (no
//!   compression); index `k >= 1` names
//!   `compression_methods[k - 1]`. Blocks tile the `.ucas`
//!   in order; padding between blocks belongs to no block.
//! - Compression method names: fixed-length NUL-padded
//!   ASCII strings.
//! - Directory index: `directory index size` bytes. Only
//!   the mount-point FString at its head is decoded; the
//!   entries are hashed and are not interpreted.
//! - Chunk metas: 24 bytes per chunk — the chunk's FIoHash
//!   (20 bytes: BLAKE3 of the chunk's uncompressed payload,
//!   truncated) and a flags word whose bit 0 is set exactly
//!   when the chunk has at least one compressed block
//!   (verified on all 3,871 corpus chunks).
//!
//! A chunk's blocks are the consecutive blocks (in `.ucas`
//! order) whose uncompressed sizes sum exactly to the
//! chunk's declared uncompressed length, taking chunks in
//! uncompressed-offset order. Extraction verifies every
//! chunk's BLAKE3 hash against its TOC meta before writing
//! it — the pak extractor's verify-before-write discipline.
//!
//! Compression routes: stored blocks copy through; `Zlib`
//! and `Gzip` inflate natively (flate2); `LZ4` decodes
//! natively (lz4_flex block format); `Oodle` decodes
//! through the operator-configured external `ooz` decoder
//! (`ooz_decoder` config key; ooz v7.0, pinned upstream —
//! see the `local-iostore-rung` skill) driven as a bounded
//! child process, one block per invocation, framed as
//! `[u32 LE uncompressed size][block bytes]`. With no
//! decoder configured, Oodle chunks are recorded
//! `decoder_unavailable` — never faked. Encrypted
//! containers are recorded, never decrypted.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{GAME_EXTRACT_BYTES_MAX, IOSTORE_TOC_BYTES_MAX, PAK_TARGET_BYTES_MAX};
use fathom_core::paths;
use fathom_core::process::{self, ProcessSpec};
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};
use sha2::Digest;

type Result<T> = std::result::Result<T, FathomError>;

/// Serialized size of one compressed block entry.
const BLOCK_ENTRY_BYTES: u64 = 12;
/// Serialized size of one chunk id.
const CHUNK_ID_BYTES: u64 = 12;
/// Serialized size of one chunk meta (FIoHash + flags).
const CHUNK_META_BYTES: u64 = 24;
/// Serialized size of one chunk record.
const CHUNK_RECORD_BYTES: u64 = 10;
/// Container flag: payloads are compressed.
const CONTAINER_FLAG_COMPRESSED: u32 = 1;
/// Container flag: payloads are encrypted.
const CONTAINER_FLAG_ENCRYPTED: u32 = 2;
/// The TOC header's serialized size.
const HEADER_BYTES: u64 = 144;
/// Per-invocation deadline for the external Oodle decoder.
const OODLE_DECODER_TIMEOUT: Duration = Duration::from_secs(30);
/// The TOC version this rung parses in full.
const TOC_VERSION_FULL_PARSE: u32 = 8;
/// The 16-byte UTOC magic: `-==--==--==--==-`.
const UTOC_MAGIC: &[u8; 16] = b"-==--==--==--==-";

/// One compressed block entry from the TOC.
#[derive(Clone, Debug)]
struct BlockEntry {
    compressed_size: u32,
    method_index: u8,
    serialized_offset: u64,
    uncompressed_size: u32,
}

/// One chunk of the container: its TOC identity, its place
/// in both the uncompressed and the serialized space, and
/// the blocks that carry it.
#[derive(Clone, Debug)]
struct ChunkEntry {
    block_range: (usize, usize),
    flags: u32,
    hash: [u8; 20],
    id: [u8; 12],
    serialized_length: u64,
    serialized_offset: u64,
    uncompressed_length: u64,
    uncompressed_offset: u64,
}

/// The parsed TOC header.
#[derive(Clone, Debug)]
struct TocHeader {
    block_count: u32,
    block_entry_size: u32,
    chunk_count: u32,
    compression_block_size: u32,
    compression_method_name_count: u32,
    compression_method_name_length: u32,
    container_flags: u32,
    container_id: [u8; 8],
    directory_index_size: u32,
    encryption_key_guid: [u8; 16],
    hash_lookup_entry_count: u32,
    header_size: u32,
    partition_count: u32,
    version: u32,
}

/// A fully parsed version 8 TOC.
#[derive(Clone, Debug)]
struct Toc {
    blocks: Vec<BlockEntry>,
    chunks: Vec<ChunkEntry>,
    compression_methods: Vec<String>,
    header: TocHeader,
    mount_point: Option<String>,
    trailing_bytes: u64,
    uncompressed_layout_aligned: bool,
}

/// Read one big-endian 40-bit field at `at`.
fn be_u40(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at + 5)?;
    Some(
        (u64::from(slice[0]) << 32)
            | (u64::from(slice[1]) << 24)
            | (u64::from(slice[2]) << 16)
            | (u64::from(slice[3]) << 8)
            | u64::from(slice[4]),
    )
}

/// Lowercase hex for a byte string.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Read one little-endian u24 at `at`.
fn le_u24(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 3)?;
    Some(u32::from(slice[0]) | (u32::from(slice[1]) << 8) | (u32::from(slice[2]) << 16))
}

/// Read one little-endian u32 at `at`.
fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read one little-endian u40 at `at`.
fn le_u40(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at + 5)?;
    Some(
        u64::from(slice[0])
            | (u64::from(slice[1]) << 8)
            | (u64::from(slice[2]) << 16)
            | (u64::from(slice[3]) << 24)
            | (u64::from(slice[4]) << 32),
    )
}

/// A structural contradiction inside the TOC.
fn integrity(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

/// Parse the 144-byte TOC header from the head of `bytes`.
/// Any version is accepted here; the full parse gates on
/// version separately.
fn parse_toc_header(bytes: &[u8]) -> Result<TocHeader> {
    if bytes.len() < HEADER_BYTES as usize {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "utoc is {} bytes, smaller than the {HEADER_BYTES}-byte TOC header",
                bytes.len()
            ),
        ));
    }
    if &bytes[0..16] != UTOC_MAGIC {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target lacks the IoStore UTOC magic (-==--==--==--==-)",
        ));
    }
    let word = |at: usize| le_u32(bytes, at).unwrap_or(0);
    let mut container_id = [0u8; 8];
    container_id.copy_from_slice(&bytes[56..64]);
    let mut encryption_key_guid = [0u8; 16];
    encryption_key_guid.copy_from_slice(&bytes[64..80]);
    Ok(TocHeader {
        block_count: word(28),
        block_entry_size: word(32),
        chunk_count: word(24),
        compression_block_size: word(44),
        compression_method_name_count: word(36),
        compression_method_name_length: word(40),
        container_flags: word(80),
        container_id,
        directory_index_size: word(48),
        encryption_key_guid,
        hash_lookup_entry_count: word(84),
        header_size: word(20),
        partition_count: word(52),
        version: word(16),
    })
}

/// Decode the mount-point FString at the head of the
/// directory index. Returns `None` when the bytes do not
/// decode cleanly; the index body is never interpreted.
fn read_mount_point(index: &[u8]) -> Option<String> {
    let length = i32::from_le_bytes([
        *index.first()?,
        *index.get(1)?,
        *index.get(2)?,
        *index.get(3)?,
    ]);
    if length > 0 {
        let count = usize::try_from(length).ok()?;
        if count > 4096 {
            return None;
        }
        let raw = index.get(4..4 + count)?;
        let text = raw.strip_suffix(&[0])?;
        String::from_utf8(text.to_vec()).ok()
    } else if length < 0 {
        let count = usize::try_from(length.checked_neg()?).ok()?;
        if count > 4096 {
            return None;
        }
        let raw = index.get(4..4 + count.checked_mul(2)?)?;
        let (pairs, _rest) = raw.as_chunks::<2>();
        let units: Vec<u16> = pairs
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let units = units.strip_suffix(&[0])?;
        String::from_utf16(units).ok()
    } else {
        None
    }
}

/// Parse a complete version 8 TOC from the `.utoc` bytes.
/// Every section is bounds-checked against the file; the
/// chunk/block tiling must close exactly (each block is
/// consumed by exactly one chunk, and each chunk's blocks
/// sum exactly to its declared uncompressed length).
fn parse_toc(bytes: &[u8]) -> Result<Toc> {
    let header = parse_toc_header(bytes)?;
    if header.version != TOC_VERSION_FULL_PARSE {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "IoStore TOC version {}: the full chunk parse is implemented for version {TOC_VERSION_FULL_PARSE} only",
                header.version
            ),
        ));
    }
    if u64::from(header.header_size) != HEADER_BYTES {
        return Err(integrity(format!(
            "TOC header size {} does not equal the version 8 header size {HEADER_BYTES}",
            header.header_size
        )));
    }
    if u64::from(header.block_entry_size) != BLOCK_ENTRY_BYTES {
        return Err(integrity(format!(
            "TOC compressed block entry size {} does not equal {BLOCK_ENTRY_BYTES}",
            header.block_entry_size
        )));
    }
    let file_len = bytes.len() as u64;
    let mut cursor = HEADER_BYTES;
    let take = |cursor: &mut u64, count: u64, what: &str| -> Result<usize> {
        let start = *cursor;
        let end = start
            .checked_add(count)
            .ok_or_else(|| integrity(format!("TOC {what} section size overflows the file")))?;
        if end > file_len {
            return Err(FathomError::new(
                ErrorCode::Truncated,
                format!("TOC {what} section ends at {end}, past the file's {file_len} bytes"),
            ));
        }
        *cursor = end;
        Ok(usize::try_from(start).unwrap_or(usize::MAX))
    };
    let chunk_count = u64::from(header.chunk_count);
    let block_count = u64::from(header.block_count);

    let ids_at = take(
        &mut cursor,
        chunk_count
            .checked_mul(CHUNK_ID_BYTES)
            .ok_or_else(|| integrity("TOC chunk id section size overflows".to_string()))?,
        "chunk id",
    )?;
    let records_at = take(
        &mut cursor,
        chunk_count
            .checked_mul(CHUNK_RECORD_BYTES)
            .ok_or_else(|| integrity("TOC chunk record section size overflows".to_string()))?,
        "chunk record",
    )?;
    let _hash_lookup_at = take(
        &mut cursor,
        u64::from(header.hash_lookup_entry_count) * 4,
        "hash lookup",
    )?;
    let blocks_at = take(
        &mut cursor,
        block_count
            .checked_mul(BLOCK_ENTRY_BYTES)
            .ok_or_else(|| integrity("TOC block entry section size overflows".to_string()))?,
        "block entry",
    )?;
    let names_at = take(
        &mut cursor,
        u64::from(header.compression_method_name_count)
            * u64::from(header.compression_method_name_length),
        "compression method name",
    )?;
    let directory_index_at = take(
        &mut cursor,
        u64::from(header.directory_index_size),
        "directory index",
    )?;
    let metas_at = take(
        &mut cursor,
        chunk_count
            .checked_mul(CHUNK_META_BYTES)
            .ok_or_else(|| integrity("TOC chunk meta section size overflows".to_string()))?,
        "chunk meta",
    )?;
    let trailing_bytes = file_len - cursor;

    let name_length = header.compression_method_name_length as usize;
    let mut compression_methods: Vec<String> = Vec::new();
    for index in 0..header.compression_method_name_count as usize {
        let start = names_at + index * name_length;
        let raw = bytes.get(start..start + name_length).ok_or_else(|| {
            integrity("compression method name runs past the section".to_string())
        })?;
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        let name = std::str::from_utf8(&raw[..end]).map_err(|_| {
            integrity(format!(
                "compression method name {index} is not valid UTF-8"
            ))
        })?;
        compression_methods.push(name.to_string());
    }

    let mut blocks: Vec<BlockEntry> = Vec::with_capacity(header.block_count as usize);
    for index in 0..header.block_count as usize {
        let at = blocks_at + index * BLOCK_ENTRY_BYTES as usize;
        let method_index = *bytes
            .get(at + 11)
            .ok_or_else(|| integrity("block entry runs past the section".to_string()))?;
        if method_index > 0 && usize::from(method_index) > compression_methods.len() {
            return Err(integrity(format!(
                "block {index} names compression method index {method_index}, but only {} method names are declared",
                compression_methods.len()
            )));
        }
        blocks.push(BlockEntry {
            compressed_size: le_u24(bytes, at + 5).unwrap_or(0),
            method_index,
            serialized_offset: le_u40(bytes, at).unwrap_or(0),
            uncompressed_size: le_u24(bytes, at + 8).unwrap_or(0),
        });
    }

    let mut chunks: Vec<ChunkEntry> = Vec::with_capacity(header.chunk_count as usize);
    for index in 0..header.chunk_count as usize {
        let id_at = ids_at + index * CHUNK_ID_BYTES as usize;
        let mut id = [0u8; 12];
        id.copy_from_slice(
            bytes
                .get(id_at..id_at + 12)
                .ok_or_else(|| integrity("chunk id runs past the section".to_string()))?,
        );
        let record_at = records_at + index * CHUNK_RECORD_BYTES as usize;
        let meta_at = metas_at + index * CHUNK_META_BYTES as usize;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(
            bytes
                .get(meta_at..meta_at + 20)
                .ok_or_else(|| integrity("chunk meta runs past the section".to_string()))?,
        );
        chunks.push(ChunkEntry {
            block_range: (0, 0),
            flags: le_u32(bytes, meta_at + 20).unwrap_or(0),
            hash,
            id,
            serialized_length: 0,
            serialized_offset: 0,
            uncompressed_length: be_u40(bytes, record_at + 5).unwrap_or(0),
            uncompressed_offset: be_u40(bytes, record_at).unwrap_or(0),
        });
    }

    // Assign blocks to chunks: chunks in uncompressed-offset
    // order consume consecutive blocks whose uncompressed
    // sizes sum exactly to the chunk's declared length.
    let mut order: Vec<usize> = (0..chunks.len()).collect();
    order.sort_by_key(|&index| chunks[index].uncompressed_offset);
    let mut block_cursor = 0usize;
    let mut layout_aligned = header.compression_block_size > 0;
    let mut expected_offset: u64 = 0;
    for &index in &order {
        let chunk = &chunks[index];
        if layout_aligned && chunk.uncompressed_offset != expected_offset {
            layout_aligned = false;
        }
        let start = block_cursor;
        let mut sum: u64 = 0;
        while sum < chunk.uncompressed_length {
            let Some(block) = blocks.get(block_cursor) else {
                return Err(integrity(format!(
                    "chunk {index} declares {} uncompressed bytes but the block table is exhausted at {sum}",
                    chunk.uncompressed_length
                )));
            };
            sum = sum
                .checked_add(u64::from(block.uncompressed_size))
                .ok_or_else(|| integrity("chunk uncompressed size overflows".to_string()))?;
            block_cursor += 1;
            if sum > chunk.uncompressed_length {
                return Err(integrity(format!(
                    "chunk {index} declares {} uncompressed bytes but its blocks sum past it ({sum})",
                    chunk.uncompressed_length
                )));
            }
        }
        let (serialized_offset, serialized_length) = if block_cursor > start {
            let first = blocks[start].serialized_offset;
            let last = &blocks[block_cursor - 1];
            let end = last
                .serialized_offset
                .checked_add(u64::from(last.compressed_size))
                .ok_or_else(|| integrity("block serialized range overflows".to_string()))?;
            (first, end - first)
        } else {
            let end = blocks
                .last()
                .map(|block| block.serialized_offset + u64::from(block.compressed_size))
                .unwrap_or(0);
            (end, 0)
        };
        let chunk = &mut chunks[index];
        chunk.block_range = (start, block_cursor);
        chunk.serialized_length = serialized_length;
        chunk.serialized_offset = serialized_offset;
        if header.compression_block_size > 0 {
            let block_size = u64::from(header.compression_block_size);
            expected_offset = chunks[index]
                .uncompressed_offset
                .checked_add(chunks[index].uncompressed_length)
                .and_then(|end| end.checked_add(block_size - 1))
                .map(|end| end / block_size * block_size)
                .unwrap_or(u64::MAX);
        }
    }
    if block_cursor != blocks.len() {
        return Err(integrity(format!(
            "{} blocks are not claimed by any chunk",
            blocks.len() - block_cursor
        )));
    }

    let mount_point = if header.directory_index_size > 0 {
        let index_bytes = bytes
            .get(directory_index_at..directory_index_at + header.directory_index_size as usize)
            .ok_or_else(|| integrity("directory index runs past the section".to_string()))?;
        read_mount_point(index_bytes)
    } else {
        None
    };

    Ok(Toc {
        blocks,
        chunks,
        compression_methods,
        header,
        mount_point,
        trailing_bytes,
        uncompressed_layout_aligned: layout_aligned,
    })
}

/// The chunk-list document: the deterministic JSON export of
/// one parsed TOC (chunk directory in TOC order).
fn chunk_list_document(toc: &Toc, utoc_bytes: u64, ucas_bytes: Option<u64>) -> Value {
    let chunks: Vec<Value> = toc
        .chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            json!({
                "block_count": chunk.block_range.1 - chunk.block_range.0,
                "chunk_type": chunk.id[11],
                "flags": chunk.flags,
                "hash": hex_lower(&chunk.hash),
                "id": hex_lower(&chunk.id),
                "index": index,
                "serialized_length": chunk.serialized_length,
                "serialized_offset": chunk.serialized_offset,
                "uncompressed_length": chunk.uncompressed_length,
                "uncompressed_offset": chunk.uncompressed_offset,
            })
        })
        .collect();
    let total_uncompressed: u64 = toc
        .chunks
        .iter()
        .map(|chunk| chunk.uncompressed_length)
        .sum();
    json!({
        "block_count": toc.blocks.len(),
        "chunk_count": toc.chunks.len(),
        "chunks": chunks,
        "compression_block_size": toc.header.compression_block_size,
        "compression_methods": toc.compression_methods,
        "container_flags": toc.header.container_flags,
        "container_id": hex_lower(&toc.header.container_id),
        "directory_index_size": toc.header.directory_index_size,
        "format": "Unreal IoStore container (utoc/ucas)",
        "hash_lookup_entry_count": toc.header.hash_lookup_entry_count,
        "mount_point": toc.mount_point,
        "partition_count": toc.header.partition_count,
        "total_uncompressed_bytes": total_uncompressed,
        "trailing_bytes": toc.trailing_bytes,
        "ucas_bytes": ucas_bytes,
        "uncompressed_layout_aligned": toc.uncompressed_layout_aligned,
        "utoc_bytes": utoc_bytes,
        "version": toc.header.version,
    })
}

/// Per-chunk-type counts (type byte -> chunk count), in
/// ascending type order.
fn chunk_type_counts(toc: &Toc) -> Vec<(u8, u64)> {
    let mut counts: Vec<(u8, u64)> = Vec::new();
    for chunk in &toc.chunks {
        let type_byte = chunk.id[11];
        match counts.iter_mut().find(|(known, _)| *known == type_byte) {
            Some((_, count)) => *count += 1,
            None => counts.push((type_byte, 1)),
        }
    }
    counts.sort_by_key(|(type_byte, _)| *type_byte);
    counts
}

/// Whether the container declares encrypted payloads.
fn container_encrypted(header: &TocHeader) -> bool {
    header.container_flags & CONTAINER_FLAG_ENCRYPTED != 0
        || header.encryption_key_guid != [0u8; 16]
}

/// The outcome of decoding one block.
enum BlockOutcome {
    /// The decoded bytes (length already verified by the
    /// caller against the TOC).
    Decoded(Vec<u8>),
    /// Decoding cannot be attempted; the reason is named.
    Unavailable(String),
}

/// Decode one block's stored bytes per its TOC method.
/// Stored blocks copy through; `Zlib`/`Gzip`/`LZ4` decode
/// natively; `Oodle` goes through the configured external
/// decoder. A decode that fails is an integrity error; a
/// method this rung cannot run is `Unavailable`, never a
/// fabricated success.
fn decompress_block(
    toc: &Toc,
    block: &BlockEntry,
    stored: &[u8],
    ooz_decoder: Option<&Path>,
    scratch_dir: &Path,
) -> Result<BlockOutcome> {
    let expected = block.uncompressed_size as usize;
    if block.method_index == 0 {
        if stored.len() != expected {
            return Err(integrity(format!(
                "stored block carries {} bytes for {} declared uncompressed bytes",
                stored.len(),
                expected
            )));
        }
        return Ok(BlockOutcome::Decoded(stored.to_vec()));
    }
    let method = toc
        .compression_methods
        .get(usize::from(block.method_index) - 1)
        .map(String::as_str)
        .unwrap_or("");
    match method {
        "Gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(stored);
            decode_stream(&mut decoder, expected, method)
        }
        "LZ4" => {
            let decoded = lz4_flex::block::decompress(stored, expected)
                .map_err(|error| integrity(format!("LZ4 block does not decode: {error}")))?;
            Ok(BlockOutcome::Decoded(decoded))
        }
        "Oodle" => match ooz_decoder {
            Some(program) => decode_oodle_block(program, stored, expected, scratch_dir)
                .map(BlockOutcome::Decoded),
            None => Ok(BlockOutcome::Unavailable(
                "no Oodle decoder is configured (set ooz_decoder to the pinned ooz binary)"
                    .to_string(),
            )),
        },
        "Zlib" => {
            let mut decoder = flate2::read::ZlibDecoder::new(stored);
            decode_stream(&mut decoder, expected, method)
        }
        other => Ok(BlockOutcome::Unavailable(format!(
            "compression method {other:?} is not supported by this rung"
        ))),
    }
}

/// Read a decoder stream to its end, bounded at the
/// declared size plus one byte so an over-long stream is
/// an error, not a memory event.
fn decode_stream(decoder: &mut impl Read, expected: usize, method: &str) -> Result<BlockOutcome> {
    let mut decoded = Vec::with_capacity(expected);
    decoder
        .take((expected as u64).saturating_add(1))
        .read_to_end(&mut decoded)
        .map_err(|error| integrity(format!("{method} block does not decode: {error}")))?;
    Ok(BlockOutcome::Decoded(decoded))
}

/// Decode one Oodle block through the external `ooz`
/// decoder: the block is framed as
/// `[u32 LE uncompressed size][block bytes]` in a scratch
/// file (ooz's own container framing) and the decoder's
/// stdout is the payload, captured under the bounded
/// child-process discipline.
fn decode_oodle_block(
    program: &Path,
    stored: &[u8],
    expected: usize,
    scratch_dir: &Path,
) -> Result<Vec<u8>> {
    std::fs::create_dir_all(scratch_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot create Oodle scratch directory: {error}"),
        )
    })?;
    let frame_path = scratch_dir.join("oodle-block.frame");
    let mut frame = Vec::with_capacity(stored.len() + 4);
    frame.extend_from_slice(&(expected as u32).to_le_bytes());
    frame.extend_from_slice(stored);
    std::fs::write(&frame_path, &frame).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot write Oodle frame: {error}"),
        )
    })?;
    let outcome = process::run(&ProcessSpec {
        args: vec!["-c".to_string(), frame_path.display().to_string()],
        cwd: None,
        env: Vec::new(),
        output_cap: expected,
        program: program.display().to_string(),
        timeout: OODLE_DECODER_TIMEOUT,
    });
    let _ = std::fs::remove_file(&frame_path);
    let outcome = outcome?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            "Oodle decoder timed out on one block",
        ));
    }
    if outcome.exit_code != Some(0) || outcome.stdout.len() != expected {
        return Err(integrity(format!(
            "Oodle decoder returned exit {:?} with {} bytes for a block declaring {} uncompressed bytes",
            outcome.exit_code,
            outcome.stdout.len(),
            expected
        )));
    }
    Ok(outcome.stdout)
}

/// Write `bytes` to `destination` atomically (a sibling
/// temp file, then a rename).
fn write_atomic(destination: &Path, bytes: &[u8]) -> Result<()> {
    let temp = destination.with_extension("partial");
    std::fs::write(&temp, bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot write {}: {error}", temp.display()),
        )
    })?;
    std::fs::rename(&temp, destination).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot land {}: {error}", destination.display()),
        )
    })
}

/// Read a `.utoc` target's 144-byte header.
fn read_toc_head(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open utoc: {error}"),
        )
    })?;
    let mut head = vec![0u8; HEADER_BYTES as usize];
    let mut filled = 0usize;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => {
                return Err(FathomError::new(
                    ErrorCode::TargetUnavailable,
                    format!("cannot read utoc header: {error}"),
                ));
            }
        }
    }
    head.truncate(filled);
    Ok(head)
}

/// Read a `.utoc` target's bytes under the TOC size bound.
fn read_toc_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open utoc: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read utoc: {error}"),
        )
    })?;
    if bytes.len() as u64 > IOSTORE_TOC_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "utoc is {} bytes, past the {IOSTORE_TOC_BYTES_MAX}-byte TOC bound",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Validate a `.utoc` target argument and load its subject.
fn load_subject(
    config: &Config,
    args: &Value,
) -> Result<(PathBuf, fathom_core::evidence::Subject)> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    if path.extension().and_then(|ext| ext.to_str()) != Some("utoc") {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "IoStore tools expect a .utoc target",
        ));
    }
    let subject = subject_for_file_with_bound(&path, PAK_TARGET_BYTES_MAX)?;
    Ok((path, subject))
}

/// Census one Unreal IoStore container (.utoc): the header
/// facts for any TOC version, and — for version 8 — the
/// full chunk directory: chunk and block counts, the
/// compression method table, per-type chunk counts, the
/// directory index mount point, and the retained chunk
/// list export.
pub fn inspect_iostore_container(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let (path, subject) = load_subject(config, args)?;
    let sha256 = subject.sha256.clone();
    let utoc_bytes = subject.size_bytes;
    let mut evidence = Evidence::new("inspect_iostore_container", "unreal_iostore");
    evidence.subject = Some(subject);
    let head = read_toc_head(&path)?;
    let header = parse_toc_header(&head)?;
    let ucas_path = path.with_extension("ucas");
    let ucas_bytes = std::fs::metadata(&ucas_path).ok().map(|meta| meta.len());

    if header.version != TOC_VERSION_FULL_PARSE {
        let document = json!({
            "compression_block_size": header.compression_block_size,
            "directory_index_size": header.directory_index_size,
            "partition_count": header.partition_count,
            "version": header.version,
        });
        let (digest, retention_note) =
            match proof::retain_export(config, &sha256, "iostore_census", &document) {
                Ok(digest) => (Some(digest), None),
                Err(error) => (None, Some(error.message)),
            };
        evidence.add_finding(Finding::new(
            "iostore_container",
            Confidence::Observed,
            json!({
                "compression_block_size": header.compression_block_size,
                "directory_index_size": header.directory_index_size,
                "export_digest": digest,
                "format": "Unreal IoStore container (utoc/ucas)",
                "partition_count": header.partition_count,
                "target_sha256": sha256,
                "ucas_bytes": ucas_bytes,
                "utoc_bytes": utoc_bytes,
                "version": header.version,
            }),
        ));
        if let Some(note) = retention_note {
            evidence.add_unknown(
                "retention",
                format!(
                    "census retention failed ({note}); the census facts stand, but no proof can bind this run"
                ),
            );
        }
        evidence.add_unknown(
            "chunk entries",
            format!(
                "the chunk table is parsed for TOC version {TOC_VERSION_FULL_PARSE} only; this container is version {}",
                header.version
            ),
        );
        return Ok(evidence.to_value());
    }

    let bytes = read_toc_bytes(&path)?;
    let toc = parse_toc(&bytes)?;
    let document = chunk_list_document(&toc, utoc_bytes, ucas_bytes);
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "iostore_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let type_counts: serde_json::Map<String, Value> = chunk_type_counts(&toc)
        .into_iter()
        .map(|(type_byte, count)| (type_byte.to_string(), json!(count)))
        .collect();
    let last_block_end = toc
        .blocks
        .last()
        .map(|block| block.serialized_offset + u64::from(block.compressed_size));
    evidence.add_finding(Finding::new(
        "iostore_container",
        Confidence::Observed,
        json!({
            "block_count": toc.blocks.len(),
            "chunk_count": toc.chunks.len(),
            "chunk_type_counts": type_counts,
            "compression_block_size": header.compression_block_size,
            "compression_methods": toc.compression_methods,
            "container_compressed": header.container_flags & CONTAINER_FLAG_COMPRESSED != 0,
            "container_encrypted": container_encrypted(&header),
            "container_flags": header.container_flags,
            "container_id": hex_lower(&header.container_id),
            "directory_index_size": header.directory_index_size,
            "export_digest": digest,
            "format": "Unreal IoStore container (utoc/ucas)",
            "hash_lookup_entry_count": header.hash_lookup_entry_count,
            "mount_point": toc.mount_point,
            "partition_count": header.partition_count,
            "target_sha256": sha256,
            "total_uncompressed_bytes": document["total_uncompressed_bytes"],
            "ucas_bytes": ucas_bytes,
            "ucas_trailing_bytes": match (ucas_bytes, last_block_end) {
                (Some(total), Some(end)) => Some(total.saturating_sub(end)),
                _ => None,
            },
            "uncompressed_layout_aligned": toc.uncompressed_layout_aligned,
            "utoc_bytes": utoc_bytes,
            "utoc_trailing_bytes": toc.trailing_bytes,
            "version": header.version,
        }),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    if toc.trailing_bytes > 0 {
        evidence.add_unknown(
            "toc trailing bytes",
            format!(
                "{} bytes follow the chunk meta section; they are not modelled by this rung",
                toc.trailing_bytes
            ),
        );
    }
    evidence.add_unknown(
        "directory index",
        "directory index entries are hashed and are not interpreted; only the mount point is decoded",
    );
    evidence.add_unknown(
        "hash lookup table",
        "the hash-lookup table's contents are recorded by count, not interpreted",
    );
    Ok(evidence.to_value())
}

/// Extract chunk payloads from one Unreal IoStore
/// container (TOC version 8) into an output directory,
/// with a manifest. Every chunk is BLAKE3-verified
/// against its TOC meta hash before it is written;
/// chunks that cannot be decoded (no Oodle decoder
/// configured, an unsupported method, an encrypted
/// container) are recorded in the manifest, never
/// written and never faked. `chunk_ids` optionally
/// restricts the run to the named chunks (24-hex-digit
/// ids); the default is every chunk.
pub fn extract_iostore_chunks(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let (path, subject) = load_subject(config, args)?;
    let subject_sha256 = subject.sha256.clone();
    let output_dir =
        paths::validate_output_dir(config, Path::new(require_str(args, "output_dir")?))?;
    let bytes = read_toc_bytes(&path)?;
    let toc = parse_toc(&bytes)?;

    let wanted: Option<Vec<String>> = match args.get("chunk_ids") {
        Some(Value::Array(items)) => {
            let mut ids = Vec::with_capacity(items.len());
            for item in items {
                let Some(text) = item.as_str() else {
                    return Err(FathomError::new(
                        ErrorCode::InvalidRequest,
                        "chunk_ids entries must be strings",
                    ));
                };
                let normalized = text.to_lowercase();
                if normalized.len() != 24
                    || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(FathomError::new(
                        ErrorCode::InvalidRequest,
                        format!("chunk id {text:?} is not a 24-hex-digit chunk id"),
                    ));
                }
                if !toc
                    .chunks
                    .iter()
                    .any(|chunk| hex_lower(&chunk.id) == normalized)
                {
                    return Err(FathomError::new(
                        ErrorCode::InvalidRequest,
                        format!("chunk id {text:?} is not in this container"),
                    ));
                }
                ids.push(normalized);
            }
            Some(ids)
        }
        Some(_) => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                "chunk_ids must be an array of chunk id strings",
            ));
        }
        None => None,
    };

    let ucas_path = path.with_extension("ucas");
    let ucas_len = std::fs::metadata(&ucas_path)
        .map(|meta| meta.len())
        .map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot stat the paired .ucas: {error}"),
            )
        })?;
    let mut ucas = std::fs::File::open(&ucas_path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open the paired .ucas: {error}"),
        )
    })?;
    std::fs::create_dir_all(&output_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot create output directory: {error}"),
        )
    })?;
    let scratch_dir = config
        .state_dir
        .join(format!("iostore-oodle-scratch-{}", std::process::id()));
    let encrypted = container_encrypted(&toc.header);
    let ooz_decoder = config.ooz_decoder.as_deref();

    let mut rows: Vec<Value> = Vec::with_capacity(toc.chunks.len());
    let mut counts: std::collections::BTreeMap<&str, u64> = Default::default();
    let mut spent: u64 = 0;
    for (index, chunk) in toc.chunks.iter().enumerate() {
        let id_hex = hex_lower(&chunk.id);
        let mut row = json!({
            "block_count": chunk.block_range.1 - chunk.block_range.0,
            "chunk_type": chunk.id[11],
            "flags": chunk.flags,
            "hash": hex_lower(&chunk.hash),
            "id": id_hex,
            "index": index,
            "serialized_length": chunk.serialized_length,
            "serialized_offset": chunk.serialized_offset,
            "uncompressed_length": chunk.uncompressed_length,
            "uncompressed_offset": chunk.uncompressed_offset,
        });
        let finish = |rows: &mut Vec<Value>,
                      counts: &mut std::collections::BTreeMap<&str, u64>,
                      row: &mut Value,
                      status: &'static str| {
            row["status"] = json!(status);
            *counts.entry(status).or_insert(0) += 1;
            rows.push(row.clone());
        };
        if let Some(ids) = &wanted
            && !ids.contains(&id_hex)
        {
            finish(&mut rows, &mut counts, &mut row, "not_selected");
            continue;
        }
        if encrypted {
            finish(&mut rows, &mut counts, &mut row, "encrypted");
            continue;
        }
        if spent.saturating_add(chunk.uncompressed_length) > GAME_EXTRACT_BYTES_MAX {
            finish(&mut rows, &mut counts, &mut row, "skipped_budget");
            continue;
        }
        match extract_one_chunk(&toc, chunk, &mut ucas, ucas_len, ooz_decoder, &scratch_dir) {
            Ok(ChunkOutcome::Written(payload)) => {
                spent = spent.saturating_add(chunk.uncompressed_length);
                let destination = output_dir.join(format!("{id_hex}.chunk"));
                write_atomic(&destination, &payload)?;
                row["payload_sha256"] = json!(hex_lower(&sha2::Sha256::digest(&payload)));
                finish(&mut rows, &mut counts, &mut row, "written");
            }
            Ok(ChunkOutcome::Recorded(status, detail)) => {
                row["detail"] = json!(detail);
                finish(&mut rows, &mut counts, &mut row, status);
            }
            Err(error) => {
                row["detail"] = json!(error.message);
                finish(&mut rows, &mut counts, &mut row, "decode_failed");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch_dir);

    let totals: serde_json::Map<String, Value> = counts
        .iter()
        .map(|(status, count)| (status.to_string(), json!(count)))
        .collect();
    let manifest = json!({
        "chunks": rows,
        "compression_methods": toc.compression_methods,
        "format": "Unreal IoStore container (utoc/ucas)",
        "mount_point": toc.mount_point,
        "oodle_decoder": ooz_decoder.map(|program| program.display().to_string()),
        "target_sha256": subject_sha256,
        "totals": totals,
        "version": toc.header.version,
    });
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactIntegrityMismatch,
            format!("manifest serialisation failed: {error}"),
        )
    })?;
    write_atomic(&output_dir.join("manifest.json"), manifest_json.as_bytes())?;
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "iostore_extract", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut evidence = Evidence::new("extract_iostore_chunks", "unreal_iostore");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "iostore_extract",
        Confidence::Observed,
        json!({
            "chunk_count": toc.chunks.len(),
            "export_digest": digest,
            "oodle_decoder": ooz_decoder.map(|program| program.display().to_string()),
            "output_dir": output_dir.display().to_string(),
            "status_counts": counts,
            "target_sha256": subject_sha256,
        }),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "extraction retention failed ({note}); the manifest stands on disk, but no proof can bind this run"
            ),
        );
    }
    if encrypted {
        evidence.add_unknown(
            "encryption",
            "the container declares encrypted payloads; chunks were recorded, never decrypted",
        );
    }
    Ok(evidence.to_value())
}

/// The outcome of attempting one chunk's extraction.
enum ChunkOutcome {
    /// A named non-written outcome with its reason.
    Recorded(&'static str, String),
    /// The verified payload, ready to write.
    Written(Vec<u8>),
}

/// Decode and hash-verify one chunk. Structural problems
/// (a serialized range past the `.ucas` end, a payload
/// whose length or BLAKE3 hash contradicts the TOC) are
/// recorded outcomes; decoder failures are errors the
/// caller records as `decode_failed`.
fn extract_one_chunk(
    toc: &Toc,
    chunk: &ChunkEntry,
    ucas: &mut std::fs::File,
    ucas_len: u64,
    ooz_decoder: Option<&Path>,
    scratch_dir: &Path,
) -> Result<ChunkOutcome> {
    let mut payload: Vec<u8> = Vec::with_capacity(chunk.uncompressed_length as usize);
    for block_index in chunk.block_range.0..chunk.block_range.1 {
        let block = &toc.blocks[block_index];
        let end = block
            .serialized_offset
            .checked_add(u64::from(block.compressed_size))
            .ok_or_else(|| integrity("block serialized range overflows".to_string()))?;
        if end > ucas_len {
            return Ok(ChunkOutcome::Recorded(
                "serialized_range_invalid",
                format!(
                    "block {block_index} spans {}..{end}, past the .ucas size {ucas_len}",
                    block.serialized_offset
                ),
            ));
        }
        let mut stored = vec![0u8; block.compressed_size as usize];
        ucas.seek(SeekFrom::Start(block.serialized_offset))
            .and_then(|_| ucas.read_exact(&mut stored))
            .map_err(|error| {
                FathomError::new(
                    ErrorCode::TargetUnavailable,
                    format!("cannot read .ucas block {block_index}: {error}"),
                )
            })?;
        match decompress_block(toc, block, &stored, ooz_decoder, scratch_dir)? {
            BlockOutcome::Decoded(decoded) => payload.extend_from_slice(&decoded),
            BlockOutcome::Unavailable(reason) => {
                return Ok(ChunkOutcome::Recorded("decoder_unavailable", reason));
            }
        }
    }
    if payload.len() as u64 != chunk.uncompressed_length {
        return Ok(ChunkOutcome::Recorded(
            "length_mismatch",
            format!(
                "decoded payload is {} bytes; the TOC declares {}",
                payload.len(),
                chunk.uncompressed_length
            ),
        ));
    }
    if blake3::hash(&payload).as_bytes()[..20] != chunk.hash[..] {
        return Ok(ChunkOutcome::Recorded(
            "hash_mismatch",
            "the decoded payload's BLAKE3 hash does not match the TOC chunk meta".to_string(),
        ));
    }
    Ok(ChunkOutcome::Written(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A synthetic two-chunk container: chunk A stored
    /// (20 bytes), chunk B zlib-compressed (40 bytes), a
    /// one-entry method table, a mount-point directory
    /// index, and a one-word hash-lookup table.
    struct Fixture {
        payload_a: Vec<u8>,
        payload_b: Vec<u8>,
        ucas: Vec<u8>,
        utoc: Vec<u8>,
    }

    fn zlib_compress(payload: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn be40(value: u64) -> [u8; 5] {
        [
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]
    }

    fn block_entry(offset: u64, compressed: u32, uncompressed: u32, method: u8) -> [u8; 12] {
        let mut entry = [0u8; 12];
        entry[0..5].copy_from_slice(&offset.to_le_bytes()[0..5]);
        entry[5..8].copy_from_slice(&compressed.to_le_bytes()[0..3]);
        entry[8..11].copy_from_slice(&uncompressed.to_le_bytes()[0..3]);
        entry[11] = method;
        entry
    }

    fn build_fixture(method_name: &str, block_b: Vec<u8>, flags: u32) -> Fixture {
        let payload_a: Vec<u8> = (0u8..20).collect();
        let payload_b: Vec<u8> = (0u8..40).map(|value| value ^ 0x5A).collect();
        let mut ucas = payload_a.clone();
        ucas.extend_from_slice(&block_b);
        let mut utoc = vec![0u8; HEADER_BYTES as usize];
        utoc[0..16].copy_from_slice(UTOC_MAGIC);
        let word = |utoc: &mut Vec<u8>, at: usize, value: u32| {
            utoc[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        word(&mut utoc, 16, 8);
        word(&mut utoc, 20, HEADER_BYTES as u32);
        word(&mut utoc, 24, 2);
        word(&mut utoc, 28, 2);
        word(&mut utoc, 32, 12);
        word(&mut utoc, 36, 1);
        word(&mut utoc, 40, 32);
        word(&mut utoc, 44, 16);
        word(&mut utoc, 48, 14);
        word(&mut utoc, 52, 1);
        utoc[56..64].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        word(&mut utoc, 80, flags);
        word(&mut utoc, 84, 1);
        // Chunk ids (type bytes 1 and 2).
        let mut id_a = [0xA0u8; 12];
        id_a[11] = 1;
        let mut id_b = [0xB0u8; 12];
        id_b[11] = 2;
        utoc.extend_from_slice(&id_a);
        utoc.extend_from_slice(&id_b);
        // Chunk records: A at 0 (20 bytes), B at 32 (40 bytes).
        utoc.extend_from_slice(&be40(0));
        utoc.extend_from_slice(&be40(20));
        utoc.extend_from_slice(&be40(32));
        utoc.extend_from_slice(&be40(40));
        // Hash-lookup table: one sentinel word.
        utoc.extend_from_slice(&u32::MAX.to_le_bytes());
        // Block entries.
        utoc.extend_from_slice(&block_entry(0, 20, 20, 0));
        utoc.extend_from_slice(&block_entry(20, block_b.len() as u32, 40, 1));
        // Compression method name (32-byte field).
        let mut name = [0u8; 32];
        name[..method_name.len()].copy_from_slice(method_name.as_bytes());
        utoc.extend_from_slice(&name);
        // Directory index: FString "../../../".
        utoc.extend_from_slice(&10i32.to_le_bytes());
        utoc.extend_from_slice(b"../../../\0");
        // Chunk metas.
        utoc.extend_from_slice(&blake3::hash(&payload_a).as_bytes()[..20]);
        utoc.extend_from_slice(&0u32.to_le_bytes());
        utoc.extend_from_slice(&blake3::hash(&payload_b).as_bytes()[..20]);
        utoc.extend_from_slice(&1u32.to_le_bytes());
        Fixture {
            payload_a,
            payload_b,
            ucas,
            utoc,
        }
    }

    fn zlib_fixture() -> Fixture {
        let payload_b: Vec<u8> = (0u8..40).map(|value| value ^ 0x5A).collect();
        build_fixture("Zlib", zlib_compress(&payload_b), 9)
    }

    fn test_config(root: &Path, ooz_decoder: Option<PathBuf>) -> Config {
        std::fs::create_dir_all(root.join("state")).unwrap();
        Config {
            allow_programs: Vec::new(),
            allow_tools: Vec::new(),
            blender_program: None,
            ghidra_headless: None,
            http_bind: "127.0.0.1:8731".parse().unwrap(),
            ooz_decoder,
            signing_key_file: None,
            state_dir: root.join("state"),
            target_roots: vec![root.canonicalize().unwrap()],
            tool_profile: fathom_core::profile::ToolProfile::default(),
            video: fathom_core::config::VideoConfig::default(),
            web: fathom_core::config::WebConfig::default(),
        }
    }

    fn test_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("fathom-iostore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn seed_container(root: &Path, fixture: &Fixture) -> (PathBuf, PathBuf) {
        let utoc = root.join("game.utoc");
        let ucas = root.join("game.ucas");
        std::fs::write(&utoc, &fixture.utoc).unwrap();
        std::fs::write(&ucas, &fixture.ucas).unwrap();
        (utoc, root.join("out"))
    }

    fn manifest_rows(out: &Path) -> Vec<Value> {
        let text = std::fs::read_to_string(out.join("manifest.json")).unwrap();
        let manifest: Value = serde_json::from_str(&text).unwrap();
        manifest["chunks"].as_array().unwrap().clone()
    }

    #[test]
    fn validation_header_words_land_at_their_offsets() {
        let fixture = zlib_fixture();
        let header = parse_toc_header(&fixture.utoc).unwrap();
        assert_eq!(header.version, 8);
        assert_eq!(header.chunk_count, 2);
        assert_eq!(header.block_count, 2);
        assert_eq!(header.compression_block_size, 16);
        assert_eq!(header.directory_index_size, 14);
        assert_eq!(header.partition_count, 1);
        assert_eq!(header.container_flags, 9);
    }

    #[test]
    fn validation_parse_closes_on_synthetic_container() {
        let fixture = zlib_fixture();
        let toc = parse_toc(&fixture.utoc).unwrap();
        assert_eq!(toc.chunks.len(), 2);
        assert_eq!(toc.blocks.len(), 2);
        assert_eq!(toc.compression_methods, vec!["Zlib".to_string()]);
        assert_eq!(toc.mount_point.as_deref(), Some("../../../"));
        assert_eq!(toc.trailing_bytes, 0);
        assert!(toc.uncompressed_layout_aligned);
        let a = &toc.chunks[0];
        assert_eq!(a.uncompressed_offset, 0);
        assert_eq!(a.uncompressed_length, 20);
        assert_eq!(a.block_range, (0, 1));
        assert_eq!(a.serialized_offset, 0);
        assert_eq!(a.serialized_length, 20);
        assert_eq!(a.id[11], 1);
        let b = &toc.chunks[1];
        assert_eq!(b.uncompressed_offset, 32);
        assert_eq!(b.uncompressed_length, 40);
        assert_eq!(b.block_range, (1, 2));
        assert_eq!(b.serialized_offset, 20);
        assert_eq!(b.flags, 1);
    }

    #[test]
    fn validation_inspect_reports_chunk_census() {
        let fixture = zlib_fixture();
        let root = test_root("inspect");
        let (utoc, _out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({"target": utoc.display().to_string()});
        let value = inspect_iostore_container(&Registry::new(), &config, &args).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["chunk_count"], json!(2));
        assert_eq!(facts["block_count"], json!(2));
        assert_eq!(facts["version"], json!(8));
        assert_eq!(facts["mount_point"], json!("../../../"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validation_extract_writes_verified_chunks() {
        let fixture = zlib_fixture();
        let root = test_root("extract");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["status"] == json!("written")));
        let mut id_a = [0xA0u8; 12];
        id_a[11] = 1;
        let a = std::fs::read(out.join(format!("{}.chunk", hex_lower(&id_a)))).unwrap();
        assert_eq!(a, fixture.payload_a);
        let mut id_b = [0xB0u8; 12];
        id_b[11] = 2;
        let b = std::fs::read(out.join(format!("{}.chunk", hex_lower(&id_b)))).unwrap();
        assert_eq!(b, fixture.payload_b);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validation_extract_chunk_id_filter_selects_one() {
        let fixture = zlib_fixture();
        let root = test_root("filter");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let mut id_b = [0xB0u8; 12];
        id_b[11] = 2;
        let args = json!({
            "chunk_ids": [hex_lower(&id_b)],
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert_eq!(rows[0]["status"], json!("not_selected"));
        assert_eq!(rows[1]["status"], json!("written"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validation_stored_only_container_parses_and_extracts() {
        // Global-style: one stored chunk, no method names,
        // no directory index.
        let payload: Vec<u8> = (0u8..24).map(|value| value * 3).collect();
        let mut utoc = vec![0u8; HEADER_BYTES as usize];
        utoc[0..16].copy_from_slice(UTOC_MAGIC);
        let word = |utoc: &mut Vec<u8>, at: usize, value: u32| {
            utoc[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        word(&mut utoc, 16, 8);
        word(&mut utoc, 20, HEADER_BYTES as u32);
        word(&mut utoc, 24, 1);
        word(&mut utoc, 28, 1);
        word(&mut utoc, 32, 12);
        word(&mut utoc, 40, 32);
        word(&mut utoc, 44, 65_536);
        word(&mut utoc, 52, 1);
        word(&mut utoc, 84, 1);
        let mut id = [0x42u8; 12];
        id[11] = 8;
        utoc.extend_from_slice(&id);
        utoc.extend_from_slice(&be40(0));
        utoc.extend_from_slice(&be40(24));
        utoc.extend_from_slice(&u32::MAX.to_le_bytes());
        utoc.extend_from_slice(&block_entry(0, 24, 24, 0));
        utoc.extend_from_slice(&blake3::hash(&payload).as_bytes()[..20]);
        utoc.extend_from_slice(&0u32.to_le_bytes());
        let toc = parse_toc(&utoc).unwrap();
        assert_eq!(toc.chunks.len(), 1);
        assert!(toc.compression_methods.is_empty());
        assert_eq!(toc.mount_point, None);

        let root = test_root("stored");
        let utoc_path = root.join("global.utoc");
        std::fs::write(&utoc_path, &utoc).unwrap();
        std::fs::write(root.join("global.ucas"), &payload).unwrap();
        let out = root.join("out");
        let config = test_config(&root, None);
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": utoc_path.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert_eq!(rows[0]["status"], json!("written"));
        let written = std::fs::read(out.join(format!("{}.chunk", hex_lower(&id)))).unwrap();
        assert_eq!(written, payload);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adversarial_bad_magic_refused() {
        let mut fixture = zlib_fixture();
        fixture.utoc[0] = b'X';
        let error = parse_toc(&fixture.utoc).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
    }

    #[test]
    fn adversarial_wrong_version_refused_by_full_parse() {
        let mut fixture = zlib_fixture();
        fixture.utoc[16..20].copy_from_slice(&7u32.to_le_bytes());
        let error = parse_toc(&fixture.utoc).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        // The census still reports the header facts.
        let root = test_root("version");
        let (utoc, _out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({"target": utoc.display().to_string()});
        let value = inspect_iostore_container(&Registry::new(), &config, &args).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["version"], json!(7));
        assert_eq!(facts["chunk_count"], Value::Null);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adversarial_truncated_block_section_errors() {
        let fixture = zlib_fixture();
        let cut = fixture.utoc.len() - 100;
        let error = parse_toc(&fixture.utoc[..cut]).unwrap_err();
        assert!(matches!(
            error.code,
            ErrorCode::Truncated | ErrorCode::ArtifactIntegrityMismatch
        ));
    }

    #[test]
    fn adversarial_chunk_count_overflow_errors() {
        let mut fixture = zlib_fixture();
        fixture.utoc[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_toc(&fixture.utoc).is_err());
    }

    #[test]
    fn adversarial_block_sum_mismatch_errors() {
        let mut fixture = zlib_fixture();
        // Chunk B's record claims 41 bytes; its blocks sum to 40.
        let records_at = HEADER_BYTES as usize + 24;
        fixture.utoc[records_at + 19] = 41;
        let error = parse_toc(&fixture.utoc).unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
    }

    #[test]
    fn adversarial_corrupt_zlib_recorded_not_written() {
        let mut fixture = zlib_fixture();
        let last = fixture.ucas.len() - 1;
        fixture.ucas[last] ^= 0xFF;
        let root = test_root("corrupt");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert_eq!(rows[0]["status"], json!("written"));
        assert_ne!(rows[1]["status"], json!("written"));
        let mut id_b = [0xB0u8; 12];
        id_b[11] = 2;
        assert!(!out.join(format!("{}.chunk", hex_lower(&id_b))).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adversarial_oodle_chunk_without_decoder_is_unavailable() {
        let fixture = build_fixture("Oodle", vec![0x8C, 0x06, 1, 2, 3, 4], 9);
        let root = test_root("oodle-missing");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert_eq!(rows[0]["status"], json!("written"));
        assert_eq!(rows[1]["status"], json!("decoder_unavailable"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adversarial_unknown_chunk_id_refused() {
        let fixture = zlib_fixture();
        let root = test_root("unknown-id");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({
            "chunk_ids": ["ffffffffffffffffffffffff"],
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        let error = extract_iostore_chunks(&Registry::new(), &config, &args).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adversarial_encrypted_container_never_written() {
        let payload_b: Vec<u8> = (0u8..40).map(|value| value ^ 0x5A).collect();
        let fixture = build_fixture("Zlib", zlib_compress(&payload_b), 9 | 2);
        let root = test_root("encrypted");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert!(rows.iter().all(|row| row["status"] == json!("encrypted")));
        assert_eq!(
            std::fs::read_dir(&out)
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "chunk"))
                .count(),
            0
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adversarial_block_range_past_ucas_recorded() {
        let mut fixture = zlib_fixture();
        // Block B's serialized offset points past the .ucas end.
        let blocks_at = HEADER_BYTES as usize + 24 + 20 + 4;
        fixture.utoc[blocks_at + 12] = 0xFF;
        fixture.utoc[blocks_at + 13] = 0xFF;
        fixture.utoc[blocks_at + 14] = 0xFF;
        let root = test_root("past-ucas");
        let (utoc, out) = seed_container(&root, &fixture);
        let config = test_config(&root, None);
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": utoc.display().to_string(),
        });
        extract_iostore_chunks(&Registry::new(), &config, &args).unwrap();
        let rows = manifest_rows(&out);
        assert_eq!(rows[0]["status"], json!("written"));
        assert_eq!(rows[1]["status"], json!("serialized_range_invalid"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
