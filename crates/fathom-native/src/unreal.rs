//! Unreal Engine pak (version 11) reader (readers SPEC §4).
//!
//! Layout: the footer is the last 204 bytes (magic, version,
//! index offset/size/SHA-1, five compression-method name
//! slots). The index — mount point, file count, path-hash
//! seed, optional path-hash and full-directory indexes, and
//! the encoded-entries blob — is trusted only after its
//! SHA-1 matches the footer. Entry paths are
//! full-directory-index authoritative; each encoded entry
//! (two layouts, §4.3) is cross-checked against the per-entry
//! header in the data area, which is the authoritative source
//! for the encrypted flag. Stored bytes are SHA-1-verified
//! for every entry; zlib blocks are additionally decompressed
//! and size-checked.
//!
//! Honesty contract: this reader never decrypts. Encrypted
//! entries are reported with a storage-integrity fact only.
//! The path-hash index is hash-verified and recorded, never
//! decoded — paths come from the full directory index, which
//! is exactly the level the estate's oracle established.
//! Versions other than 11 refuse by name (readers SPEC §4.8).

use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{ARCHIVE_TARGET_BYTES_MAX, PAK_ENTRIES_MAX};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// The pak footer is the file's last 204 bytes.
const FOOTER_BYTES: u64 = 204;
/// Streaming chunk for stored-byte hashing.
const HASH_CHUNK_BYTES: usize = 65_536;
/// Footer magic `E1 12 6F 5A`.
const PAK_MAGIC: [u8; 4] = [0xe1, 0x12, 0x6f, 0x5a];
/// The one pak version this reader implements (readers
/// SPEC §4.8: other versions join scope only with a fixture).
const PAK_VERSION_SUPPORTED: u32 = 11;
/// Sanity bound on one data-area header's block count, so a
/// lying header cannot size an unbounded read.
const HEADER_BLOCKS_MAX: i32 = 1_000_000;

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
        .with_target("unreal pak archive")
}

fn truncated(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::Truncated, message.into()).with_target("unreal pak archive")
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into()).with_target("unreal pak archive")
}

/// Seek-based region reads over the target, opened once.
/// Every read is sized by a declared length checked against
/// the file before the read (readers SPEC §2.2).
struct RegionReader {
    file: File,
    len: u64,
}

impl RegionReader {
    fn read_range(&mut self, offset: u64, count: u64) -> Result<Vec<u8>, FathomError> {
        let end = offset
            .checked_add(count)
            .ok_or_else(|| truncated("pak region offset + size overflows".to_string()))?;
        if end > self.len {
            return Err(truncated(format!(
                "pak region [{offset}, {end}) overruns the file ({} bytes)",
                self.len
            )));
        }
        self.file.seek(SeekFrom::Start(offset)).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot seek pak target: {error}"),
            )
        })?;
        let mut buffer = vec![0_u8; usize::try_from(count).unwrap_or(usize::MAX)];
        self.file.read_exact(&mut buffer).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read pak target: {error}"),
            )
        })?;
        Ok(buffer)
    }

    fn sha1_range(&mut self, offset: u64, count: u64) -> Result<String, FathomError> {
        let end = offset
            .checked_add(count)
            .ok_or_else(|| truncated("pak hash range offset + size overflows".to_string()))?;
        if end > self.len {
            return Err(truncated(format!(
                "pak hash range [{offset}, {end}) overruns the file ({} bytes)",
                self.len
            )));
        }
        self.file.seek(SeekFrom::Start(offset)).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot seek pak target: {error}"),
            )
        })?;
        let mut hasher = Sha1::new();
        let mut remaining = count;
        let mut buffer = [0_u8; HASH_CHUNK_BYTES];
        while remaining > 0 {
            let want =
                usize::try_from(remaining.min(HASH_CHUNK_BYTES as u64)).unwrap_or(HASH_CHUNK_BYTES);
            let read = self.file.read(&mut buffer[..want]).map_err(|error| {
                FathomError::new(
                    ErrorCode::TargetUnavailable,
                    format!("cannot read pak target: {error}"),
                )
            })?;
            if read == 0 {
                return Err(truncated("pak hash range ends early".to_string()));
            }
            hasher.update(&buffer[..read]);
            remaining -= read as u64;
        }
        Ok(hex_bytes(&hasher.finalize()))
    }
}

/// Bounds-checked little-endian cursor over a hash-verified
/// region (index, FDI). Every failed read is an integrity
/// mismatch: the region's hash verified, so a structure that
/// does not parse is a lying region, not a short file.
struct RegionCursor<'a> {
    bytes: &'a [u8],
    position: usize,
    region: &'static str,
}

impl<'a> RegionCursor<'a> {
    fn new(bytes: &'a [u8], region: &'static str) -> Self {
        RegionCursor {
            bytes,
            position: 0,
            region,
        }
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                mismatch(format!(
                    "pak {} ends mid-structure at byte {}",
                    self.region, self.position
                ))
            })?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_i32(&mut self) -> Result<i32, FathomError> {
        Ok(i32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_i64(&mut self) -> Result<i64, FathomError> {
        Ok(i64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, FathomError> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64, FathomError> {
        Ok(u64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    /// An Unreal `FString`: i32 length; positive counts UTF-8
    /// bytes including a terminating NUL, negative counts
    /// UTF-16LE code units (× 2 bytes) including the NUL.
    fn read_fstring(&mut self) -> Result<String, FathomError> {
        let length = self.read_i32()?;
        if length == 0 {
            return Ok(String::new());
        }
        if length > 0 {
            let bytes = self.read_bytes(
                usize::try_from(length)
                    .map_err(|_| mismatch("pak FString length does not fit this platform"))?,
            )?;
            let text = std::str::from_utf8(bytes)
                .map_err(|_| mismatch("pak FString is not valid UTF-8"))?;
            return Ok(text.strip_suffix('\0').unwrap_or(text).to_string());
        }
        let units = usize::try_from(length.unsigned_abs())
            .map_err(|_| mismatch("pak FString length does not fit this platform"))?;
        let bytes = self.read_bytes(
            units
                .checked_mul(2)
                .ok_or_else(|| mismatch("pak FString length overflows"))?,
        )?;
        let code_units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text = String::from_utf16(&code_units)
            .map_err(|_| mismatch("pak FString is not valid UTF-16"))?;
        Ok(text.strip_suffix('\0').unwrap_or(&text).to_string())
    }
}

/// The parsed 204-byte footer.
struct Footer {
    index_offset: u64,
    index_sha1: [u8; 20],
    index_size: u64,
    /// The five compression-method name slots (indices 1–5);
    /// an empty string is an unnamed slot.
    method_slots: Vec<String>,
}

fn parse_footer(bytes: &[u8]) -> Result<Footer, FathomError> {
    if bytes.len() < FOOTER_BYTES as usize {
        return Err(unsupported("file too small to carry a pak footer"));
    }
    let footer = &bytes[bytes.len() - FOOTER_BYTES as usize..];
    if footer[..4] != PAK_MAGIC {
        return Err(unsupported(format!(
            "missing pak footer magic (expected {})",
            hex_bytes(&PAK_MAGIC)
        )));
    }
    let version = u32::from_le_bytes(footer[4..8].try_into().unwrap());
    if version != PAK_VERSION_SUPPORTED {
        return Err(unsupported(format!(
            "pak version {version} is not implemented (supported: {PAK_VERSION_SUPPORTED})"
        )));
    }
    let index_offset = i64::from_le_bytes(footer[8..16].try_into().unwrap());
    let index_size = i64::from_le_bytes(footer[16..24].try_into().unwrap());
    if index_offset < 0 || index_size < 0 {
        return Err(truncated(
            "pak footer declares a negative index offset/size",
        ));
    }
    let mut index_sha1 = [0_u8; 20];
    index_sha1.copy_from_slice(&footer[24..44]);
    let mut method_slots = Vec::with_capacity(5);
    for slot in 0..5 {
        let raw = &footer[44 + slot * 32..44 + (slot + 1) * 32];
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        method_slots.push(String::from_utf8_lossy(&raw[..end]).into_owned());
    }
    Ok(Footer {
        index_offset: index_offset as u64,
        index_sha1,
        index_size: index_size as u64,
        method_slots,
    })
}

/// One auxiliary index (path-hash or full-directory): its
/// declared position and the SHA-1 the index states for it.
struct AuxIndex {
    offset: u64,
    sha1: [u8; 20],
    size: u64,
}

/// The parsed index region.
struct Index {
    encoded_entries: Vec<u8>,
    fdi: Option<AuxIndex>,
    file_count: u32,
    legacy_file_count: i32,
    mount_point: String,
    path_hash_seed: u64,
    phi: Option<AuxIndex>,
}

fn read_aux(cursor: &mut RegionCursor) -> Result<Option<AuxIndex>, FathomError> {
    let present = cursor.read_u32()?;
    if present == 0 {
        return Ok(None);
    }
    let offset = cursor.read_i64()?;
    let size = cursor.read_i64()?;
    if offset < 0 || size < 0 {
        return Err(mismatch(
            "pak index declares a negative aux-index offset/size",
        ));
    }
    let mut sha1 = [0_u8; 20];
    sha1.copy_from_slice(cursor.read_bytes(20)?);
    Ok(Some(AuxIndex {
        offset: offset as u64,
        sha1,
        size: size as u64,
    }))
}

fn parse_index(bytes: &[u8]) -> Result<Index, FathomError> {
    let mut cursor = RegionCursor::new(bytes, "index");
    let mount_point = cursor.read_fstring()?;
    let file_count_raw = cursor.read_i32()?;
    if file_count_raw < 0 {
        return Err(mismatch("pak index declares a negative file count"));
    }
    let file_count = file_count_raw as u32;
    if file_count as usize > PAK_ENTRIES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("pak declares {file_count} entries, over PAK_ENTRIES_MAX ({PAK_ENTRIES_MAX})"),
        )
        .with_target("unreal pak archive"));
    }
    let path_hash_seed = cursor.read_u64()?;
    let phi = read_aux(&mut cursor)?;
    let fdi = read_aux(&mut cursor)?;
    let blob_len = cursor.read_i32()?;
    if blob_len < 0 {
        return Err(mismatch(
            "pak index declares a negative encoded-entries length",
        ));
    }
    let encoded_entries = cursor
        .read_bytes(
            usize::try_from(blob_len)
                .map_err(|_| mismatch("pak encoded-entries length does not fit this platform"))?,
        )?
        .to_vec();
    let legacy_file_count = cursor.read_i32()?;
    if cursor.position != bytes.len() {
        return Err(mismatch(format!(
            "pak index parse ends at byte {} of {} declared — the hash-verified region is structurally lying",
            cursor.position,
            bytes.len()
        )));
    }
    Ok(Index {
        encoded_entries,
        fdi,
        file_count,
        legacy_file_count,
        mount_point,
        path_hash_seed,
        phi,
    })
}

/// The full directory index, decoded: (path, blob offset)
/// pairs in FDI order, plus the directory count.
fn parse_fdi(bytes: &[u8], index: &Index) -> Result<(Vec<(String, u32)>, u32), FathomError> {
    let mut cursor = RegionCursor::new(bytes, "full directory index");
    let directory_count_raw = cursor.read_i32()?;
    if directory_count_raw < 0 || directory_count_raw as usize > PAK_ENTRIES_MAX {
        return Err(mismatch("pak FDI declares an implausible directory count"));
    }
    let directory_count = directory_count_raw as u32;
    let mut files: Vec<(String, u32)> = Vec::new();
    for _ in 0..directory_count {
        let directory = cursor.read_fstring()?;
        let count_raw = cursor.read_i32()?;
        if count_raw < 0 {
            return Err(mismatch("pak FDI declares a negative file count"));
        }
        for _ in 0..count_raw {
            let name = cursor.read_fstring()?;
            let offset = cursor.read_i32()?;
            if offset < 0 || offset as usize >= index.encoded_entries.len().max(1) {
                return Err(truncated(format!(
                    "pak FDI file offset {offset} overruns the encoded-entries blob ({} bytes)",
                    index.encoded_entries.len()
                )));
            }
            files.push((format!("{directory}{name}"), offset as u32));
        }
    }
    if files.len() as u32 != index.file_count {
        return Err(mismatch(format!(
            "pak FDI carries {} files but the index declares {}",
            files.len(),
            index.file_count
        )));
    }
    Ok((files, directory_count))
}

/// One decoded encoded entry, before the data-area
/// cross-check.
struct DecodedEntry {
    block_size: Option<u64>,
    block_sizes: Vec<u64>,
    blocks: u64,
    compressed_size: u64,
    /// Set when the decode itself is inconsistent (block
    /// sizes not summing to the compressed size).
    inconsistent: bool,
    layout: &'static str,
    method_index: u32,
    offset: u64,
    uncompressed_size: u64,
}

/// Bounds-checked cursor over one encoded-entry segment.
/// Overruns are `truncated`: the segment boundary came from
/// the FDI, and an entry that does not fit its segment is a
/// structural overrun.
struct SegmentCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SegmentCursor<'a> {
    fn read_u32(&mut self) -> Result<u32, FathomError> {
        let end = self
            .position
            .checked_add(4)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| truncated("encoded pak entry overruns its segment"))?;
        let value = u32::from_le_bytes(self.bytes[self.position..end].try_into().unwrap());
        self.position = end;
        Ok(value)
    }

    fn read_wide(&mut self, wide: bool) -> Result<u64, FathomError> {
        if wide {
            let end = self
                .position
                .checked_add(8)
                .filter(|end| *end <= self.bytes.len())
                .ok_or_else(|| truncated("encoded pak entry overruns its segment"))?;
            let value = u64::from_le_bytes(self.bytes[self.position..end].try_into().unwrap());
            self.position = end;
            Ok(value)
        } else {
            Ok(u64::from(self.read_u32()?))
        }
    }
}

fn decode_entry(segment: &[u8]) -> Result<DecodedEntry, FathomError> {
    let mut cursor = SegmentCursor {
        bytes: segment,
        position: 0,
    };
    let bitfield = cursor.read_u32()?;
    let method_index = (bitfield >> 23) & 0x3F;
    let low = bitfield & 0x7F_FFFF;
    let blocks = u64::from(low >> 6);
    let block_size_code = low & 0x3F;
    // Layout P — single-block escaped (readers SPEC §4.3):
    // entered only when all four conditions hold; segment
    // length is the disambiguator.
    if method_index != 0 && block_size_code == 63 && blocks == 1 && segment.len() == 20 {
        let uncompressed_size = u64::from(cursor.read_u32()?);
        let offset = u64::from(cursor.read_u32()?);
        let block_size = u64::from(cursor.read_u32()?);
        let compressed_size = u64::from(cursor.read_u32()?);
        return Ok(DecodedEntry {
            block_size: Some(block_size),
            block_sizes: vec![compressed_size],
            blocks,
            compressed_size,
            inconsistent: block_size != uncompressed_size,
            layout: "encoded_single_block",
            method_index,
            offset,
            uncompressed_size,
        });
    }
    // Layout N — standard.
    let offset = cursor.read_wide(bitfield & (1 << 31) == 0)?;
    let uncompressed_size = cursor.read_wide(bitfield & (1 << 30) == 0)?;
    let compressed_size = if method_index != 0 {
        cursor.read_wide(bitfield & (1 << 29) == 0)?
    } else {
        uncompressed_size
    };
    let (block_size, block_sizes, inconsistent) = if method_index == 0 {
        (None, Vec::new(), false)
    } else if blocks > 1 {
        let mut sizes = Vec::with_capacity(usize::try_from(blocks).unwrap_or(0));
        for _ in 0..blocks {
            sizes.push(u64::from(cursor.read_u32()?));
        }
        let sum: u64 = sizes.iter().sum();
        (
            Some(u64::from(block_size_code) << 11),
            sizes,
            sum != compressed_size,
        )
    } else {
        // blocks <= 1: no block sizes are stored in the
        // segment, so the recorded list is empty; the single
        // block's size is the compressed size (SPEC §4.3) and
        // is derived again at verification time.
        (Some(u64::from(block_size_code) << 11), Vec::new(), false)
    };
    Ok(DecodedEntry {
        block_size,
        block_sizes,
        blocks: if method_index == 0 { 0 } else { blocks },
        compressed_size,
        inconsistent,
        layout: "encoded_standard",
        method_index,
        offset,
        uncompressed_size,
    })
}

/// The data-area header's cross-check facts for one entry.
struct DataHeader {
    compressed_size: u64,
    encrypted: bool,
    header_size: u64,
    method_index: u32,
    offset: u64,
    sha1: String,
    uncompressed_size: u64,
}

fn parse_data_header(
    reader: &mut RegionReader,
    entry_offset: u64,
) -> Result<DataHeader, FathomError> {
    let head = reader.read_range(entry_offset, 48)?;
    let offset = i64::from_le_bytes(head[0..8].try_into().unwrap());
    let compressed_size = i64::from_le_bytes(head[8..16].try_into().unwrap());
    let uncompressed_size = i64::from_le_bytes(head[16..24].try_into().unwrap());
    let method_index = u32::from_le_bytes(head[24..28].try_into().unwrap());
    let sha1 = hex_bytes(&head[28..48]);
    if offset < 0 || compressed_size < 0 || uncompressed_size < 0 {
        return Err(mismatch("pak data-area header declares negative sizes"));
    }
    let (header_size, encrypted) = if method_index != 0 {
        let count_bytes = reader.read_range(entry_offset + 48, 4)?;
        let block_count = i32::from_le_bytes(count_bytes.try_into().unwrap());
        if !(0..=HEADER_BLOCKS_MAX).contains(&block_count) {
            return Err(mismatch(format!(
                "pak data-area header declares an implausible block count {block_count}"
            )));
        }
        let tail_at = entry_offset + 52 + 16 * u64::try_from(block_count).unwrap_or(0);
        let tail = reader.read_range(tail_at, 1)?;
        (tail_at - entry_offset + 1 + 4, tail[0] != 0)
    } else {
        let tail = reader.read_range(entry_offset + 48, 1)?;
        (53, tail[0] != 0)
    };
    Ok(DataHeader {
        compressed_size: compressed_size as u64,
        encrypted,
        header_size,
        method_index,
        offset: offset as u64,
        sha1,
        uncompressed_size: uncompressed_size as u64,
    })
}

/// Decompress one entry's zlib blocks and report whether the
/// total equals the declared uncompressed size. Stored bytes
/// are read per block; decompression output is bounded by
/// the declared size plus one byte.
fn verify_zlib_content(
    reader: &mut RegionReader,
    data_start: u64,
    block_sizes: &[u64],
    uncompressed_size: u64,
) -> Result<bool, FathomError> {
    use flate2::read::ZlibDecoder;
    let mut produced: u64 = 0;
    let mut at = data_start;
    for size in block_sizes {
        let stored = reader.read_range(at, *size)?;
        at += size;
        let decoder = ZlibDecoder::new(&stored[..]);
        let mut sink = Vec::new();
        let read = decoder
            .take(uncompressed_size - produced + 1)
            .read_to_end(&mut sink)
            .map_err(|_| mismatch("pak zlib block does not decompress"))?;
        produced += read as u64;
        if produced > uncompressed_size {
            return Ok(false);
        }
    }
    Ok(produced == uncompressed_size)
}

/// Lowercase hex for a byte string (SHA-1 digests, magics).
fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[allow(clippy::too_many_lines)]
pub fn inspect_unreal_pak(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let file = File::open(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target: {error}"),
        )
    })?;
    let mut reader = RegionReader {
        file,
        len: subject.size_bytes,
    };
    if reader.len < FOOTER_BYTES {
        return Err(unsupported("file too small to carry a pak footer"));
    }
    let footer_bytes = reader.read_range(reader.len - FOOTER_BYTES, FOOTER_BYTES)?;
    let footer = parse_footer(&footer_bytes)?;
    // The index is trusted only after its SHA-1 verifies.
    let index_bytes = reader.read_range(footer.index_offset, footer.index_size)?;
    if hex_bytes(&Sha1::digest(&index_bytes)) != hex_bytes(&footer.index_sha1) {
        return Err(mismatch(
            "pak index SHA-1 does not match the footer; nothing is claimed from the index",
        ));
    }
    let index = parse_index(&index_bytes)?;
    let mut phi_facts = (false, None, None, None, false);
    if let Some(phi) = &index.phi {
        let region = reader.read_range(phi.offset, phi.size)?;
        if hex_bytes(&Sha1::digest(&region)) != hex_bytes(&phi.sha1) {
            return Err(mismatch(
                "pak path-hash index SHA-1 does not match the index; nothing is claimed from it",
            ));
        }
        phi_facts = (
            true,
            Some(phi.offset),
            Some(phi.size),
            Some(hex_bytes(&phi.sha1)),
            true,
        );
    }
    let Some(fdi) = &index.fdi else {
        return Err(unsupported(
            "pak carries no full directory index; entry paths cannot be established",
        ));
    };
    let fdi_bytes = reader.read_range(fdi.offset, fdi.size)?;
    if hex_bytes(&Sha1::digest(&fdi_bytes)) != hex_bytes(&fdi.sha1) {
        return Err(mismatch(
            "pak full directory index SHA-1 does not match the index; paths are FDI-authoritative, so nothing is claimed",
        ));
    }
    let (files, directory_count) = parse_fdi(&fdi_bytes, &index)?;
    // Segment boundaries: the sorted distinct FDI offsets.
    let mut boundaries: Vec<u32> = files.iter().map(|(_, offset)| *offset).collect();
    boundaries.sort_unstable();
    boundaries.dedup();
    let mut rows: Vec<Value> = Vec::with_capacity(files.len());
    let mut examined: u64 = 0;
    let mut encrypted_count: u64 = 0;
    let mut header_mismatch_count: u64 = 0;
    let mut inconsistent_count: u64 = 0;
    let mut layout_p_count: u64 = 0;
    let mut layout_n_count: u64 = 0;
    let mut method_counts: std::collections::BTreeMap<String, u64> = Default::default();
    let mut sha1_mismatch_count: u64 = 0;
    let mut stored_total: u64 = 0;
    let mut uncompressed_total: u64 = 0;
    let mut unverifiable_methods: Vec<String> = Vec::new();
    for (path_entry, blob_offset) in &files {
        let start = *blob_offset as usize;
        let next = boundaries
            .iter()
            .copied()
            .find(|bound| *bound > *blob_offset)
            .map(|bound| bound as usize)
            .unwrap_or(index.encoded_entries.len());
        let segment = &index.encoded_entries[start..next];
        let decoded = decode_entry(segment)?;
        match decoded.layout {
            "encoded_single_block" => layout_p_count += 1,
            _ => layout_n_count += 1,
        }
        stored_total += decoded.compressed_size;
        uncompressed_total += decoded.uncompressed_size;
        let method_name: Option<String> = if decoded.method_index == 0 {
            Some("None".to_string())
        } else if (decoded.method_index as usize) <= footer.method_slots.len() {
            let name = &footer.method_slots[decoded.method_index as usize - 1];
            if name.is_empty() {
                None
            } else {
                Some(name.clone())
            }
        } else {
            None
        };
        if let Some(name) = &method_name {
            *method_counts.entry(name.clone()).or_insert(0) += 1;
        }
        let mut row = json!({
            "block_size": decoded.block_size,
            "block_sizes": decoded.block_sizes,
            "blocks": decoded.blocks,
            "compressed_size": decoded.compressed_size,
            "content_verified": Value::Null,
            "encrypted": false,
            "header_offset": Value::Null,
            "layout": decoded.layout,
            "method": method_name,
            "method_index": decoded.method_index,
            "offset": decoded.offset,
            "path": path_entry,
            "sha1": Value::Null,
            "sha1_verified": Value::Null,
            "status": "unread",
            "stored_sha1_verified": Value::Null,
            "uncompressed_size": decoded.uncompressed_size,
        });
        if decoded.inconsistent || (decoded.method_index != 0 && method_name.is_none()) {
            row["status"] = json!("index_inconsistent");
            inconsistent_count += 1;
            rows.push(row);
            continue;
        }
        let header = match parse_data_header(&mut reader, decoded.offset) {
            Ok(header) => header,
            Err(_) => {
                row["status"] = json!("header_mismatch");
                header_mismatch_count += 1;
                rows.push(row);
                continue;
            }
        };
        row["sha1"] = json!(header.sha1);
        row["encrypted"] = json!(header.encrypted);
        row["header_offset"] = json!(header.offset);
        // The header Offset field is recorded as a reported
        // fact, not cross-checked when zero: the shipping
        // writer zeroes it (writer-omitted), and the data
        // location derives from the index. A nonzero header
        // offset must agree (readers SPEC §4.4, as amended
        // by ruling D-176).
        if (header.offset != 0 && header.offset != decoded.offset)
            || header.compressed_size != decoded.compressed_size
            || header.uncompressed_size != decoded.uncompressed_size
            || header.method_index != decoded.method_index
        {
            row["status"] = json!("header_mismatch");
            header_mismatch_count += 1;
            rows.push(row);
            continue;
        }
        let data_start = decoded.offset + header.header_size;
        if header.encrypted {
            // Storage integrity only: the stored bytes are
            // hashed, never decrypted, never claimed as
            // content (readers SPEC §4.5).
            encrypted_count += 1;
            match reader.sha1_range(data_start, decoded.compressed_size) {
                Ok(digest) => {
                    row["stored_sha1_verified"] = json!(digest == header.sha1);
                    row["status"] = json!("encrypted");
                    examined += 1;
                }
                Err(_) => {
                    row["status"] = json!("unreadable");
                }
            }
            rows.push(row);
            continue;
        }
        match reader.sha1_range(data_start, decoded.compressed_size) {
            Ok(digest) => {
                let verified = digest == header.sha1;
                row["sha1_verified"] = json!(verified);
                if !verified {
                    row["status"] = json!("sha1_mismatch");
                    sha1_mismatch_count += 1;
                    rows.push(row);
                    continue;
                }
            }
            Err(_) => {
                row["status"] = json!("unreadable");
                rows.push(row);
                continue;
            }
        }
        examined += 1;
        row["status"] = json!("verified");
        match method_name.as_deref() {
            Some("None") => {
                row["content_verified"] = json!(true);
            }
            Some("Zlib") => {
                let effective: Vec<u64> = if decoded.block_sizes.is_empty() {
                    vec![decoded.compressed_size]
                } else {
                    decoded.block_sizes.clone()
                };
                let ok = verify_zlib_content(
                    &mut reader,
                    data_start,
                    &effective,
                    decoded.uncompressed_size,
                )?;
                row["content_verified"] = json!(ok);
            }
            Some(other) if !unverifiable_methods.contains(&other.to_string()) => {
                unverifiable_methods.push(other.to_string());
            }
            Some(_) => {}
            None => {}
        }
        rows.push(row);
    }
    let total = files.len() as u64;
    let method_table: Vec<Value> = footer
        .method_slots
        .iter()
        .filter(|name| !name.is_empty())
        .map(|name| json!(name))
        .collect();
    let record = json!({
        "declared_entries": index.file_count,
        "encoded_blob_bytes": index.encoded_entries.len(),
        "encoded_single_block_entries": layout_p_count,
        "encoded_standard_entries": layout_n_count,
        "encrypted_entries": encrypted_count,
        "fdi_directory_count": directory_count,
        "fdi_offset": fdi.offset,
        "fdi_present": true,
        "fdi_sha1": hex_bytes(&fdi.sha1),
        "fdi_sha1_verified": true,
        "fdi_size": fdi.size,
        "header_mismatch_entries": header_mismatch_count,
        "index_inconsistent_entries": inconsistent_count,
        "index_offset": footer.index_offset,
        "index_sha1": hex_bytes(&footer.index_sha1),
        "index_sha1_verified": true,
        "index_size": footer.index_size,
        "legacy_file_count": index.legacy_file_count,
        "method_counts": method_counts,
        "method_table": method_table,
        "mount_point": index.mount_point,
        "path_hash_seed": index.path_hash_seed,
        "phi_offset": phi_facts.1,
        "phi_present": phi_facts.0,
        "phi_sha1": phi_facts.3,
        "phi_sha1_verified": phi_facts.4,
        "phi_size": phi_facts.2,
        "sha1_mismatch_entries": sha1_mismatch_count,
        "stored_bytes_total": stored_total,
        "uncompressed_bytes_total": uncompressed_total,
        "version": PAK_VERSION_SUPPORTED,
    });
    let doc_rows: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut doc_row = row.clone();
            doc_row["key"] = row["path"].clone();
            doc_row
        })
        .collect();
    let document = json!({
        "unreal_pak": record.clone(),
        "unreal_pak_entries": doc_rows,
        "unreal_pak_entries_total": total,
        "unreal_pak_entries_truncated": false,
    });
    let mut evidence = Evidence::new("inspect_unreal_pak", "unreal");
    evidence.subject = Some(subject);
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "archive_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut facts = record;
    facts["export_digest"] = match &digest {
        Some(digest) => json!(digest),
        None => Value::Null,
    };
    evidence.add_finding(Finding::new("unreal_pak", Confidence::Observed, facts));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": total, "total": total}),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    if encrypted_count > 0 {
        evidence.add_unknown(
            "entry contents",
            format!(
                "{encrypted_count} of {total} entries are encrypted; only their stored-byte integrity was checked — pak decryption is NOT-IMPLEMENTED"
            ),
        );
    }
    if header_mismatch_count > 0 {
        evidence.add_unknown(
            "entry cross-check",
            format!(
                "{header_mismatch_count} entries' data-area headers disagree with the index decode; no content verification was performed for them"
            ),
        );
    }
    if inconsistent_count > 0 {
        evidence.add_unknown(
            "index consistency",
            format!(
                "{inconsistent_count} entries are index-inconsistent (block sizes not summing to the compressed size, an unnamed method slot, or a layout-P block size disagreeing with the uncompressed size)"
            ),
        );
    }
    if sha1_mismatch_count > 0 {
        evidence.add_unknown(
            "entry integrity",
            format!(
                "{sha1_mismatch_count} entries' stored bytes do not match the SHA-1 in their data-area headers"
            ),
        );
    }
    for method in &unverifiable_methods {
        evidence.add_unknown(
            "content verification",
            format!(
                "entries compressed with method '{method}' were stored-hash verified; decompression is not attempted for that method by this reader"
            ),
        );
    }
    evidence.coverage.examined = examined;
    evidence.coverage.total = total;
    evidence.coverage.exhaustive = examined == total && evidence.unknowns.is_empty();
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fstring(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((text.len() + 1) as i32).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
        out.push(0);
        out
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    struct Spec {
        dir: &'static str,
        name: &'static str,
        content: Vec<u8>,
        method: u32,
        layout_p: bool,
        encrypted: bool,
        /// For method != 0 standard layout: block byte
        /// lengths of the stored data (default: one block).
        blocks: Option<Vec<usize>>,
    }

    fn spec(dir: &'static str, name: &'static str, content: &[u8], method: u32) -> Spec {
        Spec {
            dir,
            name,
            content: content.to_vec(),
            method,
            layout_p: false,
            encrypted: false,
            blocks: None,
        }
    }

    struct Built {
        bytes: Vec<u8>,
        /// File offset of the index region.
        index_at: usize,
        /// File offset of each entry's data header, in spec
        /// order.
        header_at: Vec<usize>,
    }

    struct Options {
        file_count_override: Option<i32>,
        fdi_present: bool,
        phi_present: bool,
        trailing_index_byte: bool,
        version: u32,
    }

    impl Default for Options {
        fn default() -> Self {
            Options {
                file_count_override: None,
                fdi_present: true,
                phi_present: true,
                trailing_index_byte: false,
                version: 11,
            }
        }
    }

    fn build(specs: &[Spec], options: &Options) -> Built {
        // Data area first: headers + stored bytes.
        let mut out: Vec<u8> = Vec::new();
        let mut header_at = Vec::new();
        type BuiltEntry = (u64, u64, u64, u32, Vec<u8>, Vec<u8>);
        let mut entries: Vec<BuiltEntry> = Vec::new();
        for entry in specs {
            let stored = if entry.method == 1 && !entry.encrypted {
                match &entry.blocks {
                    Some(blocks) => {
                        let mut all = Vec::new();
                        let mut at = 0;
                        for size in blocks {
                            all.extend_from_slice(&zlib_compress(&entry.content[at..at + size]));
                            at += size;
                        }
                        all
                    }
                    None => zlib_compress(&entry.content),
                }
            } else {
                entry.content.clone()
            };
            let offset = out.len() as u64;
            header_at.push(out.len());
            out.extend_from_slice(&(offset as i64).to_le_bytes());
            out.extend_from_slice(&(stored.len() as i64).to_le_bytes());
            out.extend_from_slice(&(entry.content.len() as i64).to_le_bytes());
            out.extend_from_slice(&entry.method.to_le_bytes());
            out.extend_from_slice(&Sha1::digest(&stored));
            if entry.method != 0 {
                let block_count = entry.blocks.as_ref().map_or(1, |b| b.len()) as i32;
                out.extend_from_slice(&block_count.to_le_bytes());
                let mut at = 0_u64;
                for i in 0..block_count {
                    let block_stored = match &entry.blocks {
                        Some(blocks) => zlib_compress(
                            &entry.content[blocks[..i as usize].iter().sum::<usize>()
                                ..blocks[..=i as usize].iter().sum::<usize>()],
                        )
                        .len() as u64,
                        None => stored.len() as u64,
                    };
                    out.extend_from_slice(&at.to_le_bytes());
                    out.extend_from_slice(&(at + block_stored).to_le_bytes());
                    at += block_stored;
                }
            }
            out.push(u8::from(entry.encrypted));
            let header_block_size = if entry.layout_p {
                entry.content.len() as u32
            } else if entry.method == 0 {
                0
            } else {
                65_536
            };
            out.extend_from_slice(&header_block_size.to_le_bytes());
            out.extend_from_slice(&stored);
            entries.push((
                offset,
                stored.len() as u64,
                entry.content.len() as u64,
                entry.method,
                stored,
                entry.content.clone(),
            ));
        }
        // Encoded blob + FDI offsets.
        let mut blob: Vec<u8> = Vec::new();
        let mut blob_offsets = Vec::new();
        for (index, entry) in specs.iter().enumerate() {
            blob_offsets.push(blob.len() as i32);
            let (offset, comp, uncomp, method, _, _) = &entries[index];
            if entry.layout_p {
                let bitfield = (1_u32 << 23) | (1 << 6) | 63 | (1 << 31) | (1 << 30) | (1 << 29);
                blob.extend_from_slice(&bitfield.to_le_bytes());
                blob.extend_from_slice(&(*uncomp as u32).to_le_bytes());
                blob.extend_from_slice(&(*offset as u32).to_le_bytes());
                blob.extend_from_slice(&(*uncomp as u32).to_le_bytes());
                blob.extend_from_slice(&(*comp as u32).to_le_bytes());
            } else {
                let (blocks_field, code) = if *method == 0 {
                    (0_u32, 0_u32)
                } else {
                    match &entry.blocks {
                        Some(blocks) => (blocks.len() as u32, 32),
                        None => (1, 32),
                    }
                };
                let mut bitfield = (*method << 23) | (blocks_field << 6) | code;
                bitfield |= (1 << 31) | (1 << 30);
                if *method != 0 {
                    bitfield |= 1 << 29;
                }
                blob.extend_from_slice(&bitfield.to_le_bytes());
                blob.extend_from_slice(&(*offset as u32).to_le_bytes());
                blob.extend_from_slice(&(*uncomp as u32).to_le_bytes());
                if *method != 0 {
                    blob.extend_from_slice(&(*comp as u32).to_le_bytes());
                    if let Some(blocks) = &entry.blocks {
                        let mut at = 0_usize;
                        for size in blocks {
                            let block_stored = zlib_compress(&entry.content[at..at + size]).len();
                            blob.extend_from_slice(&(block_stored as u32).to_le_bytes());
                            at += size;
                        }
                    }
                }
            }
        }
        // PHI region (opaque bytes; hash-verified only).
        let phi_bytes: Vec<u8> = b"path-hash-stand-in".to_vec();
        let phi_at = out.len() as u64;
        out.extend_from_slice(&phi_bytes);
        // FDI region.
        let fdi_at = out.len() as u64;
        let mut fdi: Vec<u8> = Vec::new();
        let mut dirs: Vec<&str> = Vec::new();
        for entry in specs {
            if !dirs.contains(&entry.dir) {
                dirs.push(entry.dir);
            }
        }
        fdi.extend_from_slice(&(dirs.len() as i32).to_le_bytes());
        for dir in &dirs {
            fdi.extend_from_slice(&fstring(dir));
            let members: Vec<usize> = specs
                .iter()
                .enumerate()
                .filter(|(_, e)| e.dir == *dir)
                .map(|(i, _)| i)
                .collect();
            fdi.extend_from_slice(&(members.len() as i32).to_le_bytes());
            for i in members {
                fdi.extend_from_slice(&fstring(specs[i].name));
                fdi.extend_from_slice(&blob_offsets[i].to_le_bytes());
            }
        }
        let fdi_sha1 = Sha1::digest(&fdi);
        out.extend_from_slice(&fdi);
        // Index region.
        let index_at = out.len();
        let mut index: Vec<u8> = Vec::new();
        index.extend_from_slice(&fstring("../../../"));
        index.extend_from_slice(
            &options
                .file_count_override
                .unwrap_or(specs.len() as i32)
                .to_le_bytes(),
        );
        index.extend_from_slice(&0x8d05_6e12_u64.to_le_bytes());
        if options.phi_present {
            index.extend_from_slice(&1_u32.to_le_bytes());
            index.extend_from_slice(&(phi_at as i64).to_le_bytes());
            index.extend_from_slice(&(phi_bytes.len() as i64).to_le_bytes());
            index.extend_from_slice(&Sha1::digest(&phi_bytes));
        } else {
            index.extend_from_slice(&0_u32.to_le_bytes());
        }
        if options.fdi_present {
            index.extend_from_slice(&1_u32.to_le_bytes());
            index.extend_from_slice(&(fdi_at as i64).to_le_bytes());
            index.extend_from_slice(&(fdi.len() as i64).to_le_bytes());
            index.extend_from_slice(&fdi_sha1);
        } else {
            index.extend_from_slice(&0_u32.to_le_bytes());
        }
        index.extend_from_slice(&(blob.len() as i32).to_le_bytes());
        index.extend_from_slice(&blob);
        index.extend_from_slice(&0_i32.to_le_bytes());
        if options.trailing_index_byte {
            index.push(0);
        }
        let index_sha1 = Sha1::digest(&index);
        out.extend_from_slice(&index);
        // Footer.
        out.extend_from_slice(&PAK_MAGIC);
        out.extend_from_slice(&options.version.to_le_bytes());
        out.extend_from_slice(&(index_at as i64).to_le_bytes());
        out.extend_from_slice(&(index.len() as i64).to_le_bytes());
        out.extend_from_slice(&index_sha1);
        let mut slot = [0_u8; 32];
        slot[..4].copy_from_slice(b"Zlib");
        out.extend_from_slice(&slot);
        out.extend_from_slice(&[0_u8; 128]);
        Built {
            bytes: out,
            index_at,
            header_at,
        }
    }

    fn run_inspect(test_name: &str, bytes: &[u8]) -> (PathBuf, Value) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.pak");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": target.display().to_string()});
        let value = inspect_unreal_pak(&Registry::new(), &config, &args).unwrap();
        (root, value)
    }

    fn run_err(test_name: &str, bytes: &[u8]) -> (PathBuf, FathomError) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.pak");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": target.display().to_string()});
        let error = inspect_unreal_pak(&Registry::new(), &config, &args).unwrap_err();
        (root, error)
    }

    fn pak_facts(value: &Value) -> &Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "unreal_pak")
            .map(|finding| &finding["facts"])
            .unwrap()
    }

    fn entry_rows(value: &Value) -> &Vec<Value> {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "entries")
            .and_then(|finding| finding["facts"]["entries"].as_array())
            .unwrap()
    }

    #[test]
    fn validation_mixed_archive_verifies_everything() {
        let content_a: Vec<u8> = (0..5000_u32).map(|i| (i % 251) as u8).collect();
        let content_b: Vec<u8> = b"plain stored bytes for a method-none entry".to_vec();
        let specs = vec![
            spec("Game/Content/", "a.uasset", &content_a, 1),
            spec("Game/Content/", "b.txt", &content_b, 0),
        ];
        let built = build(&specs, &Options::default());
        let (root, value) = run_inspect("pak-mixed", &built.bytes);
        let facts = pak_facts(&value);
        assert_eq!(facts["declared_entries"], 2);
        assert_eq!(facts["version"], 11);
        assert_eq!(facts["index_sha1_verified"], true);
        assert_eq!(facts["fdi_sha1_verified"], true);
        assert_eq!(facts["phi_sha1_verified"], true);
        assert_eq!(facts["path_hash_seed"], 0x8d05_6e12_u64);
        assert_eq!(facts["mount_point"], "../../../");
        assert_eq!(facts["method_counts"]["Zlib"], 1);
        assert_eq!(facts["method_counts"]["None"], 1);
        let rows = entry_rows(&value);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["path"], "Game/Content/a.uasset");
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[0]["content_verified"], true);
        assert_eq!(rows[0]["sha1_verified"], true);
        assert_eq!(rows[0]["block_size"], 65_536);
        assert_eq!(rows[1]["status"], "verified");
        assert_eq!(rows[1]["block_size"], Value::Null);
        assert_eq!(rows[1]["blocks"], 0);
        assert_eq!(value["coverage"]["examined"], 2);
        assert_eq!(value["coverage"]["exhaustive"], true);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_layout_p_single_block_entry() {
        let content: Vec<u8> = (0..3000_u32).map(|i| (i % 17) as u8).collect();
        let mut entry = spec("Game/", "p.bin", &content, 1);
        entry.layout_p = true;
        let built = build(&[entry], &Options::default());
        let (root, value) = run_inspect("pak-layout-p", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["layout"], "encoded_single_block");
        assert_eq!(rows[0]["block_size"], 3000);
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[0]["content_verified"], true);
        assert_eq!(pak_facts(&value)["encoded_single_block_entries"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_multiblock_zlib_entry() {
        let content: Vec<u8> = (0..9000_u32).map(|i| (i % 31) as u8).collect();
        let mut entry = spec("Game/", "multi.bin", &content, 1);
        entry.blocks = Some(vec![4000, 5000]);
        let built = build(&[entry], &Options::default());
        let (root, value) = run_inspect("pak-multiblock", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["blocks"], 2);
        assert_eq!(rows[0]["block_sizes"].as_array().unwrap().len(), 2);
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[0]["content_verified"], true);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_encrypted_entry_is_reported_not_decrypted() {
        let stored = b"ciphertext-bytes-not-content".to_vec();
        let mut entry = spec("Game/", "secret.bin", &stored, 1);
        entry.encrypted = true;
        let built = build(&[entry], &Options::default());
        let (root, value) = run_inspect("pak-encrypted", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "encrypted");
        assert_eq!(rows[0]["encrypted"], true);
        assert_eq!(rows[0]["stored_sha1_verified"], true);
        assert_eq!(rows[0]["content_verified"], Value::Null);
        assert_eq!(pak_facts(&value)["encrypted_entries"], 1);
        fs::remove_dir_all(&root).ok();
    }

    // --------------------------------------------------------
    // Adversarial half: lying regions, disambiguation traps,
    // and refusal paths.
    // --------------------------------------------------------

    #[test]
    fn adversarial_version_10_is_refused_by_name() {
        let specs = vec![spec("Game/", "a.bin", b"x", 0)];
        let built = build(
            &specs,
            &Options {
                version: 10,
                ..Options::default()
            },
        );
        let (root, error) = run_err("pak-v10", &built.bytes);
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("version 10"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_index_sha1_mismatch_refuses_everything() {
        let specs = vec![spec("Game/", "a.bin", b"hello", 0)];
        let mut built = build(&specs, &Options::default());
        built.bytes[built.index_at + 2] ^= 0xFF;
        let (root, error) = run_err("pak-bad-index-sha", &built.bytes);
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_trailing_index_byte_is_a_structural_lie() {
        let specs = vec![spec("Game/", "a.bin", b"hello", 0)];
        let built = build(
            &specs,
            &Options {
                trailing_index_byte: true,
                ..Options::default()
            },
        );
        let (root, error) = run_err("pak-trailing", &built.bytes);
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_fdi_total_disagreeing_with_index_refuses() {
        let specs = vec![spec("Game/", "a.bin", b"hello", 0)];
        let built = build(
            &specs,
            &Options {
                file_count_override: Some(7),
                ..Options::default()
            },
        );
        let (root, error) = run_err("pak-fdi-disagree", &built.bytes);
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_declared_count_over_the_cap_refuses() {
        let specs = vec![spec("Game/", "a.bin", b"hello", 0)];
        let built = build(
            &specs,
            &Options {
                file_count_override: Some(100_001),
                ..Options::default()
            },
        );
        let (root, error) = run_err("pak-over-cap", &built.bytes);
        assert_eq!(error.code, ErrorCode::ResourceConstraint);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_header_disagreement_skips_content_verification() {
        let specs = vec![spec("Game/", "a.bin", b"header-lies-about-size", 0)];
        let mut built = build(&specs, &Options::default());
        // Rewrite the header's uncompressed-size field.
        let at = built.header_at[0] + 16;
        built.bytes[at..at + 8].copy_from_slice(&999_i64.to_le_bytes());
        let (root, value) = run_inspect("pak-header-lie", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "header_mismatch");
        assert_eq!(rows[0]["sha1_verified"], Value::Null);
        assert_eq!(pak_facts(&value)["header_mismatch_entries"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_zero_header_offset_is_writer_omitted() {
        // The shipping writer zeroes the data-area header's
        // Offset field; a zero header offset is writer-omitted,
        // not a disagreement (SPEC §4.4, as amended by D-176).
        let specs = vec![spec("Game/", "a.bin", b"writer-zeroes-the-offset", 0)];
        let mut built = build(&specs, &Options::default());
        let at = built.header_at[0];
        built.bytes[at..at + 8].copy_from_slice(&0_i64.to_le_bytes());
        let (root, value) = run_inspect("pak-header-offset-zero", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[0]["sha1_verified"], true);
        assert_eq!(rows[0]["header_offset"], 0);
        assert_eq!(pak_facts(&value)["header_mismatch_entries"], 0);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_nonzero_header_offset_disagreement_is_header_mismatch() {
        // A nonzero header offset is a real claim and must
        // agree with the index (SPEC §4.4, as amended by
        // D-176); only zero is writer-omitted.
        let specs = vec![spec("Game/", "a.bin", b"header-lies-about-offset", 0)];
        let mut built = build(&specs, &Options::default());
        let at = built.header_at[0];
        let written = i64::from_le_bytes(built.bytes[at..at + 8].try_into().unwrap());
        built.bytes[at..at + 8].copy_from_slice(&(written + 4096).to_le_bytes());
        let (root, value) = run_inspect("pak-header-offset-lie", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "header_mismatch");
        assert_eq!(rows[0]["sha1_verified"], Value::Null);
        assert_eq!(rows[0]["header_offset"], written + 4096);
        assert_eq!(pak_facts(&value)["header_mismatch_entries"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_block_sizes_not_summing_is_index_inconsistent() {
        let content: Vec<u8> = (0..8000_u32).map(|i| (i % 13) as u8).collect();
        let mut entry = spec("Game/", "sum.bin", &content, 1);
        entry.blocks = Some(vec![4000, 4000]);
        let mut built = build(&[entry], &Options::default());
        // Corrupt the first encoded block size in the blob:
        // find the segment by rebuilding knowledge — the
        // blob's only entry starts its block sizes after
        // 4 + 4 + 4 + 4 = 16 bytes; locate via the FDI is
        // overkill, so patch by searching the index region
        // for the stored block length. Simpler: rebuild with
        // a wrong second block size by patching the segment:
        // segment starts where the FDI points; instead we
        // patch the header-independent path — rewrite the
        // blob block-size u32 stored at a computed place:
        // index starts with mount FString (13 bytes) + count
        // (4) + seed (8) + phi (4+8+8+20) + fdi (4+8+8+20)
        // + blob length (4); segment = index_at + that sum;
        // block sizes at segment + 16.
        let index_fixed = 13 + 4 + 8 + 40 + 40 + 4;
        let segment_at = built.index_at + index_fixed;
        built.bytes[segment_at + 16..segment_at + 20].copy_from_slice(&1_u32.to_le_bytes());
        // The index SHA-1 must be recomputed for the footer,
        // else the call refuses earlier: patch the footer's
        // stored hash.
        let index_len = {
            let footer_at = built.bytes.len() - 204;
            u64::from_le_bytes(
                built.bytes[footer_at + 16..footer_at + 24]
                    .try_into()
                    .unwrap(),
            ) as usize
        };
        let digest = Sha1::digest(&built.bytes[built.index_at..built.index_at + index_len]);
        let footer_at = built.bytes.len() - 204;
        built.bytes[footer_at + 24..footer_at + 44].copy_from_slice(&digest);
        let (root, value) = run_inspect("pak-bad-sum", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "index_inconsistent");
        assert_eq!(pak_facts(&value)["index_inconsistent_entries"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_twenty_byte_segment_without_blocks_one_is_standard() {
        // A 20-byte segment whose bitfield has blocks != 1
        // must NOT take the layout-P branch even with code
        // 63 set (readers SPEC §4.10): length alone does not
        // trigger the escaped layout.
        let bitfield = 63_u32 | (1 << 31) | (1 << 30);
        let mut segment = [0_u8; 20];
        segment[0..4].copy_from_slice(&bitfield.to_le_bytes());
        segment[4..8].copy_from_slice(&7_u32.to_le_bytes());
        segment[8..12].copy_from_slice(&29_u32.to_le_bytes());
        let decoded = decode_entry(&segment).unwrap();
        assert_eq!(decoded.layout, "encoded_standard");
        assert_eq!(decoded.offset, 7);
        assert_eq!(decoded.uncompressed_size, 29);
    }

    #[test]
    fn adversarial_unnamed_method_slot_is_index_inconsistent() {
        let specs = vec![spec("Game/", "odd.bin", b"some bytes", 3)];
        let built = build(&specs, &Options::default());
        let (root, value) = run_inspect("pak-unnamed-slot", &built.bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "index_inconsistent");
        assert_eq!(rows[0]["method"], Value::Null);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_missing_fdi_refuses() {
        let specs = vec![spec("Game/", "a.bin", b"hello", 0)];
        let built = build(
            &specs,
            &Options {
                fdi_present: false,
                ..Options::default()
            },
        );
        let (root, error) = run_err("pak-no-fdi", &built.bytes);
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_tiny_file_is_unsupported() {
        let (root, error) = run_err("pak-tiny", &[0_u8; 100]);
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }
}
