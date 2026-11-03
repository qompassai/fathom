//! Unity UnityFS bundle + SerializedFile reader
//! (readers SPEC §7).
//!
//! UnityFS (bundle formats 6–8): a big-endian header, a
//! blocks-info region (node directory + block table, itself
//! possibly compressed), and concatenated data blocks.
//! SerializedFiles (versions 9–22) found inside bundles — or
//! supplied standalone — get a metadata census: types are
//! counted and identified, type trees are SKIPPED byte-exact
//! and never expanded, objects are counted exactly.
//!
//! Honesty contract: LZMA-compressed blocks info is reported
//! as LZMA and not decoded (no LZMA decoder is adopted —
//! readers SPEC §7.10); the 16-byte blocks-info data hash is
//! recorded as an unverified fact because no public
//! specification of its algorithm was found; a declared
//! bundle size disagreeing with the file is a stated fact,
//! not a refusal. NO estate Unity bundle exists: this
//! reader's acceptance is synthetic-fixture only, and the
//! first real bundle to enter the estate gets its census
//! re-run and filed (retroactive-fixture closure).

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, sha256_hex, subject_for_file_with_bound,
};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, TEXTURE_DIMENSION_MAX, UNITY_BLOCKS_INFO_BYTES_MAX,
    UNITY_EXTERNALS_MAX, UNITY_EXTRACT_BYTES_MAX, UNITY_EXTRACT_CARVES_MAX, UNITY_MB_FILES_MAX,
    UNITY_MB_OBJECTS_MAX, UNITY_MB_WALK_DEPTH_MAX, UNITY_NODES_MAX, UNITY_OBJECTS_MAX,
    UNITY_TYPES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// Bundle formats implemented (SPEC §7.8).
const BUNDLE_FORMAT_MAX: u32 = 8;
const BUNDLE_FORMAT_MIN: u32 = 6;
/// Unity class IDs whose payloads extraction writes
/// (game-extract lane): MonoBehaviour, TextAsset, Texture2D.
const CLASS_MONO_BEHAVIOUR: i64 = 114;
const CLASS_TEXT_ASSET: i64 = 49;
const CLASS_TEXTURE_2D: i64 = 28;
/// Header strings (signature, versions) live well inside
/// this prefix.
const HEADER_PREFIX_BYTES: u64 = 65_536;
/// SerializedFile versions implemented (SPEC §7.8).
const SF_VERSION_MAX: u32 = 22;
const SF_VERSION_MIN: u32 = 9;

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
        .with_target("unity bundle")
}

fn resource(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ResourceConstraint, message.into()).with_target("unity bundle")
}

fn truncated(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::Truncated, message.into()).with_target("unity bundle")
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into()).with_target("unity bundle")
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn compression_name(code: u32) -> String {
    match code {
        0 => "none".to_string(),
        1 => "lzma".to_string(),
        2 => "lz4".to_string(),
        3 => "lz4hc".to_string(),
        other => format!("unknown_{other}"),
    }
}

/// Seek-based bounded reads over the target file.
struct RegionReader {
    file: File,
    len: u64,
}

impl RegionReader {
    fn read_range(&mut self, offset: u64, count: u64) -> Result<Vec<u8>, FathomError> {
        let end = offset
            .checked_add(count)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| truncated("unity region overruns the file"))?;
        let _ = end;
        self.file.seek(SeekFrom::Start(offset)).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot seek unity target: {error}"),
            )
        })?;
        let mut buffer = vec![0_u8; usize::try_from(count).unwrap_or(usize::MAX)];
        self.file.read_exact(&mut buffer).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read unity target: {error}"),
            )
        })?;
        Ok(buffer)
    }
}

/// Big-endian cursor over the header prefix.
struct BeCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BeCursor<'a> {
    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| truncated("unity header ends mid-field"))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_cstring(&mut self) -> Result<String, FathomError> {
        let start = self.position;
        let mut at = start;
        while at < self.bytes.len() && self.bytes[at] != 0 {
            at += 1;
        }
        if at >= self.bytes.len() {
            return Err(truncated("unity header string is unterminated"));
        }
        let text = String::from_utf8_lossy(&self.bytes[start..at]).into_owned();
        self.position = at + 1;
        Ok(text)
    }

    fn read_i64(&mut self) -> Result<i64, FathomError> {
        Ok(i64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, FathomError> {
        Ok(u32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }
}

/// The parsed UnityFS header.
struct BundleHeader {
    blocks_info_at_end: bool,
    bundle_size: i64,
    compressed_blocks_info_size: u32,
    data_start: u64,
    flags: u32,
    format_version: u32,
    has_directory_info: bool,
    uncompressed_blocks_info_size: u32,
    unity_revision: String,
    unity_version: String,
}

fn parse_bundle_header(prefix: &[u8]) -> Result<BundleHeader, FathomError> {
    let mut cursor = BeCursor {
        bytes: prefix,
        position: 0,
    };
    let signature = cursor.read_cstring()?;
    if signature != "UnityFS" {
        return Err(unsupported(format!(
            "not a UnityFS bundle (signature '{signature}')"
        )));
    }
    let format_version = cursor.read_u32()?;
    if !(BUNDLE_FORMAT_MIN..=BUNDLE_FORMAT_MAX).contains(&format_version) {
        return Err(unsupported(format!(
            "UnityFS format {format_version} is not implemented (supported: {BUNDLE_FORMAT_MIN}..={BUNDLE_FORMAT_MAX})"
        )));
    }
    let unity_version = cursor.read_cstring()?;
    let unity_revision = cursor.read_cstring()?;
    let bundle_size = cursor.read_i64()?;
    let compressed_blocks_info_size = cursor.read_u32()?;
    let uncompressed_blocks_info_size = cursor.read_u32()?;
    let flags = cursor.read_u32()?;
    let mut data_start = cursor.position as u64;
    if format_version >= 7 {
        data_start = data_start.div_ceil(16) * 16;
    }
    Ok(BundleHeader {
        blocks_info_at_end: flags & 0x40 != 0,
        bundle_size,
        compressed_blocks_info_size,
        data_start,
        flags,
        format_version,
        has_directory_info: flags & 0x80 != 0,
        uncompressed_blocks_info_size,
        unity_revision,
        unity_version,
    })
}

/// One blocks-info block-table row.
struct Block {
    compressed_size: u32,
    compression: u32,
    uncompressed_size: u32,
}

/// One blocks-info node (file) row.
struct Node {
    flags: u32,
    offset: i64,
    path: String,
    size: i64,
}

/// The decoded blocks-info region.
struct BlocksInfo {
    blocks: Vec<Block>,
    data_hash: String,
    nodes: Vec<Node>,
}

fn parse_blocks_info(bytes: &[u8]) -> Result<BlocksInfo, FathomError> {
    let mut cursor = BeCursor { bytes, position: 0 };
    let data_hash = hex_bytes(cursor.read_bytes(16)?);
    let block_count = cursor.read_u32()?;
    let mut blocks = Vec::with_capacity(block_count.min(1_000_000) as usize);
    for _ in 0..block_count {
        let uncompressed_size = cursor.read_u32()?;
        let compressed_size = cursor.read_u32()?;
        let block_flags = u16::from_be_bytes(cursor.read_bytes(2)?.try_into().unwrap());
        blocks.push(Block {
            compressed_size,
            compression: u32::from(block_flags & 0x3F),
            uncompressed_size,
        });
    }
    let node_count = cursor.read_u32()?;
    if node_count as usize > UNITY_NODES_MAX {
        return Err(resource(format!(
            "unity bundle declares {node_count} nodes, over UNITY_NODES_MAX ({UNITY_NODES_MAX})"
        )));
    }
    let mut nodes = Vec::with_capacity(node_count as usize);
    for _ in 0..node_count {
        let offset = cursor.read_i64()?;
        let size = cursor.read_i64()?;
        let flags = cursor.read_u32()?;
        let path = cursor.read_cstring()?;
        nodes.push(Node {
            flags,
            offset,
            path,
            size,
        });
    }
    Ok(BlocksInfo {
        blocks,
        data_hash,
        nodes,
    })
}

/// Endianness-aware cursor over a SerializedFile's bytes.
struct SfCursor<'a> {
    bytes: &'a [u8],
    little: bool,
    position: usize,
}

impl<'a> SfCursor<'a> {
    /// Align the position to a 4-byte boundary (the
    /// alignment object rows use from version 14).
    fn align_stream(&mut self) {
        self.position = self.position.next_multiple_of(4);
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| truncated("serialized file ends mid-structure"))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_cstring(&mut self) -> Result<String, FathomError> {
        let start = self.position;
        let mut at = start;
        while at < self.bytes.len() && self.bytes[at] != 0 {
            at += 1;
        }
        if at >= self.bytes.len() {
            return Err(truncated("serialized file string is unterminated"));
        }
        let text = String::from_utf8_lossy(&self.bytes[start..at]).into_owned();
        self.position = at + 1;
        Ok(text)
    }

    fn read_i16(&mut self) -> Result<i16, FathomError> {
        let raw = self.read_bytes(2)?;
        Ok(if self.little {
            i16::from_le_bytes(raw.try_into().unwrap())
        } else {
            i16::from_be_bytes(raw.try_into().unwrap())
        })
    }

    fn read_i32(&mut self) -> Result<i32, FathomError> {
        let raw = self.read_bytes(4)?;
        Ok(if self.little {
            i32::from_le_bytes(raw.try_into().unwrap())
        } else {
            i32::from_be_bytes(raw.try_into().unwrap())
        })
    }

    fn read_i64(&mut self) -> Result<i64, FathomError> {
        let raw = self.read_bytes(8)?;
        Ok(if self.little {
            i64::from_le_bytes(raw.try_into().unwrap())
        } else {
            i64::from_be_bytes(raw.try_into().unwrap())
        })
    }

    fn read_u8(&mut self) -> Result<u8, FathomError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, FathomError> {
        let raw = self.read_bytes(2)?;
        Ok(if self.little {
            u16::from_le_bytes(raw.try_into().unwrap())
        } else {
            u16::from_be_bytes(raw.try_into().unwrap())
        })
    }

    fn read_u32(&mut self) -> Result<u32, FathomError> {
        let raw = self.read_bytes(4)?;
        Ok(if self.little {
            u32::from_le_bytes(raw.try_into().unwrap())
        } else {
            u32::from_be_bytes(raw.try_into().unwrap())
        })
    }

    fn read_u64(&mut self) -> Result<u64, FathomError> {
        let raw = self.read_bytes(8)?;
        Ok(if self.little {
            u64::from_le_bytes(raw.try_into().unwrap())
        } else {
            u64::from_be_bytes(raw.try_into().unwrap())
        })
    }
}

/// One object's payload location inside its SerializedFile
/// (game-extract lane): the byte ranges the census counts
/// but does not surface, retained so extraction can slice
/// payloads without re-walking the metadata.
struct SfPayload {
    byte_size: u32,
    byte_start: u64,
    class_id: i64,
    path_id: i64,
    script_type_index: i16,
    type_index: i32,
}

/// The SerializedFile metadata census (SPEC §7.5).
struct SfSummary {
    data_offset: u64,
    endianness: &'static str,
    little: bool,
    object_count: u32,
    objects: Vec<Value>,
    objects_by_class: Value,
    objects_truncated: bool,
    payloads: Vec<SfPayload>,
    type_count: u32,
    types: Vec<Value>,
    unity_version: Option<String>,
    version: u32,
}

fn sf_summary_json(summary: &SfSummary) -> Value {
    json!({
        "endianness": summary.endianness,
        "object_count": summary.object_count,
        "objects": summary.objects,
        "objects_by_class": summary.objects_by_class,
        "objects_truncated": summary.objects_truncated,
        "type_count": summary.type_count,
        "types": summary.types,
        "unity_version": summary.unity_version,
        "version": summary.version,
    })
}

/// Skip one type tree (SPEC §7.5): node headers then the
/// string blob. Tree bytes are never expanded into types.
fn skip_type_tree(cursor: &mut SfCursor, version: u32) -> Result<(), FathomError> {
    if version >= 12 || version == 10 {
        // Blob layout (verified against the UnityPy
        // reader): node count, string-buffer size,
        // fixed-size nodes (28 bytes, 36 with the ref-type
        // hash from version 18), then the string buffer.
        let node_count = cursor.read_u32()?;
        let buffer_size = cursor.read_u32()?;
        let node_bytes = if version >= 18 { 36 } else { 28 };
        let nodes_bytes = (node_count as usize)
            .checked_mul(node_bytes)
            .ok_or_else(|| resource("type tree node table overflows"))?;
        cursor.read_bytes(nodes_bytes)?;
        cursor.read_bytes(buffer_size as usize)?;
        return Ok(());
    }
    // Pre-blob layout as modelled by the original reader;
    // no real pre-blob file has been verified against it.
    let node_count = cursor.read_u32()?;
    for _ in 0..node_count {
        cursor.read_bytes(2)?; // node version
        cursor.read_bytes(1)?; // level
        cursor.read_bytes(1)?; // is_array
        cursor.read_bytes(2)?; // type string offset
        cursor.read_bytes(2)?; // name string offset
        cursor.read_bytes(8)?; // byte size
        cursor.read_bytes(4)?; // index
        cursor.read_bytes(4)?; // flags
        if version >= 18 {
            cursor.read_bytes(8)?; // ref-type hash
        }
    }
    let blob_size = cursor.read_u32()?;
    cursor.read_bytes(blob_size as usize)?;
    Ok(())
}

/// Parse a SerializedFile's metadata census from its full
/// uncompressed bytes, retaining object rows up to the
/// shared record cap.
fn parse_serialized_file(bytes: &[u8]) -> Result<SfSummary, FathomError> {
    parse_serialized_file_capped(bytes, UNITY_OBJECTS_MAX)
}

/// As `parse_serialized_file`, with the retained payload
/// rows bounded by `payload_cap` instead of the shared
/// record cap. The JSON object rows keep the shared cap
/// either way (they are record bulk, not census data), and
/// `objects_truncated` reports the payload bound, which is
/// the one a census reads.
fn parse_serialized_file_capped(
    bytes: &[u8],
    payload_cap: usize,
) -> Result<SfSummary, FathomError> {
    if bytes.len() < 16 {
        return Err(truncated("serialized file is shorter than its header"));
    }
    let be_u32 = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    // The header layout is fixed (verified 2026-11-02
    // against real version-22 files and the UnityPy
    // reader, discharging the retroactive-fixture debt):
    // four big-endian u32s (metadata size, file size,
    // version at offset 8, data offset), the endianness
    // byte at 16 with three reserved bytes, and — version
    // 22 only — an extended tail (u32 metadata size at 20,
    // i64 file size at 24, i64 data offset at 32, i64
    // unknown at 40) before the metadata at offset 48.
    // Before 22 the legacy u32 fields are authoritative;
    // at 22 the extended fields replace them and the
    // legacy size/offset fields read as zero.
    let version = be_u32(8);
    if !(SF_VERSION_MIN..=SF_VERSION_MAX).contains(&version) {
        return Err(unsupported(format!(
            "serialized file version {version} is not implemented (supported: {SF_VERSION_MIN}..={SF_VERSION_MAX})"
        )));
    }
    let (data_offset, metadata_start) = if version >= 22 {
        if bytes.len() < 48 {
            return Err(truncated(
                "serialized file is shorter than its version-22 header",
            ));
        }
        let data_offset = i64::from_be_bytes(bytes[32..40].try_into().unwrap());
        if data_offset < 0 {
            return Err(mismatch("version-22 data offset is negative"));
        }
        (data_offset as u64, 48usize)
    } else {
        (u64::from(be_u32(12)), 20usize)
    };
    let endian_byte = bytes
        .get(16)
        .copied()
        .ok_or_else(|| truncated("serialized file ends before the endianness byte"))?;
    let little = endian_byte == 0;
    let mut cursor = SfCursor {
        bytes,
        little,
        position: metadata_start,
    };
    let unity_version = if version >= 7 {
        Some(cursor.read_cstring()?)
    } else {
        None
    };
    if version >= 8 {
        cursor.read_u32()?; // script compatibility (skipped)
    }
    let enable_type_tree = if version >= 10 {
        cursor.read_u8()? != 0
    } else {
        true
    };
    let type_count = cursor.read_u32()?;
    if type_count as usize > UNITY_TYPES_MAX {
        return Err(resource(format!(
            "serialized file declares {type_count} types, over UNITY_TYPES_MAX ({UNITY_TYPES_MAX})"
        )));
    }
    let mut types = Vec::with_capacity(type_count as usize);
    for _ in 0..type_count {
        let class_id = cursor.read_i32()?;
        let (_is_stripped, script_type_index) = if version >= 16 {
            (cursor.read_u8()? != 0, cursor.read_i16()?)
        } else {
            (false, -1)
        };
        let type_hash = if version >= 13 {
            if (version >= 16 && class_id == 114) || (version < 16 && class_id < 0) {
                cursor.read_bytes(16)?; // script id
            }
            // The old type hash follows for every type.
            Some(hex_bytes(cursor.read_bytes(16)?))
        } else {
            None
        };
        if enable_type_tree {
            skip_type_tree(&mut cursor, version)?;
            if version >= 21 {
                // Type dependencies (plain types; the
                // reader does not walk ref types).
                let dependency_count = cursor.read_i32()?;
                if dependency_count < 0 {
                    return Err(mismatch(
                        "serialized type declares a negative dependency count",
                    ));
                }
                let dependency_bytes = (dependency_count as usize)
                    .checked_mul(4)
                    .ok_or_else(|| resource("serialized type dependency list overflows"))?;
                cursor.read_bytes(dependency_bytes)?;
            }
        }
        types.push(json!({
            "class_id": class_id,
            "script_type_index": script_type_index,
            "type_hash": type_hash,
        }));
    }
    let object_count = cursor.read_u32()?;
    let mut objects = Vec::new();
    let mut payloads = Vec::new();
    let mut objects_by_class_map: std::collections::BTreeMap<String, u64> = Default::default();
    let mut objects_truncated = false;
    for index in 0..object_count {
        if version >= 14 {
            cursor.align_stream();
        }
        let path_id = if version >= 14 {
            cursor.read_i64()?
        } else {
            i64::from(cursor.read_i32()?)
        };
        let byte_start = if version >= 22 {
            cursor.read_u64()?
        } else {
            u64::from(cursor.read_u32()?)
        };
        let byte_size = cursor.read_u32()?;
        let type_index = cursor.read_i32()?;
        // Before version 16 the row carries its class id;
        // from 16 on, the class comes from the type row
        // and the row holds no class bytes.
        let class_id = if version < 16 {
            Some(cursor.read_u16()?)
        } else {
            None
        };
        if version < 11 {
            cursor.read_u16()?; // is_destroyed (skipped)
        }
        // The row's script type index exists only in
        // versions 11..17; later versions carry it solely
        // in the type row.
        let row_script_type_index = if (11..17).contains(&version) {
            Some(cursor.read_i16()?)
        } else {
            None
        };
        if version == 15 || version == 16 {
            cursor.read_u8()?; // is_stripped (skipped)
        }
        let type_row = types.get(usize::try_from(type_index).unwrap_or(usize::MAX));
        let census_class = match class_id {
            Some(id) => i64::from(id),
            None => type_row
                .and_then(|row| row["class_id"].as_i64())
                .unwrap_or(-1),
        };
        *objects_by_class_map
            .entry(census_class.to_string())
            .or_insert(0) += 1;
        let script_type_index = row_script_type_index
            .or_else(|| {
                type_row
                    .and_then(|row| row["script_type_index"].as_i64())
                    .and_then(|value| i16::try_from(value).ok())
            })
            .unwrap_or(-1);
        if (index as usize) < payload_cap {
            payloads.push(SfPayload {
                byte_size,
                byte_start,
                class_id: census_class,
                path_id,
                script_type_index,
                type_index,
            });
        } else {
            objects_truncated = true;
        }
        if (index as usize) < UNITY_OBJECTS_MAX {
            objects.push(json!({
                "byte_size": byte_size,
                "byte_start": byte_start,
                "class_id": class_id,
                "path_id": path_id,
                "type_index": type_index,
            }));
        }
    }
    let objects_by_class = json!(objects_by_class_map);
    Ok(SfSummary {
        data_offset,
        endianness: if little { "little" } else { "big" },
        little,
        object_count,
        objects,
        objects_by_class,
        objects_truncated,
        payloads,
        type_count,
        types,
        unity_version,
        version,
    })
}

/// The retained-document records for one serialized file
/// (readers SPEC §2.5): the `unity_serialized` summary
/// record keyed by node path (or "standalone"), and the
/// `unity_serialized_objects` rows keyed by decimal path_id.
fn serialized_doc_records(summary: &SfSummary, node_key: &str) -> (Value, Vec<Value>) {
    let record = json!({
        "endianness": summary.endianness,
        "key": node_key,
        "object_count": summary.object_count,
        "objects_by_class": summary.objects_by_class,
        "type_count": summary.type_count,
        "types": summary.types,
        "unity_version": summary.unity_version,
        "version": summary.version,
    });
    let rows = summary
        .objects
        .iter()
        .map(|object| {
            let mut row = object.clone();
            row["key"] = json!(object["path_id"].to_string());
            row["node"] = json!(node_key);
            row
        })
        .collect();
    (record, rows)
}

/// Decompress the blocks a node spans and return the node's
/// uncompressed bytes. Returns Err(message) when a spanned
/// block uses a compression this reader does not decode.
fn node_bytes(
    reader: &mut RegionReader,
    blocks_file_start: u64,
    info: &BlocksInfo,
    node: &Node,
) -> Result<Vec<u8>, String> {
    if node.offset < 0 || node.size < 0 {
        return Err("node declares negative offset/size".to_string());
    }
    let want_start = node.offset as u64;
    let want_end = want_start + node.size as u64;
    let mut out = Vec::with_capacity(node.size as usize);
    let mut uncompressed_at: u64 = 0;
    let mut file_at = blocks_file_start;
    for block in &info.blocks {
        let block_start = uncompressed_at;
        let block_end = block_start + u64::from(block.uncompressed_size);
        let overlaps = block_end > want_start && block_start < want_end;
        if overlaps {
            let stored = reader
                .read_range(file_at, u64::from(block.compressed_size))
                .map_err(|error| error.message.clone())?;
            let plain = match block.compression {
                0 => stored,
                1 => {
                    return Err("node spans an LZMA-compressed block (not decoded)".to_string());
                }
                2 | 3 => lz4_flex::block::decompress(&stored, block.uncompressed_size as usize)
                    .map_err(|error| format!("lz4 block does not decompress: {error}"))?,
                other => {
                    return Err(format!(
                        "node spans a block with compression code {other} (not decoded)"
                    ));
                }
            };
            let slice_start = want_start.saturating_sub(block_start) as usize;
            let slice_end = (want_end.min(block_end) - block_start) as usize;
            out.extend_from_slice(&plain[slice_start..slice_end]);
        }
        uncompressed_at = block_end;
        file_at += u64::from(block.compressed_size);
    }
    if out.len() as u64 != node.size as u64 {
        return Err("node extends past the last data block".to_string());
    }
    Ok(out)
}

#[allow(clippy::too_many_lines)]
pub fn inspect_unity_bundle(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let file = File::open(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target: {error}"),
        )
    })?;
    let mut reader = RegionReader {
        file,
        len: file_len,
    };
    let prefix = reader.read_range(0, file_len.min(HEADER_PREFIX_BYTES))?;
    // Standalone SerializedFile targets: the header probe is
    // the whole detection — stated in the container record.
    if !prefix.starts_with(b"UnityFS\0") {
        let bytes = reader.read_range(0, file_len)?;
        let summary = parse_serialized_file(&bytes)?;
        let record = json!({
            "container": "serialized_file",
            "detection": "heuristic — header probe (no UnityFS signature)",
            "serialized_file": sf_summary_json(&summary),
        });
        let (serialized_record, object_rows) = serialized_doc_records(&summary, "standalone");
        let object_total = summary.object_count;
        let objects_truncated = summary.objects_truncated;
        let document = json!({
            "unity_bundle": record.clone(),
            "unity_bundle_entries": [],
            "unity_bundle_entries_total": 0,
            "unity_bundle_entries_truncated": false,
            "unity_serialized": [serialized_record],
            "unity_serialized_objects": object_rows,
            "unity_serialized_objects_total": object_total,
            "unity_serialized_objects_truncated": objects_truncated,
            "unity_serialized_total": 1,
            "unity_serialized_truncated": false,
        });
        let mut evidence = Evidence::new("inspect_unity_bundle", "unity");
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
        evidence.add_finding(Finding::new("unity_bundle", Confidence::Observed, facts));
        if let Some(note) = retention_note {
            evidence.add_unknown(
                "retention",
                format!(
                    "census retention failed ({note}); the census facts stand, but no proof can bind this run"
                ),
            );
        }
        evidence.coverage.examined = 1;
        evidence.coverage.total = 1;
        evidence.coverage.exhaustive = evidence.unknowns.is_empty();
        return Ok(evidence.to_value());
    }
    let header = parse_bundle_header(&prefix)?;
    let compression = header.flags & 0x3F;
    let mut record = json!({
        "blocks_info_at_end": header.blocks_info_at_end,
        "blocks_info_compression": compression_name(compression),
        "blocks_info_compressed_bytes": header.compressed_blocks_info_size,
        "blocks_info_uncompressed_bytes": header.uncompressed_blocks_info_size,
        "bundle_size_actual": file_len,
        "bundle_size_declared": header.bundle_size,
        "bundle_size_discrepancy": header.bundle_size >= 0 && header.bundle_size as u64 != file_len,
        "container": "unityfs",
        "format_version": header.format_version,
        "has_directory_info": header.has_directory_info,
        "unity_revision": header.unity_revision,
        "unity_version": header.unity_version,
    });
    let mut evidence = Evidence::new("inspect_unity_bundle", "unity");
    evidence.subject = Some(subject);
    // LZMA blocks info: header-only census (SPEC §7.4).
    if compression == 1 {
        record["blocks_info_decoded"] = json!(false);
        let document = json!({"unity_bundle": record.clone()});
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
        evidence.add_finding(Finding::new("unity_bundle", Confidence::Observed, facts));
        if let Some(note) = retention_note {
            evidence.add_unknown(
                "retention",
                format!(
                    "census retention failed ({note}); the census facts stand, but no proof can bind this run"
                ),
            );
        }
        evidence.add_unknown(
            "node directory",
            "the blocks-info region is LZMA-compressed and is not decoded by this reader (LZMA support declined, readers SPEC §7.10); the node census is unknown",
        );
        evidence.coverage.examined = 0;
        evidence.coverage.total = 0;
        evidence.coverage.exhaustive = false;
        return Ok(evidence.to_value());
    }
    if !matches!(compression, 0 | 2 | 3) {
        return Err(unsupported(format!(
            "blocks-info compression code {compression} is not implemented (supported: 0 none, 2 LZ4, 3 LZ4HC; 1 LZMA is reported, not decoded)"
        )));
    }
    if header.uncompressed_blocks_info_size as usize > UNITY_BLOCKS_INFO_BYTES_MAX {
        return Err(resource(format!(
            "blocks info declares {} uncompressed bytes, over UNITY_BLOCKS_INFO_BYTES_MAX ({UNITY_BLOCKS_INFO_BYTES_MAX})",
            header.uncompressed_blocks_info_size
        )));
    }
    let blocks_info_offset = if header.blocks_info_at_end {
        // The region sits at the physical end of the file;
        // the declared bundle size is a recorded fact that
        // may disagree (SPEC §6.4) and never positions reads.
        if file_len < u64::from(header.compressed_blocks_info_size) {
            return Err(truncated(
                "file is smaller than the blocks-info region at its end",
            ));
        }
        file_len - u64::from(header.compressed_blocks_info_size)
    } else {
        header.data_start
    };
    let stored_info = reader.read_range(
        blocks_info_offset,
        u64::from(header.compressed_blocks_info_size),
    )?;
    let info_bytes = match compression {
        0 => stored_info,
        _ => {
            lz4_flex::block::decompress(&stored_info, header.uncompressed_blocks_info_size as usize)
                .map_err(|error| mismatch(format!("blocks info does not decompress: {error}")))?
        }
    };
    if info_bytes.len() != header.uncompressed_blocks_info_size as usize {
        return Err(mismatch(
            "blocks info decompressed size disagrees with the header declaration",
        ));
    }
    let info = parse_blocks_info(&info_bytes)?;
    let blocks_file_start = if header.blocks_info_at_end {
        header.data_start
    } else {
        blocks_info_offset + u64::from(header.compressed_blocks_info_size)
    };
    record["blocks"] = json!(
        info.blocks
            .iter()
            .map(|block| json!({
                "compressed_size": block.compressed_size,
                "compression": compression_name(block.compression),
                "uncompressed_size": block.uncompressed_size,
            }))
            .collect::<Vec<_>>()
    );
    record["blocks_info_decoded"] = json!(true);
    record["data_hash"] = json!(info.data_hash);
    record["data_hash_verification"] =
        json!("recorded_unverified — no public algorithm specification found");
    let mut rows: Vec<Value> = Vec::with_capacity(info.nodes.len());
    let mut examined: u64 = 0;
    let mut serialized_count: u64 = 0;
    let mut serialized_records: Vec<Value> = Vec::new();
    let mut serialized_object_rows: Vec<Value> = Vec::new();
    let mut serialized_object_total: u64 = 0;
    let mut serialized_objects_truncated = false;
    let mut unreadable_notes: Vec<String> = Vec::new();
    for node in &info.nodes {
        let is_serialized = node.flags & 4 != 0;
        let mut row = json!({
            "deleted": node.flags & 2 != 0,
            "directory": node.flags & 1 != 0,
            "flags": node.flags,
            "kind": if is_serialized { "serialized_file" } else { "file" },
            "offset": node.offset,
            "path": node.path,
            "serialized": is_serialized,
            "size": node.size,
            "status": "listed",
        });
        if is_serialized {
            serialized_count += 1;
            match node_bytes(&mut reader, blocks_file_start, &info, node) {
                Ok(bytes) => match parse_serialized_file(&bytes) {
                    Ok(summary) => {
                        row["serialized"] = sf_summary_json(&summary);
                        row["status"] = json!("censused");
                        examined += 1;
                        serialized_object_total += u64::from(summary.object_count);
                        serialized_objects_truncated |= summary.objects_truncated;
                        let (record, object_rows) = serialized_doc_records(&summary, &node.path);
                        serialized_records.push(record);
                        serialized_object_rows.extend(object_rows);
                    }
                    Err(error) => {
                        row["status"] = json!("unreadable");
                        unreadable_notes.push(format!("{}: {}", node.path, error.message));
                    }
                },
                Err(note) => {
                    row["status"] = json!("unreadable");
                    unreadable_notes.push(format!("{}: {note}", node.path));
                }
            }
        } else {
            examined += 1;
        }
        rows.push(row);
    }
    record["node_count"] = json!(info.nodes.len());
    record["serialized_file_count"] = json!(serialized_count);
    let total = info.nodes.len() as u64;
    let doc_rows: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut doc_row = row.clone();
            doc_row["key"] = row["path"].clone();
            doc_row
        })
        .collect();
    let serialized_total = serialized_records.len() as u64;
    let document = json!({
        "unity_bundle": record.clone(),
        "unity_bundle_entries": doc_rows,
        "unity_bundle_entries_total": total,
        "unity_bundle_entries_truncated": false,
        "unity_serialized": serialized_records,
        "unity_serialized_objects": serialized_object_rows,
        "unity_serialized_objects_total": serialized_object_total,
        "unity_serialized_objects_truncated": serialized_objects_truncated,
        "unity_serialized_total": serialized_total,
        "unity_serialized_truncated": false,
    });
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
    evidence.add_finding(Finding::new("unity_bundle", Confidence::Observed, facts));
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
    if !unreadable_notes.is_empty() {
        evidence.add_unknown(
            "serialized files",
            format!(
                "{} serialized file(s) could not be censused: {}",
                unreadable_notes.len(),
                unreadable_notes.join("; ")
            ),
        );
    }
    evidence.add_unknown(
        "data hash",
        "the blocks-info data hash is recorded as a fact; its algorithm has no public specification, so it is not verified",
    );
    evidence.coverage.examined = examined;
    evidence.coverage.total = total;
    evidence.coverage.exhaustive = examined == total && evidence.unknowns.is_empty();
    Ok(evidence.to_value())
}

// ---------------------------------------------------------------------
// MonoBehaviour census (BQ-2): typetree-independent.
// ---------------------------------------------------------------------

/// Unity class ID of MonoScript, the fixed-layout identity
/// record a MonoBehaviour's `m_Script` pointer names.
const CLASS_MONO_SCRIPT: i64 = 115;

/// Per-object anomaly rows retained in the census record;
/// the anomaly counts themselves stay exact past the cap.
const MB_ANOMALIES_RETAINED_MAX: usize = 100;

/// A MonoScript's identity, parsed from its fixed-layout
/// payload: the script class a MonoBehaviour belongs to.
/// Field order is the census's sort order (assembly,
/// namespace, class), matching the record's grouping.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScriptIdentity {
    assembly: String,
    namespace: String,
    class: String,
}

/// Read one 4-aligned, length-prefixed string from a payload
/// cursor positioned at the payload's start. Payload strings
/// are strict UTF-8; the error is a plain message because a
/// bad payload is an anomaly in the caller's census, not a
/// failure of the census itself.
fn read_payload_string(cursor: &mut SfCursor) -> Result<String, String> {
    let len = cursor.read_i32().map_err(|error| error.message)?;
    if len < 0 || len as usize > cursor.bytes.len() {
        return Err(format!("payload string declares {len} bytes"));
    }
    let raw = cursor
        .read_bytes(len as usize)
        .map_err(|error| error.message)?;
    let text =
        String::from_utf8(raw.to_vec()).map_err(|_| "payload string is not UTF-8".to_string())?;
    cursor.align_stream();
    Ok(text)
}

/// Parse a MonoScript payload (fixed layout, verified
/// against the corpus): m_Name, m_ExecutionOrder,
/// m_PropertiesHash (16 bytes), m_ClassName, m_Namespace,
/// m_AssemblyName. Trailing bytes (m_IsEditorScript) are
/// not part of the identity and are not read.
fn parse_mono_script(slice: &[u8], little: bool) -> Result<ScriptIdentity, String> {
    let mut cursor = SfCursor {
        bytes: slice,
        little,
        position: 0,
    };
    let _name = read_payload_string(&mut cursor)?;
    cursor.read_i32().map_err(|error| error.message)?;
    cursor.read_bytes(16).map_err(|error| error.message)?;
    let class = read_payload_string(&mut cursor)?;
    let namespace = read_payload_string(&mut cursor)?;
    let assembly = read_payload_string(&mut cursor)?;
    Ok(ScriptIdentity {
        assembly,
        namespace,
        class,
    })
}

/// The fixed-layout head of one MonoBehaviour payload.
/// m_Name is parsed (it validates the header's shape) but
/// not retained: the census groups by script class.
struct MbHeader {
    payload_bytes: usize,
    script_file: i32,
    script_path: i64,
}

/// Parse a MonoBehaviour header (fixed layout):
/// m_GameObject (PPtr), m_Enabled, m_Script (PPtr), m_Name;
/// everything after the name is script field data, counted
/// in bytes and never expanded — the per-script type trees
/// that would describe it are not present in shipped builds
/// (every type row in the corpus carries zero tree nodes).
fn parse_mb_header(slice: &[u8], little: bool) -> Result<MbHeader, String> {
    if slice.len() < 32 {
        return Err(format!(
            "payload is {} bytes, under the 32-byte header",
            slice.len()
        ));
    }
    let mut cursor = SfCursor {
        bytes: slice,
        little,
        position: 0,
    };
    cursor.read_i32().map_err(|error| error.message)?; // m_GameObject file index
    cursor.read_i64().map_err(|error| error.message)?; // m_GameObject path id
    let enabled = cursor.read_u8().map_err(|error| error.message)?;
    if enabled > 1 {
        return Err(format!("m_Enabled is {enabled}, not 0 or 1"));
    }
    cursor.position = 16;
    let script_file = cursor.read_i32().map_err(|error| error.message)?;
    let script_path = cursor.read_i64().map_err(|error| error.message)?;
    cursor.position = 28;
    let _name = read_payload_string(&mut cursor)?;
    Ok(MbHeader {
        payload_bytes: slice.len() - cursor.position,
        script_file,
        script_path,
    })
}

/// The payload bytes of one object row, bounds-checked
/// against the file's data area.
fn payload_slice<'a>(
    bytes: &'a [u8],
    summary: &SfSummary,
    payload: &SfPayload,
) -> Option<&'a [u8]> {
    let start = summary.data_offset.checked_add(payload.byte_start)?;
    let end = start.checked_add(u64::from(payload.byte_size))?;
    bytes.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

/// Second-pass walk of one SerializedFile's metadata to its
/// externals table — the file names a PPtr file index
/// resolves through. `parse_serialized_file` stops after the
/// object table by design (its census never needed
/// externals); this walk re-covers the same ground with the
/// same cursor discipline and fails closed on any byte-layout
/// disagreement. Returns external file base names in table
/// order (index + 1 is the PPtr file index).
fn parse_sf_externals(bytes: &[u8]) -> Result<Vec<String>, FathomError> {
    if bytes.len() < 20 {
        return Err(truncated("serialized file is shorter than its header"));
    }
    let be_u32 = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    let version = be_u32(8);
    if !(SF_VERSION_MIN..=SF_VERSION_MAX).contains(&version) {
        return Err(unsupported(format!(
            "serialized file version {version} is not implemented (supported: {SF_VERSION_MIN}..={SF_VERSION_MAX})"
        )));
    }
    let metadata_start = if version >= 22 {
        if bytes.len() < 48 {
            return Err(truncated(
                "serialized file is shorter than its version-22 header",
            ));
        }
        48usize
    } else {
        20usize
    };
    let little = bytes[16] == 0;
    let mut cursor = SfCursor {
        bytes,
        little,
        position: metadata_start,
    };
    if version >= 7 {
        cursor.read_cstring()?;
    }
    if version >= 8 {
        cursor.read_u32()?; // script compatibility (skipped)
    }
    let enable_type_tree = if version >= 10 {
        cursor.read_u8()? != 0
    } else {
        true
    };
    let type_count = cursor.read_u32()?;
    if type_count as usize > UNITY_TYPES_MAX {
        return Err(resource(format!(
            "serialized file declares {type_count} types, over UNITY_TYPES_MAX ({UNITY_TYPES_MAX})"
        )));
    }
    for _ in 0..type_count {
        let class_id = cursor.read_i32()?;
        if version >= 16 {
            cursor.read_u8()?; // is_stripped (skipped)
            cursor.read_i16()?; // script type index (skipped)
        }
        if version >= 13 {
            if (version >= 16 && class_id == 114) || (version < 16 && class_id < 0) {
                cursor.read_bytes(16)?; // script id
            }
            cursor.read_bytes(16)?; // type hash
        }
        if enable_type_tree {
            skip_type_tree(&mut cursor, version)?;
            if version >= 21 {
                let dependency_count = cursor.read_i32()?;
                if dependency_count < 0 {
                    return Err(mismatch(
                        "serialized type declares a negative dependency count",
                    ));
                }
                let dependency_bytes = (dependency_count as usize)
                    .checked_mul(4)
                    .ok_or_else(|| resource("serialized type dependency list overflows"))?;
                cursor.read_bytes(dependency_bytes)?;
            }
        }
    }
    // Object rows are skipped, never retained: the walk only
    // needs their byte widths, which the layout fixes.
    let object_count = cursor.read_u32()?;
    for _ in 0..object_count {
        if version >= 14 {
            cursor.align_stream();
        }
        if version >= 14 {
            cursor.read_i64()?;
        } else {
            cursor.read_i32()?;
        }
        if version >= 22 {
            cursor.read_u64()?;
        } else {
            cursor.read_u32()?;
        }
        cursor.read_u32()?; // byte size
        cursor.read_i32()?; // type index
        if version < 16 {
            cursor.read_u16()?; // class id
        }
        if version < 11 {
            cursor.read_u16()?; // is_destroyed
        }
        if (11..17).contains(&version) {
            cursor.read_i16()?; // row script type index
        }
        if version == 15 || version == 16 {
            cursor.read_u8()?; // is_stripped
        }
    }
    if version >= 11 {
        let script_count = cursor.read_i32()?;
        if script_count < 0 || script_count as usize > UNITY_EXTERNALS_MAX {
            return Err(resource(format!(
                "serialized file declares {script_count} script-type rows, over UNITY_EXTERNALS_MAX ({UNITY_EXTERNALS_MAX})"
            )));
        }
        for _ in 0..script_count {
            cursor.read_i32()?; // local serialized file index
            if version < 14 {
                cursor.read_i32()?;
            } else {
                cursor.align_stream();
                cursor.read_i64()?;
            }
        }
    }
    let external_count = cursor.read_i32()?;
    if external_count < 0 || external_count as usize > UNITY_EXTERNALS_MAX {
        return Err(resource(format!(
            "serialized file declares {external_count} externals, over UNITY_EXTERNALS_MAX ({UNITY_EXTERNALS_MAX})"
        )));
    }
    let mut names = Vec::with_capacity(external_count as usize);
    for _ in 0..external_count {
        if version >= 6 {
            cursor.read_cstring()?; // temp_empty (skipped)
        }
        if version >= 5 {
            cursor.read_bytes(16)?; // guid
            cursor.read_i32()?; // type
        }
        let path = cursor.read_cstring()?;
        names.push(path.rsplit(['/', '\\']).next().unwrap_or(&path).to_string());
    }
    Ok(names)
}

/// Loose SerializedFile names in a Unity data directory: the
/// engine's own file vocabulary (bundle nodes are discovered
/// by signature instead and need no name rule).
fn is_serialized_name(name: &str) -> bool {
    name == "globalgamemanagers"
        || name == "globalgamemanagers.assets"
        || name == "resources.assets"
        || name == "unity default resources"
        || name == "unity_builtin_extra"
        || name.ends_with(".assets")
        || (name.len() > 5
            && name.starts_with("level")
            && name[5..].chars().all(|c| c.is_ascii_digit()))
}

/// One census source: a SerializedFile whose bytes live in a
/// loose file or in one node of a UnityFS bundle.
struct MbSource {
    /// Registry key: the file base name scripts resolve by.
    key: String,
    /// Human-facing source name (relative path, or
    /// `bundle!node` for bundle members).
    display: String,
    container: &'static str,
    load: MbSourceLoad,
}

enum MbSourceLoad {
    Loose(PathBuf),
    /// Bundle members are identified by the source's
    /// display name in the run's decoded-node cache.
    BundleNode,
}

/// Walk a data directory (bounded) and collect candidate
/// files: UnityFS bundles by signature, loose SerializedFiles
/// by name. Returns (candidates, capped, unreadable).
fn walk_mb_candidates(root: &Path) -> (Vec<PathBuf>, bool, usize) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut capped = false;
    let mut unreadable = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .collect();
        paths.sort();
        for path in paths {
            let Ok(file_type) = std::fs::symlink_metadata(&path).map(|m| m.file_type()) else {
                unreadable += 1;
                continue;
            };
            if file_type.is_dir() {
                if depth < UNITY_MB_WALK_DEPTH_MAX {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if candidates.len() >= UNITY_MB_FILES_MAX {
                capped = true;
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let is_bundle = std::fs::File::open(&path)
                .and_then(|mut f| {
                    let mut sig = [0u8; 8];
                    f.read_exact(&mut sig).map(|()| sig)
                })
                .map(|sig| &sig == b"UnityFS\0")
                .unwrap_or(false);
            if is_bundle || is_serialized_name(&name) {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    (candidates, capped, unreadable)
}

/// Decode one UnityFS bundle's serialized nodes to
/// (node path, bytes) pairs, mirroring the census path in
/// `inspect_unity_bundle`: LZMA blocks info and undecodable
/// blocks are named errors, never worked around.
fn bundle_serialized_nodes(path: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let file_len = std::fs::metadata(path)
        .map_err(|error| format!("cannot stat bundle: {error}"))?
        .len();
    if file_len > ARCHIVE_TARGET_BYTES_MAX {
        return Err(format!(
            "bundle declares {file_len} bytes, over ARCHIVE_TARGET_BYTES_MAX ({ARCHIVE_TARGET_BYTES_MAX})"
        ));
    }
    let file = File::open(path).map_err(|error| format!("cannot open bundle: {error}"))?;
    let mut reader = RegionReader {
        file,
        len: file_len,
    };
    let prefix = reader
        .read_range(0, file_len.min(HEADER_PREFIX_BYTES))
        .map_err(|error| error.message)?;
    if !prefix.starts_with(b"UnityFS\0") {
        return Err("file has no UnityFS signature".to_string());
    }
    let header = parse_bundle_header(&prefix).map_err(|error| error.message)?;
    let compression = header.flags & 0x3F;
    if compression == 1 {
        return Err("blocks info is LZMA-compressed and is not decoded by this reader".to_string());
    }
    if !matches!(compression, 0 | 2 | 3) {
        return Err(format!(
            "blocks-info compression code {compression} is not implemented"
        ));
    }
    if header.uncompressed_blocks_info_size as usize > UNITY_BLOCKS_INFO_BYTES_MAX {
        return Err(format!(
            "blocks info declares {} uncompressed bytes, over UNITY_BLOCKS_INFO_BYTES_MAX ({UNITY_BLOCKS_INFO_BYTES_MAX})",
            header.uncompressed_blocks_info_size
        ));
    }
    let blocks_info_offset = if header.blocks_info_at_end {
        if file_len < u64::from(header.compressed_blocks_info_size) {
            return Err("file is smaller than the blocks-info region at its end".to_string());
        }
        file_len - u64::from(header.compressed_blocks_info_size)
    } else {
        header.data_start
    };
    let stored_info = reader
        .read_range(
            blocks_info_offset,
            u64::from(header.compressed_blocks_info_size),
        )
        .map_err(|error| error.message)?;
    let info_bytes = match compression {
        0 => stored_info,
        _ => {
            lz4_flex::block::decompress(&stored_info, header.uncompressed_blocks_info_size as usize)
                .map_err(|error| format!("blocks info does not decompress: {error}"))?
        }
    };
    if info_bytes.len() != header.uncompressed_blocks_info_size as usize {
        return Err(
            "blocks info decompressed size disagrees with the header declaration".to_string(),
        );
    }
    let info = parse_blocks_info(&info_bytes).map_err(|error| error.message)?;
    if info.nodes.len() > UNITY_NODES_MAX {
        return Err(format!(
            "bundle declares {} nodes, over UNITY_NODES_MAX ({UNITY_NODES_MAX})",
            info.nodes.len()
        ));
    }
    let blocks_file_start = if header.blocks_info_at_end {
        header.data_start
    } else {
        blocks_info_offset + u64::from(header.compressed_blocks_info_size)
    };
    let mut out = Vec::new();
    for node in &info.nodes {
        if node.flags & 4 == 0 {
            continue;
        }
        let bytes = node_bytes(&mut reader, blocks_file_start, &info, node)?;
        out.push((node.path.clone(), bytes));
    }
    Ok(out)
}

/// Per-source parse retained between the census's two
/// passes (script registry first, behaviours second), so a
/// MonoBehaviour can resolve a script declared in a file
/// the walk meets later.
struct MbParsed {
    display: String,
    key: String,
    container: &'static str,
    externals: Vec<String>,
    /// Loose-file path for a standalone SerializedFile;
    /// bundle members re-read from the run's node cache.
    loose_path: Option<PathBuf>,
    summary: SfSummary,
}

/// Accumulates the census across sources.
#[derive(Default)]
struct MbAccum {
    anomalies: Vec<String>,
    anomaly_count: u64,
    counts: BTreeMap<ScriptIdentity, u64>,
    null_script_references: u64,
    script_anomalies: Vec<String>,
    script_anomaly_count: u64,
    unresolved: BTreeMap<String, u64>,
}

impl MbAccum {
    fn anomaly(&mut self, message: String) {
        self.anomaly_count += 1;
        if self.anomalies.len() < MB_ANOMALIES_RETAINED_MAX {
            self.anomalies.push(message);
        }
    }

    fn script_anomaly(&mut self, message: String) {
        self.script_anomaly_count += 1;
        if self.script_anomalies.len() < MB_ANOMALIES_RETAINED_MAX {
            self.script_anomalies.push(message);
        }
    }
}

/// Census the MonoBehaviours of one Unity data directory
/// without consulting any type tree: fixed-layout headers
/// and MonoScript identities from raw payloads, script
/// references resolved through each file's externals table.
#[allow(clippy::too_many_lines)]
pub fn census_unity_monobehaviours(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target_raw = require_str(args, "target")?;
    let target = paths::validate_target(config, Path::new(target_raw))?;
    let metadata = std::fs::metadata(&target).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat target {}: {error}", target.display()),
        )
    })?;
    if !metadata.is_dir() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "census_unity_monobehaviours target {} is not a directory",
                target.display()
            ),
        ));
    }
    let target_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (candidates, walk_capped, walk_unreadable) = walk_mb_candidates(&target);
    // Expand candidates into sources (loose files + bundle
    // nodes). Bundle bytes are decoded once and kept: the
    // census walks its sources twice.
    let mut sources: Vec<MbSource> = Vec::new();
    let mut bundle_cache: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut failed: Vec<Value> = Vec::new();
    for candidate in &candidates {
        let rel = candidate
            .strip_prefix(&target)
            .unwrap_or(candidate)
            .display()
            .to_string();
        let name = candidate
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let is_bundle = std::fs::File::open(candidate)
            .and_then(|mut f| {
                let mut sig = [0u8; 8];
                f.read_exact(&mut sig).map(|()| sig)
            })
            .map(|sig| &sig == b"UnityFS\0")
            .unwrap_or(false);
        if is_bundle {
            match bundle_serialized_nodes(candidate) {
                Ok(nodes) => {
                    for (node_path, bytes) in nodes {
                        let display = format!("{rel}!{node_path}");
                        let key = node_path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or(&node_path)
                            .to_string();
                        bundle_cache.insert(display.clone(), bytes);
                        sources.push(MbSource {
                            key,
                            display,
                            container: "bundle_node",
                            load: MbSourceLoad::BundleNode,
                        });
                    }
                }
                Err(reason) => failed.push(json!({"error": reason, "source": rel})),
            }
        } else {
            sources.push(MbSource {
                key: name,
                display: rel,
                container: "serialized_file",
                load: MbSourceLoad::Loose(candidate.clone()),
            });
        }
    }
    if sources.is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "no readable SerializedFiles under {} ({} candidate file(s), {} failed)",
                target.display(),
                candidates.len(),
                failed.len()
            ),
        ));
    }
    let load_bytes = |source: &MbSource,
                      bundle_cache: &BTreeMap<String, Vec<u8>>|
     -> Result<Vec<u8>, String> {
        match &source.load {
            MbSourceLoad::Loose(path) => {
                let size = std::fs::metadata(path)
                    .map_err(|error| format!("cannot stat file: {error}"))?
                    .len();
                if size > ARCHIVE_TARGET_BYTES_MAX {
                    return Err(format!(
                        "file declares {size} bytes, over ARCHIVE_TARGET_BYTES_MAX ({ARCHIVE_TARGET_BYTES_MAX})"
                    ));
                }
                std::fs::read(path).map_err(|error| format!("cannot read file: {error}"))
            }
            MbSourceLoad::BundleNode => bundle_cache
                .get(&source.display)
                .cloned()
                .ok_or_else(|| "bundle node bytes were not retained".to_string()),
        }
    };
    // Pass 1: parse every source and build the script
    // registry — (file base name, path id) -> identity.
    let mut accum = MbAccum::default();
    let mut parsed: Vec<MbParsed> = Vec::new();
    let mut registry: BTreeMap<(String, i64), ScriptIdentity> = BTreeMap::new();
    let mut monoscripts_total: u64 = 0;
    for source in &sources {
        let bytes = match load_bytes(source, &bundle_cache) {
            Ok(bytes) => bytes,
            Err(reason) => {
                failed.push(json!({"error": reason, "source": source.display}));
                continue;
            }
        };
        let summary = match parse_serialized_file_capped(&bytes, UNITY_MB_OBJECTS_MAX) {
            Ok(summary) => summary,
            Err(error) => {
                failed.push(json!({"error": error.message, "source": source.display}));
                continue;
            }
        };
        let externals = match parse_sf_externals(&bytes) {
            Ok(externals) => externals,
            Err(error) => {
                failed.push(json!({"error": error.message, "source": source.display}));
                continue;
            }
        };
        for payload in &summary.payloads {
            if payload.class_id != CLASS_MONO_SCRIPT {
                continue;
            }
            monoscripts_total += 1;
            let Some(slice) = payload_slice(&bytes, &summary, payload) else {
                accum.script_anomaly(format!(
                    "{}: MonoScript {} payload lies outside the file bytes",
                    source.display, payload.path_id
                ));
                continue;
            };
            match parse_mono_script(slice, summary.little) {
                Ok(identity) => {
                    let reg_key = (source.key.clone(), payload.path_id);
                    if let Some(existing) = registry.get(&reg_key) {
                        if *existing != identity {
                            accum.script_anomaly(format!(
                                "{}: MonoScript {} redeclared with a different identity; the first stands",
                                source.display, payload.path_id
                            ));
                        }
                    } else {
                        registry.insert(reg_key, identity);
                    }
                }
                Err(reason) => accum.script_anomaly(format!(
                    "{}: MonoScript {} does not parse ({reason})",
                    source.display, payload.path_id
                )),
            }
        }
        parsed.push(MbParsed {
            display: source.display.clone(),
            key: source.key.clone(),
            container: source.container,
            externals,
            loose_path: match &source.load {
                MbSourceLoad::Loose(path) => Some(path.clone()),
                MbSourceLoad::BundleNode => None,
            },
            summary,
        });
    }
    // Pass 2: census the MonoBehaviours of every parsed
    // source against the completed registry.
    let mut file_rows: Vec<Value> = Vec::new();
    let mut monobehaviours_total: u64 = 0;
    let mut payload_bytes_total: u64 = 0;
    let mut truncated_files: Vec<String> = Vec::new();
    for source in &parsed {
        let bytes = match &source.loose_path {
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            },
            None => match bundle_cache.get(&source.display) {
                Some(bytes) => bytes.clone(),
                None => continue,
            },
        };
        let mut file_behaviours: u64 = 0;
        let mut file_payload_bytes: u64 = 0;
        for payload in &source.summary.payloads {
            if payload.class_id != CLASS_MONO_BEHAVIOUR {
                continue;
            }
            file_behaviours += 1;
            let Some(slice) = payload_slice(&bytes, &source.summary, payload) else {
                accum.anomaly(format!(
                    "{}: MonoBehaviour {} payload lies outside the file bytes",
                    source.display, payload.path_id
                ));
                continue;
            };
            let header = match parse_mb_header(slice, source.summary.little) {
                Ok(header) => header,
                Err(reason) => {
                    accum.anomaly(format!(
                        "{}: MonoBehaviour {} header does not parse ({reason})",
                        source.display, payload.path_id
                    ));
                    continue;
                }
            };
            file_payload_bytes += header.payload_bytes as u64;
            if header.script_path == 0 {
                accum.null_script_references += 1;
                continue;
            }
            let target_key = if header.script_file == 0 {
                Some(source.key.clone())
            } else if header.script_file > 0 {
                source
                    .externals
                    .get((header.script_file - 1) as usize)
                    .cloned()
            } else {
                None
            };
            match target_key {
                Some(script_file_name) => {
                    match registry.get(&(script_file_name.clone(), header.script_path)) {
                        Some(identity) => {
                            *accum.counts.entry(identity.clone()).or_insert(0) += 1;
                        }
                        None => {
                            *accum
                                .unresolved
                                .entry(format!("{script_file_name}:{}", header.script_path))
                                .or_insert(0) += 1;
                        }
                    }
                }
                None => {
                    *accum
                        .unresolved
                        .entry(format!(
                            "<external {}>:{}",
                            header.script_file, header.script_path
                        ))
                        .or_insert(0) += 1;
                }
            }
        }
        monobehaviours_total += file_behaviours;
        payload_bytes_total += file_payload_bytes;
        if source.summary.objects_truncated {
            truncated_files.push(source.display.clone());
        }
        file_rows.push(json!({
            "container": source.container,
            "monobehaviours": file_behaviours,
            "objects_total": source.summary.object_count,
            "objects_truncated": source.summary.objects_truncated,
            "payload_bytes_after_header": file_payload_bytes,
            "source": source.display,
        }));
    }
    let counts_by_script_class: Vec<Value> = {
        let mut rows: Vec<(&ScriptIdentity, &u64)> = accum.counts.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        rows.iter()
            .map(|(identity, count)| {
                json!({
                    "assembly": identity.assembly,
                    "class": identity.class,
                    "count": count,
                    "namespace": identity.namespace,
                })
            })
            .collect()
    };
    let unresolved_rows: Vec<Value> = accum
        .unresolved
        .iter()
        .map(|(target, count)| json!({"count": count, "target": target}))
        .collect();
    let unresolved_total: u64 = accum.unresolved.values().sum();
    let record = json!({
        "counts_by_script_class": counts_by_script_class,
        "distinct_script_classes": accum.counts.len(),
        "files": file_rows,
        "files_examined": parsed.len(),
        "files_failed": failed,
        "header_anomalies": accum.anomalies,
        "header_anomaly_count": accum.anomaly_count,
        "monoscript_anomalies": accum.script_anomalies,
        "monoscript_anomaly_count": accum.script_anomaly_count,
        "root": target_name,
        "totals": {
            "monobehaviours": monobehaviours_total,
            "monoscripts": monoscripts_total,
            "null_script_references": accum.null_script_references,
            "payload_bytes_after_header": payload_bytes_total,
            "unresolved_script_references": unresolved_total,
        },
        "unresolved_script_references": unresolved_rows,
    });
    // Retention binds to the census record's own hash (the
    // directory-target pattern of the game census).
    let canonical = serde_json::to_string(&record).unwrap_or_default();
    let key = sha256_hex(canonical.as_bytes());
    let (digest, retention_note) =
        match proof::retain_export(config, &key, "unity_monobehaviour_census", &record) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut facts = record.clone();
    facts["export_digest"] = match &digest {
        Some(digest) => json!(digest),
        None => Value::Null,
    };
    let mut evidence = Evidence::new("census_unity_monobehaviours", "unity");
    evidence.add_finding(Finding::new(
        "unity_monobehaviour_census",
        Confidence::Observed,
        facts,
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    if !failed.is_empty() {
        evidence.add_unknown(
            "sources",
            format!(
                "{} source(s) could not be censused: {}",
                failed.len(),
                failed
                    .iter()
                    .map(|row| format!("{} ({})", row["source"], row["error"]))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        );
    }
    if unresolved_total > 0 {
        evidence.add_unknown(
            "script references",
            format!(
                "{unresolved_total} MonoBehaviour(s) reference a MonoScript that is not in the censused files; they are counted under unresolved_script_references by target, never dropped"
            ),
        );
    }
    if accum.anomaly_count > 0 || accum.script_anomaly_count > 0 {
        evidence.add_unknown(
            "payload anomalies",
            format!(
                "{} MonoBehaviour header(s) and {} MonoScript payload(s) did not parse; they are named in the census record and counted in its totals",
                accum.anomaly_count, accum.script_anomaly_count
            ),
        );
    }
    if !truncated_files.is_empty() {
        evidence.add_unknown(
            "object rows",
            format!(
                "object rows were truncated at UNITY_MB_OBJECTS_MAX in: {}; counts for those files are a floor, not a total",
                truncated_files.join(", ")
            ),
        );
    }
    if walk_capped {
        evidence.add_unknown(
            "walk coverage",
            format!(
                "the directory walk stopped at UNITY_MB_FILES_MAX ({UNITY_MB_FILES_MAX}) candidate files; counts are a floor, not a total"
            ),
        );
    }
    if walk_unreadable > 0 {
        evidence.add_unknown(
            "walk coverage",
            format!("{walk_unreadable} directory entries could not be read and are uncounted"),
        );
    }
    evidence.coverage.examined = parsed.len() as u64;
    evidence.coverage.total = sources.len() as u64;
    evidence.coverage.exhaustive =
        evidence.coverage.examined == evidence.coverage.total && evidence.unknowns.is_empty();
    Ok(evidence.to_value())
}

// ---------------------------------------------------------------------
// Extraction (game-extract lane)
// ---------------------------------------------------------------------

/// Accumulates one extraction run: manifest entries, notes
/// for anything not extracted, and the byte budget spent.
struct ExtractState {
    entries: Vec<Value>,
    notes: Vec<String>,
    written_bytes: u64,
}

/// Find embedded moc3 payloads inside a MonoBehaviour
/// payload (the hand census's carve rule): scan for the
/// MOC3 magic; take the length from the int32 at 4/8/12
/// bytes before the magic when it lands plausibly,
/// otherwise carve to the end of the payload.
fn carve_moc3_spans(payload: &[u8], little: bool) -> Vec<(usize, usize, String)> {
    let mut spans = Vec::new();
    let mut search_from = 0usize;
    while spans.len() < UNITY_EXTRACT_CARVES_MAX {
        let Some(relative) = payload[search_from..]
            .windows(4)
            .position(|window| window == b"MOC3")
        else {
            break;
        };
        let offset = search_from + relative;
        let mut carved = None;
        for back in [4usize, 8, 12] {
            if offset < back {
                continue;
            }
            let raw = &payload[offset - back..offset];
            let length = if little {
                i32::from_le_bytes(raw.try_into().unwrap())
            } else {
                i32::from_be_bytes(raw.try_into().unwrap())
            };
            if length <= 1024 {
                continue;
            }
            let Ok(length) = usize::try_from(length) else {
                continue;
            };
            let Some(end) = offset.checked_add(length) else {
                continue;
            };
            if end > payload.len() || payload.get(end..end + 4) == Some(b"MOC3".as_slice()) {
                continue;
            }
            carved = Some((offset, length, format!("int32_at_minus_{back}")));
            break;
        }
        let span = carved.unwrap_or_else(|| {
            (
                offset,
                payload.len() - offset,
                "to_end_of_payload".to_string(),
            )
        });
        search_from = offset + 4;
        spans.push(span);
    }
    spans
}

/// How a written payload's content was recognised, when it
/// was: moc3 magic, a model3 JSON signature, or a Cubism
/// file-name suffix (the hand census's detection rule).
fn cubism_detection(name: &str, script: &[u8]) -> Option<&'static str> {
    if script.starts_with(b"MOC3") {
        return Some("moc3_magic");
    }
    if script
        .windows(b"\"FileReferences\"".len())
        .any(|window| window == b"\"FileReferences\"")
    {
        return Some("model3_signature");
    }
    let lower = name.to_ascii_lowercase();
    if [".moc3", ".model3.json", ".cdi3.json", ".exp3.json"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return Some("cubism_name");
    }
    None
}

/// Extract every payload of the classes the lane writes
/// from one SerializedFile's bytes into
/// `out_dir/<node name>/`, appending manifest entries.
fn extract_serialized(
    node_key: &str,
    bytes: &[u8],
    out_dir: &Path,
    state: &mut ExtractState,
) -> Result<(), FathomError> {
    let summary = parse_serialized_file(bytes)?;
    let subdir_name = safe_file_name(node_key, "serialized");
    let subdir = out_dir.join(&subdir_name);
    std::fs::create_dir_all(&subdir).map_err(|error| io_error("create", &subdir, error))?;
    for payload in &summary.payloads {
        if !matches!(
            payload.class_id,
            CLASS_MONO_BEHAVIOUR | CLASS_TEXT_ASSET | CLASS_TEXTURE_2D
        ) {
            continue;
        }
        extract_object(
            &summary,
            bytes,
            payload,
            node_key,
            &subdir_name,
            &subdir,
            state,
        )?;
    }
    Ok(())
}

/// Extract one object's payload; every outcome — written,
/// out of bounds, over budget — lands as a manifest entry.
fn extract_object(
    summary: &SfSummary,
    bytes: &[u8],
    payload: &SfPayload,
    node_key: &str,
    subdir_name: &str,
    subdir: &Path,
    state: &mut ExtractState,
) -> Result<(), FathomError> {
    let class_name = match payload.class_id {
        CLASS_MONO_BEHAVIOUR => "MonoBehaviour",
        CLASS_TEXT_ASSET => "TextAsset",
        _ => "Texture2D",
    };
    let mut entry = json!({
        "bytes": payload.byte_size,
        "class": class_name,
        "class_id": payload.class_id,
        "kind": "object",
        "node": node_key,
        "path_id": payload.path_id,
        "status": "not_extracted",
    });
    let Some(start) = summary
        .data_offset
        .checked_add(payload.byte_start)
        .and_then(|value| usize::try_from(value).ok())
    else {
        entry["reason"] = json!("payload offset overflows the file size type");
        state.entries.push(entry);
        return Ok(());
    };
    let Some(slice) = start
        .checked_add(payload.byte_size as usize)
        .and_then(|end| bytes.get(start..end))
    else {
        entry["reason"] = json!("payload range lies outside the serialized file");
        state.entries.push(entry);
        return Ok(());
    };
    match payload.class_id {
        CLASS_TEXT_ASSET => {
            extract_text_asset(summary, payload, slice, subdir_name, subdir, state, entry)?
        }
        CLASS_TEXTURE_2D => {
            extract_texture(summary, payload, slice, subdir_name, subdir, state, entry)?
        }
        _ => extract_mono_behaviour(summary, payload, slice, subdir_name, subdir, state, entry)?,
    }
    Ok(())
}

/// Map an I/O failure on an extraction path to the typed
/// error the tools return (the house pattern for file
/// access failures, mirroring the census readers).
fn io_error(action: &str, path: &Path, error: std::io::Error) -> FathomError {
    FathomError::new(
        ErrorCode::TargetUnavailable,
        format!("cannot {action} {}: {error}", path.display()),
    )
}

/// Write one payload through the byte budget; Ok(None)
/// means the budget refused it (the caller records the
/// skip), Err is an I/O failure.
fn write_budgeted(
    state: &mut ExtractState,
    dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<Option<String>, FathomError> {
    if state.written_bytes.saturating_add(bytes.len() as u64) > UNITY_EXTRACT_BYTES_MAX {
        return Ok(None);
    }
    let digest = write_extracted(dir, file_name, bytes)?;
    state.written_bytes += bytes.len() as u64;
    Ok(Some(digest))
}

/// Write one extracted payload atomically (temp file, then
/// rename) and return its sha256.
fn write_extracted(dir: &Path, file_name: &str, bytes: &[u8]) -> Result<String, FathomError> {
    let temp = dir.join(format!(".tmp-{file_name}"));
    let destination = dir.join(file_name);
    std::fs::write(&temp, bytes).map_err(|error| io_error("write", &temp, error))?;
    std::fs::rename(&temp, &destination)
        .map_err(|error| io_error("rename", &destination, error))?;
    Ok(sha256_hex(bytes))
}

/// Read one i32 at `*position` in the file's endianness.
fn read_i32_at(bytes: &[u8], position: &mut usize, little: bool) -> Option<i32> {
    let raw = bytes.get(*position..position.checked_add(4)?)?;
    *position += 4;
    Some(if little {
        i32::from_le_bytes(raw.try_into().ok()?)
    } else {
        i32::from_be_bytes(raw.try_into().ok()?)
    })
}

/// Read one Unity serialized length-prefixed byte field
/// (i32 length, content, 4-byte alignment of the whole
/// field) at `*position`; None on any overrun or negative
/// length.
fn read_serialized_bytes<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    little: bool,
) -> Option<&'a [u8]> {
    let field_start = *position;
    let length = read_i32_at(bytes, position, little)?;
    if length < 0 {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    let content_start = field_start.checked_add(4)?;
    let content_end = content_start.checked_add(length)?;
    let content = bytes.get(content_start..content_end)?;
    let field_len = 4usize.checked_add(length)?;
    let aligned_len = field_len.checked_add(3)? / 4 * 4;
    *position = field_start.checked_add(aligned_len)?.min(bytes.len());
    Some(content)
}

/// Parse a TextAsset payload's name and script bytes
/// (m_Name then m_Script, both length-prefixed).
fn parse_text_asset(payload: &[u8], little: bool) -> Option<(String, &[u8])> {
    let mut position = 0usize;
    let name = read_serialized_bytes(payload, &mut position, little)?;
    let script = read_serialized_bytes(payload, &mut position, little)?;
    Some((String::from_utf8_lossy(name).into_owned(), script))
}

/// Parse a Texture2D payload's leading metadata (name,
/// width, height, complete image size, format, mip
/// count). Three serialized layouts exist, each verified
/// against shipped files and UnityPy's parse of them:
/// `modern` (Unity 2022-era: a forced-fallback format
/// and flag bytes precede the fields, a mips-stripped
/// count sits before the format), `unity6` (Unity 6000:
/// the fallback fields are gone, one flag word and the
/// mips-stripped count remain), and `legacy` (the fields
/// directly after the name). All three are tried under
/// strict validation — dimensions inside the texture
/// bound, a plausible format code, and a mip count the
/// dimensions can actually carry (a 0×0 record is
/// accepted only as the consistent empty texture a
/// runtime-generated font atlas serializes as) — and
/// the layout that matched is recorded; none matching
/// records the metadata as absent, never guessed. Pixel
/// decoding is out of scope: image-data placement needs
/// the type tree the readers SPEC keeps unexpanded, so
/// the raw payload is what extraction retains and the
/// manifest says so.
fn parse_texture_prefix(payload: &[u8], little: bool) -> Option<Value> {
    let mut position = 0usize;
    let name = read_serialized_bytes(payload, &mut position, little)?;
    let name = String::from_utf8_lossy(name).into_owned();
    // (prefix bytes after the name, mips-stripped count
    // present, layout tag)
    for (skip, stripped, layout) in [
        (8_usize, true, "modern"),
        (4, true, "unity6"),
        (0, false, "legacy"),
    ] {
        if let Some(meta) = texture_fields(payload, position, little, skip, stripped, layout, &name)
        {
            return Some(meta);
        }
    }
    None
}

/// Read the numeric Texture2D fields at `start` under
/// one layout and validate them (see parse_texture_prefix).
fn texture_fields(
    payload: &[u8],
    start: usize,
    little: bool,
    skip: usize,
    stripped: bool,
    layout: &str,
    name: &str,
) -> Option<Value> {
    let mut position = start.checked_add(skip)?;
    if position > payload.len() {
        return None;
    }
    let width = read_i32_at(payload, &mut position, little)?;
    let height = read_i32_at(payload, &mut position, little)?;
    let complete_image_size = read_i32_at(payload, &mut position, little)?;
    if stripped {
        let _mips_stripped = read_i32_at(payload, &mut position, little)?;
    }
    let format = read_i32_at(payload, &mut position, little)?;
    let mip_count = read_i32_at(payload, &mut position, little)?;
    if complete_image_size < 0 || !(0..=128).contains(&format) {
        return None;
    }
    // A texture with pixels records their size; only the
    // consistent empty texture (below) has size 0.
    if width > 0 && complete_image_size == 0 {
        return None;
    }
    let dims_ok = if width == 0 && height == 0 {
        complete_image_size == 0 && mip_count == 1
    } else {
        (1..=TEXTURE_DIMENSION_MAX).contains(&width)
            && (1..=TEXTURE_DIMENSION_MAX).contains(&height)
            && mip_count >= 1
            // A texture cannot carry more mip levels than
            // its largest dimension supports.
            && (mip_count as u32) <= 32 - (width.max(height) as u32).leading_zeros()
    };
    if !dims_ok {
        return None;
    }
    Some(json!({
        "complete_image_size": complete_image_size,
        "format": format,
        "format_name": texture_format_name(format),
        "height": height,
        "layout": layout,
        "mip_count": mip_count,
        "name": name,
        "width": width,
    }))
}

/// Names for the TextureFormat codes the estate's corpus
/// uses; anything else reports as `unknown_<code>` — the
/// numeric code is always recorded alongside.
fn texture_format_name(code: i32) -> String {
    let name = match code {
        1 => "Alpha8",
        2 => "ARGB4444",
        3 => "RGB24",
        4 => "RGBA32",
        5 => "ARGB32",
        7 => "RGB565",
        10 => "DXT1",
        12 => "DXT5",
        25 => "BC7",
        other => return format!("unknown_{other}"),
    };
    name.to_string()
}

/// Reduce a Unity object or node name to one safe
/// file-name component: ASCII alphanumerics and `.`/`-`/`_`
/// survive, everything else becomes `_`; capped at 128
/// chars; an empty or dot-only result falls back.
fn safe_file_name(name: &str, fallback: &str) -> String {
    let out: String = name
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return fallback.to_string();
    }
    out
}

/// Extract a TextAsset: the script bytes verbatim under
/// the asset's own name; an unparseable header falls back
/// to the raw object payload, recorded as such.
#[allow(clippy::too_many_arguments)]
fn extract_text_asset(
    summary: &SfSummary,
    payload: &SfPayload,
    slice: &[u8],
    subdir_name: &str,
    subdir: &Path,
    state: &mut ExtractState,
    mut entry: Value,
) -> Result<(), FathomError> {
    let (file_name, data, form, detected) = match parse_text_asset(slice, summary.little) {
        Some((name, script)) => {
            let detected = cubism_detection(&name, script);
            (
                safe_file_name(&name, &format!("textasset_{}", payload.path_id)),
                script,
                "text_asset_script",
                detected,
            )
        }
        None => (
            format!("textasset_{}.bin", payload.path_id),
            slice,
            "raw_object",
            None,
        ),
    };
    entry["detected"] = json!(detected);
    entry["payload_form"] = json!(form);
    match write_budgeted(state, subdir, &file_name, data)? {
        Some(digest) => {
            entry["bytes_written"] = json!(data.len());
            entry["file"] = json!(format!("{subdir_name}/{file_name}"));
            entry["sha256"] = json!(digest);
            entry["status"] = json!("extracted");
        }
        None => {
            entry["status"] = json!("skipped_budget");
        }
    }
    state.entries.push(entry);
    Ok(())
}

/// Extract a Texture2D: leading metadata in the manifest,
/// raw payload bytes on disk; pixel data is not decoded
/// (see `parse_texture_prefix`).
#[allow(clippy::too_many_arguments)]
fn extract_texture(
    summary: &SfSummary,
    payload: &SfPayload,
    slice: &[u8],
    subdir_name: &str,
    subdir: &Path,
    state: &mut ExtractState,
    mut entry: Value,
) -> Result<(), FathomError> {
    let metadata = parse_texture_prefix(slice, summary.little);
    let file_name = match metadata.as_ref().and_then(|meta| meta["name"].as_str()) {
        Some(name) => format!(
            "{}.tex2d.bin",
            safe_file_name(name, &format!("texture2d_{}", payload.path_id))
        ),
        None => format!("texture2d_{}.bin", payload.path_id),
    };
    entry["payload_form"] = json!("raw_object");
    entry["pixel_data"] =
        json!("not_decoded — image-data placement requires the type tree; raw payload retained");
    entry["texture"] = metadata.unwrap_or(Value::Null);
    match write_budgeted(state, subdir, &file_name, slice)? {
        Some(digest) => {
            entry["bytes_written"] = json!(slice.len());
            entry["file"] = json!(format!("{subdir_name}/{file_name}"));
            entry["sha256"] = json!(digest);
            entry["status"] = json!("extracted");
        }
        None => {
            entry["status"] = json!("skipped_budget");
        }
    }
    state.entries.push(entry);
    Ok(())
}

/// Extract a MonoBehaviour: raw payload bytes (typetree
/// expansion is out of scope), plus any embedded moc3
/// spans carved out as their own entries.
#[allow(clippy::too_many_arguments)]
fn extract_mono_behaviour(
    summary: &SfSummary,
    payload: &SfPayload,
    slice: &[u8],
    subdir_name: &str,
    subdir: &Path,
    state: &mut ExtractState,
    mut entry: Value,
) -> Result<(), FathomError> {
    let file_name = format!("monobehaviour_{}.bin", payload.path_id);
    entry["payload_form"] = json!("raw_object");
    entry["script_type_index"] = json!(payload.script_type_index);
    entry["type_hash"] = summary
        .types
        .get(usize::try_from(payload.type_index).unwrap_or(usize::MAX))
        .and_then(|row| row.get("type_hash").cloned())
        .unwrap_or(Value::Null);
    match write_budgeted(state, subdir, &file_name, slice)? {
        Some(digest) => {
            entry["bytes_written"] = json!(slice.len());
            entry["file"] = json!(format!("{subdir_name}/{file_name}"));
            entry["sha256"] = json!(digest);
            entry["status"] = json!("extracted");
        }
        None => {
            entry["status"] = json!("skipped_budget");
        }
    }
    let node_value = entry["node"].clone();
    state.entries.push(entry);
    for (index, (offset, length, source)) in carve_moc3_spans(slice, summary.little)
        .into_iter()
        .enumerate()
    {
        let carved = &slice[offset..offset + length];
        let carve_name = format!("monobehaviour_{}_carve{index}.moc3", payload.path_id);
        let mut carve_entry = json!({
            "bytes": length,
            "kind": "moc3_carve",
            "length_source": source,
            "moc3_version": carved.get(4).copied(),
            "node": node_value,
            "offset_in_payload": offset,
            "source_path_id": payload.path_id,
            "status": "not_extracted",
        });
        match write_budgeted(state, subdir, &carve_name, carved)? {
            Some(digest) => {
                carve_entry["bytes_written"] = json!(carved.len());
                carve_entry["file"] = json!(format!("{subdir_name}/{carve_name}"));
                carve_entry["sha256"] = json!(digest);
                carve_entry["status"] = json!("extracted");
            }
            None => {
                carve_entry["status"] = json!("skipped_budget");
            }
        }
        state.entries.push(carve_entry);
    }
    Ok(())
}

/// Decode a bundle's blocks-info block (the parallel of
/// the inline path in `inspect_unity_bundle`, kept separate
/// so the census path is untouched). Ok(None) means the
/// blocks-info block itself is LZMA-compressed — the §7.10
/// gap the census path also declines.
fn load_blocks_info(
    reader: &mut RegionReader,
    header: &BundleHeader,
    file_len: u64,
) -> Result<Option<(BlocksInfo, u64)>, FathomError> {
    let compression = header.flags & 0x3F;
    if compression == 1 {
        return Ok(None);
    }
    if !matches!(compression, 0 | 2 | 3) {
        return Err(unsupported(format!(
            "blocks-info compression code {compression} is not implemented (supported: 0 none, 2 LZ4, 3 LZ4HC; 1 LZMA is reported, not decoded)"
        )));
    }
    if header.uncompressed_blocks_info_size as usize > UNITY_BLOCKS_INFO_BYTES_MAX {
        return Err(resource(format!(
            "blocks info declares {} uncompressed bytes, over UNITY_BLOCKS_INFO_BYTES_MAX ({UNITY_BLOCKS_INFO_BYTES_MAX})",
            header.uncompressed_blocks_info_size
        )));
    }
    let blocks_info_offset = if header.blocks_info_at_end {
        if file_len < u64::from(header.compressed_blocks_info_size) {
            return Err(truncated(
                "file is smaller than the blocks-info region at its end",
            ));
        }
        file_len - u64::from(header.compressed_blocks_info_size)
    } else {
        header.data_start
    };
    let stored_info = reader.read_range(
        blocks_info_offset,
        u64::from(header.compressed_blocks_info_size),
    )?;
    let info_bytes = match compression {
        0 => stored_info,
        _ => {
            lz4_flex::block::decompress(&stored_info, header.uncompressed_blocks_info_size as usize)
                .map_err(|error| mismatch(format!("blocks info does not decompress: {error}")))?
        }
    };
    if info_bytes.len() != header.uncompressed_blocks_info_size as usize {
        return Err(mismatch(
            "blocks info decompressed size disagrees with the header declaration",
        ));
    }
    let info = parse_blocks_info(&info_bytes)?;
    let blocks_file_start = if header.blocks_info_at_end {
        header.data_start
    } else {
        blocks_info_offset + u64::from(header.compressed_blocks_info_size)
    };
    Ok(Some((info, blocks_file_start)))
}

/// Extract from a UnityFS bundle target: serialized nodes
/// go through `extract_serialized`, plain nodes are written
/// verbatim, directory nodes are recorded as skipped.
fn extract_from_bundle(
    reader: &mut RegionReader,
    header: &BundleHeader,
    file_len: u64,
    out_dir: &Path,
    state: &mut ExtractState,
    facts: &mut Value,
) -> Result<(), FathomError> {
    facts["container"] = json!("unityfs");
    facts["format_version"] = json!(header.format_version);
    facts["unity_version"] = json!(header.unity_version);
    let Some((info, blocks_file_start)) = load_blocks_info(reader, header, file_len)? else {
        facts["blocks_info_decoded"] = json!(false);
        state.notes.push(
            "blocks info block is LZMA-compressed (readers SPEC §7.10): not decoded by this reader, no extraction performed"
                .to_string(),
        );
        return Ok(());
    };
    facts["blocks_info_decoded"] = json!(true);
    facts["block_count"] = json!(info.blocks.len());
    facts["node_count"] = json!(info.nodes.len());
    if info.nodes.len() > UNITY_NODES_MAX {
        return Err(resource(format!(
            "bundle declares {} nodes, over UNITY_NODES_MAX ({UNITY_NODES_MAX})",
            info.nodes.len()
        )));
    }
    for node in &info.nodes {
        if node.flags & 1 != 0 {
            continue; // directory node: no payload
        }
        let node_data = match node_bytes(reader, blocks_file_start, &info, node) {
            Ok(data) => data,
            Err(message) => {
                state.entries.push(json!({
                    "kind": "node",
                    "node": node.path,
                    "reason": message,
                    "status": "not_extracted",
                }));
                continue;
            }
        };
        if node.flags & 4 != 0 {
            if let Err(error) = extract_serialized(&node.path, &node_data, out_dir, state) {
                state
                    .notes
                    .push(format!("{}: {}", node.path, error.message));
            }
        } else {
            let file_name = safe_file_name(&node.path, "node");
            let mut entry = json!({
                "bytes": node_data.len(),
                "kind": "node_file",
                "node": node.path,
                "status": "not_extracted",
            });
            match write_budgeted(state, out_dir, &file_name, &node_data)? {
                Some(digest) => {
                    entry["bytes_written"] = json!(node_data.len());
                    entry["file"] = json!(file_name);
                    entry["sha256"] = json!(digest);
                    entry["status"] = json!("extracted");
                }
                None => {
                    entry["status"] = json!("skipped_budget");
                }
            }
            state.entries.push(entry);
        }
    }
    Ok(())
}

/// Extract payloads from a UnityFS bundle or a standalone
/// SerializedFile into a caller-named output directory,
/// with a manifest (game-extract lane). TextAsset script
/// bytes verbatim, Texture2D metadata + raw payload
/// (pixels not decoded), MonoBehaviour raw payload plus
/// carved moc3 spans.
#[allow(clippy::too_many_lines)]
pub fn extract_unity_bundle(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let out_dir = paths::validate_output_dir(config, Path::new(require_str(args, "output_dir")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let file = File::open(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target: {error}"),
        )
    })?;
    let mut reader = RegionReader {
        file,
        len: file_len,
    };
    let prefix = reader.read_range(0, file_len.min(HEADER_PREFIX_BYTES))?;
    let mut state = ExtractState {
        entries: Vec::new(),
        notes: Vec::new(),
        written_bytes: 0,
    };
    let mut facts = json!({ "target": path.display().to_string() });
    if prefix.starts_with(b"UnityFS\0") {
        let header = parse_bundle_header(&prefix)?;
        extract_from_bundle(
            &mut reader,
            &header,
            file_len,
            &out_dir,
            &mut state,
            &mut facts,
        )?;
    } else {
        let bytes = reader.read_range(0, file_len)?;
        facts["container"] = json!("serialized_file");
        extract_serialized("standalone", &bytes, &out_dir, &mut state)?;
    }
    let extracted = state
        .entries
        .iter()
        .filter(|entry| entry["status"] == "extracted")
        .count();
    let skipped_budget = state
        .entries
        .iter()
        .filter(|entry| entry["status"] == "skipped_budget")
        .count();
    let carves = state
        .entries
        .iter()
        .filter(|entry| entry["kind"] == "moc3_carve")
        .count();
    let totals = json!({
        "bytes_written": state.written_bytes,
        "carves": carves,
        "entries": state.entries.len(),
        "extracted": extracted,
        "skipped_budget": skipped_budget,
    });
    let manifest = json!({
        "container": facts["container"].clone(),
        "entries": state.entries,
        "notes": state.notes,
        "target": path.display().to_string(),
        "target_sha256": subject_sha256,
        "tool": "extract_unity_bundle",
        "totals": totals,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("extraction manifest does not serialise: {error}")))?;
    write_extracted(&out_dir, "manifest.json", &manifest_bytes)?;
    facts["entries"] = json!(state.entries.len());
    facts["extracted"] = json!(extracted);
    facts["manifest_path"] = json!(out_dir.join("manifest.json").display().to_string());
    facts["output_dir"] = json!(out_dir.display().to_string());
    facts["totals"] = totals;
    let mut evidence = Evidence::new("extract_unity_bundle", "unity");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new("unity_extract", Confidence::Observed, facts));
    for note in &state.notes {
        evidence.add_unknown("extraction", note.clone());
    }
    let exhaustive = state.notes.is_empty()
        && state
            .entries
            .iter()
            .all(|entry| entry["status"] == "extracted");
    evidence.coverage.examined = state.entries.len() as u64;
    evidence.coverage.total = state.entries.len() as u64;
    evidence.coverage.exhaustive = exhaustive;
    match proof::retain_export(config, &subject_sha256, "unity_extract", &manifest) {
        Ok(digest) => {
            evidence.add_finding(Finding::new(
                "unity_extract_export",
                Confidence::Observed,
                json!({ "export_digest": digest }),
            ));
        }
        Err(error) => {
            evidence.add_unknown(
                "retention",
                format!("extraction manifest retention failed: {}", error.message),
            );
        }
    }
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn be32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    /// Build a SerializedFile (version 21, little-endian)
    /// with two types (one MonoBehaviour with a hash) and
    /// three objects. `with_trees` toggles enableTypeTree.
    fn build_sf(with_trees: bool) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        // Metadata (little-endian after the header).
        body.extend_from_slice(b"2021.3.1f1\0"); // unity version
        body.extend_from_slice(&0_u32.to_le_bytes()); // script compat
        body.push(u8::from(with_trees)); // enableTypeTree
        body.extend_from_slice(&2_u32.to_le_bytes()); // type count
        for (class_id, script_index) in [(1_i32, -1_i16), (114, 0)] {
            body.extend_from_slice(&class_id.to_le_bytes());
            body.push(0); // is_stripped
            body.extend_from_slice(&script_index.to_le_bytes());
            if class_id == 114 {
                body.extend_from_slice(&[0x11; 16]); // script id
                body.extend_from_slice(&[0x22; 16]); // type hash
            } else {
                body.extend_from_slice(&[0x33; 16]); // type hash
            }
            if with_trees {
                // Blob tree: node count, string-buffer
                // size, fixed-size nodes, buffer bytes.
                let blob = b"GameObject\0Name\0";
                body.extend_from_slice(&1_u32.to_le_bytes()); // nodes
                body.extend_from_slice(&(blob.len() as u32).to_le_bytes());
                body.extend_from_slice(&1_u16.to_le_bytes()); // version
                body.push(0); // level
                body.push(0); // is_array
                body.extend_from_slice(&0_u32.to_le_bytes()); // type offset
                body.extend_from_slice(&5_u32.to_le_bytes()); // name offset
                body.extend_from_slice(&(-1_i64).to_le_bytes()); // byte size
                body.extend_from_slice(&0_i32.to_le_bytes()); // index
                body.extend_from_slice(&0_i32.to_le_bytes()); // flags
                body.extend_from_slice(&0_u64.to_le_bytes()); // ref hash (v>=18)
                body.extend_from_slice(blob);
                body.extend_from_slice(&0_i32.to_le_bytes()); // type dependencies
            }
        }
        body.extend_from_slice(&3_u32.to_le_bytes()); // object count
        while !body.len().is_multiple_of(4) {
            body.push(0); // object rows start 4-aligned
        }
        for i in 0..3_i64 {
            body.extend_from_slice(&(1000 + i).to_le_bytes()); // path_id
            body.extend_from_slice(&(i as u32 * 16).to_le_bytes()); // byte_start
            body.extend_from_slice(&16_u32.to_le_bytes()); // byte_size
            body.extend_from_slice(&0_i32.to_le_bytes()); // type_index
        }
        let total = 16 + 4 + body.len();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&0_u32.to_be_bytes()); // metadata size
        out.extend_from_slice(&(total as u32).to_be_bytes()); // file size
        out.extend_from_slice(&21_u32.to_be_bytes()); // version
        out.extend_from_slice(&0_u32.to_be_bytes()); // data offset
        out.push(0); // little-endian
        out.extend_from_slice(&[0; 3]);
        out.extend_from_slice(&body);
        assert_eq!(out.len(), total);
        out
    }

    struct BundleOptions {
        blocks_info_at_end: bool,
        blocks_info_compression: u32,
        bundle_size_override: Option<i64>,
        data_block_compression: u32,
        format: u32,
    }

    impl Default for BundleOptions {
        fn default() -> Self {
            BundleOptions {
                blocks_info_at_end: false,
                blocks_info_compression: 2,
                bundle_size_override: None,
                data_block_compression: 2,
                format: 8,
            }
        }
    }

    /// Build a SerializedFile version 22 (little-endian)
    /// with three types and five objects.
    fn build_sf22() -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"2022.3.1f1\0");
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(1); // enableTypeTree
        body.extend_from_slice(&3_u32.to_le_bytes());
        for (class_id, script_index) in [(1_i32, -1_i16), (4, -1), (114, 2)] {
            body.extend_from_slice(&class_id.to_le_bytes());
            body.push(0);
            body.extend_from_slice(&script_index.to_le_bytes());
            if class_id == 114 {
                body.extend_from_slice(&[0x33; 16]);
                body.extend_from_slice(&[0x44; 16]);
            } else {
                body.extend_from_slice(&[0x55; 16]); // type hash
            }
            body.extend_from_slice(&0_u32.to_le_bytes()); // tree nodes: 0
            body.extend_from_slice(&0_u32.to_le_bytes()); // tree blob: 0
            body.extend_from_slice(&0_i32.to_le_bytes()); // type dependencies
        }
        body.extend_from_slice(&5_u32.to_le_bytes());
        while !body.len().is_multiple_of(4) {
            body.push(0); // object rows start 4-aligned
        }
        for i in 0..5_i64 {
            body.extend_from_slice(&(2000 + i).to_le_bytes());
            body.extend_from_slice(&(i as u64 * 32).to_le_bytes()); // byte_start u64
            body.extend_from_slice(&32_u32.to_le_bytes());
            body.extend_from_slice(&0_i32.to_le_bytes());
        }
        // The real version-22 header (48 bytes): legacy
        // u32 fields, endianness byte + reserved, then the
        // extended tail (metadata size, file size, data
        // offset, unknown).
        let total = 48 + body.len();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&0_u32.to_be_bytes()); // legacy metadata size
        out.extend_from_slice(&0_u32.to_be_bytes()); // legacy file size
        out.extend_from_slice(&22_u32.to_be_bytes()); // version
        out.extend_from_slice(&0_u32.to_be_bytes()); // legacy data offset
        out.push(0); // little-endian
        out.extend_from_slice(&[0; 3]); // reserved
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()); // metadata size
        out.extend_from_slice(&(total as i64).to_be_bytes()); // file size
        out.extend_from_slice(&(total as i64).to_be_bytes()); // data offset
        out.extend_from_slice(&0_i64.to_be_bytes()); // unknown
        out.extend_from_slice(&body);
        assert_eq!(out.len(), total);
        out
    }

    /// Build a UnityFS bundle with one data block holding
    /// [serialized file][plain file] node contents.
    fn build_bundle(sf: &[u8], plain: &[u8], options: &BundleOptions) -> Vec<u8> {
        let mut plain_data = sf.to_vec();
        plain_data.extend_from_slice(plain);
        let (block_stored, block_compressed_size) = match options.data_block_compression {
            2 | 3 => {
                let compressed = lz4_flex::block::compress(&plain_data);
                let len = compressed.len() as u32;
                (compressed, len)
            }
            _ => {
                let len = plain_data.len() as u32;
                (plain_data.clone(), len)
            }
        };
        // Blocks info (big-endian).
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&[0xAB; 16]); // data hash
        info.extend_from_slice(&be32(1)); // block count
        info.extend_from_slice(&be32(plain_data.len() as u32));
        info.extend_from_slice(&be32(block_compressed_size));
        info.extend_from_slice(&(options.data_block_compression as u16).to_be_bytes());
        info.extend_from_slice(&be32(2)); // node count
        info.extend_from_slice(&0_i64.to_be_bytes()); // SF offset
        info.extend_from_slice(&(sf.len() as i64).to_be_bytes());
        info.extend_from_slice(&4_u32.to_be_bytes()); // serialized flag
        info.extend_from_slice(b"level0\0");
        info.extend_from_slice(&(sf.len() as i64).to_be_bytes()); // plain offset
        info.extend_from_slice(&(plain.len() as i64).to_be_bytes());
        info.extend_from_slice(&0_u32.to_be_bytes());
        info.extend_from_slice(b"readme.txt\0");
        let (info_stored, info_compressed_size) = match options.blocks_info_compression {
            2 | 3 => {
                let compressed = lz4_flex::block::compress(&info);
                let len = compressed.len() as u32;
                (compressed, len)
            }
            _ => {
                let len = info.len() as u32;
                (info.clone(), len)
            }
        };
        // Header.
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(b"UnityFS\0");
        header.extend_from_slice(&be32(options.format));
        header.extend_from_slice(b"5.x.x\0");
        header.extend_from_slice(b"2021.3.1f1\0");
        let header_len = header.len() + 8 + 4 + 4 + 4;
        let data_start = if options.format >= 7 {
            header_len.div_ceil(16) * 16
        } else {
            header_len
        };
        let total = if options.blocks_info_at_end {
            data_start + block_stored.len() + info_stored.len()
        } else {
            data_start + info_stored.len() + block_stored.len()
        };
        let bundle_size = options.bundle_size_override.unwrap_or(total as i64);
        header.extend_from_slice(&bundle_size.to_be_bytes());
        header.extend_from_slice(&be32(info_compressed_size));
        header.extend_from_slice(&be32(info.len() as u32));
        let mut flags = options.blocks_info_compression | 0x80;
        if options.blocks_info_at_end {
            flags |= 0x40;
        }
        header.extend_from_slice(&be32(flags));
        header.resize(data_start, 0);
        let mut out = header;
        if options.blocks_info_at_end {
            out.extend_from_slice(&block_stored);
            out.extend_from_slice(&info_stored);
        } else {
            out.extend_from_slice(&info_stored);
            out.extend_from_slice(&block_stored);
        }
        out
    }

    fn run(test_name: &str, bytes: &[u8]) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.bundle");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": target.display().to_string()});
        let result = inspect_unity_bundle(&Registry::new(), &config, &args);
        (root, result)
    }

    fn bundle_facts(value: &Value) -> &Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "unity_bundle")
            .map(|finding| &finding["facts"])
            .unwrap()
    }

    fn node_rows(value: &Value) -> &Vec<Value> {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "entries")
            .and_then(|finding| finding["facts"]["entries"].as_array())
            .unwrap()
    }

    #[test]
    fn validation_bundle_with_serialized_file_census() {
        let sf = build_sf(true);
        let bundle = build_bundle(&sf, b"plain text node", &BundleOptions::default());
        let (root, result) = run("unity-bundle", &bundle);
        let value = result.unwrap();
        let facts = bundle_facts(&value);
        assert_eq!(facts["format_version"], 8);
        assert_eq!(facts["blocks_info_compression"], "lz4");
        assert_eq!(facts["blocks_info_decoded"], true);
        assert_eq!(facts["data_hash"], "abababababababababababababababab");
        assert_eq!(facts["node_count"], 2);
        assert_eq!(facts["serialized_file_count"], 1);
        assert_eq!(facts["bundle_size_discrepancy"], false);
        let rows = node_rows(&value);
        assert_eq!(rows[0]["kind"], "serialized_file");
        assert_eq!(rows[0]["status"], "censused");
        let summary = &rows[0]["serialized"];
        assert_eq!(summary["version"], 21);
        assert_eq!(summary["endianness"], "little");
        assert_eq!(summary["type_count"], 2);
        assert_eq!(summary["types"][0]["class_id"], 1);
        assert_eq!(
            summary["types"][0]["type_hash"],
            "33333333333333333333333333333333"
        );
        assert_eq!(summary["types"][1]["class_id"], 114);
        assert_eq!(
            summary["types"][1]["type_hash"],
            "22222222222222222222222222222222"
        );
        assert_eq!(summary["object_count"], 3);
        assert_eq!(summary["objects"][2]["path_id"], 1002);
        assert_eq!(rows[1]["kind"], "file");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_type_trees_absent_also_parses() {
        let sf = build_sf(false);
        let bundle = build_bundle(&sf, b"x", &BundleOptions::default());
        let (root, result) = run("unity-no-trees", &bundle);
        let value = result.unwrap();
        let rows = node_rows(&value);
        assert_eq!(rows[0]["status"], "censused");
        assert_eq!(rows[0]["serialized"]["object_count"], 3);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_standalone_serialized_file() {
        let sf = build_sf(true);
        let (root, result) = run("unity-standalone", &sf);
        let value = result.unwrap();
        let facts = bundle_facts(&value);
        assert_eq!(facts["container"], "serialized_file");
        assert_eq!(facts["serialized_file"]["object_count"], 3);
        assert_eq!(facts["serialized_file"]["type_count"], 2);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_blocks_info_at_end_and_format_6() {
        let sf = build_sf(true);
        let at_end = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                blocks_info_at_end: true,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-at-end", &at_end);
        let value = result.unwrap();
        assert_eq!(node_rows(&value)[0]["status"], "censused");
        fs::remove_dir_all(&root).ok();
        let format6 = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                format: 6,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-format6", &format6);
        let value = result.unwrap();
        assert_eq!(bundle_facts(&value)["format_version"], 6);
        assert_eq!(node_rows(&value)[0]["status"], "censused");
        fs::remove_dir_all(&root).ok();
    }

    // --------------------------------------------------------
    // Adversarial half.
    // --------------------------------------------------------

    #[test]
    fn adversarial_lzma_blocks_info_is_header_only() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                blocks_info_compression: 1,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-lzma-info", &bundle);
        let value = result.unwrap();
        let facts = bundle_facts(&value);
        assert_eq!(facts["blocks_info_compression"], "lzma");
        assert_eq!(facts["blocks_info_decoded"], false);
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|u| u["aspect"] == "node directory")
        );
        assert_eq!(value["coverage"]["exhaustive"], false);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_node_spanning_lzma_block_is_unreadable() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                data_block_compression: 1,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-lzma-block", &bundle);
        let value = result.unwrap();
        let rows = node_rows(&value);
        assert_eq!(rows[0]["status"], "unreadable");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_format_5_is_refused_by_name() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                format: 5,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-format5", &bundle);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("format 5"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_declared_size_discrepancy_is_a_fact_not_a_refusal() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                bundle_size_override: Some(123_456),
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-size-lie", &bundle);
        let value = result.unwrap();
        assert_eq!(bundle_facts(&value)["bundle_size_discrepancy"], true);
        assert_eq!(bundle_facts(&value)["bundle_size_declared"], 123_456);
        assert_eq!(node_rows(&value)[0]["status"], "censused");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_sf_version_23_standalone_refuses() {
        let mut sf = build_sf(true);
        sf[8..12].copy_from_slice(&23_u32.to_be_bytes());
        let (root, result) = run("unity-sf23", &sf);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_unknown_blocks_info_compression_refuses() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                blocks_info_compression: 9,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-bad-compression", &bundle);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains('9'), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_non_unity_file_is_unsupported() {
        let (root, result) = run("unity-junk", b"this is not a unity artifact at all");
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_format7_uncompressed_info_and_directory_node() {
        // Hand-build: format 7, blocks-info compression 0,
        // three nodes (serialized, plain, directory).
        let sf = build_sf(true);
        let mut plain_data = sf.clone();
        plain_data.extend_from_slice(b"plain");
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&[0xCD; 16]);
        info.extend_from_slice(&be32(1));
        info.extend_from_slice(&be32(plain_data.len() as u32));
        info.extend_from_slice(&be32(plain_data.len() as u32));
        info.extend_from_slice(&0_u16.to_be_bytes());
        info.extend_from_slice(&be32(3));
        info.extend_from_slice(&0_i64.to_be_bytes());
        info.extend_from_slice(&(sf.len() as i64).to_be_bytes());
        info.extend_from_slice(&4_u32.to_be_bytes());
        info.extend_from_slice(b"level0\0");
        info.extend_from_slice(&(sf.len() as i64).to_be_bytes());
        info.extend_from_slice(&5_i64.to_be_bytes());
        info.extend_from_slice(&0_u32.to_be_bytes());
        info.extend_from_slice(b"readme.txt\0");
        info.extend_from_slice(&0_i64.to_be_bytes());
        info.extend_from_slice(&0_i64.to_be_bytes());
        info.extend_from_slice(&1_u32.to_be_bytes()); // directory flag
        info.extend_from_slice(b"subdir/\0");
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(b"UnityFS\0");
        header.extend_from_slice(&be32(7));
        header.extend_from_slice(b"5.x.x\0");
        header.extend_from_slice(b"2021.3.1f1\0");
        let header_len = header.len() + 8 + 4 + 4 + 4;
        let data_start = header_len.div_ceil(16) * 16;
        let total = data_start + info.len() + plain_data.len();
        header.extend_from_slice(&(total as i64).to_be_bytes());
        header.extend_from_slice(&be32(info.len() as u32));
        header.extend_from_slice(&be32(info.len() as u32));
        header.extend_from_slice(&be32(0x80));
        header.resize(data_start, 0);
        let mut bundle = header;
        bundle.extend_from_slice(&info);
        bundle.extend_from_slice(&plain_data);
        let (root, result) = run("unity-format7", &bundle);
        let value = result.unwrap();
        assert_eq!(bundle_facts(&value)["format_version"], 7);
        assert_eq!(bundle_facts(&value)["blocks_info_compression"], "none");
        let rows = node_rows(&value);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["status"], "censused");
        assert_eq!(rows[2]["directory"], true);
        assert_eq!(rows[2]["kind"], "file");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_standalone_sf22_three_types_five_objects() {
        let sf = build_sf22();
        let (root, result) = run("unity-sf22", &sf);
        let value = result.unwrap();
        let facts = bundle_facts(&value);
        let summary = &facts["serialized_file"];
        assert_eq!(summary["version"], 22);
        assert_eq!(summary["type_count"], 3);
        assert_eq!(summary["object_count"], 5);
        assert_eq!(summary["objects"][4]["path_id"], 2004);
        assert_eq!(summary["objects_by_class"]["1"], 5);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_sf_version_8_node_is_a_per_node_unknown() {
        let mut sf8 = build_sf(true);
        sf8[8..12].copy_from_slice(&8_u32.to_be_bytes());
        let bundle = build_bundle(&sf8, b"data", &BundleOptions::default());
        let (root, result) = run("unity-sf8-node", &bundle);
        let value = result.unwrap();
        let rows = node_rows(&value);
        assert_eq!(rows[0]["status"], "unreadable");
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|u| u["aspect"] == "serialized files")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_node_count_over_bound_refuses() {
        // Blocks info declaring UNITY_NODES_MAX + 1 nodes.
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&[0xAB; 16]);
        info.extend_from_slice(&be32(0)); // no blocks
        info.extend_from_slice(&be32(100_001));
        let compressed = lz4_flex::block::compress(&info);
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(b"UnityFS\0");
        header.extend_from_slice(&be32(8));
        header.extend_from_slice(b"5.x.x\0");
        header.extend_from_slice(b"2021.3.1f1\0");
        let header_len = header.len() + 8 + 4 + 4 + 4;
        let data_start = header_len.div_ceil(16) * 16;
        let total = data_start + compressed.len();
        header.extend_from_slice(&(total as i64).to_be_bytes());
        header.extend_from_slice(&be32(compressed.len() as u32));
        header.extend_from_slice(&be32(info.len() as u32));
        header.extend_from_slice(&be32(2 | 0x80));
        header.resize(data_start, 0);
        let mut bundle = header;
        bundle.extend_from_slice(&compressed);
        let (root, result) = run("unity-node-cap", &bundle);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceConstraint);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_block_compression_7_names_the_code() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                data_block_compression: 7,
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-comp7", &bundle);
        let value = result.unwrap();
        let rows = node_rows(&value);
        assert_eq!(rows[0]["status"], "unreadable");
        assert!(value["unknowns"].as_array().unwrap().iter().any(|u| {
            u["reason"]
                .as_str()
                .unwrap_or("")
                .contains("compression code 7")
        }));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_node_table_fails_the_census() {
        let sf = build_sf(true);
        let mut bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                blocks_info_at_end: true,
                ..BundleOptions::default()
            },
        );
        // Shrink the file by 3 bytes: the blocks-info region
        // sits at the physical end, so its bytes are cut and
        // the census cannot be established.
        bundle.truncate(bundle.len() - 3);
        let (root, result) = run("unity-truncated", &bundle);
        assert!(result.is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_bundle_size_lying_smaller_is_also_a_fact() {
        let sf = build_sf(true);
        let bundle = build_bundle(
            &sf,
            b"data",
            &BundleOptions {
                bundle_size_override: Some(10),
                ..BundleOptions::default()
            },
        );
        let (root, result) = run("unity-size-small", &bundle);
        let value = result.unwrap();
        assert_eq!(bundle_facts(&value)["bundle_size_discrepancy"], true);
        assert_eq!(bundle_facts(&value)["bundle_size_declared"], 10);
        fs::remove_dir_all(&root).ok();
    }

    /// SerializedFile (v21, little-endian) carrying three
    /// payload objects: a TextAsset whose script is a fake
    /// moc3, a Texture2D, and a MonoBehaviour embedding a
    /// moc3 behind an int32 length prefix.
    fn sf_with_payloads() -> Vec<u8> {
        let mut script = b"MOC3\x05".to_vec();
        script.extend(std::iter::repeat_n(0x11_u8, 100));
        let mut text_asset = Vec::new();
        text_asset.extend_from_slice(&9_i32.to_le_bytes());
        text_asset.extend_from_slice(b"Hero.moc3");
        text_asset.extend_from_slice(&[0, 0, 0]); // align 13 -> 16
        text_asset.extend_from_slice(&(script.len() as i32).to_le_bytes());
        text_asset.extend_from_slice(&script);
        while !text_asset.len().is_multiple_of(4) {
            text_asset.push(0);
        }
        let mut texture = Vec::new();
        texture.extend_from_slice(&7_i32.to_le_bytes());
        texture.extend_from_slice(b"HeroTex");
        texture.push(0); // align 11 -> 12
        for value in [64_i32, 32, 8192, 4, 1] {
            texture.extend_from_slice(&value.to_le_bytes());
        }
        texture.extend(std::iter::repeat_n(0x22_u8, 100));
        let mut moc3 = b"MOC3\x05".to_vec();
        moc3.extend(std::iter::repeat_n(0x33_u8, 1100));
        let mut mono = Vec::new();
        mono.extend_from_slice(&(moc3.len() as i32).to_le_bytes());
        mono.extend_from_slice(&moc3);
        let mut meta = Vec::new();
        meta.extend_from_slice(b"2022.3.0f1\0");
        meta.extend_from_slice(&0_u32.to_le_bytes()); // script compatibility
        meta.push(0); // type tree disabled
        meta.extend_from_slice(&3_u32.to_le_bytes()); // type count
        for class_id in [49_i32, 28] {
            meta.extend_from_slice(&class_id.to_le_bytes());
            meta.push(0); // is_stripped
            meta.extend_from_slice(&(-1_i16).to_le_bytes());
            meta.extend(std::iter::repeat_n(0xEF_u8, 16)); // type hash
        }
        meta.extend_from_slice(&114_i32.to_le_bytes());
        meta.push(0);
        meta.extend_from_slice(&(-1_i16).to_le_bytes());
        meta.extend(std::iter::repeat_n(0xAB_u8, 16)); // script id
        meta.extend(std::iter::repeat_n(0xCD_u8, 16)); // type hash
        meta.extend_from_slice(&3_u32.to_le_bytes()); // object count
        while !meta.len().is_multiple_of(4) {
            meta.push(0); // object rows start 4-aligned
        }
        let sizes = [text_asset.len(), texture.len(), mono.len()];
        let mut start = 0_u32;
        for (index, size) in sizes.iter().enumerate() {
            meta.extend_from_slice(&(index as i64 + 1).to_le_bytes()); // path_id
            meta.extend_from_slice(&start.to_le_bytes());
            meta.extend_from_slice(&(*size as u32).to_le_bytes());
            meta.extend_from_slice(&(index as i32).to_le_bytes()); // type_index
            start += *size as u32;
        }
        let data_offset = 20 + meta.len();
        let total = data_offset + sizes.iter().sum::<usize>();
        let mut out = Vec::new();
        out.extend_from_slice(&0_u32.to_be_bytes()); // metadata size
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&21_u32.to_be_bytes());
        out.extend_from_slice(&(data_offset as u32).to_be_bytes());
        out.push(0); // little-endian
        out.extend_from_slice(&[0, 0, 0]); // reserved
        out.extend_from_slice(&meta);
        out.extend_from_slice(&text_asset);
        out.extend_from_slice(&texture);
        out.extend_from_slice(&mono);
        out
    }

    fn run_extract(
        test_name: &str,
        bytes: &[u8],
    ) -> (PathBuf, PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.assets");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let out_dir = root.join("out");
        let args = json!({
            "output_dir": out_dir.display().to_string(),
            "target": target.display().to_string(),
        });
        let result = extract_unity_bundle(&Registry::new(), &config, &args);
        (root, out_dir, result)
    }

    #[test]
    fn extract_writes_text_asset_texture_and_carved_moc3() {
        let (root, out_dir, result) = run_extract("extract-payloads", &sf_with_payloads());
        let value = result.unwrap();
        let facts = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "unity_extract")
            .map(|finding| finding["facts"].clone())
            .unwrap();
        assert_eq!(facts["totals"]["extracted"], 4);
        assert_eq!(facts["totals"]["carves"], 1);
        let manifest: Value =
            serde_json::from_slice(&fs::read(out_dir.join("manifest.json")).unwrap()).unwrap();
        let entries = manifest["entries"].as_array().unwrap();
        let text = entries
            .iter()
            .find(|entry| entry["class"] == "TextAsset")
            .unwrap();
        assert_eq!(text["detected"], "moc3_magic");
        assert_eq!(text["file"], "standalone/Hero.moc3");
        let written = fs::read(out_dir.join("standalone/Hero.moc3")).unwrap();
        assert!(written.starts_with(b"MOC3\x05"));
        assert_eq!(written.len(), 105);
        let texture = entries
            .iter()
            .find(|entry| entry["class"] == "Texture2D")
            .unwrap();
        assert_eq!(texture["texture"]["width"], 64);
        assert_eq!(texture["texture"]["format_name"], "RGBA32");
        let mono = entries
            .iter()
            .find(|entry| entry["class"] == "MonoBehaviour")
            .unwrap();
        assert_eq!(mono["type_hash"], "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
        let carve = entries
            .iter()
            .find(|entry| entry["kind"] == "moc3_carve")
            .unwrap();
        assert_eq!(carve["length_source"], "int32_at_minus_4");
        assert_eq!(carve["moc3_version"], 5);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_texture_prefix_modern_layout() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&9_i32.to_le_bytes());
        payload.extend_from_slice(b"HeroAtlas");
        payload.extend_from_slice(&[0, 0, 0]); // align 13 -> 16
        payload.extend_from_slice(&4_i32.to_le_bytes()); // forced fallback format
        payload.extend_from_slice(&[0, 1, 0, 0]); // flag bytes + padding
        for value in [8192_i32, 8192, 21845, 0, 25, 14] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        let meta = parse_texture_prefix(&payload, true).unwrap();
        assert_eq!(meta["layout"], "modern");
        assert_eq!(meta["width"], 8192);
        assert_eq!(meta["height"], 8192);
        assert_eq!(meta["format_name"], "BC7");
        assert_eq!(meta["mip_count"], 14);
    }

    #[test]
    fn validation_texture_prefix_unity6_layout_and_empty_font() {
        // The Unity 6000 shape (flag word, then fields
        // with mips-stripped), taken from a shipped file.
        let mut payload = Vec::new();
        payload.extend_from_slice(&4_i32.to_le_bytes());
        payload.extend_from_slice(b"Knob");
        payload.extend_from_slice(&0_i32.to_le_bytes()); // alpha-optional + padding
        for value in [64_i32, 64, 21844, 0, 4, 7] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        let meta = parse_texture_prefix(&payload, true).unwrap();
        assert_eq!(meta["layout"], "unity6");
        assert_eq!(meta["width"], 64);
        assert_eq!(meta["format_name"], "RGBA32");
        assert_eq!(meta["mip_count"], 7);
        // A runtime-generated font atlas serializes as a
        // consistent empty texture (0x0, no image data).
        let mut payload = Vec::new();
        payload.extend_from_slice(&12_i32.to_le_bytes());
        payload.extend_from_slice(b"Font Texture");
        payload.extend_from_slice(&0_i32.to_le_bytes()); // alpha-optional + padding
        for value in [0_i32, 0, 0, 0, 4, 1] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        let meta = parse_texture_prefix(&payload, true).unwrap();
        assert_eq!(meta["width"], 0);
        assert_eq!(meta["height"], 0);
    }

    #[test]
    fn adversarial_texture_prefix_rejects_absurd_fields() {
        // Mirrors a shipped-file trap seen in the corpus:
        // fields that line up as a plausible legacy read
        // but carry an impossible format/mip combination.
        let mut payload = Vec::new();
        payload.extend_from_slice(&9_i32.to_le_bytes());
        payload.extend_from_slice(b"blowImage");
        payload.extend_from_slice(&[0, 0, 0]);
        for value in [4_i32, 256, 794, 794, 1891308] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        assert!(parse_texture_prefix(&payload, true).is_none());
    }

    #[test]
    fn extract_refuses_output_dir_outside_roots() {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-extract-outside",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.assets");
        fs::write(&target, sf_with_payloads()).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let outside =
            std::env::temp_dir().join(format!("fathom-extract-outside-{}", std::process::id()));
        let args = json!({
            "output_dir": outside.display().to_string(),
            "target": target.display().to_string(),
        });
        let result = extract_unity_bundle(&Registry::new(), &config, &args);
        assert!(result.is_err());
        assert!(!outside.exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn extract_truncated_serialized_file_fails_closed() {
        let bytes = sf_with_payloads();
        let (root, out_dir, result) = run_extract("extract-truncated", &bytes[..40]);
        assert!(result.is_err());
        assert!(!out_dir.join("manifest.json").exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn carve_falls_back_when_length_prefix_lies() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&9_999_999_i32.to_le_bytes());
        payload.extend_from_slice(b"MOC3\x05");
        payload.extend(std::iter::repeat_n(0x44_u8, 50));
        let spans = carve_moc3_spans(&payload, true);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].0, 4);
        assert_eq!(spans[0].2, "to_end_of_payload");
    }

    #[test]
    fn serialized_bytes_reject_negative_length() {
        let bytes = (-3_i32).to_le_bytes();
        let mut position = 0;
        assert!(read_serialized_bytes(&bytes, &mut position, true).is_none());
    }

    #[test]
    fn safe_file_name_flattens_paths() {
        assert_eq!(safe_file_name("a/b\\c:d", "x"), "a_b_c_d");
        assert_eq!(safe_file_name("..", "fallback"), "fallback");
        assert_eq!(safe_file_name("Hero.moc3", "x"), "Hero.moc3");
    }

    // ---------------------------------------------------------
    // MonoBehaviour census (BQ-2)
    // ---------------------------------------------------------

    fn mb_i16(out: &mut Vec<u8>, value: i16, little: bool) {
        if little {
            out.extend_from_slice(&value.to_le_bytes());
        } else {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn mb_i32(out: &mut Vec<u8>, value: i32, little: bool) {
        if little {
            out.extend_from_slice(&value.to_le_bytes());
        } else {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn mb_i64(out: &mut Vec<u8>, value: i64, little: bool) {
        if little {
            out.extend_from_slice(&value.to_le_bytes());
        } else {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn mb_u32(out: &mut Vec<u8>, value: u32, little: bool) {
        if little {
            out.extend_from_slice(&value.to_le_bytes());
        } else {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn mb_aligned_string(out: &mut Vec<u8>, text: &str, little: bool) {
        mb_i32(out, text.len() as i32, little);
        out.extend_from_slice(text.as_bytes());
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    /// One object row of the census fixture: (path id,
    /// class id, payload). Class 114 rows are type index 0
    /// and 115 rows type index 1, matching the fixed type
    /// table the builder writes.
    struct MbFixtureObject {
        class_id: i64,
        path_id: i64,
        payload: Vec<u8>,
    }

    /// A version-22 SerializedFile with type trees disabled
    /// (the shipped-build shape): types 114 + 115, the given
    /// objects, an empty script-types section, and the given
    /// externals (full paths; the parser keeps base names).
    fn mb_build_sf(little: bool, objects: &[MbFixtureObject], externals: &[&str]) -> Vec<u8> {
        let mut meta: Vec<u8> = Vec::new();
        meta.extend_from_slice(b"2022.3.0f1\0"); // unity version
        mb_u32(&mut meta, 0, little); // script compatibility
        meta.push(0); // type trees disabled
        mb_u32(&mut meta, 2, little); // type count
        for (index, class_id) in [CLASS_MONO_BEHAVIOUR, CLASS_MONO_SCRIPT].iter().enumerate() {
            mb_i32(&mut meta, *class_id as i32, little);
            meta.push(0); // is_stripped
            mb_i16(&mut meta, index as i16, little); // script type index
            if *class_id == CLASS_MONO_BEHAVIOUR {
                meta.extend_from_slice(&[0x51; 16]); // script id
            }
            meta.extend_from_slice(&[0x52; 16]); // type hash
        }
        mb_u32(&mut meta, objects.len() as u32, little);
        let mut start: u64 = 0;
        for object in objects {
            while !meta.len().is_multiple_of(4) {
                meta.push(0);
            }
            mb_i64(&mut meta, object.path_id, little);
            // byte_start is a u64 in the file's endianness.
            if little {
                mb_u32(&mut meta, start as u32, little);
                mb_u32(&mut meta, 0, little);
            } else {
                mb_u32(&mut meta, 0, little);
                mb_u32(&mut meta, start as u32, little);
            }
            start += object.payload.len() as u64;
            mb_u32(&mut meta, object.payload.len() as u32, little);
            mb_i32(
                &mut meta,
                if object.class_id == CLASS_MONO_SCRIPT {
                    1
                } else {
                    0
                },
                little,
            );
        }
        mb_i32(&mut meta, 0, little); // script types: none
        mb_i32(&mut meta, externals.len() as i32, little);
        for path in externals {
            meta.extend_from_slice(b"\0"); // temp_empty
            meta.extend_from_slice(&[0x53; 16]); // guid
            mb_i32(&mut meta, 0, little); // type
            meta.extend_from_slice(path.as_bytes());
            meta.push(0);
        }
        let data_offset = 48 + meta.len() as u64;
        let file_size = data_offset + start;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        out.extend_from_slice(&(file_size as u32).to_be_bytes());
        out.extend_from_slice(&22_u32.to_be_bytes());
        out.extend_from_slice(&(data_offset as u32).to_be_bytes());
        out.push(if little { 0 } else { 1 });
        out.extend_from_slice(&[0; 3]);
        // Extended tail (the layout parse_serialized_file
        // verifies): u32 metadata size at 20, i64 file size
        // at 24, i64 data offset at 32, i64 unknown at 40.
        out.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        out.extend_from_slice(&file_size.to_be_bytes());
        out.extend_from_slice(&data_offset.to_be_bytes());
        out.extend_from_slice(&0_i64.to_be_bytes());
        out.extend_from_slice(&meta);
        for object in objects {
            out.extend_from_slice(&object.payload);
        }
        out
    }

    fn mb_script_payload(class: &str, namespace: &str, assembly: &str, little: bool) -> Vec<u8> {
        let mut out = Vec::new();
        mb_aligned_string(&mut out, class, little); // m_Name mirrors the class in fixtures
        mb_i32(&mut out, 0, little); // m_ExecutionOrder
        out.extend_from_slice(&[0; 16]); // m_PropertiesHash
        mb_aligned_string(&mut out, class, little);
        mb_aligned_string(&mut out, namespace, little);
        mb_aligned_string(&mut out, assembly, little);
        out.push(0); // m_IsEditorScript
        out
    }

    fn mb_behaviour_payload(
        script_file: i32,
        script_path: i64,
        extra: &[u8],
        little: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        mb_i32(&mut out, 0, little); // m_GameObject file index
        mb_i64(&mut out, 4242, little); // m_GameObject path id
        out.push(1); // m_Enabled
        out.extend_from_slice(&[0; 3]); // alignment to offset 16
        mb_i32(&mut out, script_file, little);
        mb_i64(&mut out, script_path, little);
        mb_aligned_string(&mut out, "", little); // m_Name
        out.extend_from_slice(extra);
        out
    }

    fn mb_run_census(dir: &Path) -> Value {
        let cfg = format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            dir.join("state"),
            dir
        );
        let config = Config::from_toml_str(&cfg).unwrap();
        census_unity_monobehaviours(
            &Registry::new(),
            &config,
            &json!({"target": dir.to_string_lossy()}),
        )
        .unwrap()
    }

    fn mb_record(value: &Value) -> &Value {
        &value["findings"][0]["facts"]
    }

    fn mb_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fathom-mb-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mb_census_resolves_same_file_scripts() {
        let root = mb_temp_dir("same-file");
        let objects = vec![
            MbFixtureObject {
                class_id: CLASS_MONO_SCRIPT,
                path_id: 100,
                payload: mb_script_payload("Widget", "Game", "Assembly-CSharp", true),
            },
            MbFixtureObject {
                class_id: CLASS_MONO_BEHAVIOUR,
                path_id: 1,
                payload: mb_behaviour_payload(0, 100, &[7; 7], true),
            },
            MbFixtureObject {
                class_id: CLASS_MONO_BEHAVIOUR,
                path_id: 2,
                payload: mb_behaviour_payload(0, 100, &[7; 7], true),
            },
            MbFixtureObject {
                class_id: CLASS_MONO_BEHAVIOUR,
                path_id: 3,
                payload: mb_behaviour_payload(0, 0, &[7; 3], true),
            },
        ];
        fs::write(
            root.join("resources.assets"),
            mb_build_sf(true, &objects, &[]),
        )
        .unwrap();
        let value = mb_run_census(&root);
        let record = mb_record(&value);
        assert_eq!(record["totals"]["monobehaviours"], 3);
        assert_eq!(record["totals"]["monoscripts"], 1);
        assert_eq!(record["totals"]["null_script_references"], 1);
        assert_eq!(record["totals"]["unresolved_script_references"], 0);
        // All three headers parse, so all three payloads
        // count — including the null-script behaviour's 3.
        assert_eq!(record["totals"]["payload_bytes_after_header"], 17);
        assert_eq!(record["header_anomaly_count"], 0);
        assert_eq!(record["distinct_script_classes"], 1);
        assert_eq!(record["counts_by_script_class"][0]["class"], "Widget");
        assert_eq!(record["counts_by_script_class"][0]["count"], 2);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mb_census_resolves_cross_file_scripts() {
        let root = mb_temp_dir("cross-file");
        let level = vec![MbFixtureObject {
            class_id: CLASS_MONO_BEHAVIOUR,
            path_id: 9,
            payload: mb_behaviour_payload(1, 55, &[1; 4], true),
        }];
        fs::write(
            root.join("level0"),
            mb_build_sf(true, &level, &["resources.assets"]),
        )
        .unwrap();
        let resources = vec![MbFixtureObject {
            class_id: CLASS_MONO_SCRIPT,
            path_id: 55,
            payload: mb_script_payload("Hud", "", "Assembly-CSharp", true),
        }];
        fs::write(
            root.join("resources.assets"),
            mb_build_sf(true, &resources, &[]),
        )
        .unwrap();
        let value = mb_run_census(&root);
        let record = mb_record(&value);
        assert_eq!(record["totals"]["monobehaviours"], 1);
        assert_eq!(record["totals"]["unresolved_script_references"], 0);
        assert_eq!(record["counts_by_script_class"][0]["class"], "Hud");
        assert_eq!(record["counts_by_script_class"][0]["count"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mb_census_reads_big_endian_files() {
        let root = mb_temp_dir("big-endian");
        let objects = vec![
            MbFixtureObject {
                class_id: CLASS_MONO_SCRIPT,
                path_id: 7,
                payload: mb_script_payload("Dial", "Ui", "Game", false),
            },
            MbFixtureObject {
                class_id: CLASS_MONO_BEHAVIOUR,
                path_id: 8,
                payload: mb_behaviour_payload(0, 7, &[3; 5], false),
            },
        ];
        fs::write(
            root.join("resources.assets"),
            mb_build_sf(false, &objects, &[]),
        )
        .unwrap();
        let value = mb_run_census(&root);
        let record = mb_record(&value);
        assert_eq!(record["totals"]["monobehaviours"], 1);
        assert_eq!(record["counts_by_script_class"][0]["class"], "Dial");
        assert_eq!(record["totals"]["payload_bytes_after_header"], 5);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mb_census_names_a_truncated_header() {
        let root = mb_temp_dir("truncated");
        let objects = vec![MbFixtureObject {
            class_id: CLASS_MONO_BEHAVIOUR,
            path_id: 1,
            payload: vec![0; 10],
        }];
        fs::write(
            root.join("resources.assets"),
            mb_build_sf(true, &objects, &[]),
        )
        .unwrap();
        let value = mb_run_census(&root);
        let record = mb_record(&value);
        assert_eq!(record["totals"]["monobehaviours"], 1);
        assert_eq!(record["header_anomaly_count"], 1);
        assert_eq!(record["distinct_script_classes"], 0);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mb_census_counts_dangling_script_references() {
        let root = mb_temp_dir("dangling");
        let objects = vec![MbFixtureObject {
            class_id: CLASS_MONO_BEHAVIOUR,
            path_id: 1,
            payload: mb_behaviour_payload(0, 999, &[0; 2], true),
        }];
        fs::write(
            root.join("resources.assets"),
            mb_build_sf(true, &objects, &[]),
        )
        .unwrap();
        let value = mb_run_census(&root);
        let record = mb_record(&value);
        assert_eq!(record["totals"]["unresolved_script_references"], 1);
        assert_eq!(
            record["unresolved_script_references"][0]["target"],
            "resources.assets:999"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mb_externals_walk_returns_base_names() {
        let objects = vec![MbFixtureObject {
            class_id: CLASS_MONO_SCRIPT,
            path_id: 1,
            payload: mb_script_payload("A", "", "B", true),
        }];
        let bytes = mb_build_sf(
            true,
            &objects,
            &["Assets/first.assets", "C:\\x\\second.assets"],
        );
        let names = parse_sf_externals(&bytes).unwrap();
        assert_eq!(
            names,
            vec!["first.assets".to_string(), "second.assets".to_string()]
        );
    }
}
