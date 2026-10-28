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
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, UNITY_BLOCKS_INFO_BYTES_MAX, UNITY_NODES_MAX, UNITY_OBJECTS_MAX,
    UNITY_TYPES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// Bundle formats implemented (SPEC §7.8).
const BUNDLE_FORMAT_MAX: u32 = 8;
const BUNDLE_FORMAT_MIN: u32 = 6;
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

/// The SerializedFile metadata census (SPEC §7.5).
struct SfSummary {
    endianness: &'static str,
    object_count: u32,
    objects: Vec<Value>,
    objects_by_class: Value,
    objects_truncated: bool,
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
/// uncompressed bytes.
fn parse_serialized_file(bytes: &[u8]) -> Result<SfSummary, FathomError> {
    if bytes.len() < 16 {
        return Err(truncated("serialized file is shorter than its header"));
    }
    let be_u32 = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    let (version, _file_size, _data_offset) = {
        // Version sits at offset 8 for versions < 22; the
        // version-22 header moves file size before it. The
        // version at offset 8 for a v22 file reads as the low
        // half of the i64 file size — so probe: if the
        // offset-8 value is in range AND the offset-4 file
        // size equals the byte length, it is a <22 header;
        // else try the v22 layout.
        let v_early = be_u32(8);
        let size_early = be_u32(4);
        if (SF_VERSION_MIN..=21).contains(&v_early) && u64::from(size_early) == bytes.len() as u64 {
            (v_early, u64::from(size_early), u64::from(be_u32(12)))
        } else if bytes.len() >= 24 {
            let size22 = i64::from_be_bytes(bytes[4..12].try_into().unwrap());
            let v22 = be_u32(12);
            if v22 == 22 && size22 == bytes.len() as i64 {
                (v22, size22 as u64, {
                    i64::from_be_bytes(bytes[16..24].try_into().unwrap()) as u64
                })
            } else if (SF_VERSION_MIN..=SF_VERSION_MAX).contains(&v_early) {
                // Trust the early version read; the size
                // disagreement is the caller's fact, not a
                // parse barrier.
                (v_early, u64::from(size_early), u64::from(be_u32(12)))
            } else {
                return Err(unsupported(format!(
                    "serialized file version cannot be established from the header (offset-8 value {v_early})"
                )));
            }
        } else {
            return Err(unsupported(format!(
                "serialized file version {v_early} is not implemented (supported: {SF_VERSION_MIN}..={SF_VERSION_MAX})"
            )));
        }
    };
    if !(SF_VERSION_MIN..=SF_VERSION_MAX).contains(&version) {
        return Err(unsupported(format!(
            "serialized file version {version} is not implemented (supported: {SF_VERSION_MIN}..={SF_VERSION_MAX})"
        )));
    }
    let header_len = if version >= 22 { 24 } else { 16 };
    let endian_byte = bytes
        .get(header_len)
        .copied()
        .ok_or_else(|| truncated("serialized file ends before the endianness byte"))?;
    let little = endian_byte == 0;
    let mut cursor = SfCursor {
        bytes,
        little,
        position: header_len + 4, // endianness byte + 3 reserved
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
        let (is_stripped, script_type_index) = if version >= 16 {
            (cursor.read_u8()? != 0, cursor.read_i16()?)
        } else {
            (false, -1)
        };
        let type_hash = if version >= 13 && (class_id == 114 || is_stripped || class_id < 0) {
            if class_id == 114 || (version < 16 && class_id < 0) {
                cursor.read_bytes(16)?; // script id
            }
            Some(hex_bytes(cursor.read_bytes(16)?))
        } else {
            None
        };
        if enable_type_tree {
            skip_type_tree(&mut cursor, version)?;
        }
        types.push(json!({
            "class_id": class_id,
            "script_type_index": script_type_index,
            "type_hash": type_hash,
        }));
    }
    let object_count = cursor.read_u32()?;
    let mut objects = Vec::new();
    let mut objects_by_class_map: std::collections::BTreeMap<String, u64> = Default::default();
    let mut objects_truncated = false;
    for index in 0..object_count {
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
        let class_id = if version >= 11 {
            Some(cursor.read_u16()?)
        } else {
            None
        };
        let census_class = match class_id {
            Some(id) => i64::from(id),
            None => types
                .get(usize::try_from(type_index).unwrap_or(usize::MAX))
                .and_then(|row| row["class_id"].as_i64())
                .unwrap_or(-1),
        };
        *objects_by_class_map
            .entry(census_class.to_string())
            .or_insert(0) += 1;
        if version >= 16 {
            cursor.read_i16()?; // script type index (in type row already)
        }
        if (index as usize) < UNITY_OBJECTS_MAX {
            objects.push(json!({
                "byte_size": byte_size,
                "byte_start": byte_start,
                "class_id": class_id,
                "path_id": path_id,
                "type_index": type_index,
            }));
        } else {
            objects_truncated = true;
        }
    }
    let objects_by_class = json!(objects_by_class_map);
    Ok(SfSummary {
        endianness: if little { "little" } else { "big" },
        object_count,
        objects,
        objects_by_class,
        objects_truncated,
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
            }
            if with_trees {
                body.extend_from_slice(&1_u32.to_le_bytes()); // nodes
                body.extend_from_slice(&1_u16.to_le_bytes()); // version
                body.push(0); // level
                body.push(0); // is_array
                body.extend_from_slice(&0_u16.to_le_bytes());
                body.extend_from_slice(&5_u16.to_le_bytes());
                body.extend_from_slice(&(-1_i64).to_le_bytes()); // byte size
                body.extend_from_slice(&0_u32.to_le_bytes()); // index
                body.extend_from_slice(&0_i32.to_le_bytes()); // flags
                body.extend_from_slice(&0_u64.to_le_bytes()); // ref hash (v>=18)
                let blob = b"GameObject\0Name\0";
                body.extend_from_slice(&(blob.len() as u32).to_le_bytes());
                body.extend_from_slice(blob);
            }
        }
        body.extend_from_slice(&3_u32.to_le_bytes()); // object count
        for i in 0..3_i64 {
            body.extend_from_slice(&(1000 + i).to_le_bytes()); // path_id
            body.extend_from_slice(&(i as u32 * 16).to_le_bytes()); // byte_start
            body.extend_from_slice(&16_u32.to_le_bytes()); // byte_size
            body.extend_from_slice(&0_i32.to_le_bytes()); // type_index
            body.extend_from_slice(&1_u16.to_le_bytes()); // class_id
            body.extend_from_slice(&(-1_i16).to_le_bytes()); // script idx
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
            }
            body.extend_from_slice(&0_u32.to_le_bytes()); // tree nodes: 0
            body.extend_from_slice(&0_u32.to_le_bytes()); // tree blob: 0
        }
        body.extend_from_slice(&5_u32.to_le_bytes());
        for i in 0..5_i64 {
            body.extend_from_slice(&(2000 + i).to_le_bytes());
            body.extend_from_slice(&(i as u64 * 32).to_le_bytes()); // byte_start u64
            body.extend_from_slice(&32_u32.to_le_bytes());
            body.extend_from_slice(&0_i32.to_le_bytes());
            body.extend_from_slice(&1_u16.to_le_bytes());
            body.extend_from_slice(&(-1_i16).to_le_bytes());
        }
        let total = 24 + 4 + body.len();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&0_u32.to_be_bytes());
        out.extend_from_slice(&(total as i64).to_be_bytes());
        out.extend_from_slice(&22_u32.to_be_bytes());
        out.extend_from_slice(&0_i64.to_be_bytes());
        out.push(0);
        out.extend_from_slice(&[0; 3]);
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
        assert_eq!(summary["types"][0]["type_hash"], Value::Null);
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
}
