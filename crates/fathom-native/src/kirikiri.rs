//! KiriKiri `.xp3` archive census and extraction (R6).
//!
//! The XP3 layout: an 11-byte magic, a u64 index offset,
//! then entry payloads, and at the index offset a flag
//! byte selecting a plain index (`[u64 size][index]`) or
//! a zlib-compressed index (`[u64 compressed size][u64
//! plain size][zlib stream]`). The index is a sequence
//! of chunks, each `[4-byte type][u64 size][payload]`;
//! `File` chunks carry subchunks of the same shape:
//! `info` (flags, original/stored sizes, UTF-16LE name),
//! `segm` (28-byte segment records: flags — bit 0 =
//! zlib-compressed — absolute offset, original and
//! stored sizes), and `adlr` (a u32 archive hash this
//! reader carries but does not interpret).
//!
//! Extraction concatenates an entry's segments in
//! order, inflating flagged segments, and writes only
//! when the produced length equals the declared
//! original size. Entries whose info flags mark them
//! protected are recorded, never written: protection is
//! a title-specific obfuscation with no honest generic
//! decode.
//!
//! Corpus note: no .xp3 archive exists in the moved
//! corpus tree, so this reader is proven by synthetic
//! fixtures built to the format (stored + zlib segments,
//! compressed index) and the absence is recorded in the
//! programme report rather than papered over.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, sha256_hex, subject_for_file_with_bound,
};
use fathom_core::limits::{
    GAME_EXTRACT_BYTES_MAX, PAK_TARGET_BYTES_MAX, XP3_ENTRIES_MAX, XP3_INDEX_BYTES_MAX,
    XP3_SEGMENTS_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

const XP3_MAGIC: &[u8; 11] = b"XP3\x0d\x0a\x20\x0a\x1a\x8b\x67\x01";

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

/// One segment of one entry.
#[derive(Clone)]
struct Segment {
    /// Whether the segment payload is zlib-compressed.
    compressed: bool,
    /// Absolute file offset of the stored bytes.
    offset: u64,
    /// Declared decompressed size.
    original_size: u64,
    /// Declared stored size.
    stored_size: u64,
}

/// One index entry.
struct Entry {
    /// The adlr hash word, carried uninterpreted.
    hash: Option<u32>,
    /// Entry name as declared (UTF-16LE in the index).
    name: String,
    /// Declared total decompressed size.
    original_size: u64,
    /// Whether the info flags mark the entry protected.
    protected: bool,
    /// Segments in content order.
    segments: Vec<Segment>,
    /// Declared total stored size.
    stored_size: u64,
}

/// The shared parse both handlers consume.
struct Parsed {
    /// Entries in index order.
    entries: Vec<Entry>,
    /// Whether the index itself was zlib-compressed.
    index_compressed: bool,
}

fn read_exact_at(file: &mut File, offset: u64, count: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| mismatch(format!("cannot seek xp3: {error}")))?;
    let mut buffer = vec![0u8; count];
    file.read_exact(&mut buffer)
        .map_err(|error| mismatch(format!("cannot read xp3: {error}")))?;
    Ok(buffer)
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Walk `[type][u64 size][payload]` chunks inside
/// `bytes`, invoking `visit` for each; sizes must tile
/// the buffer exactly.
fn walk_chunks(bytes: &[u8], mut visit: impl FnMut(&str, &[u8]) -> Result<()>) -> Result<()> {
    let mut pos = 0usize;
    while pos < bytes.len() {
        let header = bytes
            .get(pos..pos + 12)
            .ok_or_else(|| mismatch("xp3 chunk header is truncated".into()))?;
        let kind = std::str::from_utf8(&header[0..4])
            .map_err(|_| mismatch("xp3 chunk type is not ASCII".into()))?;
        let size =
            u64_at(header, 4).ok_or_else(|| mismatch("xp3 chunk size is unreadable".into()))?;
        let end = pos
            .checked_add(12)
            .and_then(|p| p.checked_add(size as usize))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| mismatch(format!("xp3 chunk {kind} overruns its container")))?;
        visit(kind, &bytes[pos + 12..end])?;
        pos = end;
    }
    Ok(())
}

/// Parse one File chunk's subchunks into an entry.
fn parse_file_chunk(payload: &[u8]) -> Result<Entry> {
    let mut entry = Entry {
        hash: None,
        name: String::new(),
        original_size: 0,
        protected: false,
        segments: Vec::new(),
        stored_size: 0,
    };
    let mut saw_info = false;
    walk_chunks(payload, |kind, body| {
        match kind {
            "info" => {
                // u32 flags, u64 original, u64 stored,
                // u16 name length (UTF-16 units), name.
                let flags = u32_at(body, 0)
                    .ok_or_else(|| mismatch("xp3 info subchunk is truncated".into()))?;
                entry.protected = flags & 0x01 != 0;
                entry.original_size = u64_at(body, 4)
                    .ok_or_else(|| mismatch("xp3 info sizes are truncated".into()))?;
                entry.stored_size = u64_at(body, 12)
                    .ok_or_else(|| mismatch("xp3 info sizes are truncated".into()))?;
                let name_units = body
                    .get(20..22)
                    .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
                    .ok_or_else(|| mismatch("xp3 info name is truncated".into()))?
                    as usize;
                let name_bytes = body
                    .get(22..22 + name_units * 2)
                    .ok_or_else(|| mismatch("xp3 info name overruns its subchunk".into()))?;
                let words: Vec<u16> = name_bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                let name = String::from_utf16(&words)
                    .map_err(|_| mismatch("xp3 entry name is not UTF-16".into()))?;
                entry.name = name.strip_suffix('\0').unwrap_or(&name).to_string();
                saw_info = true;
            }
            "segm" => {
                if body.len() % 28 != 0 {
                    return Err(mismatch("xp3 segm subchunk is not 28-byte tiled".into()));
                }
                if body.len() / 28 > XP3_SEGMENTS_MAX {
                    return Err(mismatch("xp3 entry segment count exceeds the bound".into()));
                }
                for record in body.as_chunks::<28>().0 {
                    entry.segments.push(Segment {
                        compressed: u32_at(record, 0).unwrap_or(0) & 0x01 != 0,
                        offset: u64_at(record, 4).unwrap_or(0),
                        original_size: u64_at(record, 12).unwrap_or(0),
                        stored_size: u64_at(record, 20).unwrap_or(0),
                    });
                }
            }
            "adlr" => {
                entry.hash = u32_at(body, 0);
            }
            _ => {}
        }
        Ok(())
    })?;
    if !saw_info {
        return Err(mismatch("xp3 File chunk carries no info subchunk".into()));
    }
    Ok(entry)
}

/// Parse the header and index of the archive at `path`.
fn parse_archive(path: &Path, file_len: u64) -> Result<Parsed> {
    let mut file =
        File::open(path).map_err(|error| mismatch(format!("cannot open xp3 archive: {error}")))?;
    let header = read_exact_at(&mut file, 0, 19)?;
    if &header[0..11] != XP3_MAGIC {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target lacks the XP3 magic",
        ));
    }
    let index_offset =
        u64_at(&header, 11).ok_or_else(|| mismatch("xp3 index offset is unreadable".into()))?;
    if index_offset.checked_add(1).is_none_or(|end| end > file_len) {
        return Err(mismatch("xp3 index offset is out of file".into()));
    }
    let flag = read_exact_at(&mut file, index_offset, 1)?[0];
    let index = match flag {
        0 => {
            let size = u64_at(&read_exact_at(&mut file, index_offset + 1, 8)?, 0)
                .ok_or_else(|| mismatch("xp3 index size is unreadable".into()))?;
            if size > XP3_INDEX_BYTES_MAX {
                return Err(mismatch("xp3 index exceeds the census bound".into()));
            }
            read_exact_at(&mut file, index_offset + 9, size as usize)?
        }
        1 => {
            let sizes = read_exact_at(&mut file, index_offset + 1, 16)?;
            let compressed_size = u64_at(&sizes, 0)
                .ok_or_else(|| mismatch("xp3 index sizes are unreadable".into()))?;
            let plain_size = u64_at(&sizes, 8)
                .ok_or_else(|| mismatch("xp3 index sizes are unreadable".into()))?;
            if plain_size > XP3_INDEX_BYTES_MAX {
                return Err(mismatch("xp3 index exceeds the census bound".into()));
            }
            let stored = read_exact_at(&mut file, index_offset + 17, compressed_size as usize)?;
            let mut decoder = flate2::read::ZlibDecoder::new(&stored[..]);
            let mut plain = Vec::new();
            decoder
                .by_ref()
                .take(XP3_INDEX_BYTES_MAX + 1)
                .read_to_end(&mut plain)
                .map_err(|error| mismatch(format!("xp3 index does not inflate: {error}")))?;
            if plain.len() as u64 != plain_size {
                return Err(mismatch(
                    "xp3 inflated index size disagrees with its header".into(),
                ));
            }
            plain
        }
        other => {
            return Err(mismatch(format!(
                "xp3 index flag {other} is not a supported form"
            )));
        }
    };
    let mut entries = Vec::new();
    walk_chunks(&index, |kind, payload| {
        if kind == "File" {
            if entries.len() >= XP3_ENTRIES_MAX {
                return Err(mismatch("xp3 entry count exceeds the census bound".into()));
            }
            entries.push(parse_file_chunk(payload)?);
        }
        Ok(())
    })?;
    Ok(Parsed {
        entries,
        index_compressed: flag == 1,
    })
}

fn entry_row(entry: &Entry) -> Value {
    json!({
        "compressed_segments": entry.segments.iter().filter(|s| s.compressed).count(),
        "hash": entry.hash,
        "name": entry.name,
        "original_size": entry.original_size,
        "protected": entry.protected,
        "segments": entry.segments.len(),
        "stored_size": entry.stored_size,
    })
}

pub fn inspect_xp3_archive(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, PAK_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut evidence = Evidence::new("inspect_xp3_archive", "kirikiri");
    evidence.subject = Some(subject);
    let parsed = parse_archive(&path, file_len)?;
    let rows: Vec<Value> = parsed.entries.iter().map(entry_row).collect();
    let document = json!({
        "entries": rows,
        "index_compressed": parsed.index_compressed,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "xp3_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "xp3_archive",
        Confidence::Observed,
        json!({
            "entries": parsed.entries.len(),
            "export_digest": digest,
            "format": "KiriKiri XP3",
            "index_compressed": parsed.index_compressed,
            "target_sha256": sha256,
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows.len(), "total": rows.len()}),
    ));
    if parsed.entries.iter().any(|entry| entry.protected) {
        evidence.add_unknown(
            "protected entries",
            "protected entries are listed but their payload obfuscation is title-specific and not decoded",
        );
    }
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

/// Validate an entry name into a safe relative path:
/// both separators split, absolute forms and `..`
/// segments refuse the entry.
fn safe_entry_relpath(name: &str) -> Option<PathBuf> {
    let normalized = name.replace('\\', "/");
    let mut relative = PathBuf::new();
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        relative.push(segment);
    }
    if relative.as_os_str().is_empty() {
        None
    } else {
        Some(relative)
    }
}

/// Write `bytes` to `destination` atomically.
fn write_atomic(destination: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
    }
    let temp = destination.with_extension("partial");
    {
        let mut file = File::create(&temp)
            .map_err(|error| mismatch(format!("cannot create output file: {error}")))?;
        file.write_all(bytes)
            .map_err(|error| mismatch(format!("cannot write output file: {error}")))?;
    }
    std::fs::rename(&temp, destination)
        .map_err(|error| mismatch(format!("cannot finalise output file: {error}")))?;
    Ok(())
}

/// Read and (if flagged) inflate one segment, verifying
/// its produced length against the declaration.
fn read_segment(file: &mut File, segment: &Segment) -> Result<Vec<u8>> {
    let stored = read_exact_at(file, segment.offset, segment.stored_size as usize)?;
    if !segment.compressed {
        if stored.len() as u64 != segment.original_size {
            return Err(mismatch("xp3 stored segment size disagrees".into()));
        }
        return Ok(stored);
    }
    let mut decoder = flate2::read::ZlibDecoder::new(&stored[..]);
    let mut plain = Vec::new();
    decoder
        .by_ref()
        .take(segment.original_size + 1)
        .read_to_end(&mut plain)
        .map_err(|error| mismatch(format!("xp3 segment does not inflate: {error}")))?;
    if plain.len() as u64 != segment.original_size {
        return Err(mismatch(
            "xp3 inflated segment size disagrees with its record".into(),
        ));
    }
    Ok(plain)
}

pub fn extract_xp3_archive(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let output_arg = require_str(args, "output_dir")?;
    let output_dir = paths::validate_output_dir(config, Path::new(output_arg))?;
    let subject = subject_for_file_with_bound(&path, PAK_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut evidence = Evidence::new("extract_xp3_archive", "kirikiri");
    evidence.subject = Some(subject);
    let parsed = parse_archive(&path, file_len)?;
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open xp3 archive: {error}")))?;
    std::fs::create_dir_all(&output_dir)
        .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
    let mut rows: Vec<Value> = Vec::new();
    let mut counts: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    let mut spent: u64 = 0;
    for entry in &parsed.entries {
        let mut row = json!({
            "name": entry.name,
            "original_size": entry.original_size,
        });
        let finish = |rows: &mut Vec<Value>,
                      counts: &mut std::collections::BTreeMap<&str, u64>,
                      row: &mut Value,
                      status: &'static str| {
            row["status"] = json!(status);
            *counts.entry(status).or_insert(0) += 1;
            rows.push(std::mem::take(row));
        };
        if entry.protected {
            finish(&mut rows, &mut counts, &mut row, "protected");
            continue;
        }
        let Some(relative) = safe_entry_relpath(&entry.name) else {
            finish(&mut rows, &mut counts, &mut row, "refused_path");
            continue;
        };
        if spent + entry.original_size > GAME_EXTRACT_BYTES_MAX {
            finish(&mut rows, &mut counts, &mut row, "skipped_budget");
            continue;
        }
        // Bounds: every segment must sit inside the file.
        let in_bounds = entry.segments.iter().all(|segment| {
            segment
                .offset
                .checked_add(segment.stored_size)
                .is_some_and(|end| end <= file_len)
        });
        if !in_bounds {
            finish(&mut rows, &mut counts, &mut row, "unreadable");
            continue;
        }
        let mut content: Vec<u8> = Vec::new();
        let mut failed = false;
        for segment in &entry.segments {
            match read_segment(&mut file, segment) {
                Ok(part) => content.extend_from_slice(&part),
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if failed || content.len() as u64 != entry.original_size {
            finish(&mut rows, &mut counts, &mut row, "unreadable");
            continue;
        }
        let destination = output_dir.join(&relative);
        match write_atomic(&destination, &content) {
            Ok(()) => {
                spent += entry.original_size;
                row["bytes"] = json!(content.len());
                row["path"] = json!(relative.display().to_string());
                row["sha256"] = json!(sha256_hex(&content));
                finish(&mut rows, &mut counts, &mut row, "extracted");
            }
            Err(_) => finish(&mut rows, &mut counts, &mut row, "unreadable"),
        }
    }
    let totals = json!({
        "entries": parsed.entries.len(),
        "extracted": counts.get("extracted").copied().unwrap_or(0),
        "protected": counts.get("protected").copied().unwrap_or(0),
        "refused_path": counts.get("refused_path").copied().unwrap_or(0),
        "skipped_budget": counts.get("skipped_budget").copied().unwrap_or(0),
        "unreadable": counts.get("unreadable").copied().unwrap_or(0),
    });
    let manifest = json!({
        "entries": rows,
        "format": "KiriKiri XP3",
        "notes": [
            "entry content is the concatenation of its segments in index order; inflated segments must produce exactly their declared size",
            "protected entries are recorded, never written; their obfuscation is title-specific",
        ],
        "source_sha256": sha256,
        "totals": totals,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("cannot serialise manifest: {error}")))?;
    std::fs::write(output_dir.join("manifest.json"), &manifest_bytes)
        .map_err(|error| mismatch(format!("cannot write manifest: {error}")))?;
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "xp3_extract", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "xp3_extract",
        Confidence::Observed,
        json!({
            "bytes_written": spent,
            "entries": parsed.entries.len(),
            "export_digest": digest,
            "extracted": counts.get("extracted").copied().unwrap_or(0),
            "format": "KiriKiri XP3",
            "output_dir": output_dir.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({
            "entries": manifest["entries"],
            "returned": parsed.entries.len(),
            "total": parsed.entries.len(),
        }),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "manifest retention failed ({note}); the on-disk manifest stands, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_chunk(out: &mut Vec<u8>, kind: &str, payload: &[u8]) {
        out.extend_from_slice(kind.as_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(payload);
    }

    fn file_chunk(name: &str, segments: &[Segment], protected: bool) -> Vec<u8> {
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&(if protected { 1u32 } else { 0u32 }).to_le_bytes());
        let original: u64 = segments.iter().map(|s| s.original_size).sum();
        let stored: u64 = segments.iter().map(|s| s.stored_size).sum();
        info.extend_from_slice(&original.to_le_bytes());
        info.extend_from_slice(&stored.to_le_bytes());
        let units: Vec<u16> = name.encode_utf16().collect();
        info.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for unit in units {
            info.extend_from_slice(&unit.to_le_bytes());
        }
        let mut segm: Vec<u8> = Vec::new();
        for segment in segments {
            segm.extend_from_slice(&(if segment.compressed { 1u32 } else { 0u32 }).to_le_bytes());
            segm.extend_from_slice(&segment.offset.to_le_bytes());
            segm.extend_from_slice(&segment.original_size.to_le_bytes());
            segm.extend_from_slice(&segment.stored_size.to_le_bytes());
        }
        let mut out: Vec<u8> = Vec::new();
        push_chunk(&mut out, "info", &info);
        push_chunk(&mut out, "segm", &segm);
        push_chunk(&mut out, "adlr", &7u32.to_le_bytes());
        out
    }

    /// Build an archive with two entries: one stored,
    /// one zlib segment; plain index.
    fn build_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let plain = b"hello xp3 world".to_vec();
        let packed_plain = b"zlib segment content, zlib segment content".to_vec();
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&packed_plain).expect("compress");
        let packed = encoder.finish().expect("finish");
        // Layout: header 19 bytes (magic 11 + offset 8),
        // payloads, then index. Offsets are patched once
        // positions are known: build payloads first at
        // their final positions.
        let header_len = 19u64;
        let plain_off = header_len;
        let packed_off = plain_off + plain.len() as u64;
        let index_off = packed_off + packed.len() as u64;
        let seg_plain = Segment {
            compressed: false,
            offset: plain_off,
            original_size: plain.len() as u64,
            stored_size: plain.len() as u64,
        };
        let seg_packed = Segment {
            compressed: true,
            offset: packed_off,
            original_size: packed_plain.len() as u64,
            stored_size: packed.len() as u64,
        };
        let mut index: Vec<u8> = Vec::new();
        push_chunk(
            &mut index,
            "File",
            &file_chunk("data/plain.txt", &[seg_plain], false),
        );
        push_chunk(
            &mut index,
            "File",
            &file_chunk("data/packed.txt", &[seg_packed], false),
        );
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(XP3_MAGIC);
        out.extend_from_slice(&index_off.to_le_bytes());
        out.extend_from_slice(&plain);
        out.extend_from_slice(&packed);
        out.push(0); // plain index flag
        out.extend_from_slice(&(index.len() as u64).to_le_bytes());
        out.extend_from_slice(&index);
        (out, plain, packed_plain)
    }

    fn write_temp(bytes: &[u8], tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fathom-xp3-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("fixture.xp3");
        std::fs::write(&path, bytes).expect("write fixture");
        path
    }

    #[test]
    fn validation_parse_two_entries() {
        let (bytes, plain, packed_plain) = build_fixture();
        let path = write_temp(&bytes, "parse");
        let parsed = parse_archive(&path, bytes.len() as u64).expect("parse");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "data/plain.txt");
        assert_eq!(parsed.entries[0].original_size, plain.len() as u64);
        assert_eq!(parsed.entries[1].original_size, packed_plain.len() as u64);
        assert_eq!(parsed.entries[1].segments.len(), 1);
        assert!(parsed.entries[1].segments[0].compressed);
        assert_eq!(parsed.entries[0].hash, Some(7));
    }

    #[test]
    fn validation_segments_reconstruct_content() {
        let (bytes, plain, packed_plain) = build_fixture();
        let path = write_temp(&bytes, "segments");
        let parsed = parse_archive(&path, bytes.len() as u64).expect("parse");
        let mut file = File::open(&path).expect("open");
        let first = read_segment(&mut file, &parsed.entries[0].segments[0]).expect("stored");
        assert_eq!(first, plain);
        let second = read_segment(&mut file, &parsed.entries[1].segments[0]).expect("zlib");
        assert_eq!(second, packed_plain);
    }

    #[test]
    fn adversarial_bad_magic_is_refused() {
        let (mut bytes, _, _) = build_fixture();
        bytes[0] = b'Y';
        let path = write_temp(&bytes, "magic");
        let result = parse_archive(&path, bytes.len() as u64);
        assert!(result.is_err());
    }

    #[test]
    fn adversarial_index_offset_out_of_file_is_refused() {
        let (mut bytes, _, _) = build_fixture();
        bytes[11..19].copy_from_slice(&u64::MAX.to_le_bytes());
        let path = write_temp(&bytes, "offset");
        let result = parse_archive(&path, bytes.len() as u64);
        assert!(result.is_err());
    }

    #[test]
    fn adversarial_traversal_name_is_refused_by_the_path_check() {
        assert!(safe_entry_relpath("../evil.txt").is_none());
        assert!(safe_entry_relpath("data/ok.txt").is_some());
        assert!(safe_entry_relpath("data\\..\\evil.txt").is_none());
    }
}
