//! GameMaker `data.win` census and audio extraction
//! (R6).
//!
//! A data.win file is a FORM container: an 8-byte header
//! (`FORM` + total size) and a sequence of chunks, each
//! `[4-byte name][u32 size][payload]`. The chunk walk
//! must land exactly at the end of the FORM or the file
//! is refused — a lying chunk size is the classic
//! malformed case and there is no honest partial read.
//!
//! The census reports the chunk table, the GEN8 display
//! and file names (GEN8 string pointers aim at
//! NUL-terminated character data, unlike STRG entries
//! which are length-prefixed — both proven against the
//! corpus), the STRG string count with the strings
//! themselves, and per-chunk entry counts for the
//! chunks that carry the standard count + offset-table
//! shape (SPRT, OBJT, ROOM, SOND, SCPT, FONT, TXTR,
//! BGND, PATH, TMLN, AUDO, GLOB). Chunk payloads beyond
//! those counts are binary structures whose full parse
//! is out of scope; the census says so.
//!
//! Extraction covers the AUDO chunk only: each entry is
//! `[u32 size][audio bytes]` and entry spans derived
//! from the offset table must equal size + 4 exactly.
//! Entries are written verbatim with an extension from
//! their magic (RIFF -> .wav, OggS -> .ogg). Everything
//! else in data.win stays census-only.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, sha256_hex, subject_for_file_with_bound,
};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, GAME_EXTRACT_BYTES_MAX, GM_CHUNKS_MAX, GM_ENTRIES_MAX,
    GM_STRING_BYTES_MAX, GM_STRINGS_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

const FORM_MAGIC: &[u8; 4] = b"FORM";
/// Chunks whose bodies open with a count + offset table.
const COUNTED_CHUNKS: [&str; 12] = [
    "AGRP", "AUDO", "BGND", "FONT", "GLOB", "OBJT", "PATH", "ROOM", "SCPT", "SOND", "SPRT", "TXTR",
];

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

/// One FORM chunk.
struct Chunk {
    /// Body size in bytes (excluding the 8-byte header).
    body_size: u32,
    /// Chunk name (four ASCII bytes).
    name: String,
    /// File offset of the chunk body.
    offset: u64,
}

/// Walk the FORM chunk table, reading headers from
/// the source; the walk must end exactly at the
/// declared FORM end.
fn walk_chunks<R: Read + Seek>(file: &mut R, file_len: u64) -> Result<Vec<Chunk>> {
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|error| mismatch(format!("cannot read data.win header: {error}")))?;
    if &header[0..4] != FORM_MAGIC {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target lacks the GameMaker FORM magic",
        ));
    }
    let declared = u32::from_le_bytes(header[4..8].try_into().unwrap_or([0; 4])) as u64;
    let form_end = declared
        .checked_add(8)
        .ok_or_else(|| mismatch("data.win FORM size overflows".to_string()))?;
    if form_end > file_len {
        return Err(mismatch(format!(
            "data.win FORM declares {declared} bytes but the file is {file_len}"
        )));
    }
    let mut chunks = Vec::new();
    let mut pos: u64 = 8;
    while pos < form_end {
        file.seek(SeekFrom::Start(pos))
            .map_err(|error| mismatch(format!("cannot seek chunk header: {error}")))?;
        let mut chunk_head = [0u8; 8];
        file.read_exact(&mut chunk_head)
            .map_err(|error| mismatch(format!("cannot read chunk header: {error}")))?;
        let name = std::str::from_utf8(&chunk_head[0..4])
            .map_err(|_| mismatch("chunk name is not ASCII".into()))?
            .to_string();
        if !name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Err(mismatch(format!("chunk name {name:?} is not printable")));
        }
        let size = u32::from_le_bytes(chunk_head[4..8].try_into().unwrap_or([0; 4]));
        let next = pos
            .checked_add(8)
            .and_then(|p| p.checked_add(size as u64))
            .ok_or_else(|| mismatch("chunk size overflows".into()))?;
        if next > form_end {
            return Err(mismatch(format!("chunk {name} overruns the FORM end")));
        }
        chunks.push(Chunk {
            body_size: size,
            name,
            offset: pos + 8,
        });
        if chunks.len() > GM_CHUNKS_MAX {
            return Err(mismatch("chunk count exceeds the census bound".into()));
        }
        pos = next;
    }
    if pos != form_end {
        return Err(mismatch("chunk walk does not end at the FORM end".into()));
    }
    Ok(chunks)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .unwrap_or(0)
}

/// Read `count` bytes at `offset`.
fn read_at<R: Read + Seek>(file: &mut R, offset: u64, count: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| mismatch(format!("cannot seek data.win: {error}")))?;
    let mut buffer = vec![0u8; count];
    file.read_exact(&mut buffer)
        .map_err(|error| mismatch(format!("cannot read data.win: {error}")))?;
    Ok(buffer)
}

/// Read a u32 at `offset`.
fn read_u32<R: Read + Seek>(file: &mut R, offset: u64) -> Result<u32> {
    Ok(u32_at(&read_at(file, offset, 4)?, 0))
}

/// Read a NUL-terminated string whose characters start
/// at `offset` (the GEN8 pointer form).
fn read_c_string<R: Read + Seek>(file: &mut R, offset: u64, file_len: u64) -> Result<String> {
    if offset >= file_len {
        return Err(mismatch("GEN8 string pointer is out of file".into()));
    }
    let room = (file_len - offset).min(GM_STRING_BYTES_MAX as u64) as usize;
    let bytes = read_at(file, offset, room)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec())
        .map_err(|_| mismatch("GEN8 string is not UTF-8".into()))
}

/// Read a length-prefixed string at `offset` (the STRG
/// record form): u32 length + bytes (no NUL counted).
fn read_length_string<R: Read + Seek>(file: &mut R, offset: u64, file_len: u64) -> Result<String> {
    let len = read_u32(file, offset)? as u64;
    if len > GM_STRING_BYTES_MAX as u64 || offset + 4 + len > file_len {
        return Err(mismatch("STRG string length is out of bounds".into()));
    }
    let bytes = read_at(file, offset + 4, len as usize)?;
    String::from_utf8(bytes).map_err(|_| mismatch("STRG string is not UTF-8".into()))
}

/// The count + offset table at a chunk body, validated:
/// offsets must be non-decreasing and inside the file.
fn count_table<R: Read + Seek>(
    file: &mut R,
    chunk: &Chunk,
    file_len: u64,
) -> Result<(u32, Vec<u32>)> {
    let count = read_u32(file, chunk.offset)?;
    if count as u64 > GM_ENTRIES_MAX {
        return Err(mismatch(format!(
            "chunk {} declares {count} entries, over the census bound",
            chunk.name
        )));
    }
    let mut offsets = Vec::with_capacity(count as usize);
    let mut previous = 0u32;
    for index in 0..count {
        let at = chunk
            .offset
            .checked_add(4 + (index as u64) * 4)
            .ok_or_else(|| mismatch("offset table overflows".into()))?;
        let value = read_u32(file, at)?;
        if (value as u64) > file_len || (index > 0 && value < previous) {
            return Err(mismatch(format!(
                "chunk {} offset table is not monotone in-file",
                chunk.name
            )));
        }
        previous = value;
        offsets.push(value);
    }
    Ok((count, offsets))
}

/// Facts the two handlers share from one parse.
struct Parsed {
    chunks: Vec<Chunk>,
    counts: Vec<(String, u32)>,
    display_name: Option<String>,
    file_name: Option<String>,
    strings: Vec<String>,
}

fn parse<R: Read + Seek>(file: &mut R, file_len: u64) -> Result<Parsed> {
    let chunks = walk_chunks(file, file_len)?;
    let mut counts = Vec::new();
    let mut display_name = None;
    let mut file_name = None;
    let mut strings = Vec::new();
    for chunk in &chunks {
        if chunk.name == "GEN8" {
            // GEN8: byte 0 is the debugger flag; the
            // display name pointer is at +4 and the file
            // name pointer at +8 (character-data form).
            let display_ptr = read_u32(file, chunk.offset + 4)?;
            let file_ptr = read_u32(file, chunk.offset + 8)?;
            if display_ptr > 0 {
                display_name = read_c_string(file, display_ptr as u64, file_len).ok();
            }
            if file_ptr > 0 {
                file_name = read_c_string(file, file_ptr as u64, file_len).ok();
            }
        }
        if COUNTED_CHUNKS.contains(&chunk.name.as_str()) {
            let (count, _) = count_table(file, chunk, file_len)?;
            counts.push((chunk.name.clone(), count));
        }
        if chunk.name == "STRG" {
            let (count, offsets) = count_table(file, chunk, file_len)?;
            counts.push(("STRG".to_string(), count));
            if count as u64 > GM_STRINGS_MAX {
                return Err(mismatch("STRG count exceeds the census bound".into()));
            }
            for offset in offsets {
                strings.push(read_length_string(file, offset as u64, file_len)?);
            }
        }
    }
    Ok(Parsed {
        chunks,
        counts,
        display_name,
        file_name,
        strings,
    })
}

fn chunk_rows(chunks: &[Chunk]) -> Vec<Value> {
    chunks
        .iter()
        .map(|chunk| json!({"name": chunk.name, "size": chunk.body_size}))
        .collect()
}

pub fn inspect_gamemaker_datawin(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut evidence = Evidence::new("inspect_gamemaker_datawin", "gamemaker");
    evidence.subject = Some(subject);
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open data.win: {error}")))?;
    let parsed = parse(&mut file, file_len)?;
    let counts: Vec<Value> = parsed
        .counts
        .iter()
        .map(|(name, count)| json!({"chunk": name, "entries": count}))
        .collect();
    let document = json!({
        "chunks": chunk_rows(&parsed.chunks),
        "counts": parsed.counts.iter().map(|(n, c)| json!({"chunk": n, "entries": c})).collect::<Vec<_>>(),
        "strings": parsed.strings,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "gamemaker_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "gamemaker_datawin",
        Confidence::Observed,
        json!({
            "chunks": chunk_rows(&parsed.chunks),
            "counts": counts,
            "display_name": parsed.display_name,
            "export_digest": digest,
            "file_name": parsed.file_name,
            "format": "GameMaker data.win (FORM)",
            "string_count": parsed.strings.len(),
            "target_sha256": sha256,
        }),
    ));
    evidence.add_finding(Finding::new(
        "strings",
        Confidence::Observed,
        json!({
            "entries": parsed.strings,
            "returned": parsed.strings.len(),
            "total": parsed.strings.len(),
        }),
    ));
    evidence.add_unknown(
        "chunk payloads",
        "chunk payloads beyond entry counts (sprite/object/room structures) are not parsed; \
         their full structure is out of scope for the census",
    );
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

/// Write `bytes` to `destination` atomically; returns
/// the payload SHA-256.
fn write_atomic(destination: &Path, bytes: &[u8]) -> Result<String> {
    let temp = destination.with_extension("partial");
    {
        let mut file = File::create(&temp)
            .map_err(|error| mismatch(format!("cannot create output file: {error}")))?;
        file.write_all(bytes)
            .map_err(|error| mismatch(format!("cannot write output file: {error}")))?;
    }
    std::fs::rename(&temp, destination)
        .map_err(|error| mismatch(format!("cannot finalise output file: {error}")))?;
    Ok(sha256_hex(bytes))
}

pub fn extract_gamemaker_audio(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let output_arg = require_str(args, "output_dir")?;
    let output_dir = paths::validate_output_dir(config, Path::new(output_arg))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut evidence = Evidence::new("extract_gamemaker_audio", "gamemaker");
    evidence.subject = Some(subject);
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open data.win: {error}")))?;
    let chunks = walk_chunks(&mut file, file_len)?;
    let Some(audo) = chunks.iter().find(|chunk| chunk.name == "AUDO") else {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "data.win carries no AUDO chunk",
        ));
    };
    let (count, offsets) = count_table(&mut file, audo, file_len)?;
    let chunk_end = audo.offset + audo.body_size as u64;
    std::fs::create_dir_all(&output_dir)
        .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
    let mut rows: Vec<Value> = Vec::new();
    let mut counts_map: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    let mut spent: u64 = 0;
    for (index, offset) in offsets.iter().enumerate() {
        let offset = *offset as u64;
        let span_end = offsets
            .get(index + 1)
            .map(|next| *next as u64)
            .unwrap_or(chunk_end);
        let mut row = json!({"index": index, "offset": offset});
        let finish = |rows: &mut Vec<Value>,
                      counts: &mut std::collections::BTreeMap<&str, u64>,
                      row: &mut Value,
                      status: &'static str| {
            row["status"] = json!(status);
            *counts.entry(status).or_insert(0) += 1;
            rows.push(std::mem::take(row));
        };
        let declared = match read_u32(&mut file, offset) {
            Ok(value) => value as u64,
            Err(_) => {
                finish(&mut rows, &mut counts_map, &mut row, "unreadable");
                continue;
            }
        };
        if declared + 4 != span_end - offset {
            finish(&mut rows, &mut counts_map, &mut row, "size_mismatch");
            continue;
        }
        if spent + declared > GAME_EXTRACT_BYTES_MAX {
            finish(&mut rows, &mut counts_map, &mut row, "skipped_budget");
            continue;
        }
        let bytes = match read_at(&mut file, offset + 4, declared as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                finish(&mut rows, &mut counts_map, &mut row, "unreadable");
                continue;
            }
        };
        let extension = if bytes.starts_with(b"RIFF") {
            "wav"
        } else if bytes.starts_with(b"OggS") {
            "ogg"
        } else {
            "bin"
        };
        let name = format!("audio_{index:03}.{extension}");
        let destination: PathBuf = output_dir.join(&name);
        match write_atomic(&destination, &bytes) {
            Ok(digest) => {
                spent += declared;
                row["bytes"] = json!(declared);
                row["path"] = json!(name);
                row["sha256"] = json!(digest);
                finish(&mut rows, &mut counts_map, &mut row, "extracted");
            }
            Err(_) => finish(&mut rows, &mut counts_map, &mut row, "unreadable"),
        }
    }
    let manifest = json!({
        "entries": rows,
        "format": "GameMaker data.win (FORM)",
        "notes": [
            "AUDO entries are [u32 size][audio bytes]; an entry is written only when its declared size equals its offset-table span",
            "chunk payloads other than AUDO are census-only in this lane",
        ],
        "source_sha256": sha256,
        "totals": {
            "entries": count,
            "extracted": counts_map.get("extracted").copied().unwrap_or(0),
            "size_mismatch": counts_map.get("size_mismatch").copied().unwrap_or(0),
            "skipped_budget": counts_map.get("skipped_budget").copied().unwrap_or(0),
            "unreadable": counts_map.get("unreadable").copied().unwrap_or(0),
        },
    });
    let manifest_path = output_dir.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("cannot serialise manifest: {error}")))?;
    std::fs::write(&manifest_path, &manifest_bytes)
        .map_err(|error| mismatch(format!("cannot write manifest: {error}")))?;
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "gamemaker_audio_extract", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "gamemaker_audio_extract",
        Confidence::Observed,
        json!({
            "bytes_written": spent,
            "entries": count,
            "export_digest": digest,
            "extracted": counts_map.get("extracted").copied().unwrap_or(0),
            "format": "GameMaker data.win (FORM)",
            "output_dir": output_dir.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({
            "entries": manifest["entries"],
            "returned": count,
            "total": count,
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

    /// Build a minimal data.win: GEN8 with two string
    /// pointers, STRG with two strings, AUDO with one
    /// RIFF entry.
    fn build_fixture() -> Vec<u8> {
        // String area first (absolute offsets known once
        // the header size is fixed): the fixture lays out
        // FORM header (8) + GEN8 chunk (8+24) + STRG
        // chunk + AUDO chunk; strings live inside STRG.
        let wav: Vec<u8> = {
            let mut w = b"RIFF".to_vec();
            w.extend_from_slice(&20u32.to_le_bytes());
            w.extend_from_slice(b"WAVEfmt ");
            w.extend_from_slice(&[0u8; 12]);
            w
        };
        // STRG body: count 2, offsets (filled later),
        // string records. The GEN8 body carries its own
        // NUL-terminated strings after its fields (35
        // bytes total), as in real files.
        let gen8_body_len = 35usize;
        let mut strg_body: Vec<u8> = Vec::new();
        strg_body.extend_from_slice(&2u32.to_le_bytes());
        let offsets_at = strg_body.len();
        strg_body.extend_from_slice(&[0u8; 8]);
        let strg_body_start = 8 + (8 + gen8_body_len) + 8; // FORM + GEN8 + STRG header
        let s0_at = strg_body_start + strg_body.len();
        let mut s0 = Vec::new();
        s0.extend_from_slice(&4u32.to_le_bytes());
        s0.extend_from_slice(b"Game");
        let s1_at = s0_at + s0.len();
        let mut s1 = Vec::new();
        s1.extend_from_slice(&5u32.to_le_bytes());
        s1.extend_from_slice(b"Music");
        strg_body[offsets_at..offsets_at + 4].copy_from_slice(&(s0_at as u32).to_le_bytes());
        strg_body[offsets_at + 4..offsets_at + 8].copy_from_slice(&(s1_at as u32).to_le_bytes());
        strg_body.extend_from_slice(&s0);
        strg_body.extend_from_slice(&s1);
        // GEN8 body: debug byte + pad, display/file
        // pointers -> the body's own NUL-terminated
        // strings at body offsets 24 and 29.
        let gen8_body_start = 8 + 8; // FORM header + chunk header
        let mut gen8_body = vec![0u8; gen8_body_len];
        gen8_body[0] = 1;
        gen8_body[4..8].copy_from_slice(&((gen8_body_start + 24) as u32).to_le_bytes());
        gen8_body[8..12].copy_from_slice(&((gen8_body_start + 29) as u32).to_le_bytes());
        gen8_body[24..29].copy_from_slice(b"Game\0");
        gen8_body[29..35].copy_from_slice(b"Music\0");
        // AUDO body: count 1, offset, entry.
        let audo_body_start = strg_body_start + strg_body.len() + 8;
        let entry_at = audo_body_start + 4 + 4;
        let mut audo_body: Vec<u8> = Vec::new();
        audo_body.extend_from_slice(&1u32.to_le_bytes());
        audo_body.extend_from_slice(&(entry_at as u32).to_le_bytes());
        audo_body.extend_from_slice(&(wav.len() as u32).to_le_bytes());
        audo_body.extend_from_slice(&wav);
        // Assemble.
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(FORM_MAGIC);
        out.extend_from_slice(&0u32.to_le_bytes()); // patched below
        out.extend_from_slice(b"GEN8");
        out.extend_from_slice(&(gen8_body.len() as u32).to_le_bytes());
        out.extend_from_slice(&gen8_body);
        out.extend_from_slice(b"STRG");
        out.extend_from_slice(&(strg_body.len() as u32).to_le_bytes());
        out.extend_from_slice(&strg_body);
        out.extend_from_slice(b"AUDO");
        out.extend_from_slice(&(audo_body.len() as u32).to_le_bytes());
        out.extend_from_slice(&audo_body);
        let total = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&total.to_le_bytes());
        out
    }

    #[test]
    fn validation_chunk_walk_is_exact() {
        let bytes = build_fixture();
        let len = bytes.len() as u64;
        let mut cursor = std::io::Cursor::new(bytes);
        let chunks = walk_chunks(&mut cursor, len).expect("walk");
        let names: Vec<&str> = chunks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["GEN8", "STRG", "AUDO"]);
    }

    #[test]
    fn validation_parse_reads_names_counts_and_strings() {
        let bytes = build_fixture();
        let len = bytes.len() as u64;
        let mut cursor = std::io::Cursor::new(bytes);
        let parsed = parse(&mut cursor, len).expect("parse");
        assert_eq!(parsed.display_name.as_deref(), Some("Game"));
        assert_eq!(parsed.file_name.as_deref(), Some("Music"));
        assert_eq!(parsed.strings, ["Game", "Music"]);
        assert!(parsed.counts.contains(&("AUDO".to_string(), 1)));
        assert!(parsed.counts.contains(&("STRG".to_string(), 2)));
    }

    #[test]
    fn adversarial_lying_chunk_size_is_refused() {
        let mut bytes = build_fixture();
        bytes[12] = 0xFF; // GEN8 size low byte -> huge
        bytes[13] = 0xFF;
        let len = bytes.len() as u64;
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(walk_chunks(&mut cursor, len).is_err());
    }

    #[test]
    fn adversarial_bad_magic_is_refused() {
        let mut bytes = build_fixture();
        bytes[0] = b'X';
        let len = bytes.len() as u64;
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(walk_chunks(&mut cursor, len).is_err());
    }
}
