//! ASAR archive reader (SPEC §9.2), implemented directly.
//!
//! Layout: a size pickle (`u32` 4, `u32` header-pickle length),
//! then the header pickle (`u32` payload size, `u32` JSON string
//! length, the JSON header), then file data at
//! `8 + header_pickle_length`. Entry offsets are relative to the
//! data start. Every read is bounds-checked against the archive;
//! a malformed header is `unsupported_target`, never a panic.

use serde_json::{Map, Value, json};
use std::path::Path;

use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use rea_core::limits::ASAR_ENTRIES_MAX;
use rea_core::paths;
use rea_core::registry::{Registry, require_str};

#[derive(Debug)]
pub struct AsarArchive {
    pub data_start: usize,
    pub entries: Vec<AsarEntry>,
    pub header_bytes: usize,
}

#[derive(Debug)]
pub struct AsarEntry {
    pub directory: bool,
    pub offset: Option<u64>,
    pub path: String,
    pub size: u64,
    pub unpacked: bool,
}

/// Parse an ASAR archive from its full bytes.
pub fn parse_asar(bytes: &[u8]) -> Result<AsarArchive, ReaError> {
    let unsupported = |message: &str| {
        ReaError::new(ErrorCode::UnsupportedTarget, message.to_string()).with_target("asar archive")
    };
    if bytes.len() < 16 {
        return Err(unsupported("file too small to be an ASAR archive"));
    }
    if read_u32(bytes, 0)? != 4 {
        return Err(unsupported("bad ASAR size pickle"));
    }
    let header_pickle_len = read_u32(bytes, 4)? as usize;
    let data_start = 8_usize
        .checked_add(header_pickle_len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| unsupported("ASAR header pickle overruns the file"))?;
    let string_len = read_u32(bytes, 12)? as usize;
    let json_start: usize = 16;
    let json_end = json_start
        .checked_add(string_len)
        .filter(|end| *end <= data_start)
        .ok_or_else(|| unsupported("ASAR header string overruns the header pickle"))?;
    let header: Value = serde_json::from_slice(&bytes[json_start..json_end])
        .map_err(|_| unsupported("ASAR header is not valid JSON"))?;
    let mut entries = Vec::new();
    let files = header
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| unsupported("ASAR header has no files object"))?;
    walk_entries(files, "", &mut entries);
    Ok(AsarArchive {
        data_start,
        entries,
        header_bytes: header_pickle_len,
    })
}

/// Extract one packed entry's bytes (bounds-checked).
pub fn extract<'a>(
    bytes: &'a [u8],
    archive: &AsarArchive,
    entry: &AsarEntry,
) -> Result<&'a [u8], ReaError> {
    if entry.unpacked {
        return Err(ReaError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is unpacked; its bytes live in the sibling .asar.unpacked directory",
        ));
    }
    let offset = entry.offset.ok_or_else(|| {
        ReaError::new(
            ErrorCode::UnsupportedTarget,
            "entry has no data offset (directory or link)",
        )
    })?;
    let start = archive
        .data_start
        .checked_add(offset as usize)
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| ReaError::new(ErrorCode::Truncated, "entry offset overruns the archive"))?;
    let end = start
        .checked_add(entry.size as usize)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| ReaError::new(ErrorCode::Truncated, "entry size overruns the archive"))?;
    Ok(&bytes[start..end])
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ReaError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ReaError::new(ErrorCode::UnsupportedTarget, "ASAR header truncated"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn walk_entries(files: &Map<String, Value>, prefix: &str, out: &mut Vec<AsarEntry>) {
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    for name in names {
        let node = &files[name];
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let unpacked = node
            .get("unpacked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if let Some(children) = node.get("files").and_then(Value::as_object) {
            out.push(AsarEntry {
                directory: true,
                offset: None,
                path: path.clone(),
                size: 0,
                unpacked,
            });
            walk_entries(children, &path, out);
        } else {
            out.push(AsarEntry {
                directory: false,
                offset: node
                    .get("offset")
                    .and_then(Value::as_str)
                    .and_then(|text| text.parse::<u64>().ok()),
                path,
                size: node.get("size").and_then(Value::as_u64).unwrap_or(0),
                unpacked,
            });
        }
    }
}

pub fn inspect_asar(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        ReaError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    let archive = parse_asar(&bytes)?;
    let total = archive.entries.len();
    let file_count = archive.entries.iter().filter(|e| !e.directory).count();
    let unpacked_count = archive.entries.iter().filter(|e| e.unpacked).count();
    let total_bytes: u64 = archive.entries.iter().map(|e| e.size).sum();
    let shown: Vec<Value> = archive
        .entries
        .iter()
        .take(ASAR_ENTRIES_MAX)
        .map(|entry| {
            json!({
                "directory": entry.directory,
                "offset": entry.offset,
                "path": entry.path,
                "size": entry.size,
                "unpacked": entry.unpacked,
            })
        })
        .collect();
    let mut evidence = Evidence::new("inspect_asar", "asar");
    evidence.subject = Some(subject);
    let mut summary = Finding::new(
        "asar",
        Confidence::Observed,
        json!({
            "data_start": archive.data_start,
            "entry_count": total,
            "file_count": file_count,
            "header_bytes": archive.header_bytes,
            "total_file_bytes": total_bytes,
            "unpacked_entries": unpacked_count,
        }),
    );
    if unpacked_count > 0 {
        summary = summary
            .with_limitation("unpacked entries are listed; their bytes live outside the archive");
    }
    evidence.add_finding(summary);
    let mut entries_finding = Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": shown, "returned": total.min(ASAR_ENTRIES_MAX), "total": total}),
    );
    if total > ASAR_ENTRIES_MAX {
        entries_finding =
            entries_finding.with_limitation("entry listing truncated at the count bound");
    }
    evidence.add_finding(entries_finding);
    evidence.coverage.examined = total.min(ASAR_ENTRIES_MAX) as u64;
    evidence.coverage.total = total as u64;
    evidence.coverage.exhaustive = total <= ASAR_ENTRIES_MAX;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal archive byte-for-byte the way
    /// @electron/asar writes one (two pickles + data). The
    /// permanent cross-check is the real-tool fixture test in
    /// tests/asar_fixture.rs.
    pub fn build_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut files_json = String::new();
        let mut data = Vec::new();
        for (index, (name, content)) in files.iter().enumerate() {
            if index > 0 {
                files_json.push(',');
            }
            files_json.push_str(&format!(
                "\"{name}\":{{\"size\":{},\"offset\":\"{}\"}}",
                content.len(),
                data.len()
            ));
            data.extend_from_slice(content);
        }
        let header = format!("{{\"files\":{{{files_json}}}}}");
        let mut header_pickle = Vec::new();
        let payload_len = 4 + header.len();
        let padded = payload_len.div_ceil(4) * 4;
        header_pickle.extend_from_slice(&(padded as u32).to_le_bytes());
        header_pickle.extend_from_slice(&(header.len() as u32).to_le_bytes());
        header_pickle.extend_from_slice(header.as_bytes());
        header_pickle.resize(4 + padded, 0);
        let mut out = Vec::new();
        out.extend_from_slice(&4_u32.to_le_bytes());
        out.extend_from_slice(&(header_pickle.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_pickle);
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn adversarial_bad_magic_rejected() {
        assert!(parse_asar(b"MZ and some bytes here").is_err());
        assert!(parse_asar(&[4, 0, 0, 0]).is_err());
    }

    #[test]
    fn adversarial_overrun_header_rejected() {
        let mut bytes = build_archive(&[("a.txt", b"hi")]);
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_asar(&bytes).is_err());
    }

    #[test]
    fn validation_roundtrip_entries_and_extract() {
        let bytes = build_archive(&[("a.txt", b"hello"), ("b.txt", b"world!")]);
        let archive = parse_asar(&bytes).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].path, "a.txt");
        assert_eq!(archive.entries[0].size, 5);
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[1]).unwrap(),
            b"world!"
        );
    }
}
