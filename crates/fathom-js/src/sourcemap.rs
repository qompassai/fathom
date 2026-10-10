//! `inspect_source_map` (SPEC §9.2): source-map v3 parsing and
//! generated→original position mapping.
//!
//! The parser is hand-implemented: JSON header fields (`sources`,
//! `sourcesContent` presence, `names`) plus the base64-VLQ
//! `mappings` payload, decoded with cumulative-delta state exactly
//! as the v3 format defines. Malformed maps produce typed errors;
//! a position with no covering segment is reported unmapped, not
//! invented.

use serde_json::{Value, json};
use std::fs;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// Per-map read bound.
pub const MAP_BYTES_MAX: u64 = 16_777_216;
/// Characters accepted in one `mappings` payload.
const MAPPINGS_CHARS_MAX: usize = 8_388_608;
/// Names inventoried from one map.
const NAMES_MAX: usize = 65_536;
/// Mapping segments decoded from one map.
const SEGMENTS_MAX: usize = 1_000_000;
/// Sources inventoried from one map.
const SOURCES_MAX: usize = 4_096;

/// One decoded mapping segment.
#[derive(Debug)]
struct Segment {
    generated_column: u32,
    name_index: Option<u32>,
    original_column: u32,
    original_line: u32,
    source_index: Option<u32>,
}

/// A parsed source-map v3 document.
#[derive(Debug)]
pub struct SourceMap {
    /// The generated file the map describes (`file` field).
    pub generated_file: Option<String>,
    lines: Vec<Vec<Segment>>,
    /// Declared names, in declaration order.
    pub names: Vec<String>,
    /// Total decoded mapping segments.
    pub segment_count: usize,
    /// `sourceRoot`, when declared.
    pub source_root: Option<String>,
    /// Declared sources, in declaration order.
    pub sources: Vec<String>,
    /// Per-source `sourcesContent` presence, aligned with
    /// `sources`: true only where the entry is an actual string.
    pub sources_content_present: Vec<bool>,
}

/// An original position resolved from a generated position.
#[derive(Debug)]
pub struct OriginalPosition {
    /// Original column (0-based, as the format stores it).
    pub column: u32,
    /// Original line (0-based, as the format stores it).
    pub line: u32,
    /// Resolved name, when the covering segment carries one.
    pub name: Option<String>,
    /// Source path, with `sourceRoot` applied when declared.
    pub source: String,
}

fn malformed(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message.into())
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into())
}

/// Parse one source-map v3 document.
pub fn parse_source_map(text: &str) -> Result<SourceMap, FathomError> {
    let document: Value = serde_json::from_str(text)
        .map_err(|e| unsupported(format!("not a source-map JSON document: {e}")))?;
    let version = document.get("version").and_then(Value::as_u64);
    if version != Some(3) {
        return Err(unsupported(format!(
            "source-map version must be 3, found {version:?}"
        )));
    }
    let sources_values = document
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| unsupported("source map has no sources array"))?;
    if sources_values.len() > SOURCES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("source count exceeds the bound of {SOURCES_MAX}"),
        ));
    }
    let mut sources = Vec::with_capacity(sources_values.len());
    for value in sources_values {
        let source = value
            .as_str()
            .ok_or_else(|| unsupported("sources entries must be strings"))?;
        sources.push(source.to_string());
    }
    let sources_content_present = match document.get("sourcesContent") {
        None => vec![false; sources.len()],
        Some(Value::Null) => vec![false; sources.len()],
        Some(value) => {
            let entries = value
                .as_array()
                .ok_or_else(|| malformed("sourcesContent must be an array when present"))?;
            (0..sources.len())
                .map(|index| entries.get(index).is_some_and(Value::is_string))
                .collect()
        }
    };
    let mut names = Vec::new();
    if let Some(value) = document.get("names") {
        let entries = value
            .as_array()
            .ok_or_else(|| malformed("names must be an array when present"))?;
        if entries.len() > NAMES_MAX {
            return Err(FathomError::new(
                ErrorCode::ResourceConstraint,
                format!("name count exceeds the bound of {NAMES_MAX}"),
            ));
        }
        for entry in entries {
            let name = entry
                .as_str()
                .ok_or_else(|| malformed("names entries must be strings"))?;
            names.push(name.to_string());
        }
    }
    let mappings = document
        .get("mappings")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("source map has no mappings string"))?;
    if mappings.len() > MAPPINGS_CHARS_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("mappings payload exceeds the bound of {MAPPINGS_CHARS_MAX} characters"),
        ));
    }
    let (lines, segment_count) = decode_mappings(mappings, sources.len(), names.len())?;
    Ok(SourceMap {
        generated_file: document
            .get("file")
            .and_then(Value::as_str)
            .map(str::to_string),
        lines,
        names,
        segment_count,
        source_root: document
            .get("sourceRoot")
            .and_then(Value::as_str)
            .map(str::to_string),
        sources,
        sources_content_present,
    })
}

/// Decode the VLQ mappings payload into per-line segment lists.
fn decode_mappings(
    mappings: &str,
    source_count: usize,
    name_count: usize,
) -> Result<(Vec<Vec<Segment>>, usize), FathomError> {
    let mut lines = Vec::new();
    let mut name_index: i64 = 0;
    let mut original_column: i64 = 0;
    let mut original_line: i64 = 0;
    let mut segment_count = 0_usize;
    let mut source_index: i64 = 0;
    for line_text in mappings.split(';') {
        let mut generated_column: i64 = 0;
        let mut segments = Vec::new();
        if !line_text.is_empty() {
            for segment_text in line_text.split(',') {
                if segment_text.is_empty() {
                    return Err(malformed("empty segment in mappings"));
                }
                let fields = decode_segment_fields(segment_text)?;
                if fields.len() != 1 && fields.len() != 4 && fields.len() != 5 {
                    return Err(malformed(format!(
                        "segment has {} fields; the format allows 1, 4, or 5",
                        fields.len()
                    )));
                }
                generated_column += fields[0];
                if generated_column < 0 {
                    return Err(malformed("generated column went negative"));
                }
                segment_count += 1;
                if segment_count > SEGMENTS_MAX {
                    return Err(FathomError::new(
                        ErrorCode::ResourceConstraint,
                        format!("segment count exceeds the bound of {SEGMENTS_MAX}"),
                    ));
                }
                let mut segment = Segment {
                    generated_column: generated_column as u32,
                    name_index: None,
                    original_column: 0,
                    original_line: 0,
                    source_index: None,
                };
                if fields.len() >= 4 {
                    source_index += fields[1];
                    original_line += fields[2];
                    original_column += fields[3];
                    if source_index < 0 || source_index as usize >= source_count {
                        return Err(malformed("segment source index is out of range"));
                    }
                    if original_line < 0 || original_column < 0 {
                        return Err(malformed("segment original position went negative"));
                    }
                    segment.original_column = original_column as u32;
                    segment.original_line = original_line as u32;
                    segment.source_index = Some(source_index as u32);
                    if fields.len() == 5 {
                        name_index += fields[4];
                        if name_index < 0 || name_index as usize >= name_count {
                            return Err(malformed("segment name index is out of range"));
                        }
                        segment.name_index = Some(name_index as u32);
                    }
                }
                segments.push(segment);
            }
        }
        lines.push(segments);
    }
    Ok((lines, segment_count))
}

/// Decode every VLQ field of one segment.
fn decode_segment_fields(segment: &str) -> Result<Vec<i64>, FathomError> {
    let chars: Vec<char> = segment.chars().collect();
    let mut cursor = 0_usize;
    let mut fields = Vec::new();
    while cursor < chars.len() {
        fields.push(decode_vlq(&chars, &mut cursor)?);
    }
    Ok(fields)
}

/// Decode one base64-VLQ value at the cursor.
fn decode_vlq(chars: &[char], cursor: &mut usize) -> Result<i64, FathomError> {
    let mut shift = 0_u32;
    let mut value: u64 = 0;
    loop {
        let ch = chars
            .get(*cursor)
            .ok_or_else(|| malformed("truncated VLQ value in mappings"))?;
        *cursor += 1;
        let digit = base64_digit(*ch)
            .ok_or_else(|| malformed(format!("invalid base64 digit in mappings: {ch}")))?;
        let continuation = digit & 32 != 0;
        let chunk = u64::from(digit & 31);
        if shift >= 60 {
            return Err(malformed("VLQ value exceeds 60 bits of payload"));
        }
        value |= chunk << shift;
        shift += 5;
        if !continuation {
            break;
        }
    }
    let magnitude = (value >> 1) as i64;
    if value & 1 == 1 {
        Ok(-magnitude)
    } else {
        Ok(magnitude)
    }
}

fn base64_digit(ch: char) -> Option<u8> {
    match ch {
        'A'..='Z' => Some(ch as u8 - b'A'),
        'a'..='z' => Some(ch as u8 - b'a' + 26),
        '0'..='9' => Some(ch as u8 - b'0' + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    }
}

impl SourceMap {
    /// The evidence rows for the declared sources.
    pub fn source_rows(&self) -> Vec<Value> {
        self.sources
            .iter()
            .enumerate()
            .map(|(index, _source)| {
                json!({
                    "content_present": self
                        .sources_content_present
                        .get(index)
                        .copied()
                        .unwrap_or(false),
                    "source": self.source_at(index),
                })
            })
            .collect()
    }

    fn source_at(&self, index: usize) -> String {
        let source = self.sources.get(index).cloned().unwrap_or_default();
        match &self.source_root {
            Some(root) if !root.is_empty() && !source.starts_with('/') => {
                if root.ends_with('/') {
                    format!("{root}{source}")
                } else {
                    format!("{root}/{source}")
                }
            }
            _ => source,
        }
    }

    /// Map a generated position to its original position using
    /// greatest-lower-bound segment semantics, as the v3 format
    /// defines. Returns `None` when no segment covers the position.
    pub fn map_position(
        &self,
        generated_line: u32,
        generated_column: u32,
    ) -> Option<OriginalPosition> {
        let line = self.lines.get(generated_line as usize)?;
        let segment = line
            .iter()
            .rev()
            .find(|segment| segment.generated_column <= generated_column)?;
        let source_index = segment.source_index?;
        Some(OriginalPosition {
            column: segment.original_column,
            line: segment.original_line,
            name: segment
                .name_index
                .and_then(|index| self.names.get(index as usize).cloned()),
            source: self.source_at(source_index as usize),
        })
    }
}

/// Read and report one `.map` file, mapping a generated position
/// when both coordinates are supplied.
pub fn inspect_source_map(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    if !target
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".map"))
    {
        return Err(unsupported("target is not a .map file"));
    }
    let metadata = fs::metadata(&target).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat source map: {e}"),
        )
    })?;
    if metadata.len() > MAP_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("source map exceeds the read bound of {MAP_BYTES_MAX} bytes"),
        ));
    }
    let text = fs::read_to_string(&target).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot read source map as UTF-8: {e}"),
        )
    })?;
    let map = parse_source_map(&text)?;
    let generated_line = args.get("generated_line").and_then(Value::as_u64);
    let generated_column = args.get("generated_column").and_then(Value::as_u64);
    if generated_line.is_some() != generated_column.is_some() {
        return Err(malformed(
            "generated_line and generated_column must be supplied together",
        ));
    }

    let mut evidence = Evidence::new("inspect_source_map", "javascript");
    evidence.add_finding(Finding::new(
        "source_map",
        Confidence::Observed,
        json!({
            "file": target.file_name().map(|n| n.to_string_lossy().into_owned()),
            "generated_file": map.generated_file,
            "names_count": map.names.len(),
            "segment_count": map.segment_count,
            "source_root": map.source_root,
            "sources": map.source_rows(),
            "sources_count": map.sources.len(),
            "version": 3,
        }),
    ));
    if let (Some(line), Some(column)) = (generated_line, generated_column) {
        if line > u64::from(u32::MAX) || column > u64::from(u32::MAX) {
            return Err(malformed("generated position exceeds u32 bounds"));
        }
        let mapped = map.map_position(line as u32, column as u32);
        evidence.add_finding(
            Finding::new(
                "source_position",
                Confidence::Derived,
                json!({
                    "generated": {"column": column, "line": line},
                    "mapped": mapped.is_some(),
                    "original": mapped.as_ref().map(|original| json!({
                        "column": original.column,
                        "line": original.line,
                        "name": original.name,
                        "source": original.source,
                    })),
                }),
            )
            .with_limitation(
                "Mapping uses greatest-lower-bound segment semantics per source-map v3; the covering segment's original position is reported, not an interpolated one.",
            ),
        );
    }
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Hand-encoded map: line 0 has a named segment at column 0
    /// (orig 0:0, name 0) and a segment at column 10 (orig 2:4);
    /// line 1 has a segment at column 0 (orig 5:1).
    const MAP_TEXT: &str = r#"{
        "version": 3,
        "file": "app.js",
        "sources": ["src/orig.ts", "src/other.ts"],
        "sourcesContent": [null, "export const x = 1;"],
        "names": ["greet"],
        "mappings": "AAAAA,UAEI;AAGH"
    }"#;

    #[test]
    fn validation_parse_and_map_positions() {
        let map = parse_source_map(MAP_TEXT).unwrap();
        assert_eq!(map.sources.len(), 2);
        assert_eq!(map.segment_count, 3);
        let at_start = map.map_position(0, 0).unwrap();
        assert_eq!(at_start.source, "src/orig.ts");
        assert_eq!(at_start.line, 0);
        assert_eq!(at_start.column, 0);
        assert_eq!(at_start.name.as_deref(), Some("greet"));
        let between = map.map_position(0, 12).unwrap();
        assert_eq!(between.line, 2);
        assert_eq!(between.column, 4);
        assert!(between.name.is_none());
        let second_line = map.map_position(1, 0).unwrap();
        assert_eq!(second_line.line, 5);
        assert_eq!(second_line.column, 1);
    }

    #[test]
    fn validation_sources_content_presence_is_per_source() {
        let map = parse_source_map(MAP_TEXT).unwrap();
        assert_eq!(map.sources_content_present, vec![false, true]);
    }

    #[test]
    fn validation_tool_end_to_end_maps_a_position() {
        let root = std::env::temp_dir().join(format!("fathom-map-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut file = fs::File::create(root.join("app.js.map")).unwrap();
        file.write_all(MAP_TEXT.as_bytes()).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({
            "target": root.join("app.js.map").display().to_string(),
            "generated_line": 0,
            "generated_column": 12,
        });
        let value = inspect_source_map(&Registry::new(), &config, &args).unwrap();
        let position = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == "source_position")
            .expect("position finding");
        assert_eq!(position["facts"]["mapped"], true);
        assert_eq!(position["facts"]["original"]["line"], 2);
        assert_eq!(position["facts"]["original"]["column"], 4);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_bad_vlq_digit_is_a_typed_error() {
        let text = r#"{"version": 3, "sources": ["a.ts"], "mappings": "A!A"}"#;
        assert_eq!(
            parse_source_map(text).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn adversarial_out_of_range_source_index_is_a_typed_error() {
        let text = r#"{"version": 3, "sources": ["a.ts"], "mappings": "AKAA"}"#;
        assert_eq!(
            parse_source_map(text).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn adversarial_truncated_json_is_unsupported_not_a_panic() {
        let text = "{\"version\": 3, \"sources\": [\"a.ts\"";
        assert_eq!(
            parse_source_map(text).unwrap_err().code,
            ErrorCode::UnsupportedTarget
        );
    }

    #[test]
    fn adversarial_unmapped_position_is_none_not_invented() {
        let map = parse_source_map(MAP_TEXT).unwrap();
        assert!(map.map_position(9, 0).is_none());
        assert!(map.map_position(1, 0).is_some());
    }

    #[test]
    fn adversarial_version_two_is_unsupported() {
        let text = r#"{"version": 2, "sources": [], "mappings": ""}"#;
        assert_eq!(
            parse_source_map(text).unwrap_err().code,
            ErrorCode::UnsupportedTarget
        );
    }
}
