//! Unreal `.uasset` package summary census (R5).
//!
//! Parses the FPackageFileSummary header of one `.uasset`:
//! the name table, the import map, and the export map, so
//! a package's contents are visible as data — object names
//! and classes — without full property parsing (out of
//! scope by design; the summary honestly cannot see
//! property values).
//!
//! Two summary layouts are supported, both proven against
//! the moved corpus (HYPERDEEP's legacy -7 packages and
//! Iced Coffee's legacy -9 packages, thousands of files
//! each):
//!
//! * `legacy_folder`: magic, legacy version, the UE5
//!   version word (legacy <= -7), UE4 + licensee versions,
//!   custom versions, total header size, the FolderName
//!   string, package flags, name count/offset, the
//!   gatherable-text pair, then export/import counts and
//!   offsets.
//! * `ue5_package_name`: after the custom versions, a
//!   20-byte opaque block (a GUID and one word whose
//!   semantics this census does not need), the total
//!   header size, one further word, the PackageName
//!   string, package flags, name count/offset, the
//!   soft-object-paths pair, the gatherable-text pair,
//!   then export/import counts and offsets.
//!
//! Both layouts are unversioned in the corpus (UE4 and
//! UE5 version fields zero), so version-gated fields
//! (LocalizationId and friends) are absent; a package
//! whose name table does not parse to printable strings
//! under its layout is refused rather than misread.
//! Export/import entry strides are derived per file from
//! the neighbouring map offsets and validated, because
//! the serialized entry size varies by engine version.

use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, UASSET_EXPORTS_MAX, UASSET_IMPORTS_MAX, UASSET_LISTED_MAX,
    UASSET_NAME_BYTES_MAX, UASSET_NAMES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

const SUMMARY_BYTES_MAX: u64 = 268_435_456; // 256 MiB read cap for one package.
const UASSET_MAGIC: u32 = 0x9E2A_83C1;

/// One export-map row.
struct ExportRow {
    /// Resolved class name (via the class package index).
    class: String,
    /// Object name.
    name: String,
    /// Declared serialized size in bytes.
    serial_size: i64,
}

/// One import-map row.
struct ImportRow {
    /// Class name (e.g. "Class", "Material").
    class_name: String,
    /// Class package (e.g. "/Script/Engine").
    class_package: String,
    /// Imported object name.
    name: String,
}

/// The parsed summary facts the census reports.
struct Summary {
    /// Export rows in map order (bounded at listing).
    exports: Vec<ExportRow>,
    /// Total export count declared by the summary.
    exports_total: i32,
    /// Import rows in map order (bounded at listing).
    imports: Vec<ImportRow>,
    /// Total import count declared by the summary.
    imports_total: i32,
    /// Legacy file version (negative).
    legacy_version: i32,
    /// Summary layout that validated.
    layout: &'static str,
    /// The full name table.
    names: Vec<String>,
    /// Package name (ue5 layout) or folder name (legacy).
    package_label: String,
    /// Total header size declared by the summary.
    total_header_size: i32,
    /// UE4 package version (0 = unversioned).
    ue4_version: i32,
    /// UE5 package version (0 = unversioned/absent).
    ue5_version: u32,
}

/// A little-endian cursor over the package bytes.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    fn skip(&mut self, count: usize) -> Result<()> {
        self.pos = self.pos.checked_add(count).ok_or_else(bad)?;
        if self.pos > self.bytes.len() {
            return Err(bad());
        }
        Ok(())
    }

    fn u32(&mut self) -> Result<u32> {
        let end = self.pos.checked_add(4).ok_or_else(bad)?;
        let slice = self.bytes.get(self.pos..end).ok_or_else(bad)?;
        self.pos = end;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// One FString (i32 length; negative = UTF-16).
    fn fstring(&mut self) -> Result<String> {
        let len = self.i32()?;
        if len == 0 {
            return Ok(String::new());
        }
        if len < 0 {
            let units = (len as i64).unsigned_abs();
            if units > (UASSET_NAME_BYTES_MAX as u64) / 2 {
                return Err(bad());
            }
            let byte_len = (units as usize).checked_mul(2).ok_or_else(bad)?;
            let end = self.pos.checked_add(byte_len).ok_or_else(bad)?;
            let slice = self.bytes.get(self.pos..end).ok_or_else(bad)?;
            self.pos = end;
            let words: Vec<u16> = slice
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let text = String::from_utf16(&words).map_err(|_| bad())?;
            return Ok(text.strip_suffix('\0').unwrap_or(&text).to_string());
        }
        if len as u64 > UASSET_NAME_BYTES_MAX as u64 {
            return Err(bad());
        }
        let end = self.pos.checked_add(len as usize).ok_or_else(bad)?;
        let slice = self.bytes.get(self.pos..end).ok_or_else(bad)?;
        self.pos = end;
        let text = std::str::from_utf8(slice).map_err(|_| bad())?;
        Ok(text.strip_suffix('\0').unwrap_or(text).to_string())
    }
}

fn bad() -> FathomError {
    FathomError::new(
        ErrorCode::ArtifactIntegrityMismatch,
        "uasset summary is truncated or malformed",
    )
}

/// Resolve an FName index pair at `at` to its string.
fn name_at(bytes: &[u8], names: &[String], at: usize) -> Option<String> {
    let slice = bytes.get(at..at + 4)?;
    let index = i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    if index < 0 {
        return None;
    }
    names.get(index as usize).cloned()
}

/// Resolve a package index (negative = import, positive
/// = export, zero = none) to an object name.
fn package_index_name(
    index: i32,
    imports: &[ImportRow],
    export_names: &[String],
) -> Option<String> {
    if index < 0 {
        let at = index.checked_neg()?.checked_sub(1)? as usize;
        imports.get(at).map(|row| row.name.clone())
    } else if index > 0 {
        let at = (index as usize).checked_sub(1)?;
        export_names.get(at).cloned()
    } else {
        None
    }
}

/// Parse the name table at `offset`.
fn parse_names(bytes: &[u8], offset: i32, count: i32) -> Result<Vec<String>> {
    if count < 0 || count as u64 > UASSET_NAMES_MAX || offset < 0 {
        return Err(bad());
    }
    let mut cursor = Cursor::new(bytes);
    cursor.pos = offset as usize;
    let mut names = Vec::new();
    for _ in 0..count {
        let name = cursor.fstring()?;
        if name.is_empty() || !name.chars().all(|ch| !ch.is_control() || ch == '\t') {
            return Err(bad());
        }
        cursor.skip(4)?; // Per-name hash word.
        names.push(name);
    }
    Ok(names)
}

/// Derive a map's entry stride from neighbouring
/// offsets: the smallest offset strictly greater than
/// `map_offset` (or the total header size), divided by
/// the entry count, must be integral and in range.
fn derive_stride(
    map_offset: i32,
    count: i32,
    neighbours: &[i32],
    min: usize,
    max: usize,
) -> Option<usize> {
    if count <= 0 || map_offset < 0 {
        return None;
    }
    let mut best: Option<i32> = None;
    for candidate in neighbours {
        if *candidate > map_offset && best.is_none_or(|held| *candidate < held) {
            best = Some(*candidate);
        }
    }
    let end = best?;
    let span = (end as usize).checked_sub(map_offset as usize)?;
    if !span.is_multiple_of(count as usize) {
        return None;
    }
    let stride = span / count as usize;
    if (min..=max).contains(&stride) {
        Some(stride)
    } else {
        None
    }
}

/// Parse the import map rows (bounded at listing).
fn parse_imports(
    bytes: &[u8],
    names: &[String],
    offset: i32,
    count: i32,
    stride: usize,
) -> Vec<ImportRow> {
    let mut rows = Vec::new();
    for index in 0..count {
        if rows.len() >= UASSET_LISTED_MAX {
            break;
        }
        let base = match (offset as usize).checked_add((index as usize) * stride) {
            Some(value) => value,
            None => break,
        };
        let (Some(class_package), Some(class_name), Some(name)) = (
            name_at(bytes, names, base),
            name_at(bytes, names, base + 8),
            name_at(bytes, names, base + 20),
        ) else {
            break;
        };
        rows.push(ImportRow {
            class_name,
            class_package,
            name,
        });
    }
    rows
}

/// Parse the export map rows (bounded at listing) and
/// every export's object name for class resolution.
fn parse_exports(
    bytes: &[u8],
    names: &[String],
    imports: &[ImportRow],
    offset: i32,
    count: i32,
    stride: usize,
) -> Vec<ExportRow> {
    let mut export_names: Vec<String> = Vec::new();
    let mut class_indices: Vec<i32> = Vec::new();
    let mut serial_sizes: Vec<i64> = Vec::new();
    for index in 0..count {
        let base = match (offset as usize).checked_add((index as usize) * stride) {
            Some(value) => value,
            None => break,
        };
        let Some(name) = name_at(bytes, names, base + 16) else {
            break;
        };
        let class_index = bytes
            .get(base..base + 4)
            .map(|slice| i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
            .unwrap_or(0);
        let serial_size = bytes
            .get(base + 28..base + 36)
            .map(|slice| i64::from_le_bytes(slice.try_into().unwrap_or([0; 8])))
            .unwrap_or(0);
        export_names.push(name);
        class_indices.push(class_index);
        serial_sizes.push(serial_size);
    }
    let mut rows = Vec::new();
    for (index, name) in export_names.iter().enumerate() {
        if rows.len() >= UASSET_LISTED_MAX {
            break;
        }
        let class = package_index_name(class_indices[index], imports, &export_names)
            .unwrap_or_else(|| "None".to_string());
        rows.push(ExportRow {
            class,
            name: name.clone(),
            serial_size: serial_sizes[index],
        });
    }
    rows
}

/// Parse the whole summary under one layout; returns
/// None when the package does not validate under it.
fn parse_summary(bytes: &[u8], layout: &'static str) -> Result<Summary> {
    let mut cursor = Cursor::new(bytes);
    if cursor.u32()? != UASSET_MAGIC {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target lacks the uasset package magic (C1 83 2A 9E)",
        ));
    }
    let legacy_version = cursor.i32()?;
    let ue5_version = if legacy_version <= -7 {
        cursor.u32()?
    } else {
        0
    };
    let ue4_version = cursor.i32()?;
    let _licensee = cursor.i32()?;
    let custom_count = cursor.i32()?;
    if !(0..=4096).contains(&custom_count) {
        return Err(bad());
    }
    cursor.skip((custom_count as usize) * 20)?;
    if layout == "ue5_package_name" {
        cursor.skip(20)?; // GUID + one word (opaque here).
    }
    let total_header_size = cursor.i32()?;
    if layout == "ue5_package_name" {
        cursor.skip(4)?;
    }
    let package_label = cursor.fstring()?;
    let _package_flags = cursor.u32()?;
    let name_count = cursor.i32()?;
    let name_offset = cursor.i32()?;
    let names = parse_names(bytes, name_offset, name_count)?;
    if layout == "ue5_package_name" {
        cursor.skip(8)?; // Soft-object-paths count/offset.
    }
    cursor.skip(8)?; // Gatherable-text count/offset.
    let export_count = cursor.i32()?;
    let export_offset = cursor.i32()?;
    let import_count = cursor.i32()?;
    let import_offset = cursor.i32()?;
    let depends_offset = cursor.i32()?;
    if export_count < 0
        || export_count as u64 > UASSET_EXPORTS_MAX
        || import_count < 0
        || import_count as u64 > UASSET_IMPORTS_MAX
    {
        return Err(bad());
    }
    let neighbours = [
        depends_offset,
        total_header_size,
        import_offset,
        export_offset,
    ];
    let import_stride =
        derive_stride(import_offset, import_count, &neighbours, 28, 40).unwrap_or(28);
    let imports = if import_count > 0 {
        parse_imports(bytes, &names, import_offset, import_count, import_stride)
    } else {
        Vec::new()
    };
    let export_stride = derive_stride(export_offset, export_count, &neighbours, 44, 200);
    let exports = match export_stride {
        Some(stride) if export_count > 0 => {
            parse_exports(bytes, &names, &imports, export_offset, export_count, stride)
        }
        _ => Vec::new(),
    };
    Ok(Summary {
        exports,
        exports_total: export_count,
        imports,
        imports_total: import_count,
        legacy_version,
        layout,
        names,
        package_label,
        total_header_size,
        ue4_version,
        ue5_version,
    })
}

pub fn inspect_uasset_package(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let package_bytes = subject.size_bytes;
    let mut evidence = Evidence::new("inspect_uasset_package", "unreal_uasset");
    evidence.subject = Some(subject);
    if package_bytes > SUMMARY_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("uasset package exceeds the {SUMMARY_BYTES_MAX}-byte read cap"),
        ));
    }
    let bytes = std::fs::read(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactIntegrityMismatch,
            format!("cannot read uasset package: {error}"),
        )
    })?;
    let legacy_peek = if bytes.len() >= 8 {
        i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    } else {
        return Err(bad());
    };
    let layout = if legacy_peek <= -8 {
        "ue5_package_name"
    } else {
        "legacy_folder"
    };
    let summary = parse_summary(&bytes, layout).map_err(|error| {
        if error.code == ErrorCode::UnsupportedTarget {
            error
        } else {
            FathomError::new(
                ErrorCode::ArtifactIntegrityMismatch,
                format!(
                    "uasset summary does not validate under the {layout} layout; \
                     version-gated summary fields beyond the corpus layouts are a named gap"
                ),
            )
        }
    })?;
    let mut class_histogram: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    for row in &summary.exports {
        *class_histogram.entry(row.class.clone()).or_insert(0) += 1;
    }
    let classes: Vec<Value> = class_histogram
        .iter()
        .map(|(class, count)| json!({"class": class, "exports": count}))
        .collect();
    let exports: Vec<Value> = summary
        .exports
        .iter()
        .map(|row| {
            json!({
                "class": row.class,
                "name": row.name,
                "serial_size": row.serial_size,
            })
        })
        .collect();
    let imports: Vec<Value> = summary
        .imports
        .iter()
        .map(|row| {
            json!({
                "class_name": row.class_name,
                "class_package": row.class_package,
                "name": row.name,
            })
        })
        .collect();
    let document = json!({
        "class_histogram": classes,
        "exports": exports,
        "imports": imports,
        "names": summary.names,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "uasset_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "uasset_package",
        Confidence::Observed,
        json!({
            "class_histogram": document["class_histogram"],
            "export_digest": digest,
            "exports_listed": exports.len(),
            "exports_total": summary.exports_total,
            "format": "Unreal package summary (uasset)",
            "imports_listed": imports.len(),
            "imports_total": summary.imports_total,
            "legacy_version": summary.legacy_version,
            "name_count": summary.names.len(),
            "package_label": summary.package_label,
            "summary_layout": summary.layout,
            "target_sha256": sha256,
            "total_header_size": summary.total_header_size,
            "ue4_version": summary.ue4_version,
            "ue5_version": summary.ue5_version,
        }),
    ));
    evidence.add_finding(Finding::new(
        "exports",
        Confidence::Observed,
        json!({"entries": exports, "returned": exports.len(), "total": summary.exports_total}),
    ));
    evidence.add_finding(Finding::new(
        "imports",
        Confidence::Observed,
        json!({"entries": imports, "returned": imports.len(), "total": summary.imports_total}),
    ));
    evidence.add_finding(Finding::new(
        "names",
        Confidence::Observed,
        json!({
            "entries": document["names"]
                .as_array()
                .map(|rows| rows.iter().take(UASSET_LISTED_MAX).collect::<Vec<_>>())
                .unwrap_or_default(),
            "returned": summary.names.len().min(UASSET_LISTED_MAX),
            "total": summary.names.len(),
        }),
    ));
    if summary.exports_total > 0 && summary.exports.is_empty() {
        evidence.add_unknown(
            "export entries",
            "export stride could not be derived from neighbouring offsets; count only",
        );
    }
    evidence.add_unknown(
        "property data",
        "property values are out of scope for the summary census by design",
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one FString (ASCII) to a byte buffer.
    fn push_fstring(out: &mut Vec<u8>, text: &str) {
        let len = (text.len() + 1) as i32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(text.as_bytes());
        out.push(0);
    }

    struct Built {
        bytes: Vec<u8>,
        name_count_at: usize,
    }

    /// Build a minimal legacy_folder package: 5 names,
    /// 2 imports, 1 export of class Material.
    fn build_legacy() -> Built {
        let names = [
            "/Game/mat_groundplane",
            "/Script/CoreUObject",
            "/Script/Engine",
            "Class",
            "Material",
        ];
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&UASSET_MAGIC.to_le_bytes());
        out.extend_from_slice(&(-7i32).to_le_bytes()); // legacy
        out.extend_from_slice(&0u32.to_le_bytes()); // ue5 version word
        out.extend_from_slice(&0i32.to_le_bytes()); // ue4 version
        out.extend_from_slice(&0i32.to_le_bytes()); // licensee
        out.extend_from_slice(&0i32.to_le_bytes()); // custom versions
        // Header fields after the name count/offset are
        // position-dependent; build the name table first
        // in a scratch buffer to know its offset.
        let mut table: Vec<u8> = Vec::new();
        for name in names {
            push_fstring(&mut table, name);
            table.extend_from_slice(&0u32.to_le_bytes());
        }
        // Name offset =
        // current len + 4 (ths) + fstring("None") + 4
        // (flags) + 8 (count/offset) + 8 (gatherable) +
        // 20 (counts/offsets x5) is where maps go; the
        // name table sits right after the summary tail.
        let summary_tail_len = 4 + 9 + 4 + 8 + 8 + 20; // ths + folder fstring + flags + count/offset + gatherable + 5 words
        let name_offset = (out.len() + summary_tail_len) as i32;
        let import_offset = name_offset + table.len() as i32;
        let export_offset = import_offset + 28 * 2;
        let depends_offset = export_offset + 104;
        let total_header_size = depends_offset;
        out.extend_from_slice(&total_header_size.to_le_bytes());
        push_fstring(&mut out, "None");
        out.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // flags
        let name_count_at = out.len();
        out.extend_from_slice(&(names.len() as i32).to_le_bytes());
        out.extend_from_slice(&name_offset.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes()); // gatherable count
        out.extend_from_slice(&0i32.to_le_bytes()); // gatherable offset
        out.extend_from_slice(&1i32.to_le_bytes()); // export count
        out.extend_from_slice(&export_offset.to_le_bytes());
        out.extend_from_slice(&2i32.to_le_bytes()); // import count
        out.extend_from_slice(&import_offset.to_le_bytes());
        out.extend_from_slice(&depends_offset.to_le_bytes());
        debug_assert_eq!(out.len() as i32, name_offset);
        out.extend_from_slice(&table);
        debug_assert_eq!(out.len() as i32, import_offset);
        // Import 0: class package /Script/CoreUObject (1),
        // class Class (3), outer 0, name Package pseudo —
        // real shape: (ClassPackage, ClassName, Outer, Name).
        for (cp, cn, nm) in [(1i32, 3i32, 2i32), (2, 3, 4)] {
            out.extend_from_slice(&cp.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes());
            out.extend_from_slice(&cn.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes()); // outer index
            out.extend_from_slice(&nm.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes());
        }
        debug_assert_eq!(out.len() as i32, export_offset);
        // Export: class index -2 (import 1 = Material),
        // name index 0, serial size 55.
        let mut entry = vec![0u8; 104];
        entry[0..4].copy_from_slice(&(-2i32).to_le_bytes());
        entry[16..20].copy_from_slice(&0i32.to_le_bytes());
        entry[28..36].copy_from_slice(&55i64.to_le_bytes());
        out.extend_from_slice(&entry);
        Built {
            bytes: out,
            name_count_at,
        }
    }

    #[test]
    fn validation_legacy_package_parses() {
        let built = build_legacy();
        let summary = parse_summary(&built.bytes, "legacy_folder").expect("parse");
        assert_eq!(summary.names.len(), 5);
        assert_eq!(summary.imports_total, 2);
        assert_eq!(summary.exports_total, 1);
        assert_eq!(summary.exports.len(), 1);
        assert_eq!(summary.exports[0].class, "Material");
        assert_eq!(summary.exports[0].serial_size, 55);
        assert_eq!(summary.imports[0].class_package, "/Script/CoreUObject");
    }

    #[test]
    fn adversarial_bad_magic_is_refused() {
        let mut built = build_legacy();
        built.bytes[0] = 0;
        let error = match parse_summary(&built.bytes, "legacy_folder") {
            Ok(_) => panic!("bad magic must refuse"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
    }

    #[test]
    fn adversarial_truncated_summary_is_refused() {
        let built = build_legacy();
        let error = match parse_summary(&built.bytes[..30], "legacy_folder") {
            Ok(_) => panic!("truncated summary must refuse"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
    }

    #[test]
    fn adversarial_lying_name_count_is_refused() {
        let mut built = build_legacy();
        // Inflate the declared name count far past the
        // table the file actually carries.
        built.bytes[built.name_count_at..built.name_count_at + 4]
            .copy_from_slice(&999i32.to_le_bytes());
        let result = parse_summary(&built.bytes, "legacy_folder");
        assert!(result.is_err());
    }
}
