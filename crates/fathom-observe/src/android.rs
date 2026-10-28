//! `inspect_android_apk` (SPEC §9.4): static APK inventory.
//!
//! Hand-implemented, bounded readers — no JADX/JDK engine:
//! a ZIP central-directory reader (stored + deflate entries;
//! ZIP64 and multi-disk archives are named walls), and a binary
//! AXML parser for `AndroidManifest.xml` covering the manifest
//! element, permissions, features, the application element, and
//! components with their intent-filter actions/categories.
//! DEX contents and `resources.arsc` are inventoried by name only
//! and declared unknown — they are not decoded here.

use serde::Serialize;
use serde_json::{Value, json};
use std::io::Read;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::limits::TARGET_BYTES_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// Entries listed individually in the inventory finding.
const ENTRIES_LISTED_MAX: usize = 4_096;
/// Native libraries listed per ABI.
const LIBRARIES_PER_ABI_MAX: usize = 256;
/// Uncompressed bytes accepted for the manifest entry.
const MANIFEST_BYTES_MAX: usize = 16_777_216;
/// String-pool strings accepted from one AXML document.
const POOL_STRINGS_MAX: u32 = 65_536;
/// Attributes accepted on one AXML element.
const ELEMENT_ATTRIBUTES_MAX: u16 = 512;
/// Elements accepted in one AXML document.
const ELEMENTS_MAX: usize = 65_536;
/// ZIP entries accepted from one archive.
const ZIP_ENTRIES_MAX: usize = 100_000;

#[derive(Debug, Serialize)]
struct ApplicationInfo {
    allow_backup: Option<bool>,
    debuggable: Option<bool>,
    label: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Component {
    actions: Vec<String>,
    categories: Vec<String>,
    exported: Option<bool>,
    kind: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Feature {
    name: Option<String>,
    required: Option<bool>,
}

#[derive(Debug, Default, Serialize)]
struct Manifest {
    application: Option<ApplicationInfo>,
    components: Vec<Component>,
    declared_permissions: Vec<String>,
    features: Vec<Feature>,
    package: Option<String>,
    permissions: Vec<String>,
    uses_sdk: Option<UsesSdk>,
    version_code: Option<String>,
    version_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct UsesSdk {
    min_sdk: Option<String>,
    target_sdk: Option<String>,
}

#[derive(Debug)]
struct ZipEntry {
    compressed_size: u64,
    encrypted: bool,
    local_header_offset: u64,
    method: u16,
    name: String,
    size: u64,
}

fn malformed(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message.into())
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into())
}

/// Inspect one APK file.
pub(crate) fn inspect_android_apk(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    if !target.is_file() {
        return Err(unsupported("APK target must be a regular file"));
    }
    let data = read_bounded(&target)?;
    let entries = parse_zip(&data)?;

    let mut evidence = Evidence::new("inspect_android_apk", "android");
    evidence.add_finding(Finding::new(
        "apk_archive",
        Confidence::Observed,
        json!({
            "sha256": sha256_hex(&data),
            "size_bytes": data.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "apk_inventory",
        Confidence::Observed,
        json!({
            "entries": entries
                .iter()
                .take(ENTRIES_LISTED_MAX)
                .map(|entry| json!({
                    "compressed_size": entry.compressed_size,
                    "encrypted": entry.encrypted,
                    "method": entry.method,
                    "name": entry.name,
                    "size": entry.size,
                }))
                .collect::<Vec<_>>(),
            "entries_truncated": entries.len() > ENTRIES_LISTED_MAX,
            "entry_count": entries.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "apk_contents",
        Confidence::Observed,
        contents_facts(&entries),
    ));
    match entries
        .iter()
        .find(|entry| entry.name == "AndroidManifest.xml")
    {
        Some(entry) => match extract_entry(&data, entry, MANIFEST_BYTES_MAX) {
            Ok(manifest_bytes) => match parse_axml(&manifest_bytes) {
                Ok(manifest) => {
                    evidence.add_finding(Finding::new(
                        "android_manifest",
                        Confidence::Observed,
                        serde_json::to_value(&manifest).unwrap_or(Value::Null),
                    ));
                }
                Err(error) => evidence.add_unknown(
                    "android_manifest",
                    format!("binary manifest did not parse: {}", error.message),
                ),
            },
            Err(error) => evidence.add_unknown(
                "android_manifest",
                format!("manifest entry could not be read: {}", error.message),
            ),
        },
        None => evidence.add_unknown(
            "android_manifest",
            "archive has no AndroidManifest.xml entry",
        ),
    }
    evidence.add_unknown(
        "dex_contents",
        "DEX files are inventoried by name; class/method decoding is not implemented",
    );
    evidence.add_unknown(
        "resources_arsc_contents",
        "resources.arsc is inventoried by name; resource table decoding is not implemented",
    );
    evidence.add_unknown(
        "signing_certificate",
        "APK signature verification is not performed by this provider",
    );
    evidence.coverage.examined = entries.len() as u64;
    evidence.coverage.total = entries.len() as u64;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

fn read_bounded(target: &Path) -> Result<Vec<u8>, FathomError> {
    let mut file = std::fs::File::open(target).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open APK: {e}"),
        )
    })?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read APK: {e}"),
        )
    })?;
    if data.len() as u64 > TARGET_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("APK exceeds the target bound of {TARGET_BYTES_MAX} bytes"),
        ));
    }
    Ok(data)
}

/// Aggregate the content-class facts from the entry list.
fn contents_facts(entries: &[ZipEntry]) -> Value {
    let mut abis: Vec<Value> = Vec::new();
    let mut assets_count = 0_usize;
    let mut dex_files = Vec::new();
    let mut has_resources = false;
    let mut signature_files = Vec::new();
    let mut abi_names: Vec<String> = Vec::new();
    for entry in entries {
        let name = entry.name.as_str();
        if name == "resources.arsc" {
            has_resources = true;
        } else if name.starts_with("assets/") {
            assets_count += 1;
        } else if name.starts_with("META-INF/") {
            signature_files.push(name.to_string());
        } else if let Some(rest) = name.strip_prefix("lib/") {
            if let Some((abi, library)) = rest.split_once('/')
                && library.ends_with(".so")
                && !library.contains('/')
            {
                if !abi_names.contains(&abi.to_string()) {
                    abi_names.push(abi.to_string());
                    abis.push(json!({"abi": abi, "libraries": []}));
                }
                if let Some(row) = abis.iter_mut().find(|row| row["abi"] == abi)
                    && let Some(list) = row["libraries"].as_array_mut()
                    && list.len() < LIBRARIES_PER_ABI_MAX
                {
                    list.push(json!(library));
                }
            }
        } else if name.starts_with("classes") && name.ends_with(".dex") {
            dex_files.push(name.to_string());
        }
    }
    json!({
        "assets_count": assets_count,
        "dex_files": dex_files,
        "has_resources_arsc": has_resources,
        "native_libraries": abis,
        "signature_files": signature_files,
    })
}

/// Parse the ZIP central directory. Local headers are consulted
/// only at extraction time; the inventory trusts the directory,
/// which is the archive's own index.
fn parse_zip(data: &[u8]) -> Result<Vec<ZipEntry>, FathomError> {
    let eocd_offset = find_eocd(data)?;
    let cursor = Cursor::new(data);
    let disk = cursor.u16(eocd_offset + 4)?;
    let entries_total = cursor.u16(eocd_offset + 10)? as usize;
    let cd_size = cursor.u32(eocd_offset + 12)? as usize;
    let cd_offset = cursor.u32(eocd_offset + 16)? as usize;
    if disk != 0 {
        return Err(unsupported("multi-disk ZIP archives are not supported"));
    }
    if entries_total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        return Err(unsupported("ZIP64 archives are not supported"));
    }
    if entries_total > ZIP_ENTRIES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("ZIP entry count exceeds the bound of {ZIP_ENTRIES_MAX}"),
        ));
    }
    let cd_end = cd_offset
        .checked_add(cd_size)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| malformed("central directory extends past the archive"))?;
    let mut entries = Vec::with_capacity(entries_total);
    let mut offset = cd_offset;
    while offset < cd_end {
        if cursor.u32(offset)? != 0x0201_4B50 {
            return Err(malformed(format!(
                "bad central directory signature at {offset}"
            )));
        }
        let flags = cursor.u16(offset + 8)?;
        let method = cursor.u16(offset + 10)?;
        let compressed_size = cursor.u32(offset + 20)? as u64;
        let size = cursor.u32(offset + 24)? as u64;
        let name_len = cursor.u16(offset + 28)? as usize;
        let extra_len = cursor.u16(offset + 30)? as usize;
        let comment_len = cursor.u16(offset + 32)? as usize;
        let local_header_offset = cursor.u32(offset + 42)? as u64;
        let name_start = offset + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| malformed("central directory name extends past the archive"))?;
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
        entries.push(ZipEntry {
            compressed_size,
            encrypted: flags & 1 != 0,
            local_header_offset,
            method,
            name,
            size,
        });
        offset = name_end + extra_len + comment_len;
    }
    if entries.len() != entries_total {
        return Err(malformed(format!(
            "central directory holds {} entries; end record declares {entries_total}",
            entries.len()
        )));
    }
    Ok(entries)
}

/// Locate the end-of-central-directory record by scanning the
/// trailing window (max comment size + record size) backwards.
fn find_eocd(data: &[u8]) -> Result<usize, FathomError> {
    if data.len() < 22 {
        return Err(unsupported("file is too small to be a ZIP archive"));
    }
    let window = data.len().min(65_557);
    let start = data.len() - window;
    let mut offset = data.len() - 22;
    loop {
        if data[offset..offset + 4] == [0x50, 0x4B, 0x05, 0x06] {
            let comment_len = u16::from_le_bytes([data[offset + 20], data[offset + 21]]) as usize;
            if offset + 22 + comment_len == data.len() {
                return Ok(offset);
            }
        }
        if offset == start {
            break;
        }
        offset -= 1;
    }
    Err(unsupported("no ZIP end-of-central-directory record found"))
}

/// Extract one entry's uncompressed bytes, bounded by `cap`.
fn extract_entry(data: &[u8], entry: &ZipEntry, cap: usize) -> Result<Vec<u8>, FathomError> {
    if entry.encrypted {
        return Err(unsupported(format!("entry {} is encrypted", entry.name)));
    }
    let cursor = Cursor::new(data);
    let offset = entry.local_header_offset as usize;
    if cursor.u32(offset)? != 0x0403_4B50 {
        return Err(malformed(format!(
            "bad local header signature for {}",
            entry.name
        )));
    }
    let name_len = cursor.u16(offset + 26)? as usize;
    let extra_len = cursor.u16(offset + 28)? as usize;
    let data_start = offset + 30 + name_len + extra_len;
    let data_end = data_start
        .checked_add(entry.compressed_size as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            malformed(format!(
                "entry {} data extends past the archive",
                entry.name
            ))
        })?;
    let compressed = &data[data_start..data_end];
    match entry.method {
        0 => {
            if compressed.len() > cap {
                return Err(FathomError::new(
                    ErrorCode::ResourceConstraint,
                    format!("entry {} exceeds the extraction bound", entry.name),
                ));
            }
            Ok(compressed.to_vec())
        }
        8 => {
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut out = Vec::new();
            let read = decoder
                .by_ref()
                .take(cap as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| malformed(format!("entry {} does not inflate: {e}", entry.name)))?;
            if read > cap {
                return Err(FathomError::new(
                    ErrorCode::ResourceConstraint,
                    format!("entry {} exceeds the extraction bound", entry.name),
                ));
            }
            Ok(out)
        }
        other => Err(unsupported(format!(
            "entry {} uses unsupported compression method {other}",
            entry.name
        ))),
    }
}

/// Bounds-checked little-endian reads over the archive bytes.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data }
    }

    fn u16(&self, offset: usize) -> Result<u16, FathomError> {
        let bytes = self
            .data
            .get(offset..offset + 2)
            .ok_or_else(|| malformed(format!("read past end of data at {offset}")))?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&self, offset: usize) -> Result<u32, FathomError> {
        let bytes = self
            .data
            .get(offset..offset + 4)
            .ok_or_else(|| malformed(format!("read past end of data at {offset}")))?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Parse a binary AXML document into the manifest model.
fn parse_axml(data: &[u8]) -> Result<Manifest, FathomError> {
    let cursor = Cursor::new(data);
    if data.len() < 8 || cursor.u32(0)? != 0x0008_0003 {
        return Err(unsupported("not a binary AXML document"));
    }
    let mut manifest = Manifest::default();
    let mut pool: Vec<String> = Vec::new();
    let mut stack: Vec<ElementFrame> = Vec::new();
    let mut elements_seen = 0_usize;
    let mut offset = 8_usize;
    while offset + 8 <= data.len() {
        let chunk_type = cursor.u16(offset)?;
        let chunk_size = cursor.u32(offset + 4)? as usize;
        if chunk_size < 8 || offset + chunk_size > data.len() {
            return Err(malformed(format!(
                "AXML chunk at {offset} declares an out-of-bounds size"
            )));
        }
        match chunk_type {
            0x0001 => pool = parse_string_pool(data, offset, chunk_size)?,
            0x0102 => {
                elements_seen += 1;
                if elements_seen > ELEMENTS_MAX {
                    return Err(FathomError::new(
                        ErrorCode::ResourceConstraint,
                        format!("AXML element count exceeds the bound of {ELEMENTS_MAX}"),
                    ));
                }
                let frame = parse_start_element(data, offset, &pool, &mut manifest, &stack)?;
                stack.push(frame);
            }
            0x0103 => {
                stack.pop();
            }
            _ => {}
        }
        offset += chunk_size;
    }
    Ok(manifest)
}

struct ElementFrame {
    component_index: Option<usize>,
    in_intent_filter: bool,
    name: String,
}

/// Parse the string-pool chunk at `offset`.
fn parse_string_pool(
    data: &[u8],
    offset: usize,
    chunk_size: usize,
) -> Result<Vec<String>, FathomError> {
    let cursor = Cursor::new(data);
    let string_count = cursor.u32(offset + 8)?;
    if string_count > POOL_STRINGS_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("string pool count exceeds the bound of {POOL_STRINGS_MAX}"),
        ));
    }
    let flags = cursor.u32(offset + 16)?;
    let utf8 = flags & 0x100 != 0;
    let strings_start = cursor.u32(offset + 20)? as usize;
    let chunk_end = offset + chunk_size;
    let mut strings = Vec::with_capacity(string_count as usize);
    for index in 0..string_count as usize {
        let relative = cursor.u32(offset + 28 + index * 4)? as usize;
        let absolute = offset
            .checked_add(strings_start)
            .and_then(|base| base.checked_add(relative))
            .filter(|position| *position < chunk_end)
            .ok_or_else(|| malformed("string pool offset is out of bounds"))?;
        strings.push(if utf8 {
            read_pool_string_utf8(data, absolute, chunk_end)?
        } else {
            read_pool_string_utf16(data, absolute, chunk_end)?
        });
    }
    Ok(strings)
}

fn read_pool_string_utf8(data: &[u8], start: usize, end: usize) -> Result<String, FathomError> {
    // Two length fields (character count, then byte count), each
    // in the high-bit continuation form, precede the bytes.
    let mut probe = start;
    let mut byte_len = 0_usize;
    for slot in 0..2 {
        let first = *data
            .get(probe)
            .ok_or_else(|| malformed("truncated UTF-8 pool string length"))?;
        if first & 0x80 != 0 {
            let second = *data
                .get(probe + 1)
                .ok_or_else(|| malformed("truncated UTF-8 pool string length"))?;
            if slot == 1 {
                byte_len = (((first & 0x7F) as usize) << 8) | second as usize;
            }
            probe += 2;
        } else {
            if slot == 1 {
                byte_len = first as usize;
            }
            probe += 1;
        }
    }
    let string_end = probe
        .checked_add(byte_len)
        .filter(|limit| *limit <= end)
        .ok_or_else(|| malformed("UTF-8 pool string extends past the pool"))?;
    Ok(String::from_utf8_lossy(&data[probe..string_end]).into_owned())
}

fn read_pool_string_utf16(data: &[u8], start: usize, end: usize) -> Result<String, FathomError> {
    let cursor = Cursor::new(data);
    let first = cursor.u16(start)? as usize;
    let (length, units_start) = if first & 0x8000 != 0 {
        let second = cursor.u16(start + 2)? as usize;
        (((first & 0x7FFF) << 16) | second, start + 4)
    } else {
        (first, start + 2)
    };
    let mut units = Vec::with_capacity(length);
    for index in 0..length {
        let unit_offset = units_start + index * 2;
        if unit_offset + 2 > end {
            return Err(malformed("UTF-16 pool string extends past the pool"));
        }
        units.push(cursor.u16(unit_offset)?);
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Parse one start-element chunk, fold it into the manifest, and
/// return the stack frame it pushes.
fn parse_start_element(
    data: &[u8],
    offset: usize,
    pool: &[String],
    manifest: &mut Manifest,
    stack: &[ElementFrame],
) -> Result<ElementFrame, FathomError> {
    let cursor = Cursor::new(data);
    let name_index = cursor.u32(offset + 20)?;
    let name = pool_string(pool, name_index)
        .ok_or_else(|| malformed("element name index is out of range"))?;
    let attribute_start = cursor.u16(offset + 24)? as usize;
    let attribute_size = cursor.u16(offset + 26)? as usize;
    let attribute_count = cursor.u16(offset + 28)?;
    if attribute_count > ELEMENT_ATTRIBUTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("element attribute count exceeds the bound of {ELEMENT_ATTRIBUTES_MAX}"),
        ));
    }
    if attribute_size < 20 {
        return Err(malformed("attribute size is smaller than the format's 20"));
    }
    let mut attrs: Vec<(String, Option<String>)> = Vec::new();
    for index in 0..attribute_count as usize {
        let attr_offset = offset + 16 + attribute_start + index * attribute_size;
        let attr_name_index = cursor.u32(attr_offset + 4)?;
        let attr_name = pool_string(pool, attr_name_index)
            .ok_or_else(|| malformed("attribute name index is out of range"))?;
        let raw_value = cursor.u32(attr_offset + 8)?;
        let data_type = *data
            .get(attr_offset + 15)
            .ok_or_else(|| malformed("attribute value extends past the chunk"))?;
        let typed_data = cursor.u32(attr_offset + 16)?;
        attrs.push((
            attr_name,
            resolve_value(pool, raw_value, data_type, typed_data),
        ));
    }
    let get = |key: &str| -> Option<String> {
        attrs
            .iter()
            .find(|(attr_name, _)| attr_name == key)
            .and_then(|(_, value)| value.clone())
    };
    let parent_is = |expected: &str| stack.last().is_some_and(|frame| frame.name == expected);
    let mut frame = ElementFrame {
        component_index: None,
        in_intent_filter: stack.iter().any(|frame| frame.in_intent_filter),
        name: name.clone(),
    };
    match name.as_str() {
        "action" | "category" => {
            if frame.in_intent_filter
                && let Some(component_index) =
                    stack.iter().rev().find_map(|frame| frame.component_index)
                && let Some(value) = get("name")
            {
                let component = &mut manifest.components[component_index];
                if name == "action" {
                    component.actions.push(value);
                } else {
                    component.categories.push(value);
                }
            }
        }
        "activity" | "activity-alias" | "provider" | "receiver" | "service" => {
            if parent_is("application") {
                manifest.components.push(Component {
                    actions: Vec::new(),
                    categories: Vec::new(),
                    exported: get("exported").map(|value| value == "true"),
                    kind: name.clone(),
                    name: get("name"),
                });
                frame.component_index = Some(manifest.components.len() - 1);
            }
        }
        "application" => {
            manifest.application = Some(ApplicationInfo {
                allow_backup: get("allowBackup").map(|value| value == "true"),
                debuggable: get("debuggable").map(|value| value == "true"),
                label: get("label"),
                name: get("name"),
            });
        }
        "intent-filter" => {
            frame.in_intent_filter = stack.iter().any(|frame| frame.component_index.is_some());
        }
        "manifest" => {
            manifest.package = get("package");
            manifest.version_code = get("versionCode");
            manifest.version_name = get("versionName");
        }
        "permission" => {
            if let Some(value) = get("name") {
                manifest.declared_permissions.push(value);
            }
        }
        "uses-feature" => {
            manifest.features.push(Feature {
                name: get("name"),
                required: get("required").map(|value| value == "true"),
            });
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(value) = get("name") {
                manifest.permissions.push(value);
            }
        }
        "uses-sdk" => {
            manifest.uses_sdk = Some(UsesSdk {
                min_sdk: get("minSdkVersion"),
                target_sdk: get("targetSdkVersion"),
            });
        }
        _ => {}
    }
    Ok(frame)
}

fn pool_string(pool: &[String], index: u32) -> Option<String> {
    if index == u32::MAX {
        return None;
    }
    pool.get(index as usize).cloned()
}

/// Resolve one attribute value: raw string first, typed value
/// second, per the AXML value rules.
fn resolve_value(pool: &[String], raw: u32, data_type: u8, data: u32) -> Option<String> {
    if raw != u32::MAX {
        return pool_string(pool, raw);
    }
    match data_type {
        0x01 => Some(format!("@0x{data:08x}")),
        0x02 => Some(format!("?0x{data:08x}")),
        0x03 => pool_string(pool, data),
        0x04 => Some(f32::from_bits(data).to_string()),
        0x10 => Some((data as i32).to_string()),
        0x11 => Some(format!("0x{data:08x}")),
        0x12 => Some(if data != 0 { "true" } else { "false" }.to_string()),
        _ => Some(format!("0x{data:08x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AXML fixture builder ------------------------------------

    fn build_string_pool(strings: &[&str]) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut body = Vec::new();
        for string in strings {
            offsets.push(body.len() as u32);
            let bytes = string.as_bytes();
            body.push(bytes.len() as u8);
            body.push(bytes.len() as u8);
            body.extend_from_slice(bytes);
            body.push(0);
        }
        let strings_start = 28 + 4 * strings.len();
        let size = strings_start + body.len();
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0x0001_u16.to_le_bytes());
        chunk.extend_from_slice(&28_u16.to_le_bytes());
        chunk.extend_from_slice(&(size as u32).to_le_bytes());
        chunk.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&0_u32.to_le_bytes());
        chunk.extend_from_slice(&0x100_u32.to_le_bytes());
        chunk.extend_from_slice(&(strings_start as u32).to_le_bytes());
        chunk.extend_from_slice(&0_u32.to_le_bytes());
        for offset in offsets {
            chunk.extend_from_slice(&offset.to_le_bytes());
        }
        chunk.extend_from_slice(&body);
        chunk
    }

    struct Attr {
        name: u32,
        raw: u32,
        data_type: u8,
        data: u32,
    }

    fn build_start_element(name: u32, attrs: &[Attr]) -> Vec<u8> {
        let size = 36 + 20 * attrs.len();
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0x0102_u16.to_le_bytes());
        chunk.extend_from_slice(&16_u16.to_le_bytes());
        chunk.extend_from_slice(&(size as u32).to_le_bytes());
        chunk.extend_from_slice(&0_u32.to_le_bytes()); // line
        chunk.extend_from_slice(&u32::MAX.to_le_bytes()); // comment
        chunk.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
        chunk.extend_from_slice(&name.to_le_bytes());
        chunk.extend_from_slice(&20_u16.to_le_bytes()); // attributeStart
        chunk.extend_from_slice(&20_u16.to_le_bytes()); // attributeSize
        chunk.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
        chunk.extend_from_slice(&0_u16.to_le_bytes()); // idIndex
        chunk.extend_from_slice(&0_u16.to_le_bytes()); // classIndex
        chunk.extend_from_slice(&0_u16.to_le_bytes()); // styleIndex
        for attr in attrs {
            chunk.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
            chunk.extend_from_slice(&attr.name.to_le_bytes());
            chunk.extend_from_slice(&attr.raw.to_le_bytes());
            chunk.extend_from_slice(&8_u16.to_le_bytes()); // value size
            chunk.push(0); // res0
            chunk.push(attr.data_type);
            chunk.extend_from_slice(&attr.data.to_le_bytes());
        }
        chunk
    }

    fn build_end_element(name: u32) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0x0103_u16.to_le_bytes());
        chunk.extend_from_slice(&16_u16.to_le_bytes());
        chunk.extend_from_slice(&24_u32.to_le_bytes());
        chunk.extend_from_slice(&0_u32.to_le_bytes());
        chunk.extend_from_slice(&u32::MAX.to_le_bytes());
        chunk.extend_from_slice(&u32::MAX.to_le_bytes());
        chunk.extend_from_slice(&name.to_le_bytes());
        chunk
    }

    fn string_attr(name: u32, value: u32) -> Attr {
        Attr {
            name,
            raw: value,
            data_type: 0x03,
            data: value,
        }
    }

    fn typed_attr(name: u32, data_type: u8, data: u32) -> Attr {
        Attr {
            name,
            raw: u32::MAX,
            data_type,
            data,
        }
    }

    /// String indices for the fixture manifest.
    /// 0 manifest, 1 package, 2 com.example.app, 3 versionCode,
    /// 4 versionName, 5 1.0, 6 uses-permission, 7 name,
    /// 8 android.permission.INTERNET, 9 application, 10 label,
    /// 11 Test App, 12 activity, 13 .MainActivity, 14 exported,
    /// 15 intent-filter, 16 action, 17 android.intent.action.MAIN,
    /// 18 uses-sdk, 19 minSdkVersion, 20 targetSdkVersion
    fn fixture_axml() -> Vec<u8> {
        let strings = [
            "manifest",
            "package",
            "com.example.app",
            "versionCode",
            "versionName",
            "1.0",
            "uses-permission",
            "name",
            "android.permission.INTERNET",
            "application",
            "label",
            "Test App",
            "activity",
            ".MainActivity",
            "exported",
            "intent-filter",
            "action",
            "android.intent.action.MAIN",
            "uses-sdk",
            "minSdkVersion",
            "targetSdkVersion",
        ];
        let mut body = build_string_pool(&strings);
        body.extend(build_start_element(
            0,
            &[string_attr(1, 2), typed_attr(3, 0x10, 7), string_attr(4, 5)],
        ));
        body.extend(build_start_element(
            18,
            &[typed_attr(19, 0x10, 24), typed_attr(20, 0x10, 34)],
        ));
        body.extend(build_end_element(18));
        body.extend(build_start_element(6, &[string_attr(7, 8)]));
        body.extend(build_end_element(6));
        body.extend(build_start_element(9, &[string_attr(10, 11)]));
        body.extend(build_start_element(
            12,
            &[string_attr(7, 13), typed_attr(14, 0x12, 0xFFFF_FFFF)],
        ));
        body.extend(build_start_element(15, &[]));
        body.extend(build_start_element(16, &[string_attr(7, 17)]));
        body.extend(build_end_element(16));
        body.extend(build_end_element(15));
        body.extend(build_end_element(12));
        body.extend(build_end_element(9));
        body.extend(build_end_element(0));
        let total = 8 + body.len();
        let mut document = Vec::new();
        document.extend_from_slice(&0x0008_0003_u32.to_le_bytes());
        document.extend_from_slice(&(total as u32).to_le_bytes());
        document.extend_from_slice(&body);
        document
    }

    // ---- ZIP fixture builder -------------------------------------

    fn build_zip(entries: &[(&str, u16, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        // (name, method, stored_bytes, _uncompressed)
        let mut data = Vec::new();
        let mut central = Vec::new();
        for (name, method, stored, uncompressed) in entries {
            let local_offset = data.len() as u32;
            data.extend_from_slice(&0x0403_4B50_u32.to_le_bytes());
            data.extend_from_slice(&20_u16.to_le_bytes());
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(&method.to_le_bytes());
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(&0_u32.to_le_bytes());
            data.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            data.extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
            data.extend_from_slice(&(name.len() as u16).to_le_bytes());
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(name.as_bytes());
            data.extend_from_slice(stored);
            central.extend_from_slice(&0x0201_4B50_u32.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            central.extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = data.len() as u32;
        let cd_size = central.len() as u32;
        data.extend_from_slice(&central);
        data.extend_from_slice(&0x0605_4B50_u32.to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&cd_size.to_le_bytes());
        data.extend_from_slice(&cd_offset.to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());
        data
    }

    #[test]
    fn validation_zip_and_manifest_end_to_end() {
        let axml = fixture_axml();
        let zip = build_zip(&[
            ("AndroidManifest.xml", 0, axml.clone(), axml.clone()),
            ("classes.dex", 0, vec![1, 2, 3], vec![1, 2, 3]),
            ("lib/arm64-v8a/libdemo.so", 0, vec![4, 5], vec![4, 5]),
        ]);
        let entries = parse_zip(&zip).unwrap();
        assert_eq!(entries.len(), 3);
        let facts = contents_facts(&entries);
        assert_eq!(facts["dex_files"][0], "classes.dex");
        assert_eq!(facts["native_libraries"][0]["abi"], "arm64-v8a");
        assert_eq!(facts["native_libraries"][0]["libraries"][0], "libdemo.so");
        let manifest_entry = &entries[0];
        let bytes = extract_entry(&zip, manifest_entry, MANIFEST_BYTES_MAX).unwrap();
        let manifest = parse_axml(&bytes).unwrap();
        assert_eq!(manifest.package.as_deref(), Some("com.example.app"));
        assert_eq!(manifest.version_code.as_deref(), Some("7"));
        assert_eq!(manifest.version_name.as_deref(), Some("1.0"));
        assert_eq!(
            manifest.uses_sdk.as_ref().unwrap().min_sdk.as_deref(),
            Some("24")
        );
        assert_eq!(manifest.permissions, vec!["android.permission.INTERNET"]);
        assert_eq!(
            manifest.application.as_ref().unwrap().label.as_deref(),
            Some("Test App")
        );
        assert_eq!(manifest.components.len(), 1);
        assert_eq!(manifest.components[0].kind, "activity");
        assert_eq!(
            manifest.components[0].name.as_deref(),
            Some(".MainActivity")
        );
        assert_eq!(manifest.components[0].exported, Some(true));
        assert_eq!(
            manifest.components[0].actions,
            vec!["android.intent.action.MAIN"]
        );
    }

    #[test]
    fn validation_deflated_manifest_extracts() {
        use std::io::Write;
        let axml = fixture_axml();
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&axml).unwrap();
        let compressed = encoder.finish().unwrap();
        let zip = build_zip(&[("AndroidManifest.xml", 8, compressed, axml.clone())]);
        let entries = parse_zip(&zip).unwrap();
        let bytes = extract_entry(&zip, &entries[0], MANIFEST_BYTES_MAX).unwrap();
        assert_eq!(bytes, axml);
    }

    #[test]
    fn validation_axml_typed_values_resolve() {
        assert_eq!(
            resolve_value(&[], u32::MAX, 0x12, 0).as_deref(),
            Some("false")
        );
        assert_eq!(
            resolve_value(&[], u32::MAX, 0x10, (-3_i32) as u32).as_deref(),
            Some("-3")
        );
        assert_eq!(
            resolve_value(&[], u32::MAX, 0x01, 0x7F01_0001).as_deref(),
            Some("@0x7f010001")
        );
    }

    #[test]
    fn adversarial_not_a_zip_is_unsupported() {
        assert_eq!(
            parse_zip(b"this is not an archive at all, really")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedTarget
        );
    }

    #[test]
    fn adversarial_truncated_zip_is_a_typed_error() {
        let zip = build_zip(&[("a.txt", 0, vec![1], vec![1])]);
        let truncated = &zip[..zip.len() - 10];
        assert!(parse_zip(truncated).is_err());
    }

    #[test]
    fn adversarial_bad_axml_magic_is_unsupported() {
        assert_eq!(
            parse_axml(b"NOPE not axml data").unwrap_err().code,
            ErrorCode::UnsupportedTarget
        );
    }

    #[test]
    fn adversarial_truncated_string_pool_is_a_typed_error() {
        let mut axml = fixture_axml();
        axml.truncate(40);
        // The file header still claims the full size; chunk parsing
        // must fail typed, never panic.
        assert!(parse_axml(&axml).is_err());
    }
}
