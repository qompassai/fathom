//! Cubism model census reader (game-extract lane).
//!
//! Censuses one Live2D model directory in its loose,
//! post-extraction form: the `.model3.json` file references
//! and parameter groups, the `.cdi3.json` display record when
//! shipped, any `.exp3.json` expressions, and the `.moc3`
//! binary itself — header, canvas info, part / drawable /
//! parameter ID tables read structurally from the binary's
//! own offset table.
//!
//! Honesty contract: the moc3 offset-table layout (count
//! info at entry 0, canvas info at entry 1, part IDs at
//! entry 3, drawable IDs at entry 33, parameter IDs at
//! entry 50) is implemented for moc3 version 5 only — the
//! layout verified against the estate's eight shipped-model
//! fixtures (three titles, 2026-11-02). Other versions fail
//! closed as unsupported rather than being parsed by
//! analogy. Drawable parent-part indices are located by a
//! range-validated scan of the arrays following the
//! drawable ID table and are reported with the array's file
//! offset so the attribution is auditable; when no array
//! validates, parent parts are recorded as unrecorded.
//! Drawable draw order has no static array in the shipped
//! format that this reader can attribute, so it is never
//! reported. A model directory without `.model3.json`
//! censuses the binary alone and states that group bindings
//! are unrecorded — several shipped games drive blink and
//! gaze by parameter name and ship no group record at all.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    CUBISM_DRAWABLES_MAX, CUBISM_ID_SLOT_BYTES, CUBISM_PARAMETERS_MAX, CUBISM_PARTS_MAX,
    FILE_COUNT_MAX, TARGET_BYTES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// Offset-table entry indices in the version-5 moc3 layout.
const CANVAS_INFO_ENTRY: usize = 1;
const COUNT_INFO_ENTRY: usize = 0;
const DRAWABLE_IDS_ENTRY: usize = 33;
const PARAMETER_IDS_ENTRY: usize = 50;
const PART_IDS_ENTRY: usize = 3;

/// The estate's standard Cubism parameter vocabulary
/// (the comparison set the hand census uses).
const STANDARD_PARAMETERS: [&str; 40] = [
    "ParamAngleX",
    "ParamAngleY",
    "ParamAngleZ",
    "ParamArmLA",
    "ParamArmRA",
    "ParamArmLB",
    "ParamArmRB",
    "ParamHandL",
    "ParamHandR",
    "ParamEyeLOpen",
    "ParamEyeROpen",
    "ParamEyeLSmile",
    "ParamEyeRSmile",
    "ParamEyeBallX",
    "ParamEyeBallY",
    "ParamEyeBallForm",
    "ParamBrowLY",
    "ParamBrowRY",
    "ParamBrowLX",
    "ParamBrowRX",
    "ParamBrowLAngle",
    "ParamBrowRAngle",
    "ParamBrowLForm",
    "ParamBrowRForm",
    "ParamMouthForm",
    "ParamMouthOpenY",
    "ParamCheek",
    "ParamBodyAngleX",
    "ParamBodyAngleY",
    "ParamBodyAngleZ",
    "ParamHairFront",
    "ParamHairSide",
    "ParamHairBack",
    "ParamHairFluffy",
    "ParamShoulderY",
    "ParamBustX",
    "ParamBustY",
    "ParamBaseX",
    "ParamBaseY",
    "ParamBreath",
];

/// Lowercase substrings marking an eye parameter (the hand
/// census's key set).
const EYE_PARAMETER_KEYS: [&str; 6] = ["eye", "blink", "blick", "brow", "gaze", "heart"];

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
        .with_target("cubism model")
}

fn resource(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ResourceConstraint, message.into()).with_target("cubism model")
}

fn truncated(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::Truncated, message.into()).with_target("cubism model")
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into()).with_target("cubism model")
}

/// Read one file whose size was checked against the target
/// bound before the read.
fn read_bounded(path: &Path) -> Result<Vec<u8>, FathomError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat {}: {error}", path.display()),
        )
    })?;
    if metadata.len() > TARGET_BYTES_MAX {
        return Err(resource(format!(
            "{} declares {} bytes, over TARGET_BYTES_MAX ({TARGET_BYTES_MAX})",
            path.display(),
            metadata.len()
        )));
    }
    std::fs::read(path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read {}: {error}", path.display()),
        )
    })
}

/// List a model directory: files at the top level and in
/// immediate subdirectories (texture sets ship in a sibling
/// folder in some rips), as (relative path, full path) pairs
/// sorted by relative path.
fn list_model_files(dir: &Path) -> Result<Vec<(String, PathBuf)>, FathomError> {
    let mut listing: Vec<(String, PathBuf)> = Vec::new();
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot list model directory {}: {error}", dir.display()),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read a model directory entry: {error}"),
            )
        })?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            subdirs.push(path);
        } else {
            listing.push((name, path));
        }
    }
    for subdir in subdirs {
        let sub_name = subdir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let entries = std::fs::read_dir(&subdir).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!(
                    "cannot list model subdirectory {}: {error}",
                    subdir.display()
                ),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                FathomError::new(
                    ErrorCode::TargetUnavailable,
                    format!("cannot read a model subdirectory entry: {error}"),
                )
            })?;
            let path = entry.path();
            if !path.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                listing.push((format!("{sub_name}/{name}"), path));
            }
        }
    }
    if listing.len() > FILE_COUNT_MAX {
        return Err(resource(format!(
            "model directory holds {} files, over FILE_COUNT_MAX ({FILE_COUNT_MAX})",
            listing.len()
        )));
    }
    listing.sort();
    Ok(listing)
}

fn file_name_of(relative: &str) -> &str {
    relative.rsplit('/').next().unwrap_or(relative)
}

fn find_in_listing<'a>(
    listing: &'a [(String, PathBuf)],
    suffix: &str,
) -> Vec<&'a (String, PathBuf)> {
    listing
        .iter()
        .filter(|(relative, _)| relative.to_lowercase().ends_with(suffix))
        .collect()
}

/// The PNG pixel size from its header, when the file is one.
fn png_size(path: &Path) -> Option<(u32, u32)> {
    use std::io::Read;
    let mut head = [0_u8; 24];
    let mut file = std::fs::File::open(path).ok()?;
    file.read_exact(&mut head).ok()?;
    if &head[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    Some((
        u32::from_be_bytes(head[16..20].try_into().unwrap()),
        u32::from_be_bytes(head[20..24].try_into().unwrap()),
    ))
}

/// The parsed `.model3.json` record.
struct Model3 {
    expressions: Vec<Value>,
    file: String,
    groups: Vec<Value>,
    moc: Option<String>,
    motions: Vec<Value>,
    physics: Option<String>,
    pose: Option<String>,
    textures: Vec<String>,
    version: Option<Value>,
}

fn load_model3(listing: &[(String, PathBuf)]) -> Result<Option<Model3>, FathomError> {
    let candidates = find_in_listing(listing, ".model3.json");
    let Some((relative, path)) = candidates.first() else {
        return Ok(None);
    };
    let bytes = read_bounded(path)?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|error| mismatch(format!("{relative} is not valid JSON: {error}")))?;
    let references = &document["FileReferences"];
    let string_list = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let optional_string = |value: &Value| -> Option<String> { value.as_str().map(str::to_string) };
    let expressions = references["Expressions"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    json!({
                        "file": item["File"],
                        "name": item["Name"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut motions: Vec<Value> = Vec::new();
    if let Some(groups) = references["Motions"].as_object() {
        let mut names: Vec<&String> = groups.keys().collect();
        names.sort();
        for name in names {
            let files = groups[name]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["File"].as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            motions.push(json!({"files": files, "group": name}));
        }
    }
    let groups = document["Groups"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    json!({
                        "ids": if item["Ids"].is_null() {
                            json!([])
                        } else {
                            item["Ids"].clone()
                        },
                        "name": item["Name"],
                        "target": item["Target"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Model3 {
        expressions,
        file: relative.clone(),
        groups,
        moc: optional_string(&references["Moc"]),
        motions,
        physics: optional_string(&references["Physics"]),
        pose: optional_string(&references["Pose"]),
        textures: string_list(&references["Textures"]),
        version: if document["Version"].is_null() {
            None
        } else {
            Some(document["Version"].clone())
        },
    }))
}

/// The parsed `.cdi3.json` display record.
struct Cdi3 {
    file: String,
    parameter_groups: Vec<Value>,
    parameters: Vec<Value>,
    parts: Vec<Value>,
}

fn load_cdi3(listing: &[(String, PathBuf)]) -> Result<Option<Cdi3>, FathomError> {
    let candidates = find_in_listing(listing, ".cdi3.json");
    let Some((relative, path)) = candidates.first() else {
        return Ok(None);
    };
    let bytes = read_bounded(path)?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|error| mismatch(format!("{relative} is not valid JSON: {error}")))?;
    let rows = |key: &str, fields: &[&str]| -> Vec<Value> {
        document[key]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        let mut row = serde_json::Map::new();
                        for field in fields {
                            row.insert((*field).to_string(), item[field].clone());
                        }
                        Value::Object(row)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(Some(Cdi3 {
        file: relative.clone(),
        parameter_groups: rows("ParameterGroups", &["Id", "Name"]),
        parameters: rows(
            "Parameters",
            &["Id", "Name", "GroupId", "Min", "Max", "Default"],
        ),
        parts: rows("Parts", &["Id", "Name"]),
    }))
}

/// Census one shipped `.exp3.json` expression file.
fn load_expressions(listing: &[(String, PathBuf)]) -> Result<Vec<Value>, FathomError> {
    let mut expressions: Vec<Value> = Vec::new();
    for (relative, path) in find_in_listing(listing, ".exp3.json") {
        let bytes = read_bounded(path)?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|error| mismatch(format!("{relative} is not valid JSON: {error}")))?;
        let parameters: Vec<String> = document["Parameters"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["Id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let eye_parameters: Vec<String> = parameters
            .iter()
            .filter(|id| {
                let lowered = id.to_lowercase();
                EYE_PARAMETER_KEYS.iter().any(|key| lowered.contains(key))
            })
            .cloned()
            .collect();
        expressions.push(json!({
            "eye_parameters": eye_parameters,
            "file": relative,
            "parameters": parameters,
            "type": document["Type"],
        }));
    }
    Ok(expressions)
}

/// Little-endian u32 at a byte offset, bounds-checked.
fn read_u32le(bytes: &[u8], offset: usize) -> Result<u32, FathomError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| truncated("moc3 ends mid-word"))?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

/// Little-endian f32 at a byte offset, bounds-checked.
fn read_f32le(bytes: &[u8], offset: usize) -> Result<f32, FathomError> {
    Ok(f32::from_bits(read_u32le(bytes, offset)?))
}

/// One 64-byte ID slot: printable ASCII up to the first NUL
/// (or the full slot), never empty.
fn parse_id_slot(slot: &[u8], table: &str) -> Result<String, FathomError> {
    let end = slot
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slot.len());
    let head = &slot[..end];
    if head.is_empty() || !head.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(mismatch(format!(
            "moc3 {table} ID slot is empty or holds non-printable bytes"
        )));
    }
    Ok(head.iter().map(|byte| *byte as char).collect())
}

/// Read one ID table (count × 64-byte slots) at a file
/// offset taken from the moc3 offset table.
fn read_id_table(
    bytes: &[u8],
    offset: u32,
    count: u32,
    table: &str,
) -> Result<Vec<String>, FathomError> {
    let start = offset as usize;
    let _end = (count as usize)
        .checked_mul(CUBISM_ID_SLOT_BYTES)
        .and_then(|span| start.checked_add(span))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| truncated(format!("moc3 {table} ID table overruns the file")))?;
    let mut ids = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let slot_start = start + index * CUBISM_ID_SLOT_BYTES;
        let slot = &bytes[slot_start..slot_start + CUBISM_ID_SLOT_BYTES];
        ids.push(parse_id_slot(slot, table)?);
    }
    Ok(ids)
}

/// Locate the drawable parent-part index array: the first
/// i32 array among the offset-table entries following the
/// drawable ID table whose every value names a part (or
/// -1, no parent). Returns the values and the file offset.
fn find_parent_indices(
    bytes: &[u8],
    offsets: &[u32],
    drawable_count: u32,
    part_count: u32,
) -> Option<(Vec<i32>, u32)> {
    let count = drawable_count as usize;
    let last = (DRAWABLE_IDS_ENTRY + 33).min(offsets.len());
    for &offset in offsets.iter().take(last).skip(DRAWABLE_IDS_ENTRY + 1) {
        let start = offset as usize;
        let Some(end) = start.checked_add(count * 4) else {
            continue;
        };
        if end > bytes.len() {
            continue;
        }
        let mut values = Vec::with_capacity(count);
        let mut valid = true;
        for index in 0..count {
            let raw = &bytes[start + index * 4..start + index * 4 + 4];
            let value = i32::from_le_bytes(raw.try_into().unwrap());
            if value < -1 || value >= part_count as i32 {
                valid = false;
                break;
            }
            values.push(value);
        }
        if valid {
            return Some((values, offset));
        }
    }
    None
}

/// The moc3 binary census.
struct Moc3 {
    canvas: Option<Value>,
    counts: [u32; 8],
    deformer_split_consistent: bool,
    drawables: Vec<String>,
    id_table_offsets: [u32; 3],
    parameters: Vec<String>,
    parent_indices: Option<(Vec<i32>, u32)>,
    parts: Vec<String>,
    version: u8,
}

fn parse_moc3(bytes: &[u8]) -> Result<Moc3, FathomError> {
    if bytes.len() < 68 {
        return Err(truncated(
            "moc3 is shorter than its header and offset table",
        ));
    }
    if &bytes[..4] != b"MOC3" {
        let magic: String = bytes[..4].iter().map(|byte| *byte as char).collect();
        return Err(unsupported(format!("not a moc3 (magic '{magic}')")));
    }
    let version = bytes[4];
    if version != 5 {
        return Err(unsupported(format!(
            "moc3 version {version} is not implemented (supported: 5 — the offset-table layout is verified only for version 5)"
        )));
    }
    if bytes[5] != 0 {
        return Err(unsupported(format!(
            "moc3 byte-order flag {} is not implemented (supported: 0, little-endian)",
            bytes[5]
        )));
    }
    let count_info_at = read_u32le(bytes, 64)? as usize;
    if count_info_at < 68 || !(count_info_at - 64).is_multiple_of(4) {
        return Err(mismatch(format!(
            "moc3 count-info offset {count_info_at} does not follow the offset table"
        )));
    }
    let entry_count = (count_info_at - 64) / 4;
    if entry_count <= PARAMETER_IDS_ENTRY {
        return Err(unsupported(format!(
            "moc3 offset table holds {entry_count} entries; the verified version-5 layout needs at least {}",
            PARAMETER_IDS_ENTRY + 1
        )));
    }
    let mut offsets = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        offsets.push(read_u32le(bytes, 64 + index * 4)?);
    }
    let mut counts = [0_u32; 8];
    for (index, count) in counts.iter_mut().enumerate() {
        *count = read_u32le(bytes, count_info_at + index * 4)?;
    }
    let (parts, deformers, warp, rotation, drawables, parameters) = (
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5],
    );
    if parts as usize > CUBISM_PARTS_MAX {
        return Err(resource(format!(
            "moc3 declares {parts} parts, over CUBISM_PARTS_MAX ({CUBISM_PARTS_MAX})"
        )));
    }
    if drawables as usize > CUBISM_DRAWABLES_MAX {
        return Err(resource(format!(
            "moc3 declares {drawables} drawables, over CUBISM_DRAWABLES_MAX ({CUBISM_DRAWABLES_MAX})"
        )));
    }
    if parameters as usize > CUBISM_PARAMETERS_MAX {
        return Err(resource(format!(
            "moc3 declares {parameters} parameters, over CUBISM_PARAMETERS_MAX ({CUBISM_PARAMETERS_MAX})"
        )));
    }
    let canvas_offset = offsets[CANVAS_INFO_ENTRY] as usize;
    let canvas = (|| -> Option<Value> {
        let values: Vec<f32> = (0..5)
            .map(|index| read_f32le(bytes, canvas_offset + index * 4).ok())
            .collect::<Option<Vec<f32>>>()?;
        let [pixels_per_unit, origin_x, origin_y, width, height] = match values.as_slice() {
            [first, second, third, fourth, fifth] => [*first, *second, *third, *fourth, *fifth],
            _ => return None,
        };
        if !values.iter().all(|value| value.is_finite())
            || pixels_per_unit <= 0.0
            || width <= 0.0
            || height <= 0.0
        {
            return None;
        }
        let centre_tolerance = f32::max(width, height) * 0.01;
        let origin_is_centre = (origin_x - width / 2.0).abs() <= centre_tolerance
            && (origin_y - height / 2.0).abs() <= centre_tolerance;
        Some(json!({
            "canvas_height": height,
            "canvas_width": width,
            "origin_is_canvas_centre": origin_is_centre,
            "origin_x": origin_x,
            "origin_y": origin_y,
            "pixels_per_unit": pixels_per_unit,
        }))
    })();
    let parts_ids = read_id_table(bytes, offsets[PART_IDS_ENTRY], parts, "part")?;
    let drawable_ids = read_id_table(bytes, offsets[DRAWABLE_IDS_ENTRY], drawables, "drawable")?;
    let parameter_ids =
        read_id_table(bytes, offsets[PARAMETER_IDS_ENTRY], parameters, "parameter")?;
    let parent_indices = find_parent_indices(bytes, &offsets, drawables, parts);
    Ok(Moc3 {
        canvas,
        counts,
        deformer_split_consistent: deformers == warp + rotation,
        drawables: drawable_ids,
        id_table_offsets: [
            offsets[PART_IDS_ENTRY],
            offsets[DRAWABLE_IDS_ENTRY],
            offsets[PARAMETER_IDS_ENTRY],
        ],
        parameters: parameter_ids,
        parent_indices,
        parts: parts_ids,
        version,
    })
}

fn eye_parameters(parameters: &[String]) -> Vec<Value> {
    parameters
        .iter()
        .enumerate()
        .filter(|(_, id)| {
            let lowered = id.to_lowercase();
            EYE_PARAMETER_KEYS.iter().any(|key| lowered.contains(key))
        })
        .map(|(index, id)| json!({"id": id, "index": index}))
        .collect()
}

fn standard_parameters(parameters: &[String]) -> Vec<String> {
    parameters
        .iter()
        .filter(|id| STANDARD_PARAMETERS.contains(&id.as_str()))
        .cloned()
        .collect()
}

/// Census one Cubism model directory (see the module
/// contract). Arguments: `target` — the model directory.
pub fn census_cubism_model(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let dir = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    if !dir.is_dir() {
        return Err(mismatch(format!(
            "cubism target {} is not a directory",
            dir.display()
        )));
    }
    let listing = list_model_files(&dir)?;
    let model3 = load_model3(&listing)?;
    let cdi3 = load_cdi3(&listing)?;
    let expressions = load_expressions(&listing)?;
    let moc_candidates: Vec<&(String, PathBuf)> = listing
        .iter()
        .filter(|(relative, _)| relative.to_lowercase().ends_with(".moc3"))
        .collect();
    let moc_entry = match (&model3, moc_candidates.len()) {
        (Some(model), _) => {
            let wanted = model
                .moc
                .as_deref()
                .map(|moc| file_name_of(moc).to_string())
                .ok_or_else(|| mismatch("model3.json carries no Moc file reference"))?;
            moc_candidates
                .iter()
                .find(|(relative, _)| file_name_of(relative) == wanted)
                .copied()
                .ok_or_else(|| {
                    mismatch(format!(
                        "model3.json names Moc '{wanted}' but no such file is in the model directory"
                    ))
                })?
        }
        (None, 1) => moc_candidates[0],
        (None, 0) => {
            return Err(unsupported(
                "no .moc3 file in the model directory; there is no model to census",
            ));
        }
        (None, count) => {
            return Err(unsupported(format!(
                "{count} .moc3 files and no .model3.json Moc reference to choose between them"
            )));
        }
    };
    let (moc_relative, moc_path) = moc_entry;
    let subject = subject_for_file_with_bound(moc_path, TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let moc_bytes = read_bounded(moc_path)?;
    let moc = parse_moc3(&moc_bytes)?;
    let mut unknowns: Vec<(String, String)> = Vec::new();
    // Referenced-file presence (textures, physics, pose).
    let resolve_reference = |reference: &str| -> Option<&(String, PathBuf)> {
        listing
            .iter()
            .find(|(relative, _)| relative == reference)
            .or_else(|| {
                listing
                    .iter()
                    .find(|(relative, _)| file_name_of(relative) == file_name_of(reference))
            })
    };
    let mut texture_rows: Vec<Value> = Vec::new();
    if let Some(model) = &model3 {
        for reference in &model.textures {
            match resolve_reference(reference) {
                Some((relative, path)) => {
                    let resolution = png_size(path);
                    texture_rows.push(json!({
                        "file": reference,
                        "found_as": relative,
                        "resolution": resolution.map(|(w, h)| json!([w, h])),
                    }));
                }
                None => {
                    texture_rows.push(json!({"file": reference, "found_as": Value::Null}));
                    unknowns.push((
                        "referenced texture".to_string(),
                        format!("model3.json references texture '{reference}', which is not in the model directory"),
                    ));
                }
            }
        }
    } else {
        for (relative, path) in find_in_listing(&listing, ".png") {
            let resolution = png_size(path);
            texture_rows.push(json!({
                "file": relative,
                "found_as": relative,
                "resolution": resolution.map(|(w, h)| json!([w, h])),
            }));
        }
        unknowns.push((
            "file references".to_string(),
            "no .model3.json in the model directory; Moc/texture/physics/pose references and EyeBlink/LipSync group bindings are unrecorded — several shipped games drive blink and gaze by parameter name and ship no group record".to_string(),
        ));
    }
    if cdi3.is_none() {
        unknowns.push((
            "parameter ranges".to_string(),
            "no .cdi3.json in the model directory; parameter display names, groups, and min/max/default ranges are unrecorded".to_string(),
        ));
    }
    if moc.canvas.is_none() {
        unknowns.push((
            "canvas info".to_string(),
            "the moc3 canvas record did not validate as five finite floats with positive size; canvas facts are unrecorded".to_string(),
        ));
    }
    if moc.parent_indices.is_none() {
        unknowns.push((
            "drawable parent parts".to_string(),
            "no range-validated parent-index array was found after the drawable ID table; drawable parent parts are unrecorded".to_string(),
        ));
    }
    let reference_row = |reference: &Option<String>| -> Value {
        match reference {
            Some(reference) => {
                let found = resolve_reference(reference);
                json!({
                    "bytes": found.map(|(_, path)| std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)),
                    "file": reference,
                    "present": found.is_some(),
                })
            }
            None => Value::Null,
        }
    };
    let drawables: Vec<Value> = moc
        .drawables
        .iter()
        .enumerate()
        .map(|(index, id)| {
            json!({
                "id": id,
                "parent_part_index": moc
                    .parent_indices
                    .as_ref()
                    .map(|(values, _)| values[index]),
            })
        })
        .collect();
    let document = json!({
        "cdi3": cdi3.as_ref().map(|cdi| json!({
            "file": cdi.file,
            "parameter_groups": cdi.parameter_groups,
            "parameters": cdi.parameters,
            "parts": cdi.parts,
        })),
        "expressions": expressions,
        "moc3": {
            "bytes": subject.size_bytes,
            "canvas": moc.canvas,
            "counts": {
                "deformers": moc.counts[1],
                "deformer_split_consistent": moc.deformer_split_consistent,
                "drawables": moc.counts[4],
                "parameters": moc.counts[5],
                "parts": moc.counts[0],
                "raw": moc.counts,
                "rotation_deformers": moc.counts[3],
                "warp_deformers": moc.counts[2],
            },
            "drawables": drawables,
            "eye_parameters": eye_parameters(&moc.parameters),
            "file": moc_relative,
            "id_table_offsets": {
                "drawables": moc.id_table_offsets[1],
                "parameters": moc.id_table_offsets[2],
                "parts": moc.id_table_offsets[0],
            },
            "parameters": moc.parameters,
            "parent_indices_offset": moc.parent_indices.as_ref().map(|(_, offset)| *offset),
            "parts": moc.parts,
            "sha256": subject_sha256,
            "standard_ids_present": standard_parameters(&moc.parameters),
            "version": moc.version,
        },
        "model": dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "model3": model3.as_ref().map(|model| json!({
            "expressions": model.expressions,
            "file": model.file,
            "groups": model.groups,
            "moc": model.moc,
            "motions": model.motions,
            "physics": reference_row(&model.physics),
            "pose": reference_row(&model.pose),
            "textures": model.textures,
            "version": model.version,
        })),
        "textures": texture_rows,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "cubism_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut evidence = Evidence::new("census_cubism_model", "cubism");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "cubism_census",
        Confidence::Observed,
        document.clone(),
    ));
    evidence.add_finding(Finding::new(
        "cubism_model",
        Confidence::Observed,
        json!({
            "cdi3_present": cdi3.is_some(),
            "drawable_count": moc.counts[4],
            "export_digest": digest,
            "group_count": model3.as_ref().map_or(0, |model| model.groups.len()),
            "moc3_file": moc_relative,
            "model3_present": model3.is_some(),
            "parameter_count": moc.counts[5],
            "parts_count": moc.counts[0],
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
    for (aspect, reason) in unknowns {
        evidence.add_unknown(aspect, reason);
    }
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Offset-table entries in the synthetic fixture (the
    /// shipped files carry 480).
    const ENTRY_COUNT: usize = 480;

    fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_f32(bytes: &mut [u8], at: usize, value: f32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn id_table(ids: &[&str]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ids.len() * CUBISM_ID_SLOT_BYTES);
        for id in ids {
            let mut slot = [0_u8; CUBISM_ID_SLOT_BYTES];
            slot[..id.len()].copy_from_slice(id.as_bytes());
            out.extend_from_slice(&slot);
        }
        out
    }

    /// Build a version-5 moc3 with the given ID tables and
    /// drawable parent indices, laid out like the shipped
    /// fixtures (count info first, canvas after it, ID
    /// tables at their format entries).
    fn build_moc3(
        parts: &[&str],
        drawables: &[&str],
        parameters: &[&str],
        parents: &[i32],
    ) -> Vec<u8> {
        assert_eq!(drawables.len(), parents.len());
        let count_info_at = 64 + ENTRY_COUNT * 4;
        let canvas_at = count_info_at + 256;
        let parts_at = canvas_at + 720;
        let drawables_at = parts_at + parts.len() * CUBISM_ID_SLOT_BYTES;
        let parents_at = drawables_at + drawables.len() * CUBISM_ID_SLOT_BYTES;
        let parameters_at = parents_at + parents.len() * 4;
        let total = parameters_at + parameters.len() * CUBISM_ID_SLOT_BYTES;
        let mut out = vec![0_u8; total];
        out[..4].copy_from_slice(b"MOC3");
        out[4] = 5;
        for (entry, offset) in [
            (COUNT_INFO_ENTRY, count_info_at),
            (CANVAS_INFO_ENTRY, canvas_at),
            (PART_IDS_ENTRY, parts_at),
            (DRAWABLE_IDS_ENTRY, drawables_at),
            (DRAWABLE_IDS_ENTRY + 1, parents_at),
            (PARAMETER_IDS_ENTRY, parameters_at),
        ] {
            write_u32(&mut out, 64 + entry * 4, offset as u32);
        }
        let counts: [u32; 8] = [
            parts.len() as u32,
            3,
            2,
            1,
            drawables.len() as u32,
            parameters.len() as u32,
            parts.len() as u32,
            0,
        ];
        for (index, count) in counts.iter().enumerate() {
            write_u32(&mut out, count_info_at + index * 4, *count);
        }
        for (index, value) in [1000.0_f32, 500.0, 500.0, 1000.0, 1000.0]
            .iter()
            .enumerate()
        {
            write_f32(&mut out, canvas_at + index * 4, *value);
        }
        out[parts_at..parts_at + parts.len() * CUBISM_ID_SLOT_BYTES]
            .copy_from_slice(&id_table(parts));
        out[drawables_at..drawables_at + drawables.len() * CUBISM_ID_SLOT_BYTES]
            .copy_from_slice(&id_table(drawables));
        for (index, parent) in parents.iter().enumerate() {
            write_u32(&mut out, parents_at + index * 4, *parent as u32);
        }
        out[parameters_at..parameters_at + parameters.len() * CUBISM_ID_SLOT_BYTES]
            .copy_from_slice(&id_table(parameters));
        out
    }

    fn png_header(width: u32, height: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        out.extend_from_slice(&13_u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out
    }

    fn run_model(
        test_name: &str,
        files: &[(&str, Vec<u8>)],
    ) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-cubism-test-{}-{test_name}",
            std::process::id()
        ));
        let model = root.join("model");
        fs::create_dir_all(&model).unwrap();
        for (name, bytes) in files {
            let path = model.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, bytes).unwrap();
        }
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": model.display().to_string()});
        let result = census_cubism_model(&Registry::new(), &config, &args);
        (root, result)
    }

    fn census_of(value: &Value) -> &Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "cubism_census")
            .map(|finding| &finding["facts"])
            .unwrap()
    }

    fn fixture_moc3() -> Vec<u8> {
        build_moc3(
            &["PartBody", "PartEye"],
            &["ArtMeshEye", "ArtMeshBody"],
            &[
                "ParamAngleX",
                "ParamEyeLOpen",
                "ParamEyeBallX",
                "ParamBreath",
                "BlinkCustom",
            ],
            &[1, 0],
        )
    }

    #[test]
    fn validation_full_model_census() {
        let model3 = json!({
            "Version": 3,
            "FileReferences": {
                "Moc": "model.moc3",
                "Textures": ["texture_00.png"],
                "Physics": "model.physics3.json",
                "Expressions": [{"Name": "smile", "File": "smile.exp3.json"}],
                "Motions": {"Idle": [{"File": "idle.motion3.json"}]},
            },
            "Groups": [
                {"Target": "Parameter", "Name": "EyeBlink", "Ids": ["ParamEyeLOpen"]},
                {"Target": "Parameter", "Name": "LipSync", "Ids": []},
            ],
        });
        let cdi3 = json!({
            "Version": 3,
            "Parameters": [{
                "Id": "ParamEyeLOpen", "Name": "Eye open", "GroupId": "Eye",
                "Min": 0, "Max": 1, "Default": 1,
            }],
            "ParameterGroups": [{"Id": "Eye", "Name": "Eyes"}],
            "Parts": [{"Id": "PartEye", "Name": "Eye"}],
        });
        let (root, result) = run_model(
            "full",
            &[
                ("model.moc3", fixture_moc3()),
                ("model.model3.json", serde_json::to_vec(&model3).unwrap()),
                ("model.cdi3.json", serde_json::to_vec(&cdi3).unwrap()),
                ("model.physics3.json", b"{}".to_vec()),
                ("texture_00.png", png_header(2048, 1024)),
            ],
        );
        let value = result.unwrap();
        let census = census_of(&value);
        assert_eq!(census["moc3"]["counts"]["parameters"], 5);
        assert_eq!(census["moc3"]["counts"]["drawables"], 2);
        assert_eq!(census["moc3"]["counts"]["parts"], 2);
        assert_eq!(
            census["moc3"]["parameters"],
            json!([
                "ParamAngleX",
                "ParamEyeLOpen",
                "ParamEyeBallX",
                "ParamBreath",
                "BlinkCustom"
            ])
        );
        assert_eq!(
            census["moc3"]["standard_ids_present"],
            json!([
                "ParamAngleX",
                "ParamEyeLOpen",
                "ParamEyeBallX",
                "ParamBreath"
            ])
        );
        let eye_ids: Vec<&str> = census["moc3"]["eye_parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert_eq!(eye_ids, ["ParamEyeLOpen", "ParamEyeBallX", "BlinkCustom"]);
        assert_eq!(census["moc3"]["drawables"][0]["parent_part_index"], 1);
        assert_eq!(census["moc3"]["drawables"][1]["parent_part_index"], 0);
        assert_eq!(census["moc3"]["canvas"]["origin_is_canvas_centre"], true);
        assert_eq!(
            census["model3"]["groups"][0]["ids"],
            json!(["ParamEyeLOpen"])
        );
        assert_eq!(census["model3"]["groups"][1]["ids"], json!([]));
        assert_eq!(census["model3"]["physics"]["present"], true);
        assert_eq!(census["textures"][0]["resolution"], json!([2048, 1024]));
        assert_eq!(census["cdi3"]["parameters"][0]["Id"], "ParamEyeLOpen");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_moc3_only_census() {
        let (root, result) = run_model("moc3-only", &[("lone.moc3", fixture_moc3())]);
        let value = result.unwrap();
        let census = census_of(&value);
        assert_eq!(census["moc3"]["counts"]["parameters"], 5);
        assert!(census["model3"].is_null());
        let unknowns = value["unknowns"].as_array().unwrap();
        assert!(
            unknowns
                .iter()
                .any(|unknown| unknown["aspect"] == "file references"),
            "the missing model3.json is an unknown: {unknowns:?}"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_bad_magic_is_refused() {
        let mut bytes = fixture_moc3();
        bytes[..4].copy_from_slice(b"XXXX");
        let (root, result) = run_model("bad-magic", &[("model.moc3", bytes)]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_id_table_is_refused() {
        let bytes = fixture_moc3();
        let cut = bytes.len() - 100;
        let (root, result) = run_model("truncated", &[("model.moc3", bytes[..cut].to_vec())]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::Truncated);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_unsupported_version_is_refused() {
        let mut bytes = fixture_moc3();
        bytes[4] = 4;
        let (root, result) = run_model("version", &[("model.moc3", bytes)]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_oversized_parameter_count_is_refused() {
        let mut bytes = fixture_moc3();
        let count_info_at = 64 + ENTRY_COUNT * 4;
        write_u32(&mut bytes, count_info_at + 5 * 4, 200_000);
        let (root, result) = run_model("oversized", &[("model.moc3", bytes)]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceConstraint);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_overrun_parameter_count_is_refused() {
        let mut bytes = fixture_moc3();
        let count_info_at = 64 + ENTRY_COUNT * 4;
        write_u32(&mut bytes, count_info_at + 5 * 4, 60);
        let (root, result) = run_model("overrun", &[("model.moc3", bytes)]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::Truncated);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_malformed_model3_is_refused() {
        let (root, result) = run_model(
            "bad-model3",
            &[
                ("model.moc3", fixture_moc3()),
                ("model.model3.json", b"{not json".to_vec()),
            ],
        );
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_model3_naming_missing_moc_is_refused() {
        let model3 = json!({
            "Version": 3,
            "FileReferences": {"Moc": "ghost.moc3", "Textures": []},
            "Groups": [],
        });
        let (root, result) = run_model(
            "ghost-moc",
            &[
                ("model.moc3", fixture_moc3()),
                ("model.model3.json", serde_json::to_vec(&model3).unwrap()),
            ],
        );
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_empty_id_slot_is_refused() {
        let mut bytes = fixture_moc3();
        // Zero the first parameter slot: parameters sit at the
        // last table; find its offset from the offset table.
        let parameters_at = read_u32le(&bytes, 64 + PARAMETER_IDS_ENTRY * 4).unwrap() as usize;
        for byte in &mut bytes[parameters_at..parameters_at + CUBISM_ID_SLOT_BYTES] {
            *byte = 0;
        }
        let (root, result) = run_model("empty-slot", &[("model.moc3", bytes)]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }
}
