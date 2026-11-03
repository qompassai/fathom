//! `fathom-spec/1` spec-record emission (rebuild lane R11).
//!
//! The spec is the only artifact that crosses the clean-room
//! wall (charter §2): testable behaviour statements in our own
//! words, data tables with units and ranges, and evidence
//! pointers — kind, locator, content hash — that let an auditor
//! on the RE side verify every claim without any copied code,
//! copied text, or extracted asset entering the spec tree.
//!
//! One tool, `spec_record` (Execute class, default-deny), three
//! operations:
//!
//! - `write` — a census evidence envelope (the retained output
//!   of `census_cubism_model`) becomes one spec document per
//!   model, written atomically into a validated output
//!   directory. Lane labels and the separation record are
//!   required caller arguments with no defaults: an unlabelled
//!   spec is refused, never emitted (Bloch lane law, fail
//!   closed).
//! - `validate` — a spec document is checked against the
//!   `fathom-spec/1` contract: shape, closed vocabularies,
//!   per-statement evidence, tolerances, lane labels,
//!   separation record, and the D-591 structure-only rule for
//!   dialogue units. The verdict carries named violations; an
//!   invalid spec is a successful execution whose verdict is
//!   `valid: false`, while a malformed or unreadable document
//!   is a typed execution error. Given a `census` argument, the
//!   validator also resolves every census-record evidence
//!   pointer against that record (hash equality + field
//!   presence).
//! - `diff` — a spec is compared against a ground-truth census
//!   in the D-565 census-diff harness shape: the per-model
//!   check list of the original Python harness, re-implemented
//!   over spec content, reporting matched/changed counts and
//!   never a bare pass.
//!
//! Bounds: input documents are capped at
//! `SPEC_DOCUMENT_BYTES_MAX`; statement, table-row, unknown,
//! and violation counts carry their own named caps in
//! `fathom-core::limits`. All work is in-memory over the two
//! input documents; the only write is the spec file itself
//! (temp file + rename) under a `paths::validate_output_dir`
//! directory.

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::limits::{
    SPEC_CHECKS_MAX, SPEC_DOCUMENT_BYTES_MAX, SPEC_EVIDENCE_POINTERS_MAX, SPEC_STATEMENTS_MAX,
    SPEC_TABLE_ROWS_MAX, SPEC_UNKNOWNS_MAX, SPEC_VIOLATIONS_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, optional_str, require_str};

/// The one spec format this rung emits and validates.
const SPEC_FORMAT_VERSION: &str = "fathom-spec/1";

/// The closed unit-kind vocabulary (charter §4 / design §3.3).
const UNIT_KINDS: [&str; 6] = [
    "data-table",
    "dialogue",
    "logic",
    "physics",
    "state-machine",
    "ui",
];

/// The Bloch content-label pair. Nothing else is a label.
const CONTENT_LABELS: [&str; 2] = ["nsfw", "sfw"];

/// The closed per-statement tolerance vocabulary.
const TOLERANCE_KINDS: [&str; 3] = ["exact", "numeric-band", "visual"];

/// Keys that would carry a target's verbatim dialogue text.
/// A dialogue spec carries structure only (D-591); any of
/// these keys anywhere in a dialogue unit is a violation.
const VERBATIM_KEYS: [&str; 3] = ["dialogue_text", "original_text", "verbatim_text"];

/// Float band for range comparisons in the diff, mirroring
/// the D-565 harness's probe tolerance.
const RANGE_TOLERANCE: f64 = 1e-6;

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
}

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message.into())
}

fn resource(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ResourceConstraint, message.into())
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into())
}

/// True when `text` is exactly 64 lowercase hex characters —
/// the shape of every SHA-256 the estate emits.
fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Read one JSON document argument: the path is validated
/// against the configured target roots, the bytes are read
/// under `SPEC_DOCUMENT_BYTES_MAX`, and the document must
/// parse as JSON. Returns the validated path, the raw bytes
/// (callers hash them for evidence pointers), and the value.
fn read_document(config: &Config, target: &str) -> Result<(PathBuf, Vec<u8>, Value), FathomError> {
    let path = paths::validate_target(config, Path::new(target))?;
    let bytes = read_bounded(&path)?;
    let value = serde_json::from_slice(&bytes).map_err(|error| {
        mismatch(format!(
            "document {} is not valid JSON: {error}",
            path.display()
        ))
    })?;
    Ok((path, bytes, value))
}

/// Read a file's bytes under `SPEC_DOCUMENT_BYTES_MAX`,
/// failing closed past the bound rather than truncating.
fn read_bounded(path: &Path) -> Result<Vec<u8>, FathomError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open document {}: {error}", path.display()),
        )
    })?;
    let mut bytes = Vec::new();
    let limit = SPEC_DOCUMENT_BYTES_MAX.saturating_add(1);
    file.take(limit).read_to_end(&mut bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot read document {}: {error}", path.display()),
        )
    })?;
    if bytes.len() as u64 > SPEC_DOCUMENT_BYTES_MAX {
        return Err(resource(format!(
            "document {} exceeds {SPEC_DOCUMENT_BYTES_MAX} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// The `cubism_census` finding's facts object of a census
/// evidence envelope — the R11 writer's one census source.
fn cubism_facts(envelope: &Value) -> Result<&Value, FathomError> {
    let findings = envelope["findings"].as_array().ok_or_else(|| {
        mismatch("census envelope carries no findings array; it is not a census record")
    })?;
    let finding = findings
        .iter()
        .find(|finding| finding["kind"] == "cubism_census")
        .ok_or_else(|| {
            unsupported(
                "census envelope carries no cubism_census finding; \
                 the R11 writer's census source is the Cubism census",
            )
        })?;
    let facts = &finding["facts"];
    if !facts.is_object() {
        return Err(mismatch("cubism_census finding carries no facts object"));
    }
    Ok(facts)
}

/// A file-name stem safe on every filesystem the estate
/// targets: alphanumerics, `-`, `_`, `.` survive; everything
/// else folds to `_`. Empty and dot-only results are refused
/// by the caller.
fn sanitize_file_stem(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

/// Caller-supplied spec metadata: everything the writer must
/// not invent. Lane labels, the title fingerprint, and the
/// separation record come from the caller or the spec is not
/// written.
struct SpecMeta<'a> {
    title: &'a str,
    fingerprint: &'a str,
    author: &'a str,
    origin_lane: &'a str,
    content_label: &'a str,
    both_sides: Option<&'a str>,
    locator: &'a str,
    census_hash: String,
}

/// Statements under construction, with their tolerances.
/// Every statement carries exactly one census-record evidence
/// pointer; the pointer's `field` names the census fact the
/// statement derives from.
struct StatementSet {
    statements: Vec<Value>,
    tolerances: Map<String, Value>,
}

impl StatementSet {
    fn new() -> Self {
        StatementSet {
            statements: Vec::new(),
            tolerances: Map::new(),
        }
    }

    fn add(
        &mut self,
        text: String,
        fact_name: &str,
        fact_value: Value,
        field: &str,
        meta: &SpecMeta,
    ) -> Result<(), FathomError> {
        if self.statements.len() >= SPEC_STATEMENTS_MAX {
            return Err(resource(format!(
                "spec would exceed {SPEC_STATEMENTS_MAX} statements"
            )));
        }
        let id = format!("S{:02}", self.statements.len() + 1);
        self.tolerances.insert(id.clone(), json!({"kind": "exact"}));
        self.statements.push(json!({
            "id": id,
            "text": text,
            "fact": {"name": fact_name, "value": fact_value},
            "evidence": [{
                "kind": "census-record",
                "locator": meta.locator,
                "field": field,
                "hash": meta.census_hash,
            }],
        }));
        Ok(())
    }
}

/// Normalize group rows from either side's spelling
/// (`Name`/`Target`/`Ids` or `name`/`target`/`ids`) into the
/// spec's one shape. Shared by the writer (census rows) and
/// the diff (ground-truth rows) so both sides normalize
/// identically.
fn normalize_groups(raw: &Value) -> Value {
    let rows = raw.as_array().cloned().unwrap_or_default();
    Value::Array(
        rows.iter()
            .map(|row| {
                let pick = |pascal: &str, lower: &str| {
                    if row[pascal].is_null() {
                        row[lower].clone()
                    } else {
                        row[pascal].clone()
                    }
                };
                json!({
                    "name": pick("Name", "name"),
                    "target": pick("Target", "target"),
                    "ids": pick("Ids", "ids"),
                })
            })
            .collect(),
    )
}

/// The probe that would close a census unknown, chosen from
/// the unknown's aspect vocabulary. Unknowns without a known
/// probe class get the generic re-census probe: an unknown is
/// never recorded without the probe that would close it.
fn probe_for(aspect: &str) -> &'static str {
    let lower = aspect.to_lowercase();
    if lower.contains("cdi3") || lower.contains("display") {
        "Census a build of the title that ships .cdi3.json, or census the loose model-directory form."
    } else if lower.contains("texture") {
        "Locate the referenced texture in the title's extracted tree and re-census the model."
    } else if lower.contains("model3") {
        "Census the loose model-directory form of the title, which ships .model3.json."
    } else {
        "Re-census with a reader that establishes this aspect."
    }
}

/// The physics fact a spec states, from whichever census
/// shape carries physics: a fresh census's `physics3`
/// document (cited by digest — the document itself is census
/// content and is never copied into the spec) or a retained
/// census's model3 physics reference row. Returns the fact
/// and the census field the statement's evidence pointer
/// must name, so the pointer resolves against the record
/// that was actually written from.
fn physics_fact(facts: &Value) -> Option<(Value, &'static str)> {
    if let Some(doc) = facts["physics3"].as_object() {
        let settings = doc["settings"].as_array().map(|rows| rows.len());
        return Some((
            json!({
                "present": true,
                "settings": settings,
                "sha256": sha256_hex(proof::canonical_json(&facts["physics3"]).as_bytes()),
                "source": "census-physics3",
            }),
            "physics3",
        ));
    }
    let reference = &facts["model3"]["physics"];
    if reference.is_object() && reference["present"] == Value::Bool(true) {
        return Some((
            json!({
                "present": true,
                "file": reference["file"],
                "bytes": reference["bytes"],
                "settings": Value::Null,
                "sha256": Value::Null,
                "source": "model3-reference",
            }),
            "model3.physics",
        ));
    }
    None
}

/// Build the spec document for one censused model. Fails
/// closed (typed mismatch) when the census record does not
/// carry the facts a spec must state; optional census content
/// (textures, model3, physics, expressions) is stated when
/// present and recorded as unknowns when its absence leaves
/// a gap.
fn build_spec_document(
    facts: &Value,
    envelope: &Value,
    meta: &SpecMeta,
) -> Result<Value, FathomError> {
    let moc = facts["moc3"].as_object().ok_or_else(|| {
        mismatch("cubism census facts carry no moc3 object; there is no model to specify")
    })?;
    let moc = Value::Object(moc.clone());
    let model = facts["model"]
        .as_str()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| mismatch("cubism census facts carry no model name"))?;
    let sha256 = moc["sha256"]
        .as_str()
        .ok_or_else(|| mismatch("cubism census facts carry no moc3 sha256"))?;
    let version = moc["version"]
        .as_u64()
        .ok_or_else(|| mismatch("cubism census facts carry no moc3 version"))?;
    let bytes = moc["bytes"]
        .as_u64()
        .ok_or_else(|| mismatch("cubism census facts carry no moc3 byte count"))?;
    let counts = &moc["counts"];
    let count_of = |key: &str| -> Result<u64, FathomError> {
        counts[key]
            .as_u64()
            .ok_or_else(|| mismatch(format!("cubism census counts carry no '{key}' count")))
    };
    let parameter_count = count_of("parameters")?;
    let drawable_count = count_of("drawables")?;
    let parts_count = count_of("parts")?;

    let parameters: Vec<String> = moc["parameters"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let ranges: Option<Vec<Value>> = moc["parameter_ranges"].as_array().cloned();
    let ranges_consistent: Option<bool> = ranges.as_ref().map(|rows| {
        rows.iter().all(|row| {
            let (min, max, default) = (
                row["min"].as_f64(),
                row["max"].as_f64(),
                row["default"].as_f64(),
            );
            match (min, max, default) {
                (Some(min), Some(max), Some(default)) => {
                    min <= max && min <= default && default <= max
                }
                _ => false,
            }
        })
    });

    let mut set = StatementSet::new();
    set.add(
        format!("The moc3 payload for this model is the file with SHA-256 {sha256}."),
        "moc3_sha256",
        Value::String(sha256.to_string()),
        "moc3.sha256",
        meta,
    )?;
    set.add(
        format!("The moc3 container version is {version}."),
        "moc3_version",
        json!(version),
        "moc3.version",
        meta,
    )?;
    set.add(
        format!("The moc3 payload is {bytes} bytes."),
        "moc3_bytes",
        json!(bytes),
        "moc3.bytes",
        meta,
    )?;
    if moc["canvas"].is_object() {
        let canvas = &moc["canvas"];
        set.add(
            format!(
                "The moc3 canvas is {} x {} at {} pixels per unit.",
                canvas["canvas_width"], canvas["canvas_height"], canvas["pixels_per_unit"]
            ),
            "canvas",
            canvas.clone(),
            "moc3.canvas",
            meta,
        )?;
    }
    set.add(
        format!("The model declares {parameter_count} parameters."),
        "parameter_count",
        json!(parameter_count),
        "moc3.counts.parameters",
        meta,
    )?;
    set.add(
        "The parameter identifiers in declaration order are this statement's fact; \
         the parameters data table carries each identifier's range."
            .to_string(),
        "parameters_ordered",
        Value::Array(
            parameters
                .iter()
                .map(|id| Value::String(id.clone()))
                .collect(),
        ),
        "moc3.parameters",
        meta,
    )?;
    let eye_ids: Vec<Value> = moc["eye_parameters"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(|id| Value::String(id.to_string())))
                .collect()
        })
        .unwrap_or_default();
    set.add(
        format!(
            "The eye-channel parameters are this statement's fact ({} ids).",
            eye_ids.len()
        ),
        "eye_parameters",
        Value::Array(eye_ids),
        "moc3.eye_parameters",
        meta,
    )?;
    let standard_ids = moc["standard_ids_present"].clone();
    set.add(
        "The standard Cubism parameter ids present, in declaration order, are this \
         statement's fact."
            .to_string(),
        "standard_ids_present",
        standard_ids,
        "moc3.standard_ids_present",
        meta,
    )?;
    set.add(
        format!(
            "The model declares {drawable_count} drawables; their ids and parent \
             parts are the drawables data table."
        ),
        "drawable_count",
        json!(drawable_count),
        "moc3.counts.drawables",
        meta,
    )?;
    set.add(
        format!(
            "The model declares {parts_count} parts; their ids in order are the \
             parts data table."
        ),
        "parts_count",
        json!(parts_count),
        "moc3.counts.parts",
        meta,
    )?;
    let textures_count = facts["textures"].as_array().map_or(0, |rows| rows.len());
    set.add(
        format!(
            "The census records {textures_count} texture files for this model \
             (metadata only; pixel data is not decoded — gap G1)."
        ),
        "textures_count",
        json!(textures_count),
        "textures",
        meta,
    )?;
    let model3 = &facts["model3"];
    let groups_fact = if model3.is_object() {
        normalize_groups(&model3["groups"])
    } else {
        Value::Null
    };
    set.add(
        if model3.is_object() {
            "The model3 group bindings are this statement's fact; empty Id lists \
             are recorded as empty."
                .to_string()
        } else {
            "No model3 group record ships with this model; group bindings are \
             unrecorded."
                .to_string()
        },
        "groups",
        groups_fact,
        // When model3 is absent the pointer cites the model3
        // slot itself: its recorded null is the evidence of
        // absence, and the field still resolves.
        if model3.is_object() {
            "model3.groups"
        } else {
            "model3"
        },
        meta,
    )?;
    match ranges_consistent {
        Some(consistent) => {
            set.add(
                format!(
                    "Every parameter range row is in band (min <= default <= max): \
                     {consistent}."
                ),
                "ranges_consistent",
                Value::Bool(consistent),
                "moc3.parameter_ranges",
                meta,
            )?;
        }
        None => {
            set.add(
                "Parameter ranges are not recorded by this census.".to_string(),
                "ranges_consistent",
                Value::Null,
                "moc3.parameter_ranges",
                meta,
            )?;
        }
    }
    if let Some((fact, field)) = physics_fact(facts) {
        set.add(
            "A physics3 document ships with this model; the spec cites it by \
             digest and summary and does not copy it."
                .to_string(),
            "physics3",
            fact,
            field,
            meta,
        )?;
    }
    let expressions_count = facts["expressions"].as_array().map_or(0, |rows| rows.len());
    if expressions_count > 0 {
        set.add(
            format!(
                "The model ships {expressions_count} expression records; their \
                 parameter values are census content, cited by this spec's \
                 evidence pointer."
            ),
            "expressions_count",
            json!(expressions_count),
            "expressions",
            meta,
        )?;
    }

    let mut tables: Vec<Value> = Vec::new();
    let parameter_rows: Vec<Value> = match &ranges {
        Some(rows) => rows
            .iter()
            .map(|row| json!([row["id"], row["min"], row["max"], row["default"]]))
            .collect(),
        None => parameters
            .iter()
            .map(|id| json!([id, Value::Null, Value::Null, Value::Null]))
            .collect(),
    };
    if parameter_rows.len() > SPEC_TABLE_ROWS_MAX {
        return Err(resource(format!(
            "parameters table would exceed {SPEC_TABLE_ROWS_MAX} rows"
        )));
    }
    tables.push(json!({
        "name": "parameters",
        "columns": ["id", "min", "max", "default"],
        "unit": "cubism parameter value (unitless; range as recorded in the moc3)",
        "rows": parameter_rows,
    }));
    let drawable_rows: Vec<Value> = moc["drawables"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| json!([row["id"], row["parent_part_index"]]))
                .collect()
        })
        .unwrap_or_default();
    if drawable_rows.len() > SPEC_TABLE_ROWS_MAX {
        return Err(resource(format!(
            "drawables table would exceed {SPEC_TABLE_ROWS_MAX} rows"
        )));
    }
    tables.push(json!({
        "name": "drawables",
        "columns": ["id", "parent_part_index"],
        "unit": "parent part index (unitless)",
        "rows": drawable_rows,
    }));
    let part_rows: Vec<Value> = moc["parts"]
        .as_array()
        .map(|rows| rows.iter().map(|id| json!([id])).collect())
        .unwrap_or_default();
    tables.push(json!({
        "name": "parts",
        "columns": ["id"],
        "unit": "identifier (unitless)",
        "rows": part_rows,
    }));

    let mut unknowns: Vec<Value> = Vec::new();
    if let Some(rows) = envelope["unknowns"].as_array() {
        for row in rows {
            let aspect = row["aspect"].as_str().unwrap_or("unrecorded aspect");
            let reason = row["reason"].as_str().unwrap_or("no reason recorded");
            unknowns.push(json!({
                "question": format!("{aspect} — {reason}"),
                "probe": probe_for(aspect),
            }));
        }
    }
    if ranges.is_none() {
        unknowns.push(json!({
            "question": "Parameter ranges are not recorded by the census for this model.",
            "probe": "Re-census with the range-carrying reader (moc3 offset-table entries 51/52/53).",
        }));
    }
    if ranges_consistent == Some(false) {
        unknowns.push(json!({
            "question": "At least one parameter range row is out of band (min/max/default).",
            "probe": "Probe the moc3 offset-table entries 51/52/53 independently and re-census.",
        }));
    }
    if !model3.is_object() {
        unknowns.push(json!({
            "question": "model3 group bindings (EyeBlink/LipSync) are unrecorded for this model.",
            "probe": "Census the loose model-directory form of the title, which ships .model3.json.",
        }));
    }
    if textures_count > 0 {
        unknowns.push(json!({
            "question": "Texture pixel data is not decoded by the census (gap G1); metadata only.",
            "probe": "Texture2D pixel decoding (type-tree expansion) — a future extraction rung.",
        }));
    }
    unknowns.push(json!({
        "question": "Drawable draw order is not established by the census (gap G3).",
        "probe": "Read draw order through lumen's moc3 geometry importer (license-gated) or a trace of the running model.",
    }));
    if unknowns.len() > SPEC_UNKNOWNS_MAX {
        return Err(resource(format!(
            "spec would exceed {SPEC_UNKNOWNS_MAX} unknowns"
        )));
    }

    Ok(json!({
        "spec_id": format!("{}/{model}/cubism-rig", meta.title),
        "spec_version": SPEC_FORMAT_VERSION,
        "title": {"id": meta.title, "fingerprint": meta.fingerprint},
        "unit": {"kind": "data-table", "name": model},
        "statements": set.statements,
        "data_tables": tables,
        "interfaces": [{
            "name": "rig-parameter-surface",
            "inputs": [],
            "outputs": ["parameters", "drawables", "parts"],
        }],
        "unknowns": unknowns,
        "tolerances": Value::Object(set.tolerances),
        "lane": {"origin_lane": meta.origin_lane, "content_label": meta.content_label},
        "separation": {
            "re_author": meta.author,
            "both_sides": meta.both_sides.map_or(Value::Null, |note| Value::String(note.to_string())),
        },
    }))
}

/// `spec_record` operation `write`: census envelope →
/// `fathom-spec/1` document on disk (see the module
/// contract). Required arguments: `target` (census envelope),
/// `output_dir`, `title`, `fingerprint`, `author`,
/// `origin_lane`, `content_label`. Optional: `both_sides`
/// (the separation record's honesty note, recorded verbatim).
pub fn write_spec(config: &Config, args: &Value) -> Result<Value, FathomError> {
    let target = require_str(args, "target")?;
    let (_, census_bytes, envelope) = read_document(config, target)?;
    let facts = cubism_facts(&envelope)?;
    let fingerprint = require_str(args, "fingerprint")?;
    if !is_hex64(fingerprint) {
        return Err(invalid(format!(
            "fingerprint '{fingerprint}' is not a 64-digit lowercase hex SHA-256"
        )));
    }
    let content_label = require_str(args, "content_label")?;
    if !CONTENT_LABELS.contains(&content_label) {
        return Err(invalid(format!(
            "content_label '{content_label}' is not one of the Bloch pair (sfw, nsfw); \
             an unlabelled or mislabelled spec is refused, never emitted"
        )));
    }
    let meta = SpecMeta {
        title: require_str(args, "title")?,
        fingerprint,
        author: require_str(args, "author")?,
        origin_lane: require_str(args, "origin_lane")?,
        content_label,
        both_sides: optional_str(args, "both_sides"),
        locator: target,
        census_hash: sha256_hex(&census_bytes),
    };
    if meta.author.is_empty() || meta.origin_lane.is_empty() || meta.title.is_empty() {
        return Err(invalid(
            "title, author, and origin_lane must be non-empty; the separation \
             record and lane labels are never defaulted",
        ));
    }
    let document = build_spec_document(facts, &envelope, &meta)?;
    let model = document["unit"]["name"]
        .as_str()
        .ok_or_else(|| mismatch("built spec carries no unit name"))?;
    let stem = sanitize_file_stem(model);
    if stem.is_empty() || stem.chars().all(|ch| ch == '.') {
        return Err(invalid(format!(
            "model name '{model}' does not yield a usable spec file name"
        )));
    }
    let file_name = format!("{stem}.spec.json");
    let output_dir =
        paths::validate_output_dir(config, Path::new(require_str(args, "output_dir")?))?;
    std::fs::create_dir_all(&output_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!(
                "cannot create output directory {}: {error}",
                output_dir.display()
            ),
        )
    })?;
    let serialized = serde_json::to_string_pretty(&document)
        .map_err(|error| mismatch(format!("built spec does not serialize: {error}")))?;
    let serialized = format!("{serialized}\n");
    let temp_path = output_dir.join(format!(".{file_name}.tmp"));
    let final_path = output_dir.join(&file_name);
    std::fs::write(&temp_path, serialized.as_bytes()).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot write spec {}: {error}", temp_path.display()),
        )
    })?;
    std::fs::rename(&temp_path, &final_path).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot commit spec {}: {error}", final_path.display()),
        )
    })?;
    let mut evidence = Evidence::new("spec_record", "spec");
    evidence.add_finding(Finding::new(
        "spec_written",
        Confidence::Observed,
        json!({
            "spec_id": document["spec_id"],
            "output": final_path.display().to_string(),
            "sha256": sha256_hex(serialized.as_bytes()),
            "bytes": serialized.len(),
            "statements": document["statements"].as_array().map_or(0, |rows| rows.len()),
            "data_tables": document["data_tables"].as_array().map_or(0, |rows| rows.len()),
            "unknowns": document["unknowns"].as_array().map_or(0, |rows| rows.len()),
            "census_sha256": meta.census_hash,
        }),
    ));
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

/// Named-violation accumulator for the validator. The list
/// is capped at `SPEC_VIOLATIONS_MAX`; past the cap the
/// verdict still reports the count of families checked, and
/// the spec is invalid either way.
struct Violations {
    list: Vec<Value>,
    rules: usize,
}

impl Violations {
    fn new() -> Self {
        Violations {
            list: Vec::new(),
            rules: 0,
        }
    }

    fn push(&mut self, code: &str, at: &str, message: String) {
        if self.list.len() < SPEC_VIOLATIONS_MAX {
            self.list
                .push(json!({"code": code, "at": at, "message": message}));
        }
    }

    fn rule(&mut self) {
        self.rules += 1;
    }
}

fn non_empty_str(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

/// Resolve a dotted evidence field path (`moc3.sha256`)
/// inside a census facts object. Returns false when any
/// segment is absent.
fn field_resolves(facts: &Value, field: &str) -> bool {
    let mut current = facts;
    for segment in field.split('.') {
        if segment.is_empty() || !current.is_object() {
            return false;
        }
        match current.get(segment) {
            Some(next) => current = next,
            None => return false,
        }
    }
    true
}

/// Iterative walk (explicit stack, depth-capped — spec
/// documents are untrusted input) looking for a verbatim
/// dialogue key anywhere in the document.
fn contains_verbatim_key(document: &Value) -> Option<String> {
    let mut stack: Vec<(String, &Value)> = vec![(String::new(), document)];
    let mut budget: usize = 200_000;
    while let Some((path, value)) = stack.pop() {
        budget = budget.saturating_sub(1);
        if budget == 0 {
            return None;
        }
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if VERBATIM_KEYS.contains(&key.as_str()) {
                        return Some(format!("{path}/{key}"));
                    }
                    if path.len() < 96 {
                        stack.push((format!("{path}/{key}"), child));
                    }
                }
            }
            Value::Array(rows) => {
                for (index, child) in rows.iter().enumerate() {
                    if path.len() < 96 {
                        stack.push((format!("{path}/{index}"), child));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// `spec_record` operation `validate`: check one spec
/// document against the `fathom-spec/1` contract (see the
/// module contract). Required argument: `target` (the spec).
/// Optional: `census` (a census envelope to resolve
/// census-record evidence pointers against).
pub fn validate_spec(config: &Config, args: &Value) -> Result<Value, FathomError> {
    let target = require_str(args, "target")?;
    let (_, _, document) = read_document(config, target)?;
    let mut violations = Violations::new();
    validate_document(&document, &mut violations);
    let mut resolved = false;
    if let Some(census_target) = optional_str(args, "census") {
        let (_, census_bytes, envelope) = read_document(config, census_target)?;
        resolved = true;
        validate_evidence_resolution(
            &document,
            &envelope,
            &sha256_hex(&census_bytes),
            &mut violations,
        );
    }
    let mut evidence = Evidence::new("spec_record", "spec");
    evidence.add_finding(Finding::new(
        "spec_validation",
        Confidence::Observed,
        json!({
            "valid": violations.list.is_empty(),
            "violations": violations.list,
            "rules_checked": violations.rules,
            "evidence_resolved": resolved,
        }),
    ));
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

/// The structural rule families, in contract order. Each
/// family increments the checked-rule count once; per-item
/// failures are individual violations.
fn validate_document(document: &Value, v: &mut Violations) {
    if !document.is_object() {
        v.rule();
        v.push(
            "SPEC_NOT_OBJECT",
            "",
            "the document is not a JSON object; no spec rule can be checked".to_string(),
        );
        return;
    }
    v.rule();
    if document["spec_version"].as_str() != Some(SPEC_FORMAT_VERSION) {
        v.push(
            "SPEC_VERSION",
            "spec_version",
            format!("spec_version must be '{SPEC_FORMAT_VERSION}'"),
        );
    }
    v.rule();
    if non_empty_str(&document["spec_id"]).is_none() {
        v.push(
            "SPEC_ID",
            "spec_id",
            "spec_id is missing or empty".to_string(),
        );
    }
    v.rule();
    let title = &document["title"];
    if !title.is_object() {
        v.push(
            "TITLE_MISSING",
            "title",
            "title is missing or not an object".to_string(),
        );
    } else {
        if non_empty_str(&title["id"]).is_none() {
            v.push(
                "TITLE_ID",
                "title.id",
                "title.id is missing or empty".to_string(),
            );
        }
        let fingerprint_ok = title["fingerprint"].as_str().is_some_and(is_hex64);
        if !fingerprint_ok {
            v.push(
                "TITLE_FINGERPRINT",
                "title.fingerprint",
                "title.fingerprint is not a 64-digit lowercase hex SHA-256".to_string(),
            );
        }
    }
    v.rule();
    let unit = &document["unit"];
    let unit_kind = unit["kind"].as_str().unwrap_or("");
    if !unit.is_object() {
        v.push(
            "UNIT_MISSING",
            "unit",
            "unit is missing or not an object".to_string(),
        );
    } else {
        if !UNIT_KINDS.contains(&unit_kind) {
            v.push(
                "UNIT_KIND",
                "unit.kind",
                format!("unit.kind '{unit_kind}' is outside the closed kind vocabulary"),
            );
        }
        if non_empty_str(&unit["name"]).is_none() {
            v.push(
                "UNIT_NAME",
                "unit.name",
                "unit.name is missing or empty".to_string(),
            );
        }
    }
    let statement_ids = validate_statements(document, v);
    validate_tolerances(document, &statement_ids, v);
    validate_tables(document, unit_kind, v);
    v.rule();
    match document["interfaces"].as_array() {
        None => v.push(
            "INTERFACES_MISSING",
            "interfaces",
            "interfaces is missing or not an array".to_string(),
        ),
        Some(rows) => {
            for (index, row) in rows.iter().enumerate() {
                if non_empty_str(&row["name"]).is_none() {
                    v.push(
                        "INTERFACE_NAME",
                        &format!("interfaces/{index}"),
                        "interface carries no name".to_string(),
                    );
                }
            }
        }
    }
    v.rule();
    match document["unknowns"].as_array() {
        None => v.push(
            "UNKNOWNS_MISSING",
            "unknowns",
            "unknowns is missing or not an array".to_string(),
        ),
        Some(rows) => {
            for (index, row) in rows.iter().enumerate() {
                if non_empty_str(&row["question"]).is_none() {
                    v.push(
                        "UNKNOWN_QUESTION",
                        &format!("unknowns/{index}"),
                        "unknown carries no question".to_string(),
                    );
                }
                if non_empty_str(&row["probe"]).is_none() {
                    v.push(
                        "UNKNOWN_PROBE",
                        &format!("unknowns/{index}"),
                        "unknown names no probe that would close it".to_string(),
                    );
                }
            }
        }
    }
    v.rule();
    let lane = &document["lane"];
    if !lane.is_object() {
        v.push(
            "LANE_MISSING",
            "lane",
            "lane is missing or not an object".to_string(),
        );
    } else {
        if non_empty_str(&lane["origin_lane"]).is_none() {
            v.push(
                "LANE_ORIGIN",
                "lane.origin_lane",
                "lane.origin_lane is missing or empty".to_string(),
            );
        }
        let label = lane["content_label"].as_str().unwrap_or("");
        if !CONTENT_LABELS.contains(&label) {
            v.push(
                "LANE_LABEL",
                "lane.content_label",
                format!("content_label '{label}' is outside the Bloch pair (sfw, nsfw)"),
            );
        }
    }
    v.rule();
    let separation = &document["separation"];
    if !separation.is_object() {
        v.push(
            "SEPARATION_MISSING",
            "separation",
            "separation record is missing or not an object".to_string(),
        );
    } else if non_empty_str(&separation["re_author"]).is_none() {
        v.push(
            "SEPARATION_AUTHOR",
            "separation.re_author",
            "the separation record names no RE-side author".to_string(),
        );
    }
    validate_state_machine(document, unit_kind, v);
    v.rule();
    if unit_kind == "dialogue"
        && let Some(path) = contains_verbatim_key(document)
    {
        v.push(
            "DIALOGUE_VERBATIM",
            &path,
            "a dialogue unit carries a verbatim-text key; shipped dialogue specs \
             carry structure only (D-591)"
                .to_string(),
        );
    }
}

/// Statement rules; returns the statement ids in order for
/// the tolerance cross-check.
fn validate_statements(document: &Value, v: &mut Violations) -> Vec<String> {
    v.rule();
    let mut ids: Vec<String> = Vec::new();
    let rows = match document["statements"].as_array() {
        Some(rows) if !rows.is_empty() => rows,
        _ => {
            v.push(
                "STATEMENTS_MISSING",
                "statements",
                "statements is missing, not an array, or empty; a spec states at least one claim"
                    .to_string(),
            );
            return ids;
        }
    };
    if rows.len() > SPEC_STATEMENTS_MAX {
        v.push(
            "STATEMENTS_BOUND",
            "statements",
            format!("statements exceed the {SPEC_STATEMENTS_MAX} bound"),
        );
    }
    let mut fact_names: Vec<String> = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let at = format!("statements/{index}");
        let id = non_empty_str(&row["id"]);
        match id {
            Some(id) => {
                if ids.iter().any(|seen| seen == id) {
                    v.push(
                        "STATEMENT_DUPLICATE",
                        &at,
                        format!("statement id '{id}' appears more than once"),
                    );
                }
                ids.push(id.to_string());
            }
            None => v.push("STATEMENT_ID", &at, "statement carries no id".to_string()),
        }
        if non_empty_str(&row["text"]).is_none() {
            v.push(
                "STATEMENT_TEXT",
                &at,
                "statement carries no claim text".to_string(),
            );
        }
        match row["evidence"].as_array() {
            Some(pointers) if !pointers.is_empty() => {
                if pointers.len() > SPEC_EVIDENCE_POINTERS_MAX {
                    v.push(
                        "STATEMENT_EVIDENCE",
                        &at,
                        format!(
                            "statement carries more than {SPEC_EVIDENCE_POINTERS_MAX} evidence pointers"
                        ),
                    );
                }
                for (p_index, pointer) in pointers.iter().enumerate() {
                    let p_at = format!("{at}/evidence/{p_index}");
                    if non_empty_str(&pointer["kind"]).is_none() {
                        v.push(
                            "EVIDENCE_KIND",
                            &p_at,
                            "evidence pointer names no kind".to_string(),
                        );
                    }
                    if non_empty_str(&pointer["locator"]).is_none() {
                        v.push(
                            "EVIDENCE_LOCATOR",
                            &p_at,
                            "evidence pointer names no locator".to_string(),
                        );
                    }
                    let hash_ok = pointer["hash"].as_str().is_some_and(is_hex64);
                    if !hash_ok {
                        v.push(
                            "EVIDENCE_HASH",
                            &p_at,
                            "evidence pointer hash is not a 64-digit lowercase hex SHA-256"
                                .to_string(),
                        );
                    }
                }
            }
            _ => v.push(
                "STATEMENT_EVIDENCE",
                &at,
                "statement carries no evidence pointer; every claim cites its evidence".to_string(),
            ),
        }
        if !row["fact"].is_null() {
            match non_empty_str(&row["fact"]["name"]) {
                Some(name) => {
                    if fact_names.iter().any(|seen| seen == name) {
                        v.push(
                            "FACT_DUPLICATE",
                            &at,
                            format!("fact name '{name}' appears more than once"),
                        );
                    }
                    fact_names.push(name.to_string());
                }
                None => v.push(
                    "FACT_SHAPE",
                    &at,
                    "a statement fact carries no name".to_string(),
                ),
            }
        }
    }
    ids
}

/// Tolerance rules: every statement id has exactly one
/// tolerance, of a closed kind, with a band when numeric.
fn validate_tolerances(document: &Value, statement_ids: &[String], v: &mut Violations) {
    v.rule();
    let tolerances = match document["tolerances"].as_object() {
        Some(map) => map,
        None => {
            v.push(
                "TOLERANCES_MISSING",
                "tolerances",
                "tolerances is missing or not an object".to_string(),
            );
            return;
        }
    };
    for id in statement_ids {
        match tolerances.get(id) {
            None => v.push(
                "TOLERANCE_MISSING",
                &format!("tolerances/{id}"),
                format!("statement '{id}' has no tolerance entry"),
            ),
            Some(entry) => {
                let kind = entry["kind"].as_str().unwrap_or("");
                if !TOLERANCE_KINDS.contains(&kind) {
                    v.push(
                        "TOLERANCE_KIND",
                        &format!("tolerances/{id}"),
                        format!("tolerance kind '{kind}' is outside the closed vocabulary"),
                    );
                }
                if kind == "numeric-band" {
                    let band_ok = entry["band"].as_f64().is_some_and(|band| band > 0.0);
                    if !band_ok {
                        v.push(
                            "TOLERANCE_BAND",
                            &format!("tolerances/{id}"),
                            "a numeric-band tolerance names no positive band".to_string(),
                        );
                    }
                }
            }
        }
    }
    for key in tolerances.keys() {
        if !statement_ids.iter().any(|id| id == key) {
            v.push(
                "TOLERANCE_ORPHAN",
                &format!("tolerances/{key}"),
                format!("tolerance entry names no statement '{key}'"),
            );
        }
    }
}

/// Data-table rules: shape, arity, bounds, and the
/// parameters table's range sanity (min <= max wherever
/// both are recorded).
fn validate_tables(document: &Value, unit_kind: &str, v: &mut Violations) {
    v.rule();
    let tables = match document["data_tables"].as_array() {
        Some(rows) => rows,
        None => {
            if unit_kind == "data-table" {
                v.push(
                    "DATA_TABLE_REQUIRED",
                    "data_tables",
                    "a data-table unit carries no data tables".to_string(),
                );
            }
            return;
        }
    };
    if unit_kind == "data-table" && tables.is_empty() {
        v.push(
            "DATA_TABLE_REQUIRED",
            "data_tables",
            "a data-table unit carries no data tables".to_string(),
        );
    }
    for (index, table) in tables.iter().enumerate() {
        let at = format!("data_tables/{index}");
        let name = non_empty_str(&table["name"]).unwrap_or("");
        if name.is_empty() {
            v.push("TABLE_NAME", &at, "data table carries no name".to_string());
        }
        let columns: Vec<&str> = match table["columns"].as_array() {
            Some(cols) if !cols.is_empty() => cols.iter().filter_map(|col| col.as_str()).collect(),
            _ => {
                v.push(
                    "TABLE_COLUMNS",
                    &at,
                    "data table names no columns".to_string(),
                );
                continue;
            }
        };
        if columns.len() != table["columns"].as_array().map_or(0, |cols| cols.len()) {
            v.push(
                "TABLE_COLUMNS",
                &at,
                "every column name must be a string".to_string(),
            );
        }
        let rows = match table["rows"].as_array() {
            Some(rows) => rows,
            None => {
                v.push(
                    "TABLE_ROWS",
                    &at,
                    "data table carries no rows array".to_string(),
                );
                continue;
            }
        };
        if rows.len() > SPEC_TABLE_ROWS_MAX {
            v.push(
                "TABLE_ROWS_BOUND",
                &at,
                format!("table rows exceed the {SPEC_TABLE_ROWS_MAX} bound"),
            );
        }
        for (row_index, row) in rows.iter().enumerate() {
            let row_at = format!("{at}/rows/{row_index}");
            match row.as_array() {
                Some(cells) if cells.len() == columns.len() => {}
                _ => {
                    v.push(
                        "TABLE_ROW_ARITY",
                        &row_at,
                        "row arity does not match the column count".to_string(),
                    );
                    continue;
                }
            }
            if name == "parameters"
                && columns == ["id", "min", "max", "default"]
                && let (Some(min), Some(max)) = (row[1].as_f64(), row[2].as_f64())
                && min > max
            {
                v.push(
                    "TABLE_RANGE_ORDER",
                    &row_at,
                    "parameter row records min greater than max".to_string(),
                );
            }
        }
    }
}

/// State-machine rules: required for state-machine and
/// dialogue units; transitions must reference declared
/// states.
fn validate_state_machine(document: &Value, unit_kind: &str, v: &mut Violations) {
    v.rule();
    let machine = &document["state_machine"];
    if !matches!(unit_kind, "state-machine" | "dialogue") {
        if !machine.is_null() && !machine.is_object() {
            v.push(
                "STATE_MACHINE_SHAPE",
                "state_machine",
                "state_machine is present but not an object".to_string(),
            );
        }
        return;
    }
    if !machine.is_object() {
        v.push(
            "STATE_MACHINE_MISSING",
            "state_machine",
            format!("a {unit_kind} unit carries no state machine"),
        );
        return;
    }
    let states: Vec<String> = match machine["states"].as_array() {
        Some(rows) => rows
            .iter()
            .filter_map(|row| {
                row.as_str()
                    .map(str::to_string)
                    .or_else(|| non_empty_str(&row["name"]).map(str::to_string))
            })
            .collect(),
        None => {
            v.push(
                "STATE_MACHINE_STATES",
                "state_machine.states",
                "the state machine declares no states array".to_string(),
            );
            return;
        }
    };
    if states.is_empty() {
        v.push(
            "STATE_MACHINE_STATES",
            "state_machine.states",
            "the state machine declares no named states".to_string(),
        );
        return;
    }
    if let Some(transitions) = machine["transitions"].as_array() {
        for (index, transition) in transitions.iter().enumerate() {
            for endpoint in ["from", "to"] {
                let name = transition[endpoint].as_str().unwrap_or("");
                if !states.iter().any(|state| state == name) {
                    v.push(
                        "STATE_MACHINE_TRANSITION",
                        &format!("state_machine/transitions/{index}"),
                        format!("transition {endpoint} names undeclared state '{name}'"),
                    );
                }
            }
        }
    }
}

/// Evidence-resolution rules (only when a census record is
/// supplied): every census-record pointer's hash must equal
/// the record's SHA-256, and its field must resolve inside
/// the census facts.
fn validate_evidence_resolution(
    document: &Value,
    envelope: &Value,
    census_hash: &str,
    v: &mut Violations,
) {
    v.rule();
    let facts = match cubism_facts(envelope) {
        Ok(facts) => facts.clone(),
        Err(_) => {
            v.push(
                "EVIDENCE_CENSUS_SHAPE",
                "census",
                "the supplied census record carries no cubism_census facts to resolve against"
                    .to_string(),
            );
            return;
        }
    };
    let Some(statements) = document["statements"].as_array() else {
        return;
    };
    for (index, statement) in statements.iter().enumerate() {
        let Some(pointers) = statement["evidence"].as_array() else {
            continue;
        };
        for (p_index, pointer) in pointers.iter().enumerate() {
            if pointer["kind"].as_str() != Some("census-record") {
                continue;
            }
            let at = format!("statements/{index}/evidence/{p_index}");
            if pointer["hash"].as_str() != Some(census_hash) {
                v.push(
                    "EVIDENCE_HASH_MISMATCH",
                    &at,
                    "the pointer hash does not equal the supplied census record's SHA-256"
                        .to_string(),
                );
            }
            if let Some(field) = pointer["field"].as_str()
                && !field_resolves(&facts, field)
            {
                v.push(
                    "EVIDENCE_FIELD_MISSING",
                    &at,
                    format!("the pointer field '{field}' does not resolve in the census facts"),
                );
            }
        }
    }
}

/// Check accumulator for the diff, in the D-565 harness
/// shape: each check records both sides (long lists elided
/// to a length marker, exactly as the Python harness did),
/// a match flag, and whether the check counts in the totals
/// — the textures-absent case is reported but never counted,
/// as before.
struct Differ {
    checks: Vec<Value>,
    matched: usize,
    differed: usize,
}

impl Differ {
    fn new() -> Self {
        Differ {
            checks: Vec::new(),
            matched: 0,
            differed: 0,
        }
    }

    fn record(&mut self, name: &str, matched: bool, gt: Value, mine: Value, note: Option<&str>) {
        if self.checks.len() >= SPEC_CHECKS_MAX {
            return;
        }
        let mut check = json!({
            "check": name,
            "counted": true,
            "match": matched,
            "gt": display(&gt),
            "mine": display(&mine),
        });
        if let Some(note) = note {
            check["note"] = Value::String(note.to_string());
        }
        self.checks.push(check);
        if matched {
            self.matched += 1;
        } else {
            self.differed += 1;
        }
    }

    fn cmp(&mut self, name: &str, gt: Value, mine: Value) {
        let matched = gt == mine;
        self.record(name, matched, gt, mine, None);
    }

    /// Compare a ground-truth value against the spec fact of
    /// the given name. An absent fact is a failed check whose
    /// spec side reads `<absent>` — a spec that does not state
    /// a fact does not get it by default.
    fn cmp_fact(&mut self, name: &str, gt: Value, facts: &BTreeMap<String, Value>, fact: &str) {
        match facts.get(fact) {
            Some(value) => self.cmp(name, gt, value.clone()),
            None => self.record(name, false, gt, Value::String("<absent>".to_string()), None),
        }
    }

    fn uncounted(&mut self, name: &str, gt: Value, mine: Value, note: &str) {
        self.checks.push(json!({
            "check": name,
            "counted": false,
            "match": true,
            "gt": gt,
            "mine": display(&mine),
            "note": note,
        }));
    }
}

/// Report-side display: lists longer than 16 entries are
/// shown as a length marker (compared in full, shown in
/// brief), mirroring the Python harness's truncation.
fn display(value: &Value) -> Value {
    match value {
        Value::Array(rows) if rows.len() > 16 => {
            Value::String(format!("<list len={}>", rows.len()))
        }
        other => other.clone(),
    }
}

/// Statement facts of a spec, by fact name (first wins; the
/// validator is the surface that flags duplicates).
fn fact_map(spec: &Value) -> BTreeMap<String, Value> {
    let mut facts = BTreeMap::new();
    if let Some(statements) = spec["statements"].as_array() {
        for statement in statements {
            if let Some(name) = statement["fact"]["name"].as_str() {
                facts
                    .entry(name.to_string())
                    .or_insert_with(|| statement["fact"]["value"].clone());
            }
        }
    }
    facts
}

/// Data tables of a spec, by table name.
fn table_map(spec: &Value) -> BTreeMap<String, &Value> {
    let mut tables = BTreeMap::new();
    if let Some(rows) = spec["data_tables"].as_array() {
        for table in rows {
            if let Some(name) = table["name"].as_str() {
                tables.entry(name.to_string()).or_insert(table);
            }
        }
    }
    tables
}

/// Ground-truth eye-parameter rows normalize to ids (the GT
/// stores strings on some titles, {index, id} rows on
/// others — the C5 harness normalisation).
fn gt_eye_ids(model: &Value) -> Value {
    let rows = model["eye_parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Value::Array(
        rows.iter()
            .map(|row| {
                if row.is_string() {
                    row.clone()
                } else {
                    row["id"].clone()
                }
            })
            .collect(),
    )
}

/// The standard-ids comparison, with the Python harness's
/// semantics: an order difference is a note, a set
/// difference is a diff.
fn standard_ids_verdict(gt: &Value, mine: &Value) -> (bool, &'static str) {
    if gt == mine {
        return (true, "ordered");
    }
    let sorted = |value: &Value| -> Vec<String> {
        let mut items: Vec<String> = value
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        items.sort();
        items
    };
    if sorted(gt) == sorted(mine) && gt.is_array() && mine.is_array() {
        (true, "set-equal, order differs")
    } else {
        (false, "SET DIFFERS")
    }
}

/// The parameter-ranges check: spec table rows against the
/// census record's ranges, index-aligned, inside
/// `RANGE_TOLERANCE` per component — the D-565 check with
/// the census record as its reference.
fn ranges_match(census_facts: &Value, tables: &BTreeMap<String, &Value>) -> (bool, Value, Value) {
    let moc = &census_facts["moc3"];
    let census_rows = moc["parameter_ranges"].as_array();
    let spec_rows = tables
        .get("parameters")
        .and_then(|table| table["rows"].as_array());
    let (Some(census_rows), Some(spec_rows)) = (census_rows, spec_rows) else {
        return (
            false,
            Value::String("<census ranges absent>".to_string()),
            Value::String("<spec rows absent>".to_string()),
        );
    };
    let parameters = moc["parameters"].as_array().cloned().unwrap_or_default();
    let aligned = census_rows.len() == spec_rows.len()
        && census_rows
            .iter()
            .zip(spec_rows.iter())
            .all(|(census, spec)| {
                let index = census["index"].as_u64().unwrap_or(u64::MAX);
                let index_ok = parameters
                    .get(usize::try_from(index).unwrap_or(usize::MAX))
                    .is_some_and(|id| id == &census["id"]);
                let within = |spec_cell: &Value, census_cell: &Value| -> bool {
                    match (spec_cell.as_f64(), census_cell.as_f64()) {
                        (Some(a), Some(b)) => (a - b).abs() < RANGE_TOLERANCE,
                        _ => false,
                    }
                };
                index_ok
                    && spec[0] == census["id"]
                    && within(&spec[1], &census["min"])
                    && within(&spec[2], &census["max"])
                    && within(&spec[3], &census["default"])
            });
    (
        aligned,
        Value::String(format!("<{} census rows>", census_rows.len())),
        Value::String(format!("<{} spec rows>", spec_rows.len())),
    )
}

/// `spec_record` operation `diff`: one spec against one
/// model of a ground-truth census, with the source census
/// record as the ranges reference (see the module
/// contract). Required arguments: `target` (the spec),
/// `reference` (the ground-truth census), `census` (the
/// census envelope the spec was written from), `model`.
pub fn diff_spec(config: &Config, args: &Value) -> Result<Value, FathomError> {
    let target = require_str(args, "target")?;
    let (_, _, spec) = read_document(config, target)?;
    let reference = require_str(args, "reference")?;
    let (_, _, gt) = read_document(config, reference)?;
    let census_target = require_str(args, "census")?;
    let (_, _, envelope) = read_document(config, census_target)?;
    let census_facts = cubism_facts(&envelope)?.clone();
    let model_name = require_str(args, "model")?;
    let model = gt["models"]
        .as_array()
        .and_then(|models| {
            models
                .iter()
                .find(|row| row["name"].as_str() == Some(model_name))
        })
        .ok_or_else(|| {
            invalid(format!(
                "model '{model_name}' is not in the reference census"
            ))
        })?
        .clone();

    let facts = fact_map(&spec);
    let tables = table_map(&spec);
    let mut differ = Differ::new();
    let (ranges_ok, ranges_gt, ranges_mine) = ranges_match(&census_facts, &tables);
    differ.record("parameter_ranges", ranges_ok, ranges_gt, ranges_mine, None);
    differ.cmp_fact(
        "ranges_consistent",
        Value::Bool(true),
        &facts,
        "ranges_consistent",
    );
    differ.cmp_fact(
        "moc3.sha256",
        model["moc3"]["sha256"].clone(),
        &facts,
        "moc3_sha256",
    );
    differ.cmp_fact(
        "moc3.version",
        model["moc3"]["version_byte"].clone(),
        &facts,
        "moc3_version",
    );
    differ.cmp_fact(
        "moc3.bytes",
        model["moc3"]["bytes"].clone(),
        &facts,
        "moc3_bytes",
    );
    differ.cmp_fact(
        "parameter_count",
        model["parameter_count"].clone(),
        &facts,
        "parameter_count",
    );
    differ.cmp_fact(
        "parameters_ordered",
        model["parameters"].clone(),
        &facts,
        "parameters_ordered",
    );
    differ.cmp_fact(
        "eye_parameters",
        gt_eye_ids(&model),
        &facts,
        "eye_parameters",
    );
    let standard_gt = model["standard_ids_present"].clone();
    match facts.get("standard_ids_present") {
        Some(mine) => {
            let (matched, note) = standard_ids_verdict(&standard_gt, mine);
            differ.record(
                "standard_ids_present",
                matched,
                standard_gt,
                mine.clone(),
                Some(note),
            );
        }
        None => differ.record(
            "standard_ids_present",
            false,
            standard_gt,
            Value::String("<absent>".to_string()),
            Some("SET DIFFERS"),
        ),
    }
    let gt_drawable_count = if !model["drawable_table_count"].is_null() {
        model["drawable_table_count"].clone()
    } else {
        model["drawable_count"].clone()
    };
    differ.cmp_fact(
        "drawable_count",
        gt_drawable_count.clone(),
        &facts,
        "drawable_count",
    );
    let spec_drawable_rows = tables
        .get("drawables")
        .and_then(|table| table["rows"].as_array())
        .map_or_else(
            || Value::String("<absent>".to_string()),
            |rows| json!(rows.len()),
        );
    differ.cmp("drawable_rows", gt_drawable_count, spec_drawable_rows);
    if !model["parts_count"].is_null() {
        differ.cmp_fact(
            "parts_count",
            model["parts_count"].clone(),
            &facts,
            "parts_count",
        );
    }
    if let Some(gt_parts) = model["parts"].as_array()
        && !gt_parts.is_empty()
        && gt_parts.iter().all(|row| row.is_string())
    {
        let spec_parts: Value = tables
            .get("parts")
            .and_then(|table| table["rows"].as_array())
            .map_or_else(
                || Value::String("<absent>".to_string()),
                |rows| Value::Array(rows.iter().map(|row| row[0].clone()).collect()),
            );
        differ.cmp("parts_list", Value::Array(gt_parts.clone()), spec_parts);
    }
    if let Some(gt_textures) = model["textures"].as_array() {
        differ.cmp_fact(
            "textures_count",
            json!(gt_textures.len()),
            &facts,
            "textures_count",
        );
    } else {
        let mine = facts
            .get("textures_count")
            .cloned()
            .unwrap_or_else(|| Value::String("<absent>".to_string()));
        differ.uncounted(
            "textures_count",
            Value::String("<absent in GT entry>".to_string()),
            mine,
            "GT entry carries no textures field; spec counted from census",
        );
    }
    if let Some(gt_groups) = model["groups"].as_array() {
        differ.cmp_fact(
            "groups",
            normalize_groups(&Value::Array(gt_groups.clone())),
            &facts,
            "groups",
        );
    } else {
        differ.cmp_fact("groups_absent_both", Value::Null, &facts, "groups");
    }

    let mut evidence = Evidence::new("spec_record", "spec");
    evidence.add_finding(Finding::new(
        "spec_census_diff",
        Confidence::Observed,
        json!({
            "model": model_name,
            "reference": reference,
            "totals": {
                "models": 1,
                "checks": differ.matched + differ.differed,
                "match": differ.matched,
                "diff": differ.differed,
            },
            "checks": differ.checks,
        }),
    ));
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

/// The R11 tool: `fathom-spec/1` writer, validator, and
/// census diff in one Execute-class surface (see the module
/// contract). `operation` selects the operation: `write`,
/// `validate`, or `diff`.
pub fn spec_record(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    match require_str(args, "operation")? {
        "write" => write_spec(config, args),
        "validate" => validate_spec(config, args),
        "diff" => diff_spec(config, args),
        other => Err(invalid(format!(
            "spec_record operation '{other}' is not one of write, validate, diff"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const MOC3_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_root(test_name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fathom-spec-test-{}-{test_name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn test_config(root: &Path) -> Config {
        Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap()
    }

    /// A retained-shape census envelope: one model, three
    /// parameters with ranges, a model3 with one group, one
    /// texture, one census unknown.
    fn fixture_census() -> Value {
        json!({
            "tool": "census_cubism_model",
            "provider": "cubism",
            "status": "partial",
            "findings": [{
                "kind": "cubism_census",
                "confidence": "observed",
                "facts": {
                    "model": "FixtureModel",
                    "model3": {
                        "file": "FixtureModel.model3.json",
                        "groups": [{"name": "EyeBlink", "target": "Parameter", "ids": ["ParamEyeLOpen"]}],
                        "physics": {"present": false, "file": null, "bytes": null},
                    },
                    "cdi3": null,
                    "expressions": [],
                    "textures": [{"file": "tex.png", "found_as": "tex.png", "resolution": [64, 64]}],
                    "moc3": {
                        "file": "FixtureModel.moc3",
                        "sha256": MOC3_SHA256,
                        "version": 5,
                        "bytes": 12345,
                        "canvas": {
                            "canvas_width": 100.0, "canvas_height": 200.0,
                            "pixels_per_unit": 100.0, "origin_x": 0.5,
                            "origin_y": 0.5, "origin_is_canvas_centre": true,
                        },
                        "counts": {"parameters": 3, "drawables": 2, "parts": 2},
                        "parameters": ["ParamAngleX", "ParamEyeLOpen", "BlinkCustom"],
                        "parameter_ranges": [
                            {"id": "ParamAngleX", "index": 0, "min": -30.0, "max": 30.0, "default": 0.0},
                            {"id": "ParamEyeLOpen", "index": 1, "min": 0.0, "max": 1.0, "default": 1.0},
                            {"id": "BlinkCustom", "index": 2, "min": 0.0, "max": 1.0, "default": 0.0},
                        ],
                        "ranges_consistent": true,
                        "eye_parameters": [
                            {"id": "ParamEyeLOpen", "index": 1},
                            {"id": "BlinkCustom", "index": 2},
                        ],
                        "standard_ids_present": ["ParamAngleX", "ParamEyeLOpen"],
                        "drawables": [
                            {"id": "ArtA", "parent_part_index": 0},
                            {"id": "ArtB", "parent_part_index": 1},
                        ],
                        "parts": ["PartRoot", "PartEye"],
                    },
                },
            }],
            "unknowns": [{
                "aspect": "parameter display names and groups",
                "reason": "no .cdi3.json in the model directory",
            }],
        })
    }

    /// The hand-made ground truth for the fixture model,
    /// in the GT census shape (PascalCase group rows).
    fn fixture_gt() -> Value {
        json!({
            "title": "Fixture Title",
            "build": {"zip_sha256": FINGERPRINT},
            "models": [{
                "name": "FixtureModel",
                "moc3": {
                    "file": "FixtureModel.moc3", "sha256": MOC3_SHA256,
                    "version_byte": 5, "bytes": 12345,
                },
                "parameter_count": 3,
                "parameters": ["ParamAngleX", "ParamEyeLOpen", "BlinkCustom"],
                "eye_parameters": ["ParamEyeLOpen", "BlinkCustom"],
                "standard_ids_present": ["ParamAngleX", "ParamEyeLOpen"],
                "drawable_table_count": 2,
                "parts_count": 2,
                "parts": ["PartRoot", "PartEye"],
                "textures": [{"file": "tex.png", "resolution": [64, 64]}],
                "groups": [{"Name": "EyeBlink", "Target": "Parameter", "Ids": ["ParamEyeLOpen"]}],
            }],
        })
    }

    fn handwritten_spec() -> Value {
        json!({
            "spec_id": "hand-title/route-a/dialogue",
            "spec_version": "fathom-spec/1",
            "title": {"id": "hand-title", "fingerprint": FINGERPRINT},
            "unit": {"kind": "dialogue", "name": "route-a"},
            "statements": [{
                "id": "S01",
                "text": "The route opens at the harbour and ends at the lighthouse.",
                "evidence": [{"kind": "trace", "locator": "traces/route-a.json", "hash": MOC3_SHA256}],
            }],
            "state_machine": {
                "states": ["start", "end"],
                "transitions": [{"from": "start", "to": "end"}],
            },
            "data_tables": [],
            "interfaces": [],
            "unknowns": [],
            "tolerances": {"S01": {"kind": "exact"}},
            "lane": {"origin_lane": "ntranch", "content_label": "nsfw"},
            "separation": {"re_author": "test RE author", "both_sides": null},
        })
    }

    fn write_args(census_path: &Path, output_dir: &Path) -> Value {
        json!({
            "target": census_path.display().to_string(),
            "output_dir": output_dir.display().to_string(),
            "title": "fixture-title",
            "fingerprint": FINGERPRINT,
            "author": "test RE author",
            "origin_lane": "ntranch",
            "content_label": "nsfw",
        })
    }

    /// Stage a census envelope in a fresh root and write its
    /// spec. Returns (root, census path, spec path).
    fn write_fixture_spec(test_name: &str, census: &Value) -> (PathBuf, PathBuf, PathBuf) {
        let root = test_root(test_name);
        let census_path = root.join("census.json");
        fs::write(&census_path, serde_json::to_string_pretty(census).unwrap()).unwrap();
        let config = test_config(&root);
        let output_dir = root.join("specs");
        let result = write_spec(&config, &write_args(&census_path, &output_dir)).unwrap();
        assert_eq!(result["findings"][0]["kind"], "spec_written");
        let spec_path = output_dir.join("FixtureModel.spec.json");
        (root, census_path, spec_path)
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn validation_facts(result: &Value) -> &Value {
        &result["findings"][0]["facts"]
    }

    fn violation_codes(result: &Value) -> Vec<String> {
        validation_facts(result)["violations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["code"].as_str().unwrap().to_string())
            .collect()
    }

    fn validate_file(root: &Path, spec: &Value, name: &str) -> Value {
        let path = root.join(name);
        fs::write(&path, serde_json::to_string_pretty(spec).unwrap()).unwrap();
        let config = test_config(root);
        validate_spec(&config, &json!({"target": path.display().to_string()})).unwrap()
    }

    // -- validation ---------------------------------------------------

    #[test]
    fn write_then_validate_clean() {
        let (root, census_path, spec_path) =
            write_fixture_spec("write-validate", &fixture_census());
        let config = test_config(&root);
        let plain =
            validate_spec(&config, &json!({"target": spec_path.display().to_string()})).unwrap();
        assert_eq!(validation_facts(&plain)["valid"], true);
        assert_eq!(validation_facts(&plain)["evidence_resolved"], false);
        let resolved = validate_spec(
            &config,
            &json!({
                "target": spec_path.display().to_string(),
                "census": census_path.display().to_string(),
            }),
        )
        .unwrap();
        assert_eq!(validation_facts(&resolved)["valid"], true);
        assert_eq!(validation_facts(&resolved)["evidence_resolved"], true);
    }

    #[test]
    fn write_is_deterministic() {
        let (root, census_path, first) = write_fixture_spec("deterministic", &fixture_census());
        let config = test_config(&root);
        let second_dir = root.join("specs-again");
        write_spec(&config, &write_args(&census_path, &second_dir)).unwrap();
        let second = second_dir.join("FixtureModel.spec.json");
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    }

    #[test]
    fn validate_accepts_handwritten_spec() {
        let root = test_root("handwritten");
        let result = validate_file(&root, &handwritten_spec(), "spec.json");
        assert_eq!(validation_facts(&result)["valid"], true);
    }

    #[test]
    fn diff_matches_fixture() {
        let (root, census_path, spec_path) = write_fixture_spec("diff-match", &fixture_census());
        let gt_path = root.join("gt.json");
        fs::write(
            &gt_path,
            serde_json::to_string_pretty(&fixture_gt()).unwrap(),
        )
        .unwrap();
        let config = test_config(&root);
        let result = diff_spec(
            &config,
            &json!({
                "target": spec_path.display().to_string(),
                "reference": gt_path.display().to_string(),
                "census": census_path.display().to_string(),
                "model": "FixtureModel",
            }),
        )
        .unwrap();
        let facts = &result["findings"][0]["facts"];
        assert_eq!(
            facts["totals"],
            json!({"models": 1, "checks": 15, "match": 15, "diff": 0})
        );
    }

    #[test]
    fn writer_unknowns_carry_probes() {
        let (_, _, spec_path) = write_fixture_spec("unknowns", &fixture_census());
        let spec = read_json(&spec_path);
        let unknowns = spec["unknowns"].as_array().unwrap();
        assert!(!unknowns.is_empty());
        for unknown in unknowns {
            assert!(non_empty_str(&unknown["question"]).is_some());
            assert!(non_empty_str(&unknown["probe"]).is_some());
        }
        assert!(
            unknowns
                .iter()
                .any(|row| row["question"].as_str().unwrap_or("").contains("cdi3"))
        );
        assert!(unknowns.iter().any(|row| {
            row["question"]
                .as_str()
                .unwrap_or("")
                .contains("draw order")
        }));
    }

    // -- adversarial --------------------------------------------------

    #[test]
    fn write_refuses_envelope_without_cubism_finding() {
        let root = test_root("no-finding");
        let census_path = root.join("census.json");
        fs::write(
            &census_path,
            serde_json::to_string(&json!({"findings": [], "unknowns": []})).unwrap(),
        )
        .unwrap();
        let config = test_config(&root);
        let result = write_spec(&config, &write_args(&census_path, &root.join("specs")));
        assert!(result.is_err());
    }

    #[test]
    fn write_refuses_bad_fingerprint() {
        let root = test_root("bad-fingerprint");
        let census_path = root.join("census.json");
        fs::write(
            &census_path,
            serde_json::to_string(&fixture_census()).unwrap(),
        )
        .unwrap();
        let config = test_config(&root);
        let mut args = write_args(&census_path, &root.join("specs"));
        args["fingerprint"] = json!("not-a-hash");
        assert!(write_spec(&config, &args).is_err());
        args["fingerprint"] = json!(&FINGERPRINT[..63]);
        assert!(write_spec(&config, &args).is_err());
    }

    #[test]
    fn write_refuses_unlisted_content_label() {
        let root = test_root("bad-label");
        let census_path = root.join("census.json");
        fs::write(
            &census_path,
            serde_json::to_string(&fixture_census()).unwrap(),
        )
        .unwrap();
        let config = test_config(&root);
        let mut args = write_args(&census_path, &root.join("specs"));
        args["content_label"] = json!("unlabelled");
        assert!(write_spec(&config, &args).is_err());
    }

    #[test]
    fn write_records_out_of_band_ranges() {
        let mut census = fixture_census();
        census["findings"][0]["facts"]["moc3"]["parameter_ranges"][0]["default"] = json!(99.0);
        let (_, _, spec_path) = write_fixture_spec("out-of-band", &census);
        let spec = read_json(&spec_path);
        let facts = fact_map(&spec);
        assert_eq!(facts["ranges_consistent"], Value::Bool(false));
    }

    #[test]
    fn validate_flags_missing_content_label() {
        let (root, _, spec_path) = write_fixture_spec("missing-label", &fixture_census());
        let mut spec = read_json(&spec_path);
        spec["lane"]
            .as_object_mut()
            .unwrap()
            .remove("content_label");
        let result = validate_file(&root, &spec, "mutated.json");
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"LANE_LABEL".to_string()));
    }

    #[test]
    fn validate_flags_statement_without_evidence() {
        let (root, _, spec_path) = write_fixture_spec("no-evidence", &fixture_census());
        let mut spec = read_json(&spec_path);
        spec["statements"][0]
            .as_object_mut()
            .unwrap()
            .insert("evidence".to_string(), json!([]));
        let result = validate_file(&root, &spec, "mutated.json");
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"STATEMENT_EVIDENCE".to_string()));
    }

    #[test]
    fn validate_flags_tampered_pointer_hash() {
        let (root, census_path, spec_path) = write_fixture_spec("tampered-hash", &fixture_census());
        let mut spec = read_json(&spec_path);
        spec["statements"][0]["evidence"][0]
            .as_object_mut()
            .unwrap()
            .insert("hash".to_string(), json!("b".repeat(64)));
        let mutated = root.join("mutated.json");
        fs::write(&mutated, serde_json::to_string_pretty(&spec).unwrap()).unwrap();
        let config = test_config(&root);
        let result = validate_spec(
            &config,
            &json!({
                "target": mutated.display().to_string(),
                "census": census_path.display().to_string(),
            }),
        )
        .unwrap();
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"EVIDENCE_HASH_MISMATCH".to_string()));
    }

    #[test]
    fn validate_flags_dialogue_verbatim() {
        let root = test_root("verbatim");
        let mut spec = handwritten_spec();
        spec["statements"][0].as_object_mut().unwrap().insert(
            "verbatim_text".to_string(),
            json!("the original's own words"),
        );
        let result = validate_file(&root, &spec, "spec.json");
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"DIALOGUE_VERBATIM".to_string()));
    }

    #[test]
    fn validate_flags_inverted_range_row() {
        let (root, _, spec_path) = write_fixture_spec("inverted-range", &fixture_census());
        let mut spec = read_json(&spec_path);
        spec["data_tables"][0]["rows"][0] = json!(["ParamAngleX", 30.0, -30.0, 0.0]);
        let result = validate_file(&root, &spec, "mutated.json");
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"TABLE_RANGE_ORDER".to_string()));
    }

    #[test]
    fn validate_flags_unknown_without_probe() {
        let (root, _, spec_path) = write_fixture_spec("no-probe", &fixture_census());
        let mut spec = read_json(&spec_path);
        spec["unknowns"][0].as_object_mut().unwrap().remove("probe");
        let result = validate_file(&root, &spec, "mutated.json");
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"UNKNOWN_PROBE".to_string()));
    }

    #[test]
    fn validate_flags_duplicate_statement_ids() {
        let (root, _, spec_path) = write_fixture_spec("duplicate-ids", &fixture_census());
        let mut spec = read_json(&spec_path);
        let first = spec["statements"][0]["id"].clone();
        spec["statements"][1]
            .as_object_mut()
            .unwrap()
            .insert("id".to_string(), first);
        let result = validate_file(&root, &spec, "mutated.json");
        assert_eq!(validation_facts(&result)["valid"], false);
        assert!(violation_codes(&result).contains(&"STATEMENT_DUPLICATE".to_string()));
    }

    #[test]
    fn diff_detects_single_fact_change() {
        let (root, census_path, spec_path) = write_fixture_spec("diff-change", &fixture_census());
        let mut gt = fixture_gt();
        gt["models"][0]["moc3"]["sha256"] = json!("c".repeat(64));
        let gt_path = root.join("gt.json");
        fs::write(&gt_path, serde_json::to_string_pretty(&gt).unwrap()).unwrap();
        let config = test_config(&root);
        let result = diff_spec(
            &config,
            &json!({
                "target": spec_path.display().to_string(),
                "reference": gt_path.display().to_string(),
                "census": census_path.display().to_string(),
                "model": "FixtureModel",
            }),
        )
        .unwrap();
        let facts = &result["findings"][0]["facts"];
        assert_eq!(facts["totals"]["checks"], 15);
        assert_eq!(facts["totals"]["match"], 14);
        assert_eq!(facts["totals"]["diff"], 1);
        let failing: Vec<&Value> = facts["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|check| check["match"] == Value::Bool(false))
            .collect();
        assert_eq!(failing.len(), 1);
        assert_eq!(failing[0]["check"], "moc3.sha256");
    }
}
