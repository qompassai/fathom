//! Flutter/Dart AOT call-graph lane (D-1620): the pinned
//! aotopsy tool (BroNils/aotopsy v1.6.0, commit
//! 01011df108eaf5a0c1757cf5842115f9fb8b6303, BSD-3-Clause) run
//! as a bounded child process over an extracted Flutter
//! library directory, with its JSONL outputs ingested into
//! evidence envelopes.
//!
//! Static-only discipline: aotopsy is a pure snapshot parser
//! — one static Go binary that reads the Dart AOT snapshot's
//! own tables; it embeds no Dart VM and executes no target
//! code (established in the D-1618 head-to-head, COMPARISON.md),
//! and fathom never executes the target libraries themselves.
//!
//! The lane's reason to exist is the call graph: aotopsy is
//! the only tool in the head-to-head that emits one (166,231
//! call edges plus a 133,207-row dispatch table on the
//! LocalSend ground truth). Its census streams (functions,
//! classes, string refs) ride along, and its endpoint and
//! behavioural-signal outputs are tagged as candidates for
//! the D-1588 security-audit lens — a candidate is a
//! candidate, never a confirmed secret or finding.
//!
//! Version honesty rule: aotopsy's own Dart version string
//! (its doctor output, snapshot.json, and run summary) is a
//! structural profile label, not the SDK patch version — on
//! the ground truth it prints 3.11.0 against a true 3.11.5.
//! The envelope's Dart version therefore derives only from
//! snapshot-hash / engine-banner evidence read directly from
//! the library pair (the same evidence blutter's
//! `extract_dart_info` reads); the aotopsy label is recorded
//! separately, labelled as a profile estimate, and never
//! leaks into the version field.
//!
//! The tool is observe-class: the registry's policy engine
//! default-denies it until the operator names
//! `aotopsy_analyze` in `allow_tools` (SPEC §8, the
//! game-extract lane pattern).
//!
//! Input validation is the blutter rung's fail-closed layer,
//! reused as-is: [`validate_flutter_lib_dir`] decides every
//! refusal (missing pair member, wrong architecture,
//! truncated or non-ELF file) with the rung's typed errors
//! before aotopsy ever runs.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject, subject_for_file};
use fathom_core::limits::{OUTPUT_BYTES_MAX, TARGET_BYTES_MAX};
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run};
use fathom_core::registry::{Registry, optional_str, require_str};

use crate::blutter::{candidate_kind, validate_flutter_lib_dir};

/// Findings-candidate records retained in the evidence.
const AOTOPSY_CANDIDATES_EVIDENCE_MAX: usize = 4_096;

/// Bytes of one aotopsy JSONL output file read (the largest
/// stream of a large application stays well under this).
const AOTOPSY_JSONL_FILE_BYTES_MAX: u64 = 268_435_456;

/// Census records retained per stream in the evidence;
/// totals are always computed over the full census, never
/// over the retained page.
const AOTOPSY_RECORDS_EVIDENCE_MAX: usize = 4_096;

/// Entries retained from one record's array fields (a class
/// layout's field list is the wide case).
const AOTOPSY_RECORD_ARRAY_ITEMS_MAX: usize = 64;

/// Characters retained from one record's string fields.
const AOTOPSY_RECORD_VALUE_CHARS_MAX: usize = 512;

/// Wall-clock bound for one aotopsy run. The full pipeline
/// took 113.8 s on the LocalSend ground truth; the bound
/// mirrors the blutter rung's cap so a wedged child is
/// stopped on the same discipline.
const AOTOPSY_TIMEOUT_SECS: u64 = 1_800;

/// The Dart version facts an envelope may claim, and the
/// aotopsy label it must not claim as a version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DartVersionFacts {
    /// Dart version from the libflutter.so engine banner
    /// (`<version> (stable|beta|dev)` in the engine's
    /// read-only data — the string blutter's
    /// `extract_libflutter_info` reads). `None` when the
    /// banner is absent: the version is then unrecorded,
    /// never filled from the profile label.
    pub version: Option<String>,
    /// Snapshot hash read from libapp.so's VM snapshot data
    /// (the 32-hex-digit hash the flags string follows).
    pub snapshot_hash: Option<String>,
    /// Snapshot build flags that follow the hash.
    pub snapshot_flags: Vec<String>,
    /// aotopsy's own Dart version label (doctor /
    /// snapshot.json / run summary), recorded separately
    /// and labelled a profile estimate. Never a version.
    pub profile_label: Option<String>,
}

/// Extract the engine-banner Dart version from libflutter.so
/// bytes: the first NUL-terminated `<version> (stable|beta|
/// dev)` string whose version token starts with a digit and
/// carries a `.`. Mirrors blutter's `extract_libflutter_info`
/// search over the engine's read-only data.
pub fn engine_banner_version(libflutter: &[u8]) -> Option<String> {
    let mut start = 0_usize;
    while start < libflutter.len() {
        if libflutter[start] != 0 {
            start += 1;
            continue;
        }
        let token_start = start + 1;
        let mut token_end = token_start;
        while token_end < libflutter.len()
            && (libflutter[token_end].is_ascii_alphanumeric()
                || matches!(libflutter[token_end], b'.' | b'-' | b'_' | b'+'))
        {
            token_end += 1;
        }
        let token = &libflutter[token_start..token_end];
        let banner_tail = &libflutter[token_end..];
        if token.len() >= 5
            && token.len() <= 32
            && token[0].is_ascii_digit()
            && token.contains(&b'.')
            && (banner_tail.starts_with(b" (stable)")
                || banner_tail.starts_with(b" (beta)")
                || banner_tail.starts_with(b" (dev)"))
            && let Ok(version) = std::str::from_utf8(token)
        {
            return Some(version.to_string());
        }
        start = token_end.max(start + 1);
    }
    None
}

/// Extract the snapshot hash and its build flags from
/// libapp.so bytes: the 32-lowercase-hex-digit hash in the
/// VM snapshot data, identified by the NUL-terminated flags
/// string that follows it (the same bytes blutter's
/// `extract_snapshot_hash_flags` reads via the
/// `_kDartVmSnapshotData` symbol). A candidate hash whose
/// flags do not name the arm64 compressed-pointers build is
/// not the snapshot hash and is passed over.
pub fn snapshot_hash_and_flags(libapp: &[u8]) -> Option<(String, Vec<String>)> {
    if libapp.len() < 33 {
        return None;
    }
    for start in 0..=(libapp.len() - 33) {
        let candidate = &libapp[start..start + 32];
        if !candidate
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            continue;
        }
        let flags_start = start + 32;
        let mut flags_end = flags_start;
        while flags_end < libapp.len() && libapp[flags_end] != 0 && flags_end - flags_start < 256 {
            flags_end += 1;
        }
        if flags_end >= libapp.len() || libapp[flags_end] != 0 {
            continue;
        }
        let Ok(flags_text) = std::str::from_utf8(&libapp[flags_start..flags_end]) else {
            continue;
        };
        let flags: Vec<String> = flags_text.split_whitespace().map(str::to_string).collect();
        if flags.len() >= 4
            && flags.iter().any(|flag| flag == "arm64")
            && flags.iter().any(|flag| flag == "compressed-pointers")
            && flags.iter().all(|flag| {
                flag.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'+')
                })
            })
        {
            let hash = std::str::from_utf8(candidate).ok()?.to_string();
            return Some((hash, flags));
        }
    }
    None
}

/// Combine the version evidence of one library pair. The
/// version comes from the engine banner only; the snapshot
/// hash and flags corroborate the build; `profile_label`
/// (aotopsy's own label, when the caller read one) is
/// carried through untouched and never consulted for the
/// version.
pub fn dart_version_facts(
    libapp: &[u8],
    libflutter: &[u8],
    profile_label: Option<String>,
) -> DartVersionFacts {
    let (snapshot_hash, snapshot_flags) = match snapshot_hash_and_flags(libapp) {
        Some((hash, flags)) => (Some(hash), flags),
        None => (None, Vec::new()),
    };
    DartVersionFacts {
        version: engine_banner_version(libflutter),
        snapshot_hash,
        snapshot_flags,
        profile_label,
    }
}

/// Parse aotopsy's profile label from its snapshot.json
/// text (the `dart_version` field). Absence is an honest
/// `None`; the value is a profile estimate by construction
/// and is only ever recorded as one.
pub fn parse_profile_label(snapshot_json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(snapshot_json).ok()?;
    value.get("dart_version")?.as_str().map(str::to_string)
}

/// One aotopsy JSONL stream, censused in full.
#[derive(Clone, Debug, Default)]
pub struct JsonlCensus {
    /// Records parsed.
    pub total: usize,
    /// Non-empty lines that are not JSON records.
    pub lines_malformed: usize,
    /// Record counts by the stream's kind field, when the
    /// caller named one.
    pub by_kind: BTreeMap<String, usize>,
    /// Records retained for the evidence, capped at
    /// `AOTOPSY_RECORDS_EVIDENCE_MAX`, values bounded by
    /// [`bound_record_value`].
    pub retained: Vec<Value>,
}

/// Bound one JSONL record for evidence retention: string
/// fields truncated to `AOTOPSY_RECORD_VALUE_CHARS_MAX`
/// characters, array fields to
/// `AOTOPSY_RECORD_ARRAY_ITEMS_MAX` entries, recursively.
fn bound_record_value(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            Value::String(text.chars().take(AOTOPSY_RECORD_VALUE_CHARS_MAX).collect())
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(AOTOPSY_RECORD_ARRAY_ITEMS_MAX)
                .map(bound_record_value)
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| (key.clone(), bound_record_value(field)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Census one aotopsy JSONL output stream. Every record is
/// counted over the full file; malformed lines are counted,
/// never silently folded into records; a missing file, an
/// oversized file, or a file with zero parseable records is
/// a typed error — a finished run that cannot show its
/// stream is never reported as partial evidence. `on_record`
/// observes each parsed record in file order (the string-ref
/// candidate scan rides it).
pub fn census_jsonl(
    path: &Path,
    kind_field: Option<&str>,
    on_record: &mut dyn FnMut(&Value),
) -> Result<JsonlCensus, FathomError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("aotopsy output {} is missing: {e}", path.display()),
        )
    })?;
    if metadata.len() > AOTOPSY_JSONL_FILE_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "aotopsy output {} exceeds {AOTOPSY_JSONL_FILE_BYTES_MAX} bytes",
                path.display()
            ),
        ));
    }
    let file = std::fs::File::open(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot open aotopsy output {}: {e}", path.display()),
        )
    })?;
    let mut census = JsonlCensus::default();
    let mut lines_total = 0_usize;
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                format!("cannot read aotopsy output {}: {e}", path.display()),
            )
        })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines_total += 1;
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            census.lines_malformed += 1;
            continue;
        };
        census.total += 1;
        if let Some(field) = kind_field
            && let Some(kind) = record.get(field).and_then(Value::as_str)
        {
            *census.by_kind.entry(kind.to_string()).or_default() += 1;
        }
        on_record(&record);
        if census.retained.len() < AOTOPSY_RECORDS_EVIDENCE_MAX {
            census.retained.push(bound_record_value(&record));
        }
    }
    if census.total == 0 {
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            format!(
                "aotopsy output {} held {lines_total} lines and no parseable records",
                path.display()
            ),
        ));
    }
    Ok(census)
}

/// Census one optional aotopsy signal stream (the endpoint
/// and behavioural outputs). Absence is reported by the
/// caller as an unknown, not folded into a zero: `None`
/// here means the file does not exist; a present file is
/// censused under the same fail-closed rules as the core
/// streams.
fn census_optional_jsonl(
    path: &Path,
    kind_field: Option<&str>,
) -> Result<Option<JsonlCensus>, FathomError> {
    if !path.is_file() {
        return Ok(None);
    }
    census_jsonl(path, kind_field, &mut |_| {}).map(Some)
}

/// Locate the pinned aotopsy binary: the operator names
/// its directory with `FATHOM_AOTOPSY_DIR` (the estate's
/// Ghidra/blutter pattern). The directory must hold the
/// `aotopsy` executable built from the pinned source.
pub fn locate_aotopsy() -> Option<PathBuf> {
    let dir = std::env::var("FATHOM_AOTOPSY_DIR").ok()?;
    let dir = PathBuf::from(dir);
    let binary = dir.join("aotopsy");
    if binary.is_file() { Some(binary) } else { None }
}

/// Read one library whole for version-evidence extraction,
/// under the target size bound validation already enforced.
fn read_library_bytes(path: &Path) -> Result<Vec<u8>, FathomError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot stat {}: {e}", path.display()),
        )
    })?;
    if metadata.len() > TARGET_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "{} exceeds the {TARGET_BYTES_MAX}-byte target bound",
                path.display()
            ),
        ));
    }
    std::fs::read(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot read {}: {e}", path.display()),
        )
    })
}

/// The `aotopsy_analyze` tool: run the pinned aotopsy over
/// a validated Flutter library directory and ingest its
/// outputs.
pub fn aotopsy_analyze(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target_raw = require_str(args, "target")?;
    let target = paths::validate_target(config, Path::new(target_raw))?;
    let output_dir = match optional_str(args, "output_dir") {
        Some(raw) => Some(paths::validate_output_dir(config, Path::new(raw))?),
        None => None,
    };
    analyze_with_aotopsy(config, &target, output_dir, locate_aotopsy())
}

/// The lane's work, with the aotopsy location explicit so
/// tests can drive it with a fixture binary.
fn analyze_with_aotopsy(
    config: &Config,
    target: &Path,
    output_dir: Option<PathBuf>,
    aotopsy_bin: Option<PathBuf>,
) -> Result<Value, FathomError> {
    let libs = validate_flutter_lib_dir(target)?;
    let aotopsy_bin = aotopsy_bin.ok_or_else(|| {
        FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "aotopsy is not located; set FATHOM_AOTOPSY_DIR to the directory \
             holding the pinned aotopsy binary",
        )
        .with_remediation(
            "Build BroNils/aotopsy v1.6.0 (01011df108eaf5a0c1757cf5842115f9fb8b6303) \
             from source and set FATHOM_AOTOPSY_DIR to its directory.",
        )
    })?;
    let subject = subject_for_file(&libs.libapp)?;
    let out_dir = match output_dir {
        Some(dir) => dir,
        None => {
            let base = paths::state_subdir(config, "aotopsy")?;
            let named = base.join(&subject.sha256[..16]);
            std::fs::create_dir_all(&named).map_err(|e| {
                FathomError::new(
                    ErrorCode::ExecutionFailure,
                    format!("cannot create output directory {}: {e}", named.display()),
                )
            })?;
            named
        }
    };
    let outcome = run(&ProcessSpec {
        args: vec![
            libs.libapp.display().to_string(),
            "--out".to_string(),
            out_dir.display().to_string(),
        ],
        cwd: None,
        env: Vec::new(),
        output_cap: OUTPUT_BYTES_MAX,
        program: aotopsy_bin.display().to_string(),
        timeout: Duration::from_secs(AOTOPSY_TIMEOUT_SECS),
    })?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!("aotopsy exceeded {AOTOPSY_TIMEOUT_SECS} seconds and was stopped"),
        ));
    }
    if outcome.exit_code != Some(0) {
        let stderr = String::from_utf8_lossy(&outcome.stderr);
        let excerpt: String = stderr.chars().take(512).collect();
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "aotopsy exited with {:?}; stderr excerpt: {excerpt}",
                outcome.exit_code
            ),
        ));
    }
    build_evidence(&libs, &out_dir, subject)
}

/// Ingest a finished aotopsy output tree into an evidence
/// envelope. Missing core streams are typed errors, never
/// partial claims; the signal streams are optional outputs
/// whose absence is recorded as an unknown.
fn build_evidence(
    libs: &crate::blutter::FlutterLibDir,
    out_dir: &Path,
    subject: Subject,
) -> Result<Value, FathomError> {
    let mut evidence = Evidence::new("aotopsy_analyze", "aotopsy").with_subject(subject);
    evidence.add_finding(Finding::new(
        "flutter_lib_dir",
        Confidence::Observed,
        json!({
            "libapp": {"path": libs.libapp.display().to_string(), "bytes": libs.app_bytes,
                "elf_machine": libs.app_facts.machine, "elf_64_bit": libs.app_facts.is_64_bit},
            "libflutter": {"path": libs.libflutter.display().to_string(),
                "bytes": libs.flutter_bytes, "elf_machine": libs.flutter_facts.machine,
                "elf_64_bit": libs.flutter_facts.is_64_bit},
            "layout": "lib/arm64-v8a",
        }),
    ));
    // The profile label rides in from aotopsy's own
    // snapshot.json when the run wrote one; it is evidence
    // about aotopsy's profile, never about the SDK version.
    let profile_label = match std::fs::read_to_string(out_dir.join("snapshot.json")) {
        Ok(text) => parse_profile_label(&text),
        Err(_) => None,
    };
    let app_bytes = read_library_bytes(&libs.libapp)?;
    let flutter_bytes = read_library_bytes(&libs.libflutter)?;
    let facts = dart_version_facts(&app_bytes, &flutter_bytes, profile_label);
    match &facts.version {
        Some(version) => evidence.add_finding(Finding::new(
            "dart_version",
            Confidence::Observed,
            json!({
                "version": version.clone(),
                "snapshot_hash": facts.snapshot_hash.clone(),
                "snapshot_flags": facts.snapshot_flags,
                "target": "android arm64",
                "source": "libflutter.so engine banner and libapp.so VM snapshot \
                           data, read directly (the extract_dart_info evidence); \
                           never aotopsy's profile label",
            }),
        )),
        None => evidence.add_unknown(
            "dart_version",
            "libflutter.so carries no engine-banner Dart version and the \
             version is unrecorded, not guessed; aotopsy's profile label \
             is an estimate and is never reported as the version",
        ),
    }
    if let Some(label) = &facts.profile_label {
        let label_matches = facts.version.as_deref() == Some(label.as_str());
        evidence.add_finding(
            Finding::new(
                "aotopsy_profile_label",
                Confidence::Observed,
                json!({
                    "label": label,
                    "label_kind": "profile_estimate_not_sdk_version",
                    "evidence_version": facts.version.clone(),
                    "label_matches_evidence_version": label_matches,
                }),
            )
            .with_limitation(
                "aotopsy's Dart label is a structural profile estimate (on the \
                 LocalSend ground truth it prints 3.11.0 against an evidence-derived \
                 3.11.5); it is recorded for provenance and must not be cited \
                 as the Dart SDK version",
            ),
        );
    }
    let mut candidates: Vec<Value> = Vec::new();
    let string_refs = census_jsonl(
        &out_dir.join("string_refs.jsonl"),
        Some("kind"),
        &mut |record| {
            if candidates.len() >= AOTOPSY_CANDIDATES_EVIDENCE_MAX {
                return;
            }
            let Some(text) = record.get("value").and_then(Value::as_str) else {
                return;
            };
            if let Some(kind) = candidate_kind(text) {
                candidates.push(json!({
                    "candidate_kind": kind,
                    "value": text.chars().take(AOTOPSY_RECORD_VALUE_CHARS_MAX)
                        .collect::<String>(),
                    "func": record.get("func").cloned().unwrap_or(Value::Null),
                    "pc": record.get("pc").cloned().unwrap_or(Value::Null),
                    "status": "candidate_for_review_not_a_finding",
                }));
            }
        },
    )?;
    let functions = census_jsonl(&out_dir.join("functions.jsonl"), None, &mut |_| {})?;
    let classes = census_jsonl(&out_dir.join("classes.jsonl"), None, &mut |_| {})?;
    let dispatch = census_jsonl(
        &out_dir.join("dispatch_table.jsonl"),
        Some("kind"),
        &mut |_| {},
    )?;
    let call_edges = census_jsonl(&out_dir.join("call_edges.jsonl"), Some("kind"), &mut |_| {})?;
    evidence.add_finding(Finding::new(
        "aotopsy_functions",
        Confidence::Observed,
        json!({
            "total": functions.total,
            "lines_malformed": functions.lines_malformed,
            "records_retained": functions.retained.len(),
            "records": functions.retained,
        }),
    ));
    evidence.add_finding(Finding::new(
        "aotopsy_classes",
        Confidence::Observed,
        json!({
            "total": classes.total,
            "lines_malformed": classes.lines_malformed,
            "records_retained": classes.retained.len(),
            "records": classes.retained,
        }),
    ));
    evidence.add_finding(Finding::new(
        "aotopsy_string_refs",
        Confidence::Observed,
        json!({
            "total": string_refs.total,
            "by_kind": string_refs.by_kind,
            "lines_malformed": string_refs.lines_malformed,
            "records_retained": string_refs.retained.len(),
            "records": string_refs.retained,
        }),
    ));
    evidence.add_finding(Finding::new(
        "dispatch_table",
        Confidence::Observed,
        json!({
            "total": dispatch.total,
            "by_kind": dispatch.by_kind,
            "lines_malformed": dispatch.lines_malformed,
            "rows_retained": dispatch.retained.len(),
            "rows": dispatch.retained,
        }),
    ));
    evidence.add_finding(Finding::new(
        "call_graph",
        Confidence::Observed,
        json!({
            "call_edges_total": call_edges.total,
            "by_kind": call_edges.by_kind,
            "lines_malformed": call_edges.lines_malformed,
            "edges_retained": call_edges.retained.len(),
            "edges": call_edges.retained,
            "source_stream": "call_edges.jsonl",
        }),
    ));
    let endpoints = census_optional_jsonl(&out_dir.join("network_endpoints.jsonl"), Some("type"))?;
    let behavioural =
        census_optional_jsonl(&out_dir.join("behavioral_findings.jsonl"), Some("category"))?;
    let crypto = census_optional_jsonl(&out_dir.join("crypto_findings.jsonl"), Some("algorithm"))?;
    if let Some(endpoints) = &endpoints {
        for record in &endpoints.retained {
            if candidates.len() >= AOTOPSY_CANDIDATES_EVIDENCE_MAX {
                break;
            }
            candidates.push(json!({
                "candidate_kind": "network_endpoint",
                "type": record.get("type").cloned().unwrap_or(Value::Null),
                "value": record.get("value").cloned().unwrap_or(Value::Null),
                "func": record.get("func").cloned().unwrap_or(Value::Null),
                "status": "candidate_for_review_not_a_finding",
            }));
        }
    }
    if let Some(behavioural) = &behavioural {
        for record in &behavioural.retained {
            if candidates.len() >= AOTOPSY_CANDIDATES_EVIDENCE_MAX {
                break;
            }
            candidates.push(json!({
                "candidate_kind": "behavioural_signal",
                "pattern": record.get("pattern").cloned().unwrap_or(Value::Null),
                "category": record.get("category").cloned().unwrap_or(Value::Null),
                "aotopsy_confidence":
                    record.get("confidence").cloned().unwrap_or(Value::Null),
                "status": "candidate_for_review_not_a_finding",
            }));
        }
    }
    if let Some(crypto) = &crypto {
        for record in &crypto.retained {
            if candidates.len() >= AOTOPSY_CANDIDATES_EVIDENCE_MAX {
                break;
            }
            candidates.push(json!({
                "candidate_kind": "crypto_signal",
                "algorithm": record.get("algorithm").cloned().unwrap_or(Value::Null),
                "status": "candidate_for_review_not_a_finding",
            }));
        }
    }
    if endpoints.is_none() && behavioural.is_none() && crypto.is_none() {
        evidence.add_unknown(
            "aotopsy_signal_outputs",
            "aotopsy wrote no network_endpoints, behavioral_findings, or \
             crypto_findings streams; no endpoint or behavioural candidates \
             are recorded",
        );
    }
    if !candidates.is_empty() {
        evidence.add_finding(
            Finding::new(
                "aotopsy_findings_candidates",
                Confidence::Inferred,
                json!({
                    "candidates": candidates,
                    "network_endpoints_total": endpoints.as_ref().map(|c| c.total),
                    "behavioural_findings_total": behavioural.as_ref().map(|c| c.total),
                    "crypto_findings_total": crypto.as_ref().map(|c| c.total),
                }),
            )
            .with_limitation(
                "Candidates are aotopsy endpoint/behavioural/crypto signals and \
                 URL-like or credential-like string refs flagged for the D-1588 \
                 audit hunt; each needs human verification before it is treated \
                 as an endpoint, a behaviour, or a credential",
            ),
        );
    }
    let examined =
        (functions.total + classes.total + string_refs.total + dispatch.total + call_edges.total)
            as u64;
    evidence.coverage.examined = examined;
    evidence.coverage.total = examined;
    evidence.coverage.exhaustive = functions.lines_malformed == 0
        && classes.lines_malformed == 0
        && string_refs.lines_malformed == 0
        && dispatch.lines_malformed == 0
        && call_edges.lines_malformed == 0;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;

    /// ELF machine value for AArch64 (`EM_AARCH64`).
    const ELF_MACHINE_AARCH64: u16 = 183;

    /// ELF machine value for x86-64 (`EM_X86_64`); named for
    /// the wrong-architecture adversarial tests.
    const ELF_MACHINE_X86_64: u16 = 62;

    fn elf64(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    /// libapp.so fixture: a valid arm64 ELF64 header plus
    /// the VM snapshot data bytes (hash + flags).
    fn libapp_fixture() -> Vec<u8> {
        let mut bytes = elf64(ELF_MACHINE_AARCH64);
        bytes.extend_from_slice(b"78da37fed6bf1489361a312568249f3f");
        bytes.extend_from_slice(
            b"product no-code_comments dedup_instructions arm64 android \
              compressed-pointers\0",
        );
        bytes
    }

    /// libflutter.so fixture: a valid arm64 ELF64 header
    /// plus the engine banner string.
    fn libflutter_fixture() -> Vec<u8> {
        let mut bytes = elf64(ELF_MACHINE_AARCH64);
        bytes.extend_from_slice(
            b"\x003.11.5 (stable) (Wed Apr 15 00:36:32 2026 -0700) \
              on \"android_arm64\"\x00",
        );
        bytes
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-aotopsy-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with_root(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn write_lib_dir(dir: &Path, app: &[u8], flutter: Option<&[u8]>) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("libapp.so"), app).unwrap();
        if let Some(bytes) = flutter {
            std::fs::write(dir.join("libflutter.so"), bytes).unwrap();
        }
    }

    /// Write a fake aotopsy: a python script that ingests
    /// like the real binary (JSONL streams + snapshot.json
    /// in the `--out` directory) with `omit` naming the one
    /// stream to leave out and `fail` forcing a non-zero
    /// exit.
    fn write_fake_aotopsy(dir: &Path, omit: &str, fail: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let script = format!(
            "#!/usr/bin/env python3\n\
             import json, os, sys\n\
             if {fail}:\n\
             \x20   sys.exit(3)\n\
             out = sys.argv[sys.argv.index('--out') + 1]\n\
             os.makedirs(out, exist_ok=True)\n\
             streams = {{\n\
             \x20 'functions.jsonl': [\n\
             \x20   {{\"pc\": \"0x1000\", \"size\": 16, \"name\": \"main\", \"owner\": \"App\"}},\n\
             \x20   {{\"pc\": \"0x1010\", \"size\": 8, \"name\": \"helper\"}}],\n\
             \x20 'classes.jsonl': [\n\
             \x20   {{\"class_name\": \"App\", \"class_id\": 1, \"instance_size\": 16, \"fields\": []}}],\n\
             \x20 'string_refs.jsonl': [\n\
             \x20   {{\"func\": \"main\", \"pc\": \"0x1004\", \"kind\": \"PP\", \"pool_idx\": 1, \"value\": \"https://api.example.com/v1\"}},\n\
             \x20   {{\"func\": \"main\", \"pc\": \"0x1008\", \"kind\": \"PP\", \"pool_idx\": 2, \"value\": \"api_key = hunter2\"}},\n\
             \x20   {{\"func\": \"main\", \"pc\": \"0x100c\", \"kind\": \"PP_peep\", \"pool_idx\": 3, \"value\": \"plain\"}}],\n\
             \x20 'dispatch_table.jsonl': [\n\
             \x20   {{\"index\": 0, \"kind\": \"null\"}},\n\
             \x20   {{\"index\": 60, \"kind\": \"code\", \"target\": \"toInt\"}}],\n\
             \x20 'call_edges.jsonl': [\n\
             \x20   {{\"from_func\": \"main\", \"from_pc\": \"0x1004\", \"kind\": \"bl\", \"target\": \"helper\"}},\n\
             \x20   {{\"from_func\": \"main\", \"from_pc\": \"0x1008\", \"kind\": \"blr\", \"target\": \"dyn\"}}],\n\
             \x20 'network_endpoints.jsonl': [\n\
             \x20   {{\"type\": \"url\", \"value\": \"https://api.example.com/v1\", \"func\": \"main\"}}],\n\
             \x20 'behavioral_findings.jsonl': [\n\
             \x20   {{\"pattern\": \"category_net_count\", \"category\": \"net\", \"functions\": None, \"edge_count\": 4, \"confidence\": \"info\"}}],\n\
             \x20 'crypto_findings.jsonl': [\n\
             \x20   {{\"algorithm\": \"AES\", \"constant\": \"0x1\", \"pool_index\": -1, \"value\": \"x\"}}],\n\
             }}\n\
             for name, rows in streams.items():\n\
             \x20   if name == '{omit}':\n\
             \x20       continue\n\
             \x20   with open(os.path.join(out, name), 'w') as fh:\n\
             \x20       for row in rows:\n\
             \x20           fh.write(json.dumps(row) + '\\n')\n\
             if '{omit}' == 'functions.jsonl':\n\
             \x20   with open(os.path.join(out, 'functions.jsonl'), 'w') as fh:\n\
             \x20       fh.write('not json at all\\n')\n\
             with open(os.path.join(out, 'snapshot.json'), 'w') as fh:\n\
             \x20   json.dump({{\"dart_version\": \"3.11.0\", \"arch\": \"arm64\"}}, fh)\n\
             print('summary dart: 3.11.0 functions: 2', file=sys.stderr)\n",
            fail = if fail { "True" } else { "False" },
            omit = omit,
        );
        let binary = dir.join("aotopsy");
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        binary
    }

    fn finding<'a>(value: &'a Value, kind: &str) -> &'a Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == kind)
            .unwrap()
    }

    // ---- validation tests ----

    #[test]
    fn validation_engine_banner_version_parses() {
        assert_eq!(
            engine_banner_version(&libflutter_fixture()),
            Some("3.11.5".to_string())
        );
        let mut beta = elf64(ELF_MACHINE_AARCH64);
        beta.extend_from_slice(b"\x003.12.0-1.2.beta (beta) on \"android_arm64\"\x00");
        assert_eq!(
            engine_banner_version(&beta),
            Some("3.12.0-1.2.beta".to_string())
        );
        assert_eq!(engine_banner_version(&elf64(ELF_MACHINE_AARCH64)), None);
        assert_eq!(engine_banner_version(b"no banner here"), None);
    }

    #[test]
    fn validation_snapshot_hash_and_flags_parse() {
        let (hash, flags) = snapshot_hash_and_flags(&libapp_fixture()).unwrap();
        assert_eq!(hash, "78da37fed6bf1489361a312568249f3f");
        assert!(flags.iter().any(|flag| flag == "compressed-pointers"));
        assert_eq!(snapshot_hash_and_flags(&elf64(ELF_MACHINE_AARCH64)), None);
    }

    #[test]
    fn validation_fixture_pair_yields_evidence_version() {
        let facts = dart_version_facts(
            &libapp_fixture(),
            &libflutter_fixture(),
            Some("3.11.0".to_string()),
        );
        assert_eq!(facts.version.as_deref(), Some("3.11.5"));
        assert_eq!(
            facts.snapshot_hash.as_deref(),
            Some("78da37fed6bf1489361a312568249f3f")
        );
        assert_eq!(facts.profile_label.as_deref(), Some("3.11.0"));
    }

    #[test]
    fn validation_profile_label_parses_from_snapshot_json() {
        assert_eq!(
            parse_profile_label("{\"dart_version\": \"3.11.0\", \"arch\": \"arm64\"}"),
            Some("3.11.0".to_string())
        );
        assert_eq!(parse_profile_label("{\"arch\": \"arm64\"}"), None);
        assert_eq!(parse_profile_label("not json"), None);
    }

    #[test]
    fn validation_jsonl_census_counts_kinds_and_malformed() {
        let dir = scratch("census");
        let path = dir.join("call_edges.jsonl");
        std::fs::write(
            &path,
            "{\"from_func\": \"a\", \"kind\": \"bl\", \"target\": \"b\"}\n\
             {\"from_func\": \"a\", \"kind\": \"blr\", \"target\": \"c\"}\n\
             not json\n\
             \n\
             {\"from_func\": \"b\", \"kind\": \"bl\", \"target\": \"c\"}\n",
        )
        .unwrap();
        let census = census_jsonl(&path, Some("kind"), &mut |_| {}).unwrap();
        assert_eq!(census.total, 3);
        assert_eq!(census.lines_malformed, 1);
        assert_eq!(census.by_kind["bl"], 2);
        assert_eq!(census.by_kind["blr"], 1);
        assert_eq!(census.retained.len(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validation_fake_aotopsy_run_ingests_evidence() {
        let root = scratch("fakerun");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture(), Some(&libflutter_fixture()));
        let fake = write_fake_aotopsy(&root.join("fake-aotopsy"), "", false);
        let config = config_with_root(&root);
        let out_dir = root.join("out");
        let value = analyze_with_aotopsy(&config, &lib, Some(out_dir), Some(fake)).unwrap();
        assert_eq!(finding(&value, "aotopsy_functions")["facts"]["total"], 2);
        assert_eq!(finding(&value, "aotopsy_classes")["facts"]["total"], 1);
        assert_eq!(finding(&value, "aotopsy_string_refs")["facts"]["total"], 3);
        assert_eq!(finding(&value, "dispatch_table")["facts"]["total"], 2);
        let graph = finding(&value, "call_graph");
        assert_eq!(graph["facts"]["call_edges_total"], 2);
        assert_eq!(graph["facts"]["by_kind"]["bl"], 1);
        assert_eq!(graph["facts"]["by_kind"]["blr"], 1);
        let version = finding(&value, "dart_version");
        assert_eq!(version["facts"]["version"], "3.11.5");
        assert_eq!(
            version["facts"]["snapshot_hash"],
            "78da37fed6bf1489361a312568249f3f"
        );
        let label = finding(&value, "aotopsy_profile_label");
        assert_eq!(label["facts"]["label"], "3.11.0");
        assert_eq!(label["facts"]["label_matches_evidence_version"], false);
        let candidates = finding(&value, "aotopsy_findings_candidates");
        let rows = candidates["facts"]["candidates"].as_array().unwrap();
        // Two string-ref candidates (url + credential-like),
        // one endpoint, one behavioural signal, one crypto
        // signal — every one a candidate, never a finding.
        assert_eq!(rows.len(), 5);
        assert!(
            rows.iter()
                .all(|row| row["status"] == "candidate_for_review_not_a_finding")
        );
        assert_eq!(candidates["facts"]["network_endpoints_total"], 1);
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- adversarial tests ----

    #[test]
    fn adversarial_missing_libflutter_is_refused() {
        let root = scratch("noflutter");
        let lib = root.join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture(), None);
        let config = config_with_root(&root);
        let err = analyze_with_aotopsy(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_wrong_arch_in_arm64_slot_is_refused() {
        let root = scratch("wrongarch");
        let lib = root.join("arm64-v8a");
        let mut wrong = elf64(ELF_MACHINE_X86_64);
        wrong.extend_from_slice(&libapp_fixture()[64..]);
        write_lib_dir(&lib, &wrong, Some(&libflutter_fixture()));
        let config = config_with_root(&root);
        let err = analyze_with_aotopsy(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_elf_is_refused() {
        let root = scratch("truncated");
        let lib = root.join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture()[..32], Some(&libflutter_fixture()));
        let config = config_with_root(&root);
        let err = analyze_with_aotopsy(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_empty_lib_dir_is_refused() {
        let root = scratch("empty");
        let lib = root.join("arm64-v8a");
        std::fs::create_dir_all(&lib).unwrap();
        let config = config_with_root(&root);
        let err = analyze_with_aotopsy(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::TargetUnavailable);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_non_elf_libapp_is_refused() {
        let root = scratch("nonelf");
        let lib = root.join("arm64-v8a");
        let text = vec![b'x'; 128];
        write_lib_dir(&lib, &text, Some(&libflutter_fixture()));
        let config = config_with_root(&root);
        let err = analyze_with_aotopsy(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_unlocated_aotopsy_is_capability_unavailable() {
        let root = scratch("nolocate");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture(), Some(&libflutter_fixture()));
        let config = config_with_root(&root);
        let err = analyze_with_aotopsy(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_profile_label_never_becomes_the_version() {
        // No engine banner in libflutter: the version stays
        // unrecorded even though a profile label exists.
        let facts = dart_version_facts(
            &libapp_fixture(),
            &elf64(ELF_MACHINE_AARCH64),
            Some("3.11.0".to_string()),
        );
        assert_eq!(facts.version, None);
        assert_eq!(facts.profile_label.as_deref(), Some("3.11.0"));
    }

    #[test]
    fn adversarial_fake_aotopsy_failure_is_execution_failure() {
        let root = scratch("fakefail");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture(), Some(&libflutter_fixture()));
        let fake = write_fake_aotopsy(&root.join("fake-aotopsy"), "", true);
        let config = config_with_root(&root);
        let err =
            analyze_with_aotopsy(&config, &lib, Some(root.join("out")), Some(fake)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ExecutionFailure);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_missing_call_edges_stream_is_unreadable_output() {
        let root = scratch("noedges");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture(), Some(&libflutter_fixture()));
        let fake = write_fake_aotopsy(&root.join("fake-aotopsy"), "call_edges.jsonl", false);
        let config = config_with_root(&root);
        let err =
            analyze_with_aotopsy(&config, &lib, Some(root.join("out")), Some(fake)).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_malformed_only_stream_is_unreadable_output() {
        let root = scratch("badstream");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(&lib, &libapp_fixture(), Some(&libflutter_fixture()));
        let fake = write_fake_aotopsy(&root.join("fake-aotopsy"), "functions.jsonl", false);
        let config = config_with_root(&root);
        let err =
            analyze_with_aotopsy(&config, &lib, Some(root.join("out")), Some(fake)).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
        std::fs::remove_dir_all(&root).ok();
    }
}
