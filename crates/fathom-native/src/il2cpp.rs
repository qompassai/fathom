//! IL2CPP project tools (Stage A): apply an Il2CppDumper
//! `script.json` method/string map to an existing Ghidra project
//! and query the named program — decompile one method, census
//! the references to an address — all headless via Java
//! GhidraScripts (`FathomIl2cpp*.java`, bundled beside
//! `FathomExportAnalysis.java`).
//!
//! The workflow is project-centric, unlike the per-subject export
//! cache in `engine`: IL2CPP naming lives in the operator's
//! project, so the project location, project name, and program
//! are arguments. Every path argument must canonicalize under a
//! configured target root. `il2cpp_apply` mutates the project and
//! is execute-class (default-deny); the two query tools are read.

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex, subject_for_file};
use fathom_core::limits::OUTPUT_BYTES_MAX;
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run};
use fathom_core::registry::{Registry, optional_str, require_str};

use crate::engine;

/// Wall-clock bound for one apply run: renaming ~160k map entries
/// plus signature comments is minutes-scale on a cold project.
const APPLY_TIMEOUT_SECS: u64 = 3600;

/// Method entries accepted from one script.json map.
const MAP_METHODS_MAX: usize = 1_000_000;

/// String entries accepted from one script.json map.
const MAP_STRINGS_MAX: usize = 200_000;

/// Default program name inside the Ghidra project.
const PROGRAM_DEFAULT: &str = "GameAssembly.dll";

/// Wall-clock bound for one decompile / xrefs run.
const QUERY_TIMEOUT_SECS: u64 = 1200;

/// Caller rows kept per xref target in the evidence document;
/// class counts are always computed over the full census.
const XREF_CALLERS_EVIDENCE_MAX: usize = 4096;

/// Targets accepted in one `il2cpp_xrefs` call.
const XREF_TARGETS_MAX: usize = 64;

/// Third-party type prefixes for caller classification, matched
/// against the caller's IL2CPP type name (the segment before the
/// first `$$`). Curated from libraries the estate's IL2CPP maps
/// actually contain; anything unmatched is `unknown`, never
/// guessed into a class.
const THIRD_PARTY_PREFIXES: &[&str] = &[
    "CodeStage",
    "Cysharp",
    "DG.",
    "ES3",
    "FBPP",
    "FancyScrollView",
    "Google",
    "Newtonsoft",
    "TMPro",
    "UniRx",
];

/// One map method: an RVA and its (raw) IL2CPP name.
#[derive(Clone, Debug, PartialEq)]
pub struct MethodEntry {
    pub name: String,
    pub raw_name: String,
    pub rva: u64,
    pub signature: Option<String>,
}

/// One map string literal: an RVA and its value.
#[derive(Clone, Debug, PartialEq)]
pub struct StringEntry {
    pub rva: u64,
    pub value: String,
}

/// Parse statistics: what the map held and what was set aside.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MapStats {
    pub duplicates_dropped: usize,
    pub invalid_address: usize,
    pub methods_kept: usize,
    pub methods_total: usize,
    pub names_sanitized: usize,
    pub strings_kept: usize,
    pub strings_total: usize,
    pub strings_unprintable: usize,
}

/// A parsed script.json map plus its parse statistics.
#[derive(Clone, Debug)]
pub struct ScriptMap {
    pub methods: Vec<MethodEntry>,
    pub stats: MapStats,
    pub strings: Vec<StringEntry>,
}

#[derive(Deserialize)]
struct RawMap {
    #[serde(default, rename = "ScriptMethod")]
    methods: Vec<RawMethod>,
    #[serde(default, rename = "ScriptString")]
    strings: Vec<RawString>,
}

#[derive(Deserialize)]
struct RawMethod {
    #[serde(rename = "Address")]
    address: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Signature")]
    signature: Option<String>,
}

#[derive(Deserialize)]
struct RawString {
    #[serde(rename = "Address")]
    address: u64,
    #[serde(rename = "Value")]
    value: String,
}

/// Classify one caller by its IL2CPP name: engine (Unity/BCL/
/// runtime), third-party (curated library prefixes), game (the
/// operator-asserted game type prefixes), or unknown.
pub fn classify_caller(name: &str, game_prefixes: &[String]) -> &'static str {
    let ty = name.split("$$").next().unwrap_or(name);
    for prefix in game_prefixes {
        if !prefix.is_empty() && (ty == prefix || ty.starts_with(&format!("{prefix}."))) {
            return "game";
        }
    }
    if ty.starts_with("UnityEngine")
        || ty.starts_with("Unity.")
        || ty == "Unity"
        || ty.starts_with("System")
        || ty.starts_with("Microsoft")
        || ty.starts_with("Mono")
        || ty.starts_with("Interop")
        || ty.starts_with("il2cpp")
    {
        return "engine";
    }
    if THIRD_PARTY_PREFIXES
        .iter()
        .any(|prefix| ty.starts_with(prefix))
    {
        return "third-party";
    }
    "unknown"
}

/// Apply the map at `map` to the named Ghidra project.
pub fn il2cpp_apply(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let (project, project_name, program) = project_args(config, args)?;
    let map_path = paths::validate_target(config, Path::new(require_str(args, "map")?))?;
    let subject = subject_for_file(&map_path)?;
    let map = load_map(&map_path)?;
    let run_dir = make_run_dir(config, "apply")?;
    let methods_tsv = run_dir.join("methods.tsv");
    let strings_tsv = run_dir.join("strings.tsv");
    write_methods_tsv(&methods_tsv, &map)?;
    write_strings_tsv(&strings_tsv, &map)?;
    let result = run_il2cpp_script(
        config,
        &run_dir,
        &ScriptRun {
            program: &program,
            project: &project,
            project_name: &project_name,
            script: "FathomIl2cppApply.java",
            script_args: &[
                methods_tsv.display().to_string(),
                strings_tsv.display().to_string(),
            ],
            timeout_secs: APPLY_TIMEOUT_SECS,
        },
    )?;
    let mut evidence = Evidence::new("il2cpp_apply", "ghidra-il2cpp");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "map",
        Confidence::Observed,
        json!({
            "duplicates_dropped": map.stats.duplicates_dropped,
            "invalid_address": map.stats.invalid_address,
            "methods_kept": map.stats.methods_kept,
            "methods_total": map.stats.methods_total,
            "names_sanitized": map.stats.names_sanitized,
            "strings_kept": map.stats.strings_kept,
            "strings_total": map.stats.strings_total,
            "strings_unprintable": map.stats.strings_unprintable,
        }),
    ));
    let mut apply_finding = Finding::new("apply", Confidence::Observed, result.clone());
    if result["name_rejected"].as_u64().unwrap_or(0) > 0 {
        apply_finding = apply_finding.with_limitation(
            "some map names were rejected by Ghidra's symbol rules even after sanitization",
        );
    }
    if result["label_only"].as_u64().unwrap_or(0) > 0
        || result["mid_function_labels"].as_u64().unwrap_or(0) > 0
    {
        apply_finding = apply_finding.with_limitation(
            "some addresses had no function to name (mid-function or unanalyzed); \
             those names were applied as labels and stay findable by name",
        );
    }
    evidence.add_finding(apply_finding);
    // The script counts every kept map row exactly once across
    // its outcome classes (created functions are also counted in
    // renamed/already_named, so the outcome classes must not be
    // summed here): rows processed is the examined count.
    evidence.coverage.examined = result["methods_total"].as_u64().unwrap_or(0);
    evidence.coverage.total = map.stats.methods_kept as u64;
    evidence.coverage.exhaustive =
        result["name_rejected"].as_u64().unwrap_or(0) == 0 && map.stats.invalid_address == 0;
    Ok(evidence.to_value())
}

/// Decompile one method (by IL2CPP name or `0x` RVA) from the
/// named project, with its depth-1 callees.
pub fn il2cpp_decompile(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let (project, project_name, program) = project_args(config, args)?;
    let method = require_str(args, "method")?;
    if method.trim().is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'method' must not be empty",
        ));
    }
    let (map, map_subject) = optional_map(config, args)?;
    let spec = query_spec(method, map.as_ref());
    let run_dir = make_run_dir(config, "decompile")?;
    let result = run_il2cpp_script(
        config,
        &run_dir,
        &ScriptRun {
            program: &program,
            project: &project,
            project_name: &project_name,
            script: "FathomIl2cppDecompile.java",
            script_args: &[spec],
            timeout_secs: QUERY_TIMEOUT_SECS,
        },
    )?;
    let mut evidence = Evidence::new("il2cpp_decompile", "ghidra-il2cpp");
    evidence.subject = map_subject;
    let game = game_prefixes(args);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    if result["found"] != json!(true) {
        evidence.add_unknown(
            "function",
            format!("no function in the project matches '{method}'"),
        );
        return Ok(evidence.to_value());
    }
    let function = &result["function"];
    evidence.add_finding(Finding::new(
        "function",
        Confidence::Observed,
        json!({
            "address": function["address"],
            "body_size": function["body_size"],
            "matched_via": result["match"],
            "name": function["name"],
            "query": method,
            "rva": function["rva"],
            "signature": function["signature"],
        }),
    ));
    if let Some(map) = &map
        && let Some(entry) = map
            .methods
            .iter()
            .find(|e| e.raw_name == method || e.rva == function["rva"].as_u64().unwrap_or(0))
        && let Some(signature) = &entry.signature
    {
        evidence.add_finding(Finding::new(
            "map_signature",
            Confidence::Observed,
            json!({"signature": signature}),
        ));
    }
    if let Some(decompile) = result.get("decompile") {
        if decompile["c"].is_null() {
            evidence.add_unknown(
                "decompile",
                format!(
                    "the decompiler produced no C: {}",
                    decompile["error"].as_str().unwrap_or("unknown error")
                ),
            );
        } else {
            let mut finding = Finding::new(
                "decompile",
                Confidence::Derived,
                json!({"bytes": decompile["bytes"], "c": decompile["c"]}),
            );
            if decompile["truncated"] == json!(true) {
                finding = finding.with_limitation("decompiled C truncated at the 1 MiB byte bound");
            }
            evidence.add_finding(finding);
        }
    }
    let callees: Vec<Value> = result["callees"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|c| {
                    json!({
                        "address": c["address"],
                        "classification": classify_caller(
                            c["name"].as_str().unwrap_or(""),
                            &game,
                        ),
                        "name": c["name"],
                        "rva": c["rva"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut callee_finding = Finding::new(
        "callees",
        Confidence::Derived,
        json!({"callees": callees, "total": result["callees_total"]}),
    );
    if result["callees_truncated"] == json!(true) {
        callee_finding =
            callee_finding.with_limitation("callee list truncated at the 1,024-entry bound");
    }
    evidence.add_finding(callee_finding);
    Ok(evidence.to_value())
}

/// Census every reference to each target (IL2CPP name or `0x`
/// RVA), grouped by containing function and namespace class.
pub fn il2cpp_xrefs(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let (project, project_name, program) = project_args(config, args)?;
    let targets = args
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'targets' is required and must be an array of strings",
            )
        })?;
    if targets.is_empty() || targets.len() > XREF_TARGETS_MAX {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument 'targets' must name between 1 and {XREF_TARGETS_MAX} targets"),
        ));
    }
    let (map, map_subject) = optional_map(config, args)?;
    let game = game_prefixes(args);
    let mut specs: Vec<String> = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    for target in targets {
        let target = target.as_str().ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "every 'targets' entry must be a string",
            )
        })?;
        specs.push(query_spec(target, map.as_ref()));
        labels.push(target.to_string());
    }
    let run_dir = make_run_dir(config, "xrefs")?;
    let result = run_il2cpp_script(
        config,
        &run_dir,
        &ScriptRun {
            program: &program,
            project: &project,
            project_name: &project_name,
            script: "FathomIl2cppXrefs.java",
            script_args: &specs,
            timeout_secs: QUERY_TIMEOUT_SECS,
        },
    )?;
    let mut evidence = Evidence::new("il2cpp_xrefs", "ghidra-il2cpp");
    evidence.subject = map_subject;
    let rows = result["targets"].as_array().cloned().unwrap_or_default();
    let mut examined: u64 = 0;
    let mut truncated_any = false;
    for (row, label) in rows.iter().zip(labels.iter()) {
        if row["found"] != json!(true) {
            evidence.add_unknown(
                "target",
                format!("no address in the project resolves '{label}'"),
            );
            continue;
        }
        examined += row["code_refs_total"].as_u64().unwrap_or(0);
        let callers_raw = row["callers"].as_array().cloned().unwrap_or_default();
        let mut by_class: BTreeMap<&str, u64> = BTreeMap::new();
        let mut callers: Vec<Value> = Vec::new();
        for caller in &callers_raw {
            let name = caller["name"].as_str().unwrap_or("");
            let class = classify_caller(name, &game);
            *by_class.entry(class).or_default() += caller["refs"].as_u64().unwrap_or(0);
            if callers.len() < XREF_CALLERS_EVIDENCE_MAX {
                callers.push(json!({
                    "address": caller["address"],
                    "classification": class,
                    "name": caller["name"],
                    "refs": caller["refs"],
                    "rva": caller["rva"],
                }));
            }
        }
        let mut finding = Finding::new(
            "xref_census",
            Confidence::Observed,
            json!({
                "address": row["address"],
                "by_class_refs": by_class,
                "callers": callers,
                "callers_total": row["callers_total"],
                "code_refs_total": row["code_refs_total"],
                "data_refs_total": row["data_refs_total"],
                "resolved_name": row["resolved_name"],
                "rva": row["rva"],
                "target": label,
            }),
        );
        if row["callers_truncated"] == json!(true) {
            finding = finding.with_limitation(
                "caller groups truncated at the 8,192-group bound; totals remain exact",
            );
            truncated_any = true;
        }
        if callers_raw.len() > XREF_CALLERS_EVIDENCE_MAX {
            finding = finding.with_limitation(
                "evidence lists the first caller groups up to the evidence bound; \
                 class counts cover the full census",
            );
        }
        evidence.add_finding(finding);
    }
    evidence.coverage.examined = examined;
    evidence.coverage.total = examined;
    evidence.coverage.exhaustive = !truncated_any;
    Ok(evidence.to_value())
}

/// The operator-asserted game type prefixes, if any.
fn game_prefixes(args: &Value) -> Vec<String> {
    args.get("game_namespaces")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a string literal is clean enough to become a Ghidra
/// comment: no control characters other than tab/newline/return
/// (flattened later), and bounded length. Metadata blob garbage
/// (the packed, NUL-ridden entries Il2CppDumper emits) fails.
fn is_printable_literal(value: &str) -> bool {
    value.chars().count() <= 4096
        && value
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
}

/// Read and parse the script.json map at `path`.
fn load_map(path: &Path) -> Result<ScriptMap, FathomError> {
    let bytes = fs::read(path).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read script map {}: {e}", path.display()),
        )
    })?;
    parse_script_map(&bytes)
}

/// Create a per-call run directory under the state dir.
fn make_run_dir(config: &Config, kind: &str) -> Result<PathBuf, FathomError> {
    let root = paths::state_subdir(config, "il2cpp")?;
    let stamp = format!(
        "{kind}-{}",
        sha256_hex(format!("{}-{kind}", std::process::id()).as_bytes())
    );
    let dir = root.join(&stamp[..stamp.len().min(24)]);
    fs::create_dir_all(&dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create il2cpp run dir: {e}"),
        )
    })?;
    Ok(dir)
}

/// Locate the directory holding the IL2CPP GhidraScripts: the
/// `FATHOM_GHIDRA_SCRIPT_DIR` override, else the crate's bundled
/// `ghidra/` directory.
fn locate_il2cpp_script_dir() -> Result<PathBuf, FathomError> {
    if let Ok(dir) = std::env::var("FATHOM_GHIDRA_SCRIPT_DIR") {
        let candidate = PathBuf::from(dir);
        if candidate.join("FathomIl2cppApply.java").exists() {
            return Ok(candidate);
        }
    }
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ghidra");
    if bundled.join("FathomIl2cppApply.java").exists() {
        return Ok(bundled);
    }
    Err(FathomError::new(
        ErrorCode::ProviderUnavailable,
        "FathomIl2cppApply.java not found (set FATHOM_GHIDRA_SCRIPT_DIR)",
    ))
}

/// Parse script.json bytes into a validated, sanitized map.
pub fn parse_script_map(bytes: &[u8]) -> Result<ScriptMap, FathomError> {
    let document: Value = serde_json::from_slice(bytes).map_err(|e| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("script map is not valid JSON: {e}"),
        )
    })?;
    if !document.is_object() {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "script map is not the expected script.json document: top level is not an object",
        ));
    }
    let raw: RawMap = serde_json::from_value(document).map_err(|e| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("script map is not the expected script.json document: {e}"),
        )
    })?;
    let mut stats = MapStats {
        methods_total: raw.methods.len(),
        strings_total: raw.strings.len(),
        ..MapStats::default()
    };
    let mut seen: std::collections::BTreeSet<(u64, String)> = std::collections::BTreeSet::new();
    let mut methods: Vec<MethodEntry> = Vec::new();
    for entry in raw.methods.into_iter().take(MAP_METHODS_MAX) {
        if entry.address == 0 || entry.address >= 0x1_0000_0000 {
            stats.invalid_address += 1;
            continue;
        }
        let sanitized = sanitize_name(&entry.name);
        if sanitized != entry.name {
            stats.names_sanitized += 1;
        }
        if !seen.insert((entry.address, sanitized.clone())) {
            stats.duplicates_dropped += 1;
            continue;
        }
        methods.push(MethodEntry {
            name: sanitized,
            raw_name: entry.name,
            rva: entry.address,
            signature: entry
                .signature
                .map(|s| flatten(&s))
                .filter(|s| !s.is_empty()),
        });
    }
    methods.sort_by_key(|e| (e.rva, e.name.clone()));
    stats.methods_kept = methods.len();
    let mut strings: Vec<StringEntry> = Vec::new();
    for entry in raw.strings.into_iter().take(MAP_STRINGS_MAX) {
        if entry.address == 0 || entry.address >= 0x1_0000_0000 {
            stats.invalid_address += 1;
            continue;
        }
        if !is_printable_literal(&entry.value) {
            stats.strings_unprintable += 1;
            continue;
        }
        strings.push(StringEntry {
            rva: entry.address,
            value: entry.value,
        });
    }
    strings.sort_by_key(|e| e.rva);
    stats.strings_kept = strings.len();
    Ok(ScriptMap {
        methods,
        stats,
        strings,
    })
}

/// The validated project arguments shared by the three tools.
fn project_args(config: &Config, args: &Value) -> Result<(PathBuf, String, String), FathomError> {
    let project = paths::validate_target(config, Path::new(require_str(args, "project")?))?;
    let project_name = require_str(args, "project_name")?.to_string();
    let program = optional_str(args, "program")
        .unwrap_or(PROGRAM_DEFAULT)
        .to_string();
    Ok((project, project_name, program))
}

/// Turn a user query (IL2CPP name or `0x` RVA) into the spec the
/// GhidraScripts consume. With a map, a name resolves to its RVA
/// there first — map identity beats project symbol state.
fn query_spec(query: &str, map: Option<&ScriptMap>) -> String {
    if let Some(hex) = query
        .strip_prefix("0x")
        .or_else(|| query.strip_prefix("0X"))
    {
        return format!("rva:{}", hex.to_lowercase());
    }
    if let Some(map) = map
        && let Some(entry) = map.methods.iter().find(|e| e.raw_name == query)
    {
        return format!("rva:{:x}", entry.rva);
    }
    format!("name:{}", sanitize_name(query))
}

/// Flatten whitespace that would break the one-row-per-entry TSV.
fn flatten(text: &str) -> String {
    text.chars()
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Load the optional script map argument, if one was given,
/// together with the subject record for the map file.
fn optional_map(
    config: &Config,
    args: &Value,
) -> Result<(Option<ScriptMap>, Option<fathom_core::evidence::Subject>), FathomError> {
    match optional_str(args, "map") {
        Some(path) => {
            let validated = paths::validate_target(config, Path::new(path))?;
            let subject = subject_for_file(&validated)?;
            Ok((Some(load_map(&validated)?), Some(subject)))
        }
        None => Ok((None, None)),
    }
}

/// One headless GhidraScript invocation against a project.
struct ScriptRun<'a> {
    program: &'a str,
    project: &'a Path,
    project_name: &'a str,
    script: &'a str,
    script_args: &'a [String],
    timeout_secs: u64,
}

/// Run one IL2CPP GhidraScript against the project and parse its
/// result document. As with the export engine, the result file's
/// presence is the success signal — analyzeHeadless exits 0 even
/// when a script fails.
fn run_il2cpp_script(
    config: &Config,
    run_dir: &Path,
    job: &ScriptRun<'_>,
) -> Result<Value, FathomError> {
    let headless = engine::locate_headless(config).ok_or_else(|| {
        FathomError::new(
            ErrorCode::ProviderUnavailable,
            "Ghidra analyzeHeadless not found",
        )
        .with_remediation("Install Ghidra 12 or set ghidra_headless / FATHOM_GHIDRA_HEADLESS.")
    })?;
    let script_dir = locate_il2cpp_script_dir()?;
    let mut argv: Vec<String> = vec![
        job.project.display().to_string(),
        job.project_name.to_string(),
        "-process".to_string(),
        job.program.to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        script_dir.display().to_string(),
        "-postScript".to_string(),
        job.script.to_string(),
        run_dir.display().to_string(),
    ];
    argv.extend(job.script_args.iter().cloned());
    let outcome = run(&ProcessSpec {
        args: argv,
        cwd: Some(run_dir.to_path_buf()),
        env: Vec::new(),
        output_cap: OUTPUT_BYTES_MAX,
        program: headless.display().to_string(),
        timeout: std::time::Duration::from_secs(job.timeout_secs),
    })?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!(
                "Ghidra {} exceeded the {}s provider bound",
                job.script, job.timeout_secs
            ),
        )
        .with_remediation("Retry the call; completed project state from earlier runs is kept."));
    }
    let produced = run_dir.join("result.json");
    if !produced.exists() {
        let stdout_text = String::from_utf8_lossy(&outcome.stdout);
        let excerpt: String = stdout_text
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "Ghidra {} produced no result (exit {:?}); output tail: {excerpt}",
                job.script, outcome.exit_code
            ),
        ));
    }
    let bytes = fs::read(&produced).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read {} result: {e}", job.script),
        )
    })?;
    if bytes.len() > OUTPUT_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "Ghidra result exceeds the output bound",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!(
                "{} result is not the expected JSON document: {e}",
                job.script
            ),
        )
    })
}

/// Sanitize one IL2CPP name for Ghidra's symbol rules: keep
/// alphanumerics and the structural characters IL2CPP names use
/// (`_ . $ ` < > { } [ ] ( ) + - # ~`); everything else (spaces,
/// slashes, quotes) becomes `_`. Deterministic, so a query name
/// sanitizes to the same symbol the apply run wrote.
pub fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '.'
                        | '$'
                        | '`'
                        | '<'
                        | '>'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '('
                        | ')'
                        | '+'
                        | '-'
                        | '#'
                        | '~'
                )
            {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Write the methods TSV the apply script consumes.
fn write_methods_tsv(path: &Path, map: &ScriptMap) -> Result<(), FathomError> {
    let mut text = String::new();
    for entry in &map.methods {
        text.push_str(&format!(
            "{:x}\t{}\t{}\n",
            entry.rva,
            entry.name,
            entry.signature.as_deref().unwrap_or("")
        ));
    }
    fs::write(path, text).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot write methods TSV: {e}"),
        )
    })
}

/// Write the strings TSV the apply script consumes.
fn write_strings_tsv(path: &Path, map: &ScriptMap) -> Result<(), FathomError> {
    let mut text = String::new();
    for entry in &map.strings {
        text.push_str(&format!("{:x}\t{}\n", entry.rva, flatten(&entry.value)));
    }
    fs::write(path, text).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot write strings TSV: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MAP: &[u8] = br#"{
        "ScriptMethod": [
            {"Address": 3913472, "Name": "la$$Load",
             "Signature": "void la__Load (la_o* __this, const MethodInfo* method);"},
            {"Address": 31404224, "Name": "UnityEngine.UI.Image$$set_sprite",
             "Signature": "void UnityEngine_UI_Image__set_sprite ();"},
            {"Address": 31404224, "Name": "UnityEngine.UI.Image$$set_sprite",
             "Signature": "void UnityEngine_UI_Image__set_sprite ();"}
        ],
        "ScriptString": [
            {"Address": 41637328, "Value": "Play"},
            {"Address": 41637332, "Value": "bad\u0001blob"}
        ]
    }"#;

    #[test]
    fn adversarial_control_character_string_is_dropped() {
        let map = parse_script_map(SAMPLE_MAP).unwrap();
        assert_eq!(map.stats.strings_total, 2);
        assert_eq!(map.stats.strings_unprintable, 1);
        assert_eq!(map.stats.strings_kept, 1);
    }

    #[test]
    fn adversarial_duplicate_method_is_dropped_and_counted() {
        let map = parse_script_map(SAMPLE_MAP).unwrap();
        assert_eq!(map.stats.methods_total, 3);
        assert_eq!(map.stats.duplicates_dropped, 1);
        assert_eq!(map.stats.methods_kept, 2);
    }

    #[test]
    fn adversarial_malformed_map_is_a_typed_error() {
        let error = parse_script_map(b"{\"ScriptMethod\":").unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
        assert!(parse_script_map(b"[]").is_err());
    }

    #[test]
    fn adversarial_zero_and_huge_addresses_are_dropped() {
        let doc = br#"{"ScriptMethod": [
            {"Address": 0, "Name": "a$$b"},
            {"Address": 4294967296, "Name": "a$$c"},
            {"Address": 16, "Name": "a$$d"}
        ]}"#;
        let map = parse_script_map(doc).unwrap();
        assert_eq!(map.stats.invalid_address, 2);
        assert_eq!(map.stats.methods_kept, 1);
        assert_eq!(map.methods[0].name, "a$$d");
    }

    #[test]
    fn adversarial_classify_never_panics_on_odd_names() {
        assert_eq!(classify_caller("", &[]), "unknown");
        assert_eq!(classify_caller("$$", &[]), "unknown");
        assert_eq!(classify_caller("no-separator", &[]), "unknown");
    }

    #[test]
    fn validation_classify_engine_third_party_game_unknown() {
        assert_eq!(
            classify_caller("UnityEngine.UI.Image$$set_sprite", &[]),
            "engine"
        );
        assert_eq!(classify_caller("System.String$$Concat", &[]), "engine");
        assert_eq!(
            classify_caller("TMPro.TMP_Text$$set_text", &[]),
            "third-party"
        );
        assert_eq!(
            classify_caller(
                "CodeStage.AntiCheat.ObscuredTypes.ObscuredFloat$$op_Implicit",
                &[]
            ),
            "third-party"
        );
        assert_eq!(classify_caller("FBPP$$GetInt", &[]), "third-party");
        assert_eq!(classify_caller("la$$Load", &["la".to_string()]), "game");
        assert_eq!(
            classify_caller("<PrivateImplementationDetails>{X}$$M", &[]),
            "unknown"
        );
    }

    #[test]
    fn validation_parse_sample_map() {
        let map = parse_script_map(SAMPLE_MAP).unwrap();
        assert_eq!(map.methods.len(), 2);
        assert_eq!(map.methods[0].raw_name, "la$$Load");
        assert_eq!(map.methods[0].rva, 0x3bb700);
        assert!(map.methods[0].signature.is_some());
        assert_eq!(map.strings.len(), 1);
        assert_eq!(map.strings[0].value, "Play");
    }

    #[test]
    fn validation_query_spec_prefers_map_and_hex() {
        let map = parse_script_map(SAMPLE_MAP).unwrap();
        assert_eq!(query_spec("la$$Load", Some(&map)), "rva:3bb700");
        assert_eq!(query_spec("0x1DF6540", None), "rva:1df6540");
        assert_eq!(
            query_spec("UnityEngine.UI.Image$$set_sprite", None),
            "name:UnityEngine.UI.Image$$set_sprite"
        );
    }

    #[test]
    fn validation_sanitize_preserves_structure_flattens_tsv() {
        assert_eq!(
            sanitize_name("UnityEngine.UI.Image$$set_sprite"),
            "UnityEngine.UI.Image$$set_sprite"
        );
        assert_eq!(sanitize_name("a b/c\"d"), "a_b_c_d");
        assert_eq!(flatten("a\tb\nc"), "a b c");
    }
}
