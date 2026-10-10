//! The Ghidra engine seam: locate `analyzeHeadless`, run the
//! batch export (SPEC §9.1), and parse its one JSON document.
//!
//! Projects are cached per subject SHA-256 under the state dir:
//! the first call imports and analyzes; later calls re-open the
//! project read-only-ish with `-noanalysis` and run only the
//! export script. The export file's presence is the success
//! signal — analyzeHeadless exits 0 even when a script fails.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::sha256_hex;
use fathom_core::limits::{GHIDRA_TIMEOUT_SECS, OUTPUT_BYTES_MAX};
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run};

/// Locate Ghidra's `analyzeHeadless`: explicit config first,
/// then `FATHOM_GHIDRA_HEADLESS`, then `$PATH`, then the Arch
/// package location. Returns the first candidate that exists.
pub fn locate_headless(config: &Config) -> Option<PathBuf> {
    if let Some(path) = &config.ghidra_headless {
        if path.exists() {
            return Some(path.clone());
        }
    }
    if let Ok(path) = std::env::var("FATHOM_GHIDRA_HEADLESS") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in ["ghidra-analyzeHeadless", "analyzeHeadless"] {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }
    let packaged = PathBuf::from("/opt/ghidra/support/analyzeHeadless");
    if packaged.exists() {
        return Some(packaged);
    }
    None
}

/// Directory holding `FathomExportAnalysis.java`: the
/// `FATHOM_GHIDRA_SCRIPT_DIR` override, else the crate's bundled
/// `ghidra/` directory (in-repo and dev builds).
fn locate_script_dir() -> Result<PathBuf, FathomError> {
    if let Ok(dir) = std::env::var("FATHOM_GHIDRA_SCRIPT_DIR") {
        let candidate = PathBuf::from(dir);
        if candidate.join("FathomExportAnalysis.java").exists() {
            return Ok(candidate);
        }
    }
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ghidra");
    if bundled.join("FathomExportAnalysis.java").exists() {
        return Ok(bundled);
    }
    Err(FathomError::new(
        ErrorCode::ProviderUnavailable,
        "FathomExportAnalysis.java not found (set FATHOM_GHIDRA_SCRIPT_DIR)",
    ))
}

/// Run (or reuse) the export for one subject and mode.
pub fn run_export(
    config: &Config,
    subject: &Path,
    subject_sha256: &str,
    mode: &str,
    target: Option<&str>,
) -> Result<Export, FathomError> {
    let cache_dir = paths::state_subdir(config, "ghidra")?
        .join(&subject_sha256[..subject_sha256.len().min(32)]);
    fs::create_dir_all(&cache_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create Ghidra cache dir: {e}"),
        )
    })?;
    let mode_key = match target {
        Some(name) => format!("{mode}-{}", &sha256_hex(name.as_bytes())[..12]),
        None => mode.to_string(),
    };
    let export_file = cache_dir.join(format!("export-{mode_key}.json"));
    if export_file.exists() {
        return read_export(&export_file);
    }
    let headless = locate_headless(config).ok_or_else(|| {
        FathomError::new(
            ErrorCode::ProviderUnavailable,
            "Ghidra analyzeHeadless not found",
        )
        .with_remediation("Install Ghidra 12 or set ghidra_headless / FATHOM_GHIDRA_HEADLESS.")
    })?;
    let script_dir = locate_script_dir()?;
    let export_dir = cache_dir.join(format!("out-{mode_key}"));
    fs::create_dir_all(&export_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create export dir: {e}"),
        )
    })?;
    let project_dir = cache_dir.join("project");
    // analyzeHeadless creates the project inside the location but
    // refuses a location directory that does not exist yet.
    fs::create_dir_all(&project_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create project dir: {e}"),
        )
    })?;
    let program_name = subject
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "program".to_string());
    let mut args: Vec<String> = vec![project_dir.display().to_string(), "fathom".to_string()];
    if project_dir.join("fathom.gpr").exists() {
        args.push("-process".to_string());
        args.push(program_name);
        args.push("-noanalysis".to_string());
    } else {
        args.push("-import".to_string());
        args.push(subject.display().to_string());
    }
    args.push("-scriptPath".to_string());
    args.push(script_dir.display().to_string());
    args.push("-postScript".to_string());
    args.push("FathomExportAnalysis.java".to_string());
    args.push(export_dir.display().to_string());
    args.push(mode.to_string());
    if let Some(name) = target {
        args.push(name.to_string());
    }
    let outcome = run(&ProcessSpec {
        args,
        cwd: Some(cache_dir.clone()),
        env: Vec::new(),
        output_cap: OUTPUT_BYTES_MAX,
        program: headless.display().to_string(),
        timeout: std::time::Duration::from_secs(GHIDRA_TIMEOUT_SECS),
    })?;
    let produced = export_dir.join("export.json");
    if !produced.exists() {
        let stdout_text = String::from_utf8_lossy(&outcome.stdout);
        let stderr_text = String::from_utf8_lossy(&outcome.stderr);
        let excerpt: String = stdout_text
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        let excerpt = if excerpt.is_empty() {
            stderr_text
                .lines()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ")
        } else {
            excerpt
        };
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "Ghidra run produced no export (exit {:?}); stderr tail: {excerpt}",
                outcome.exit_code
            ),
        ));
    }
    let bytes = fs::read(&produced).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read export: {e}"),
        )
    })?;
    if bytes.len() > OUTPUT_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "Ghidra export exceeds the output bound",
        ));
    }
    fs::write(&export_file, &bytes).ok();
    parse_export(&bytes)
}

fn read_export(path: &Path) -> Result<Export, FathomError> {
    let bytes = fs::read(path).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read cached export: {e}"),
        )
    })?;
    parse_export(&bytes)
}

fn parse_export(bytes: &[u8]) -> Result<Export, FathomError> {
    serde_json::from_slice(bytes).map_err(|e| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("Ghidra export is not the expected JSON document: {e}"),
        )
    })
}

/// The export document (SPEC §9.1). Optional fields are mode- and
/// truncation-dependent; serde defaults keep parsing total.
#[derive(Debug, Deserialize)]
pub struct Export {
    #[serde(default)]
    pub callees: Option<Vec<String>>,
    #[serde(default)]
    pub callers: Option<Vec<String>>,
    #[serde(default)]
    pub decompile: Option<Decompile>,
    #[serde(default)]
    pub function: Option<FunctionInfo>,
    #[serde(default)]
    pub function_found: Option<bool>,
    #[serde(default)]
    pub function_target: Option<String>,
    #[serde(default)]
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub functions_total: usize,
    #[serde(default)]
    pub functions_truncated: bool,
    #[serde(default)]
    pub listing: Vec<ListingRow>,
    #[serde(default)]
    pub listing_truncated: bool,
    #[serde(default)]
    pub memory_blocks: Vec<MemoryBlock>,
    pub program: ProgramInfo,
    #[serde(default)]
    pub references_to: Vec<RefInfo>,
    #[serde(default)]
    pub strings: Vec<StringInfo>,
    #[serde(default)]
    pub strings_total: usize,
    #[serde(default)]
    pub strings_truncated: bool,
    #[serde(default)]
    pub symbols: Vec<SymbolInfo>,
    #[serde(default)]
    pub symbols_total: usize,
    #[serde(default)]
    pub symbols_truncated: bool,
}

#[derive(Debug, Deserialize)]
pub struct Decompile {
    pub bytes: usize,
    pub c: String,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
pub struct FunctionInfo {
    pub address: String,
    pub body_size: u64,
    pub calling_convention: String,
    pub classification: String,
    pub name: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct ListingRow {
    pub address: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct MemoryBlock {
    pub end: String,
    pub execute: bool,
    pub initialized: bool,
    pub name: String,
    pub read: bool,
    pub size: u64,
    pub start: String,
    pub write: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProgramInfo {
    pub address_size: String,
    pub compiler_spec: String,
    pub executable_format: String,
    pub image_base: String,
    pub language_id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RefInfo {
    pub from: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct StringInfo {
    pub address: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct SymbolInfo {
    pub address: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{
        "program": {"name": "true", "language_id": "x86:LE:64:default",
            "compiler_spec": "gcc", "address_size": "64",
            "image_base": "000000", "executable_format": "ELF"},
        "memory_blocks": [{"name": ".text", "start": "1000", "end": "1fff",
            "size": 4096, "read": true, "write": false, "execute": true,
            "initialized": true}],
        "functions": [{"address": "1010", "name": "main",
            "signature": "undefined main()", "body_size": 42,
            "classification": "defined", "calling_convention": "__fastcall"}],
        "functions_total": 1, "functions_truncated": false,
        "strings": [{"address": "2000", "value": "hello"}],
        "strings_total": 1, "strings_truncated": false,
        "symbols": [{"address": "1010", "name": "main", "type": "Function",
            "source": "DEFAULT"}],
        "symbols_total": 1, "symbols_truncated": false
    }"#;

    #[test]
    fn adversarial_malformed_export_rejected() {
        assert!(parse_export(b"{\"program\":").is_err());
        assert!(parse_export(b"[]").is_err());
    }

    #[test]
    fn validation_overview_export_parses() {
        let export = parse_export(SAMPLE).unwrap();
        assert_eq!(export.program.name, "true");
        assert_eq!(export.functions.len(), 1);
        assert_eq!(export.functions[0].classification, "defined");
        assert_eq!(export.symbols[0].kind, "Function");
        assert_eq!(export.memory_blocks[0].size, 4096);
    }
}
