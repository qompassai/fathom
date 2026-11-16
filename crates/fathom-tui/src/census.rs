//! The Census stage's instrument: fathom's own game-tree
//! census, called in-process.
//!
//! `fathom_native::game::census_game_tree` is the same
//! function the MCP tool `census_game_tree` serves. It runs
//! behind fathom-core's confinement: the target must sit under
//! an operator-declared target root, so the engine declares
//! exactly the chosen directory — nothing wider.

use crate::error::WorkflowError;
use fathom_core::config::Config;
use fathom_core::registry::Registry;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

/// The census facts the rest of the pipeline consumes, pulled
/// out of fathom's evidence envelope. Everything here was
/// observed by the census; nothing is inferred.
#[derive(Clone, Debug, Default)]
pub struct CensusSummary {
    /// Asset classes as (class, file count, bytes), sorted by
    /// class name (the census emits them sorted).
    pub asset_classes: Vec<(String, u64, u64)>,
    /// Total bytes across all censused files.
    pub bytes_total: u64,
    /// Container files found (archives, bundles, images…).
    pub containers: u64,
    /// The fingerprinted engine name, or "unknown".
    pub engine: String,
    /// The engine variant, or "unknown".
    pub engine_variant: String,
    /// Total files censused.
    pub files_total: u64,
    /// Frameworks detected from file names.
    pub frameworks: Vec<String>,
    /// The target directory's own name.
    pub root_name: String,
    /// (aspect, reason) pairs the census could not resolve —
    /// carried into the spec draft verbatim.
    pub unknowns: Vec<(String, String)>,
}

/// The TOML shape used to build the run's fathom `Config`.
/// Only the two fields the census needs are set; the rest take
/// fathom's fail-closed defaults.
#[derive(Serialize)]
struct CensusConfigToml {
    /// Where census proof exports are retained (in the run dir).
    state_dir: String,
    /// The single declared root: the chosen target itself.
    target_roots: Vec<String>,
}

/// Run the census over `target`, retaining proof exports under
/// `state_dir`. Returns the evidence envelope verbatim (for
/// `census.json`) and the extracted summary.
///
/// # Errors
/// `WorkflowError::Fathom` when fathom refuses the target
/// (outside the declared root, unreadable) or the census
/// itself fails; `WorkflowError::ConfigInvalid` when the
/// target cannot be canonicalized.
pub fn run_census(
    target: &Path,
    state_dir: &Path,
) -> Result<(Value, CensusSummary), WorkflowError> {
    let canonical = target.canonicalize().map_err(|error| {
        WorkflowError::ConfigInvalid(format!(
            "target {} cannot be resolved: {error}",
            target.display()
        ))
    })?;
    let toml_text = toml::to_string(&CensusConfigToml {
        state_dir: state_dir.display().to_string(),
        target_roots: vec![canonical.display().to_string()],
    })
    .map_err(|error| WorkflowError::Internal(format!("config serialization failed: {error}")))?;
    let config = Config::from_toml_str(&toml_text)?;
    let registry = Registry::new();
    let args = serde_json::json!({ "target": canonical.display().to_string() });
    let evidence = fathom_native::game::census_game_tree(&registry, &config, &args)?;
    let summary = extract_summary(&evidence);
    Ok((evidence, summary))
}

/// Pull the summary out of the evidence envelope: the
/// `game_census` finding's facts are the census manifest.
/// Extraction is defensive — a missing field degrades to a
/// zero/empty fact plus nothing invented; the verbatim
/// envelope is preserved in `census.json` regardless.
pub fn extract_summary(evidence: &Value) -> CensusSummary {
    let mut summary = CensusSummary::default();
    let findings = evidence.get("findings").and_then(Value::as_array);
    let Some(findings) = findings else {
        return summary;
    };
    for finding in findings {
        let kind = finding.get("kind").and_then(Value::as_str).unwrap_or("");
        let facts = finding.get("facts").cloned().unwrap_or(Value::Null);
        match kind {
            "game" => {
                summary.containers = facts.get("containers").and_then(Value::as_u64).unwrap_or(0);
                summary.engine = string_field(&facts, "engine");
                summary.engine_variant = string_field(&facts, "variant");
                summary.files_total = facts.get("files").and_then(Value::as_u64).unwrap_or(0);
                summary.root_name = string_field(&facts, "root");
            }
            "game_census" => {
                summary.bytes_total = facts
                    .get("files")
                    .and_then(|files| files.get("bytes"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if summary.files_total == 0 {
                    summary.files_total = facts
                        .get("files")
                        .and_then(|files| files.get("total"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                }
                summary.asset_classes = extract_asset_classes(&facts);
                summary.frameworks = extract_frameworks(&facts);
                if summary.containers == 0 {
                    summary.containers = facts
                        .get("containers")
                        .and_then(Value::as_array)
                        .map(|rows| rows.len() as u64)
                        .unwrap_or(0);
                }
            }
            _ => {}
        }
    }
    if let Some(unknowns) = evidence.get("unknowns").and_then(Value::as_array) {
        for unknown in unknowns {
            let aspect = string_field(unknown, "aspect");
            let reason = string_field(unknown, "reason");
            if !aspect.is_empty() {
                summary.unknowns.push((aspect, reason));
            }
        }
    }
    summary
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn extract_asset_classes(manifest: &Value) -> Vec<(String, u64, u64)> {
    let mut rows = Vec::new();
    if let Some(classes) = manifest.get("asset_classes").and_then(Value::as_array) {
        for class in classes {
            rows.push((
                string_field(class, "class"),
                class.get("count").and_then(Value::as_u64).unwrap_or(0),
                class.get("bytes").and_then(Value::as_u64).unwrap_or(0),
            ));
        }
    }
    rows
}

fn extract_frameworks(manifest: &Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(frameworks) = manifest.get("frameworks").and_then(Value::as_array) {
        for framework in frameworks {
            if let Some(name) = framework.as_str() {
                names.push(name.to_string());
            } else {
                let name = string_field(framework, "name");
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_tree(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fathom-tui-census-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("data")).expect("fixture dirs");
        std::fs::write(root.join("game.exe"), b"MZ fake executable bytes").expect("exe");
        std::fs::write(root.join("data").join("script.rpy"), b"label start:\n").expect("rpy");
        std::fs::write(root.join("data").join("notes.txt"), b"hello\n").expect("txt");
        root
    }

    #[test]
    fn census_over_a_fixture_tree_reports_real_counts() {
        let root = fixture_tree("counts");
        let state = root.join("state");
        let (evidence, summary) = run_census(&root, &state).expect("census must succeed");
        assert_eq!(summary.files_total, 3, "evidence: {evidence}");
        assert!(summary.bytes_total > 0);
        assert!(!summary.asset_classes.is_empty());
        assert_eq!(
            summary.root_name,
            root.file_name().unwrap().to_string_lossy()
        );
        // The envelope is fathom's evidence record, not a bare manifest.
        assert!(evidence.get("findings").is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn census_rejects_a_missing_target() {
        let missing = PathBuf::from("/nonexistent-fathom-census-target-xyz");
        let result = run_census(&missing, Path::new("/tmp"));
        assert!(result.is_err());
    }

    #[test]
    fn extract_summary_survives_an_empty_envelope() {
        let summary = extract_summary(&Value::Null);
        assert_eq!(summary.files_total, 0);
        assert!(summary.asset_classes.is_empty());
        assert!(summary.unknowns.is_empty());
    }

    #[test]
    fn extract_summary_reads_a_synthetic_envelope() {
        let evidence = serde_json::json!({
            "findings": [
                {"kind": "game", "confidence": "observed",
                 "facts": {"containers": 2, "engine": "renpy", "files": 9,
                           "root": "demo", "variant": "unknown"}},
                {"kind": "game_census", "confidence": "observed",
                 "facts": {"files": {"total": 9, "bytes": 1234},
                           "asset_classes": [{"class": "script", "count": 4, "bytes": 40}],
                           "containers": [{}, {}],
                           "frameworks": ["renpy"]}}
            ],
            "unknowns": [{"aspect": "engine", "reason": "no rule matched"}]
        });
        let summary = extract_summary(&evidence);
        assert_eq!(summary.files_total, 9);
        assert_eq!(summary.bytes_total, 1234);
        assert_eq!(summary.engine, "renpy");
        assert_eq!(summary.containers, 2);
        assert_eq!(summary.asset_classes, vec![("script".to_string(), 4, 40)]);
        assert_eq!(summary.frameworks, vec!["renpy".to_string()]);
        assert_eq!(summary.unknowns.len(), 1);
    }
}
