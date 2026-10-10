//! Core tools registered by the composition root: discovery,
//! artifact comparison, and the evidence bundle pair (SPEC §4).

use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;

use rea_core::bundle;
use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use rea_core::paths;
use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, empty_schema, require_str, session_info};

/// Register the core tools.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "compare_artifacts",
            ToolClass::Read,
            "core",
            "Compare two artifacts: identity, sizes, and byte equality",
            json!({
                "type": "object",
                "properties": {
                    "a": {"type": "string"},
                    "b": {"type": "string"},
                },
                "required": ["a", "b"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(compare_artifacts),
    );
    registry.register(
        descriptor(
            "export_evidence_bundle",
            ToolClass::Read,
            "core",
            "Package evidence envelopes into a digest-sealed bundle",
            json!({
                "type": "object",
                "properties": {
                    "results": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["results"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(export_evidence_bundle),
    );
    registry.register(
        descriptor(
            "session_info",
            ToolClass::Read,
            "core",
            "Server identity, catalog digest, and tool availability",
            empty_schema(),
        ),
        Arc::new(|registry, config, _| Ok(session_info(config, registry))),
    );
    registry.register(
        descriptor(
            "verify_evidence_bundle",
            ToolClass::Read,
            "core",
            "Verify a bundle's digest and re-hash its subjects",
            json!({
                "type": "object",
                "properties": {
                    "bundle": {"type": "object"},
                },
                "required": ["bundle"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(verify_evidence_bundle),
    );
}

fn compare_artifacts(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let a_path = paths::validate_target(config, Path::new(require_str(args, "a")?))?;
    let b_path = paths::validate_target(config, Path::new(require_str(args, "b")?))?;
    let a = subject_for_file(&a_path)?;
    let b = subject_for_file(&b_path)?;
    let mut evidence = Evidence::new("compare_artifacts", "core");
    evidence.coverage.examined = 2;
    evidence.coverage.total = 2;
    evidence.coverage.exhaustive = true;
    evidence.add_finding(Finding::new(
        "comparison",
        Confidence::Observed,
        json!({
            "a": {"path": a.path, "sha256": a.sha256, "size_bytes": a.size_bytes},
            "b": {"path": b.path, "sha256": b.sha256, "size_bytes": b.size_bytes},
            "identical_bytes": a.sha256 == b.sha256,
            "size_delta_bytes": b.size_bytes as i64 - a.size_bytes as i64,
        }),
    ));
    Ok(evidence.to_value())
}

fn export_evidence_bundle(_: &Registry, _: &Config, args: &Value) -> Result<Value, ReaError> {
    let results = args
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ReaError::new(
                ErrorCode::InvalidRequest,
                "argument 'results' must be an array",
            )
        })?;
    bundle::build_bundle(results)
}

fn verify_evidence_bundle(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let bundle_value = args
        .get("bundle")
        .ok_or_else(|| ReaError::new(ErrorCode::InvalidRequest, "argument 'bundle' is required"))?;
    let evidence = bundle::verify_bundle(config, bundle_value)?;
    Ok(evidence.to_value())
}
