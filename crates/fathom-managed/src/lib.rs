//! Managed-code provider (SPEC §9.3): .NET metadata inventory
//! via the manual ECMA-335 reader in `metadata`. A PE without a
//! CLI header is reported as native — a finding, not an error.

#![forbid(unsafe_code)]

pub mod metadata;

use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;

use fathom_core::config::Config;
use fathom_core::error::FathomError;
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use fathom_core::paths;
use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, require_str, target_schema};

/// Register the managed provider's tool, implemented.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "inspect_managed_assembly",
            ToolClass::Read,
            "managed",
            ".NET metadata inventory: identity, types, methods, P/Invoke, signature digests",
            target_schema(),
        ),
        Arc::new(inspect_managed_assembly),
    );
}

fn inspect_managed_assembly(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        FathomError::new(
            fathom_core::error::ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    let mut evidence = Evidence::new("inspect_managed_assembly", "managed");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    let Some(inventory) = metadata::parse_pe(&bytes)? else {
        evidence.add_finding(Finding::new(
            "managed",
            Confidence::Observed,
            json!({"format": "PE", "managed": false}),
        ));
        evidence.add_unknown(
            "managed_metadata",
            "this PE has no CLI header; it is a native binary, not a .NET assembly",
        );
        return Ok(evidence.to_value());
    };
    evidence.add_finding(Finding::new(
        "assembly",
        Confidence::Observed,
        json!({
            "assembly": inventory.assembly,
            "assembly_refs": inventory.assembly_refs,
            "module": inventory.module_name,
            "runtime_version": inventory.runtime_version,
            "table_rows": inventory.table_rows,
            "type_refs": inventory.type_refs,
        }),
    ));
    evidence.add_finding(Finding::new(
        "types",
        Confidence::Observed,
        json!({
            "count": inventory.types.len(),
            "types": serde_json::to_value(&inventory.types).unwrap_or(Value::Null),
        }),
    ));
    evidence.add_finding(Finding::new(
        "methods",
        Confidence::Observed,
        json!({
            "count": inventory.methods.len(),
            "methods": serde_json::to_value(&inventory.methods).unwrap_or(Value::Null),
        }),
    ));
    if !inventory.pinvokes.is_empty() {
        evidence.add_finding(Finding::new(
            "pinvoke",
            Confidence::Observed,
            json!({
                "count": inventory.pinvokes.len(),
                "imports": serde_json::to_value(&inventory.pinvokes).unwrap_or(Value::Null),
            }),
        ));
    }
    evidence.add_unknown(
        "cil_bodies",
        "CIL method bodies are not decoded in this stage; method facts are metadata-level (name, RVA, signature digest)",
    );
    Ok(evidence.to_value())
}
