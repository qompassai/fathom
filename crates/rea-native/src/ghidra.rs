//! Ghidra-backed tool handlers (SPEC §9.1). Each handler
//! validates the target, runs (or reuses) the batch export, and
//! re-hashes the subject afterwards: an artifact that changed
//! under the engine aborts with `artifact_changed`.

use serde_json::{Value, json};
use std::path::Path;

use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::evidence::{Confidence, Evidence, Finding, Subject, subject_for_file};
use rea_core::paths;
use rea_core::registry::{Registry, require_str};

use crate::engine::{self, Export};

fn subject_and_export(
    config: &Config,
    args: &Value,
    mode: &str,
    target: Option<&str>,
) -> Result<(Subject, Export), ReaError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let export = engine::run_export(config, &path, &subject.sha256, mode, target)?;
    let after = subject_for_file(&path)?;
    if after.sha256 != subject.sha256 {
        return Err(ReaError::new(
            ErrorCode::ArtifactChanged,
            "the target changed while Ghidra analyzed it; results discarded",
        )
        .with_target(path.display().to_string()));
    }
    Ok((subject, export))
}

fn base(tool: &str, subject: Subject) -> Evidence {
    let mut evidence = Evidence::new(tool, "ghidra");
    evidence.subject = Some(subject);
    evidence
}

fn function_row(export: &Export) -> Vec<Value> {
    export
        .functions
        .iter()
        .map(|f| {
            json!({
                "address": f.address,
                "body_size": f.body_size,
                "calling_convention": f.calling_convention,
                "classification": f.classification,
                "name": f.name,
                "signature": f.signature,
            })
        })
        .collect()
}

pub fn analyze_function(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let name = require_str(args, "function")?;
    if name.trim().is_empty() {
        return Err(ReaError::new(
            ErrorCode::InvalidRequest,
            "argument 'function' must not be empty",
        ));
    }
    let (subject, export) = subject_and_export(config, args, "function", Some(name))?;
    let mut evidence = base("analyze_function", subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    if export.function_found != Some(true) {
        evidence.add_unknown(
            "function",
            format!("Ghidra found no function matching '{name}'"),
        );
        return Ok(evidence.to_value());
    }
    let function = export.function.as_ref().ok_or_else(|| {
        ReaError::new(
            ErrorCode::ExecutionFailure,
            "export marked found without a function row",
        )
    })?;
    evidence.add_finding(Finding::new(
        "function",
        Confidence::Observed,
        json!({
            "address": function.address,
            "body_size": function.body_size,
            "calling_convention": function.calling_convention,
            "classification": function.classification,
            "name": function.name,
            "signature": function.signature,
        }),
    ));
    let listing: Vec<Value> = export
        .listing
        .iter()
        .map(|row| json!({"address": row.address, "text": row.text}))
        .collect();
    let mut listing_finding = Finding::new(
        "listing",
        Confidence::Observed,
        json!({"instructions": listing}),
    );
    if export.listing_truncated {
        listing_finding =
            listing_finding.with_limitation("listing truncated at the instruction bound");
        evidence.coverage.exhaustive = false;
    }
    evidence.add_finding(listing_finding);
    evidence.add_finding(Finding::new(
        "call_graph",
        Confidence::Derived,
        json!({
            "callees": export.callees.clone().unwrap_or_default(),
            "callers": export.callers.clone().unwrap_or_default(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "references_to",
        Confidence::Observed,
        json!({
            "count": export.references_to.len(),
            "references": export.references_to.iter()
                .map(|r| json!({"from": r.from, "type": r.kind}))
                .collect::<Vec<_>>(),
        }),
    ));
    if let Some(decompile) = &export.decompile {
        let mut finding = Finding::new(
            "decompile",
            Confidence::Derived,
            json!({"bytes": decompile.bytes, "c": decompile.c}),
        );
        if decompile.truncated {
            finding = finding.with_limitation("decompiled C truncated at the byte bound");
        }
        evidence.add_finding(finding);
    } else {
        evidence.add_unknown(
            "decompile",
            "the decompiler produced no C for this function",
        );
    }
    Ok(evidence.to_value())
}

pub fn binary_overview(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("binary_overview", subject);
    let program = &export.program;
    evidence.add_finding(Finding::new(
        "program",
        Confidence::Observed,
        json!({
            "address_size": program.address_size,
            "compiler_spec": program.compiler_spec,
            "executable_format": program.executable_format,
            "image_base": program.image_base,
            "language_id": program.language_id,
            "name": program.name,
        }),
    ));
    evidence.add_finding(Finding::new(
        "memory_blocks",
        Confidence::Observed,
        json!({
            "blocks": export.memory_blocks.iter().map(|b| json!({
                "end": b.end, "execute": b.execute, "initialized": b.initialized,
                "name": b.name, "read": b.read, "size": b.size,
                "start": b.start, "write": b.write,
            })).collect::<Vec<_>>(),
        }),
    ));
    let truncated =
        export.functions_truncated || export.strings_truncated || export.symbols_truncated;
    evidence.add_finding(Finding::new(
        "inventory",
        Confidence::Observed,
        json!({
            "functions_returned": export.functions.len(),
            "functions_total": export.functions_total,
            "strings_returned": export.strings.len(),
            "strings_total": export.strings_total,
            "symbols_returned": export.symbols.len(),
            "symbols_total": export.symbols_total,
            "truncated": truncated,
        }),
    ));
    evidence.coverage.examined =
        (export.functions.len() + export.strings.len() + export.symbols.len()) as u64;
    evidence.coverage.total =
        (export.functions_total + export.strings_total + export.symbols_total) as u64;
    evidence.coverage.exhaustive = !truncated;
    Ok(evidence.to_value())
}

pub fn list_functions(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("list_functions", subject);
    let mut finding = Finding::new(
        "functions",
        Confidence::Observed,
        json!({
            "functions": function_row(&export),
            "returned": export.functions.len(),
            "total": export.functions_total,
        }),
    );
    if export.functions_truncated {
        finding = finding.with_limitation("function inventory truncated at the count bound");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = export.functions.len() as u64;
    evidence.coverage.total = export.functions_total as u64;
    evidence.coverage.exhaustive = !export.functions_truncated;
    Ok(evidence.to_value())
}

pub fn list_names(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("list_names", subject);
    let mut finding = Finding::new(
        "symbols",
        Confidence::Observed,
        json!({
            "returned": export.symbols.len(),
            "symbols": export.symbols.iter().map(|s| json!({
                "address": s.address, "name": s.name,
                "source": s.source, "type": s.kind,
            })).collect::<Vec<_>>(),
            "total": export.symbols_total,
        }),
    );
    if export.symbols_truncated {
        finding = finding.with_limitation("symbol inventory truncated at the count bound");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = export.symbols.len() as u64;
    evidence.coverage.total = export.symbols_total as u64;
    evidence.coverage.exhaustive = !export.symbols_truncated;
    Ok(evidence.to_value())
}

pub fn list_strings(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("list_strings", subject);
    let mut finding = Finding::new(
        "strings",
        Confidence::Observed,
        json!({
            "returned": export.strings.len(),
            "strings": export.strings.iter().map(|s| json!({
                "address": s.address, "value": s.value,
            })).collect::<Vec<_>>(),
            "total": export.strings_total,
        }),
    );
    if export.strings_truncated {
        finding = finding.with_limitation("string inventory truncated at the count bound");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = export.strings.len() as u64;
    evidence.coverage.total = export.strings_total as u64;
    evidence.coverage.exhaustive = !export.strings_truncated;
    Ok(evidence.to_value())
}

pub fn search_inventory(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let query_raw = require_str(args, "query")?;
    let query = query_raw.trim().to_lowercase();
    if query.is_empty() {
        return Err(ReaError::new(
            ErrorCode::InvalidRequest,
            "argument 'query' must not be empty",
        ));
    }
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("search_inventory", subject);
    let function_matches: Vec<Value> = export
        .functions
        .iter()
        .filter(|f| {
            f.name.to_lowercase().contains(&query) || f.signature.to_lowercase().contains(&query)
        })
        .map(|f| json!({"address": f.address, "name": f.name, "signature": f.signature}))
        .collect();
    let string_matches: Vec<Value> = export
        .strings
        .iter()
        .filter(|s| s.value.to_lowercase().contains(&query))
        .map(|s| json!({"address": s.address, "value": s.value}))
        .collect();
    let symbol_matches: Vec<Value> = export
        .symbols
        .iter()
        .filter(|s| s.name.to_lowercase().contains(&query))
        .map(|s| json!({"address": s.address, "name": s.name, "type": s.kind}))
        .collect();
    let truncated =
        export.functions_truncated || export.strings_truncated || export.symbols_truncated;
    let mut finding = Finding::new(
        "matches",
        Confidence::Observed,
        json!({
            "function_matches": function_matches,
            "query": query_raw,
            "string_matches": string_matches,
            "symbol_matches": symbol_matches,
        }),
    );
    if truncated {
        finding = finding.with_limitation("search covered only the retained (truncated) inventory");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined =
        (export.functions.len() + export.strings.len() + export.symbols.len()) as u64;
    evidence.coverage.total =
        (export.functions_total + export.strings_total + export.symbols_total) as u64;
    evidence.coverage.exhaustive = !truncated;
    Ok(evidence.to_value())
}
