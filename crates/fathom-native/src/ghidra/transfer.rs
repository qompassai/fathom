//! Cross-binary documentation transfer (SPEC §9.1, Ghidra G3):
//! function-hash matching and documentation propagation.
//!
//! Hash discipline: a function's hash is the SHA-256 over its
//! concatenated instruction bytes in address order, computed by
//! the export script (`transfer` mode). The hash is independent
//! of the function's name, its address, and the binary's image
//! base, so the same code in a documented binary and in a
//! stripped one hashes identically.
//!
//! Matching discipline: functions pair ONLY on a hash held by
//! exactly one source function and exactly one target function.
//! A hash shared by several functions on either side (identical
//! stubs are common) is an ambiguity, reported by name and never
//! guessed at; a hash present on one side only is unmatched and
//! reported. Nothing is ever matched by name or by address.
//!
//! The documentation set carried per matched pair: the source
//! function's name (when user-defined or imported, never a
//! default `FUN_` name), its prototype (when user-defined), its
//! plate and repeatable comments, its body comments and
//! bookmarks (re-based by entry-relative offset), and its tags.
//! The set is applied to the target through the G2 transactional
//! mutation path as ONE batch: Execute-class, `decide()`
//! default-deny, commit-or-discard with hash proof, and a
//! read-back verification of every transferred field afterwards.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Finding, subject_for_file};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::engine;
use crate::ghidra::base;
use crate::ghidra::mutate::{self, Op};
use crate::sections::{TransferFunction, VarName};

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message)
}

/// One side of a transfer: a validated target path plus the
/// functions of its `transfer` export.
struct Side {
    functions: Vec<TransferFunction>,
    path: std::path::PathBuf,
    sha256: String,
}

fn load_side(config: &Config, args: &Value, field: &str) -> Result<Side, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, field)?))?;
    let subject = subject_for_file(&path)?;
    let export = engine::run_export(config, &path, &subject.sha256, "transfer", None)?;
    let after = subject_for_file(&path)?;
    if after.sha256 != subject.sha256 {
        return Err(FathomError::new(
            ErrorCode::ArtifactChanged,
            "a transfer subject changed while Ghidra analyzed it; results discarded",
        )
        .with_target(path.display().to_string()));
    }
    let facts = export.transfer.ok_or_else(|| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            "the transfer export carried no transfer section",
        )
    })?;
    if facts.functions.is_partial() {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            "the transfer export truncated its function inventory; \
             refusing to match on a partial inventory",
        ));
    }
    Ok(Side {
        functions: facts.functions.rows,
        path,
        sha256: subject.sha256,
    })
}

/// Functions that can take part in matching at all: defined
/// functions with a real instruction hash. External and thunk
/// functions have no body of their own to document across.
fn eligible(function: &TransferFunction) -> bool {
    function.classification == "defined" && !function.hash.is_empty()
}

/// Whether a function's documentation set is worth carrying:
/// a human (or an import) named or annotated it in some way.
fn documented(function: &TransferFunction) -> bool {
    transferable_name(function).is_some()
        || function.signature_source == "USER_DEFINED"
        || !function.plate_comment.is_empty()
        || !function.repeatable_comment.is_empty()
        || !function.comments.rows.is_empty()
        || !function.bookmarks.rows.is_empty()
        || !function.tags.is_empty()
}

/// The name a transfer may carry: user-defined or imported
/// names only — a default `FUN_` name documents nothing.
fn transferable_name(function: &TransferFunction) -> Option<&str> {
    match function.name_source.as_str() {
        "USER_DEFINED" | "IMPORTED" => Some(function.name.as_str()),
        _ => None,
    }
}

/// The match plan between a source and a target inventory.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    /// Hash-ambiguous functions, by hash: source and target
    /// names sharing one hash. Reported, never transferred.
    pub ambiguous: Vec<(String, Vec<String>, Vec<String>)>,
    /// Unique pairs: (source index, target index).
    pub matched: Vec<(usize, usize)>,
    /// Source functions with no counterpart (names).
    pub unmatched_source: Vec<String>,
    /// Target functions with no counterpart (names).
    pub unmatched_target: Vec<String>,
}

/// Pair source and target functions by hash under the matching
/// discipline in the module docs. Pure: no engine, no filesystem.
pub(crate) fn plan_transfer(source: &[TransferFunction], target: &[TransferFunction]) -> Plan {
    let mut plan = Plan::default();
    let mut by_hash: BTreeMap<&str, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
    for (index, function) in source.iter().enumerate() {
        if eligible(function) {
            by_hash
                .entry(function.hash.as_str())
                .or_default()
                .0
                .push(index);
        } else if function.classification == "defined" {
            plan.unmatched_source.push(function.name.clone());
        }
    }
    for (index, function) in target.iter().enumerate() {
        if eligible(function) {
            by_hash
                .entry(function.hash.as_str())
                .or_default()
                .1
                .push(index);
        } else if function.classification == "defined" {
            plan.unmatched_target.push(function.name.clone());
        }
    }
    for (hash, (sources, targets)) in by_hash {
        match (sources.len(), targets.len()) {
            (1, 1) => plan.matched.push((sources[0], targets[0])),
            (0, _) => {
                for index in targets {
                    plan.unmatched_target.push(target[index].name.clone());
                }
            }
            (_, 0) => {
                for index in sources {
                    plan.unmatched_source.push(source[index].name.clone());
                }
            }
            _ => plan.ambiguous.push((
                hash.to_string(),
                sources
                    .iter()
                    .map(|index| source[*index].name.clone())
                    .collect(),
                targets
                    .iter()
                    .map(|index| target[*index].name.clone())
                    .collect(),
            )),
        }
    }
    plan.matched
        .sort_by_key(|(source_index, _)| source[*source_index].address.clone());
    plan.unmatched_source.sort();
    plan.unmatched_target.sort();
    plan
}

/// The prototype string for the mutation path: the source
/// signature with any calling-convention token removed — the
/// script's prototype parser takes `return name(params)`, and
/// Ghidra renders signatures as `return __stdcall name(params)`.
/// The applied result renders the convention again, so read-back
/// comparison against the source signature stays exact.
fn normalize_prototype(signature: &str) -> String {
    const CONVENTIONS: [&str; 6] = [
        "__cdecl",
        "__fastcall",
        "__pascal",
        "__stdcall",
        "__thiscall",
        "__vectorcall",
    ];
    let Some(open) = signature.find('(') else {
        return signature.to_string();
    };
    let head = signature[..open]
        .split_whitespace()
        .filter(|token| !CONVENTIONS.contains(token))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{head}{}", &signature[open..])
}

/// Signature equality up to calling-convention rendering: an
/// imported signature may carry `__stdcall` where the same
/// prototype applied in another program renders without it.
fn signatures_equal(a: &str, b: &str) -> bool {
    normalize_prototype(a) == normalize_prototype(b)
}

/// An address inside a target function: entry plus offset,
/// rendered in the hex form the mutation script parses.
fn offset_address(entry: &str, offset: u64) -> Result<String, FathomError> {
    let base = u64::from_str_radix(entry, 16)
        .map_err(|_| invalid(format!("function entry '{entry}' is not a hex address")))?;
    Ok(format!("{:x}", base.saturating_add(offset)))
}

/// The op batch carrying one source function's documentation
/// set onto its matched target function. Pure translation;
/// every op rides the G2 postcondition discipline.
pub(crate) fn build_pair_ops(
    source: &TransferFunction,
    target: &TransferFunction,
) -> Result<Vec<Op>, FathomError> {
    let mut ops = Vec::new();
    let entry = target.address.clone();
    if source.plate_comment_truncated
        || source.repeatable_comment_truncated
        || source
            .comments
            .rows
            .iter()
            .any(|comment| comment.text_truncated)
    {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "source function {} has a comment past the export bound; \
                 refusing to transfer a truncated documentation set",
                source.name
            ),
        ));
    }
    if let Some(name) = transferable_name(source)
        && name != target.name
    {
        ops.push(Op::new(
            "rename_function",
            vec![entry.clone(), name.to_string()],
        ));
    }
    if source.signature_source == "USER_DEFINED"
        && !signatures_equal(&source.signature, &target.signature)
    {
        ops.push(Op::new(
            "set_function_prototype",
            vec![entry.clone(), normalize_prototype(&source.signature)],
        ));
    }
    if !source.plate_comment.is_empty() && source.plate_comment != target.plate_comment {
        ops.push(Op::new(
            "set_comment",
            vec![
                entry.clone(),
                "plate".to_string(),
                source.plate_comment.clone(),
            ],
        ));
    }
    if !source.repeatable_comment.is_empty()
        && source.repeatable_comment != target.repeatable_comment
    {
        ops.push(Op::new(
            "set_comment",
            vec![
                entry.clone(),
                "repeatable".to_string(),
                source.repeatable_comment.clone(),
            ],
        ));
    }
    for comment in &source.comments.rows {
        let already = target.comments.rows.iter().any(|held| {
            held.offset == comment.offset && held.kind == comment.kind && held.text == comment.text
        });
        if !already {
            ops.push(Op::new(
                "set_comment",
                vec![
                    offset_address(&entry, comment.offset)?,
                    comment.kind.clone(),
                    comment.text.clone(),
                ],
            ));
        }
    }
    for bookmark in &source.bookmarks.rows {
        let already = target.bookmarks.rows.iter().any(|held| {
            held.offset == bookmark.offset
                && held.kind == bookmark.kind
                && held.category == bookmark.category
                && held.comment == bookmark.comment
        });
        if !already {
            ops.push(Op::new(
                "set_bookmark",
                vec![
                    offset_address(&entry, bookmark.offset)?,
                    bookmark.kind.clone(),
                    bookmark.category.clone(),
                    bookmark.comment.clone(),
                ],
            ));
        }
    }
    for tag in &source.tags {
        if !target.tags.contains(tag) {
            ops.push(Op::new(
                "add_function_tag",
                vec![entry.clone(), tag.clone()],
            ));
        }
    }
    Ok(ops)
}

/// Whether a target function now carries a source function's
/// full transferred documentation set (read-back verification).
fn carries(source: &TransferFunction, target: &TransferFunction) -> bool {
    if let Some(name) = transferable_name(source)
        && target.name != name
    {
        return false;
    }
    if source.signature_source == "USER_DEFINED"
        && !signatures_equal(&target.signature, &source.signature)
    {
        return false;
    }
    if !source.plate_comment.is_empty() && target.plate_comment != source.plate_comment {
        return false;
    }
    if !source.repeatable_comment.is_empty()
        && target.repeatable_comment != source.repeatable_comment
    {
        return false;
    }
    for comment in &source.comments.rows {
        let held = target.comments.rows.iter().any(|row| {
            row.offset == comment.offset && row.kind == comment.kind && row.text == comment.text
        });
        if !held {
            return false;
        }
    }
    for bookmark in &source.bookmarks.rows {
        let held = target.bookmarks.rows.iter().any(|row| {
            row.offset == bookmark.offset
                && row.kind == bookmark.kind
                && row.category == bookmark.category
                && row.comment == bookmark.comment
        });
        if !held {
            return false;
        }
    }
    source.tags.iter().all(|tag| target.tags.contains(tag))
}

/// Measured completeness of one inventory (the G3 completeness
/// finding): defined functions, documented ones, and the ratio.
fn completeness(functions: &[TransferFunction]) -> Value {
    let defined: Vec<&TransferFunction> = functions
        .iter()
        .filter(|function| function.classification == "defined")
        .collect();
    let documented_count = defined
        .iter()
        .filter(|function| documented(function))
        .count();
    let percent = if defined.is_empty() {
        100.0
    } else {
        (documented_count as f64) * 100.0 / (defined.len() as f64)
    };
    json!({
        "defined_functions": defined.len(),
        "documented_functions": documented_count,
        "percent_documented": (percent * 10.0).round() / 10.0,
    })
}

fn function_json(function: &TransferFunction) -> Value {
    json!({
        "address": function.address,
        "body_size": function.body_size,
        "classification": function.classification,
        "hash": function.hash,
        "name": function.name,
        "signature": function.signature,
    })
}

fn doc_json(function: &TransferFunction) -> Value {
    let vars = |rows: &Vec<VarName>| -> Vec<Value> {
        rows.iter()
            .map(|var| json!({"name": var.name, "type": var.kind}))
            .collect()
    };
    json!({
        "bookmarks": function.bookmarks.rows.iter().map(|bookmark| json!({
            "category": bookmark.category,
            "comment": bookmark.comment,
            "offset": bookmark.offset,
            "type": bookmark.kind,
        })).collect::<Vec<_>>(),
        "comments": function.comments.rows.iter().map(|comment| json!({
            "offset": comment.offset,
            "text": comment.text,
            "type": comment.kind,
        })).collect::<Vec<_>>(),
        "documented": documented(function),
        "locals": vars(&function.locals.rows),
        "name": function.name,
        "name_source": function.name_source,
        "parameters": vars(&function.parameters.rows),
        "plate_comment": function.plate_comment,
        "repeatable_comment": function.repeatable_comment,
        "return_type": function.return_type,
        "signature": function.signature,
        "signature_source": function.signature_source,
        "tags": function.tags,
    })
}

fn find_function<'a>(
    functions: &'a [TransferFunction],
    query: &str,
) -> Result<&'a TransferFunction, FathomError> {
    let by_address = functions
        .iter()
        .find(|function| function.address.eq_ignore_ascii_case(query));
    let by_name: Vec<&TransferFunction> = functions
        .iter()
        .filter(|function| function.name == query)
        .collect();
    match (by_address, by_name.len()) {
        (Some(function), _) => Ok(function),
        (None, 1) => Ok(by_name[0]),
        (None, 0) => Err(invalid(format!("no function named or addressed '{query}'"))),
        (None, _) => Err(invalid(format!(
            "function name '{query}' is ambiguous; use an address"
        ))),
    }
}

fn plan_json(plan: &Plan, source: &[TransferFunction], target: &[TransferFunction]) -> Value {
    json!({
        "ambiguous": plan.ambiguous.iter().map(|(hash, sources, targets)| json!({
            "hash": hash, "source_functions": sources, "target_functions": targets,
        })).collect::<Vec<_>>(),
        "matched": plan.matched.iter().map(|(s, t)| json!({
            "hash": source[*s].hash,
            "source": function_json(&source[*s]),
            "target": function_json(&target[*t]),
        })).collect::<Vec<_>>(),
        "matched_count": plan.matched.len(),
        "unmatched_source": plan.unmatched_source,
        "unmatched_target": plan.unmatched_target,
    })
}

// ---- Read tools -------------------------------------------------

pub fn get_function_hash(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let side = load_side(config, args, "target")?;
    let function = find_function(&side.functions, require_str(args, "function")?)?;
    let mut evidence = base("get_function_hash", subject_for_file(&side.path)?);
    evidence.add_finding(Finding::new(
        "function_hash",
        Confidence::Observed,
        json!({
            "algorithm": "sha256 over concatenated instruction bytes in address order",
            "function": function_json(function),
        }),
    ));
    Ok(evidence.to_value())
}

pub fn get_bulk_function_hashes(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let side = load_side(config, args, "target")?;
    let mut evidence = base("get_bulk_function_hashes", subject_for_file(&side.path)?);
    evidence.add_finding(Finding::new(
        "function_hashes",
        Confidence::Observed,
        json!({
            "algorithm": "sha256 over concatenated instruction bytes in address order",
            "functions": side.functions.iter().map(function_json).collect::<Vec<_>>(),
        }),
    ));
    Ok(evidence.to_value())
}

pub fn get_function_documentation(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let side = load_side(config, args, "target")?;
    let function = find_function(&side.functions, require_str(args, "function")?)?;
    let mut evidence = base("get_function_documentation", subject_for_file(&side.path)?);
    evidence.add_finding(Finding::new(
        "function_documentation",
        Confidence::Observed,
        json!({"documentation": doc_json(function), "function": function_json(function)}),
    ));
    Ok(evidence.to_value())
}

pub fn get_function_signature(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let side = load_side(config, args, "target")?;
    let function = find_function(&side.functions, require_str(args, "function")?)?;
    let mut evidence = base("get_function_signature", subject_for_file(&side.path)?);
    evidence.add_finding(Finding::new(
        "function_signature",
        Confidence::Observed,
        json!({
            "function": function.name,
            "parameters": function.parameters.rows.iter().map(|var| {
                json!({"name": var.name, "type": var.kind})
            }).collect::<Vec<_>>(),
            "return_type": function.return_type,
            "signature": function.signature,
            "signature_source": function.signature_source,
        }),
    ));
    Ok(evidence.to_value())
}

pub fn compare_programs_documentation(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let source = load_side(config, args, "source")?;
    let target = load_side(config, args, "target")?;
    let plan = plan_transfer(&source.functions, &target.functions);
    let mut evidence = base(
        "compare_programs_documentation",
        subject_for_file(&target.path)?,
    );
    evidence.add_finding(Finding::new(
        "comparison",
        Confidence::Observed,
        json!({
            "identical_subjects": source.sha256 == target.sha256,
            "plan": plan_json(&plan, &source.functions, &target.functions),
            "source_completeness": completeness(&source.functions),
            "target_completeness": completeness(&target.functions),
        }),
    ));
    Ok(evidence.to_value())
}

pub fn diff_functions(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let source = load_side(config, args, "source")?;
    let target = load_side(config, args, "target")?;
    let source_function = find_function(&source.functions, require_str(args, "source_function")?)?;
    let target_function = find_function(&target.functions, require_str(args, "target_function")?)?;
    let mut differences = Vec::new();
    if source_function.hash != target_function.hash {
        differences.push("hash");
    }
    if source_function.name != target_function.name {
        differences.push("name");
    }
    if !signatures_equal(&source_function.signature, &target_function.signature) {
        differences.push("signature");
    }
    if source_function.plate_comment != target_function.plate_comment {
        differences.push("plate_comment");
    }
    if source_function.comments.rows.len() != target_function.comments.rows.len() {
        differences.push("comments");
    }
    if source_function.bookmarks.rows.len() != target_function.bookmarks.rows.len() {
        differences.push("bookmarks");
    }
    if source_function.tags != target_function.tags {
        differences.push("tags");
    }
    let mut evidence = base("diff_functions", subject_for_file(&target.path)?);
    evidence.add_finding(Finding::new(
        "diff",
        Confidence::Observed,
        json!({
            "differences": differences,
            "hash_equal": source_function.hash == target_function.hash,
            "source": function_json(source_function),
            "target": function_json(target_function),
        }),
    ));
    Ok(evidence.to_value())
}

pub fn find_similar_functions(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let source = load_side(config, args, "source")?;
    let target = load_side(config, args, "target")?;
    let function = find_function(&source.functions, require_str(args, "function")?)?;
    if function.hash.is_empty() {
        return Err(invalid(
            "the named function has no instruction hash (external or thunk); \
             it cannot be matched across binaries",
        ));
    }
    let matches: Vec<&TransferFunction> = target
        .functions
        .iter()
        .filter(|candidate| candidate.hash == function.hash)
        .collect();
    let mut evidence = base("find_similar_functions", subject_for_file(&target.path)?);
    evidence.add_finding(Finding::new(
        "similar",
        Confidence::Observed,
        json!({
            "ambiguous": matches.len() > 1,
            "hash": function.hash,
            "matches": matches.iter().map(|m| function_json(m)).collect::<Vec<_>>(),
            "source_function": function_json(function),
        }),
    ));
    Ok(evidence.to_value())
}

// ---- Execute tools ----------------------------------------------

/// Shared transfer engine for the two Execute entry points:
/// apply the op batches for `pairs` to the target in ONE G2
/// transaction, then verify every transferred set by read-back.
fn run_transfer(
    tool: &str,
    config: &Config,
    source: &Side,
    target: &Side,
    pairs: &[(usize, usize)],
    plan: &Plan,
) -> Result<Value, FathomError> {
    let mut ops: Vec<Op> = Vec::new();
    let mut carrying: Vec<(usize, usize)> = Vec::new();
    for (source_index, target_index) in pairs {
        let pair_ops = build_pair_ops(
            &source.functions[*source_index],
            &target.functions[*target_index],
        )?;
        if pair_ops.is_empty() {
            carrying.push((*source_index, *target_index));
        } else {
            ops.extend(pair_ops);
            carrying.push((*source_index, *target_index));
        }
    }
    if ops.len() > mutate::OPS_PER_BATCH_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "the transfer expands to {} ops, past the {}-op batch bound; \
                 transfer in smaller selections",
                ops.len(),
                mutate::OPS_PER_BATCH_MAX
            ),
        ));
    }
    let mut evidence = base(tool, subject_for_file(&target.path)?);
    if ops.is_empty() {
        evidence.add_finding(Finding::new(
            "transfer",
            Confidence::Observed,
            json!({
                "applied": 0,
                "noop": true,
                "plan": plan_json(plan, &source.functions, &target.functions),
                "transaction": "none — every matched target already carries the source documentation",
                "verified_pairs": carrying.len(),
            }),
        ));
        return Ok(evidence.to_value());
    }
    let outcome = mutate::run_mutation(config, &target.path, &target.sha256, &ops)?;
    // Read-back: a fresh transfer export of the mutated target
    // must carry every transferred documentation set.
    let after = load_side(
        config,
        &json!({"target": target.path.display().to_string()}),
        "target",
    )?;
    let mut verified = 0usize;
    for (source_index, target_index) in &carrying {
        let source_function = &source.functions[*source_index];
        let target_address = &target.functions[*target_index].address;
        let held = after
            .functions
            .iter()
            .find(|function| &function.address == target_address)
            .ok_or_else(|| {
                FathomError::new(
                    ErrorCode::ArtifactIntegrityMismatch,
                    "a transferred function vanished from the target read-back",
                )
            })?;
        if !carries(source_function, held) {
            return Err(FathomError::new(
                ErrorCode::ArtifactIntegrityMismatch,
                format!(
                    "read-back verification failed: target function at {target_address} \
                     does not carry the documentation of source {}",
                    source_function.name
                ),
            ));
        }
        verified += 1;
    }
    evidence.add_finding(Finding::new(
        "transfer",
        Confidence::Observed,
        json!({
            "applied": outcome.applied,
            "noop": false,
            "plan": plan_json(plan, &source.functions, &target.functions),
            "project_hash_after": outcome.project_hash_after,
            "project_hash_before": outcome.project_hash_before,
            "transaction": "committed",
            "verified_pairs": verified,
        }),
    ));
    Ok(evidence.to_value())
}

pub fn apply_function_documentation(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let source = load_side(config, args, "source")?;
    let target = load_side(config, args, "target")?;
    if source.sha256 == target.sha256 {
        let mut evidence = base(
            "apply_function_documentation",
            subject_for_file(&target.path)?,
        );
        evidence.add_finding(Finding::new(
            "transfer",
            Confidence::Observed,
            json!({"applied": 0, "noop": true, "reason": "source and target are the same subject"}),
        ));
        return Ok(evidence.to_value());
    }
    let source_function = find_function(&source.functions, require_str(args, "function")?)?;
    if source_function.hash.is_empty() {
        return Err(invalid(
            "the source function has no instruction hash; it cannot be matched",
        ));
    }
    let target_function = if let Some(query) = args.get("target_function").and_then(Value::as_str) {
        find_function(&target.functions, query)?
    } else {
        let matches: Vec<&TransferFunction> = target
            .functions
            .iter()
            .filter(|candidate| candidate.hash == source_function.hash)
            .collect();
        match matches.len() {
            1 => matches[0],
            0 => {
                return Err(invalid(format!(
                    "no target function shares the source function's hash ({})",
                    source_function.hash
                )));
            }
            _ => {
                return Err(FathomError::new(
                    ErrorCode::RevisionConflict,
                    format!(
                        "hash-collision: {} target functions share this hash; \
                         name the target function explicitly instead of guessing",
                        matches.len()
                    ),
                ));
            }
        }
    };
    if target_function.hash != source_function.hash {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!(
                "function hash mismatch: source {} hashes {} but target {} hashes {}; \
                 documentation is never transferred across different code",
                source_function.name,
                source_function.hash,
                target_function.name,
                target_function.hash
            ),
        ));
    }
    let source_index = source
        .functions
        .iter()
        .position(|function| std::ptr::eq(function, source_function))
        .unwrap_or(0);
    let target_index = target
        .functions
        .iter()
        .position(|function| std::ptr::eq(function, target_function))
        .unwrap_or(0);
    let plan = Plan {
        matched: vec![(source_index, target_index)],
        ..Plan::default()
    };
    run_transfer(
        "apply_function_documentation",
        config,
        &source,
        &target,
        &[(source_index, target_index)],
        &plan,
    )
}

pub fn merge_program_documentation(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let source = load_side(config, args, "source")?;
    let target = load_side(config, args, "target")?;
    let plan = plan_transfer(&source.functions, &target.functions);
    if source.sha256 == target.sha256 {
        let mut evidence = base(
            "merge_program_documentation",
            subject_for_file(&target.path)?,
        );
        evidence.add_finding(Finding::new(
            "transfer",
            Confidence::Observed,
            json!({
                "applied": 0,
                "noop": true,
                "plan": plan_json(&plan, &source.functions, &target.functions),
                "reason": "source and target are the same subject",
            }),
        ));
        return Ok(evidence.to_value());
    }
    run_transfer(
        "merge_program_documentation",
        config,
        &source,
        &target,
        &plan.matched.clone(),
        &plan,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sections::{Bounded, TransferBookmark, TransferComment};
    use fathom_core::policy::ToolClass;
    use fathom_core::registry::Registry as CoreRegistry;

    fn bounded<T>(rows: Vec<T>) -> Bounded<T> {
        let total = rows.len() as u64;
        Bounded {
            rows,
            total,
            truncated: false,
        }
    }

    fn function(name: &str, hash: &str) -> TransferFunction {
        TransferFunction {
            address: "1000".to_string(),
            body_size: 16,
            bookmarks: bounded(vec![]),
            classification: "defined".to_string(),
            comments: bounded(vec![]),
            hash: hash.to_string(),
            locals: bounded(vec![]),
            name: name.to_string(),
            name_source: "DEFAULT".to_string(),
            parameters: bounded(vec![]),
            plate_comment: String::new(),
            plate_comment_truncated: false,
            repeatable_comment: String::new(),
            repeatable_comment_truncated: false,
            return_type: "int".to_string(),
            signature: format!("int {name}()"),
            signature_source: "DEFAULT".to_string(),
            tags: vec![],
        }
    }

    fn documented_function(name: &str, hash: &str) -> TransferFunction {
        let mut function = function(name, hash);
        function.name_source = "USER_DEFINED".to_string();
        function.plate_comment = "does the thing".to_string();
        function.comments = bounded(vec![TransferComment {
            offset: 4,
            text: "loop head".to_string(),
            text_truncated: false,
            kind: "eol".to_string(),
        }]);
        function.bookmarks = bounded(vec![TransferBookmark {
            category: "todo".to_string(),
            comment: "check bounds".to_string(),
            offset: 0,
            kind: "Note".to_string(),
        }]);
        function.tags = vec!["reviewed".to_string()];
        function
    }

    #[test]
    fn validation_plan_matches_unique_hashes() {
        let source = vec![documented_function("alpha", "aa"), function("beta", "bb")];
        let mut target_alpha = function("FUN_1000", "aa");
        target_alpha.address = "2000".to_string();
        let target = vec![target_alpha, function("gamma", "cc")];
        let plan = plan_transfer(&source, &target);
        assert_eq!(plan.matched.len(), 1);
        assert_eq!(plan.unmatched_source, vec!["beta".to_string()]);
        assert_eq!(plan.unmatched_target, vec!["gamma".to_string()]);
        assert!(plan.ambiguous.is_empty());
    }

    #[test]
    fn validation_pair_ops_carry_the_full_doc_set() {
        let source = documented_function("alpha", "aa");
        let mut target = function("FUN_2000", "aa");
        target.address = "2000".to_string();
        let ops = build_pair_ops(&source, &target).unwrap();
        let names: Vec<&str> = ops.iter().map(|op| op.name).collect();
        assert_eq!(
            names,
            vec![
                "rename_function",
                "set_comment",
                "set_comment",
                "set_bookmark",
                "add_function_tag"
            ]
        );
        // The body comment lands at target entry + offset.
        assert_eq!(ops[2].fields[0], "2004");
        let after = documented_function("alpha", "aa");
        assert!(carries(&source, &after));
    }

    #[test]
    fn validation_identical_doc_set_builds_no_ops() {
        let source = documented_function("alpha", "aa");
        let target = documented_function("alpha", "aa");
        assert!(build_pair_ops(&source, &target).unwrap().is_empty());
    }

    #[test]
    fn validation_prototype_normalization_strips_convention() {
        assert_eq!(
            normalize_prototype("int __stdcall compute_loop_v2(int count)"),
            "int compute_loop_v2(int count)"
        );
        assert_eq!(normalize_prototype("void greet(void)"), "void greet(void)");
    }

    #[test]
    fn adversarial_duplicate_hash_is_ambiguous_never_matched() {
        // Hash-collision bait: two identical stubs on each side.
        let source = vec![function("stub_a", "dd"), function("stub_b", "dd")];
        let target = vec![function("FUN_1", "dd"), function("FUN_2", "dd")];
        let plan = plan_transfer(&source, &target);
        assert!(plan.matched.is_empty());
        assert_eq!(plan.ambiguous.len(), 1);
        assert_eq!(plan.ambiguous[0].1.len(), 2);
        assert_eq!(plan.ambiguous[0].2.len(), 2);
    }

    #[test]
    fn adversarial_one_sided_duplicate_is_also_ambiguous() {
        let source = vec![documented_function("real", "ee")];
        let target = vec![function("FUN_1", "ee"), function("FUN_2", "ee")];
        let plan = plan_transfer(&source, &target);
        assert!(plan.matched.is_empty());
        assert_eq!(plan.ambiguous.len(), 1);
    }

    #[test]
    fn adversarial_truncated_source_comment_is_refused() {
        let mut source = documented_function("alpha", "aa");
        source.comments.rows[0].text_truncated = true;
        let target = function("FUN_2000", "aa");
        let err = build_pair_ops(&source, &target).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
    }

    #[test]
    fn adversarial_default_name_is_never_transferred() {
        let mut source = function("FUN_1000", "aa");
        source.plate_comment = "noted".to_string();
        let target = function("FUN_2000", "aa");
        let ops = build_pair_ops(&source, &target).unwrap();
        assert!(ops.iter().all(|op| op.name != "rename_function"));
    }

    #[test]
    fn adversarial_transfer_tools_are_execute_class_and_default_deny() {
        let mut registry = CoreRegistry::new();
        crate::register(&mut registry);
        let config = Config::from_file_form(fathom_core::config::ConfigFile::default()).unwrap();
        for name in [
            "apply_function_documentation",
            "merge_program_documentation",
        ] {
            let descriptor = registry
                .descriptors()
                .into_iter()
                .find(|d| d.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert_eq!(descriptor.tool_class, ToolClass::Execute, "{name}");
            let err = registry
                .call(
                    &config,
                    name,
                    &json!({"source": "/nonexistent", "target": "/nonexistent"}),
                )
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::AccessDenied, "{name}");
        }
        for name in [
            "compare_programs_documentation",
            "diff_functions",
            "find_similar_functions",
            "get_bulk_function_hashes",
            "get_function_documentation",
            "get_function_hash",
            "get_function_signature",
        ] {
            let descriptor = registry
                .descriptors()
                .into_iter()
                .find(|d| d.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert_eq!(descriptor.tool_class, ToolClass::Read, "{name}");
        }
    }
}
