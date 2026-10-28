//! Core tools registered by the composition root: discovery,
//! artifact comparison, the evidence bundle pair, and the
//! reconstruction-proof ledger (SPEC §4, §4.1).

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use fathom_core::bundle;
use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Completeness, Confidence, Evidence, Finding, sha256_hex, subject_for_file,
};
use fathom_core::limits::{
    PROOF_BYTES_MAX, PROOF_CLAIMS_MAX, PROOF_EVIDENCE_PER_CLAIM_MAX, PROOF_PER_SUBJECT_MAX,
    PROOF_STATEMENT_BYTES_MAX,
};
use fathom_core::paths;
use fathom_core::policy::ToolClass;
use fathom_core::proof::{self, ClaimClass, Resolution};
use fathom_core::registry::{
    Registry, descriptor, empty_schema, optional_str, require_str, session_info,
};

/// Register the core tools.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "build_reconstruction_obligation_ledger",
            ToolClass::Read,
            "core",
            "Bind caller-authored reconstruction claims to the subject's retained \
             export: server-computed record digests, subject/export/producer \
             bindings, stored as a verifiable proof",
            json!({
                "type": "object",
                "properties": {
                    "claims": {"type": "array", "items": {"type": "object"},
                        "description": "Claims to bind: {claim_id, class, statement, evidence: [{inventory, key}]}; record digests are computed by the server, never supplied"},
                    "detail": {"type": "string", "enum": ["complete", "summary"],
                        "description": "Summary is the default; complete adds the stored proof body"},
                    "export_mode": {"type": "string", "enum": ["video-ingest"],
                        "description": "Bind the subject's retained video ingest document (YouTube-RE lane) instead of a Ghidra export; 'function' does not apply"},
                    "function": {"type": "string",
                        "description": "Bind the per-function dossier export for this function instead of the overview export"},
                    "target": {"type": "string", "description": "Path under a configured target root"},
                },
                "required": ["claims", "target"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(build_reconstruction_obligation_ledger),
    );
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
            "delete_reconstruction_proof",
            ToolClass::Execute,
            "core",
            "Delete one stored reconstruction proof for a subject (operator verb)",
            json!({
                "type": "object",
                "properties": {
                    "proof_id": {"type": "string"},
                    "target": {"type": "string", "description": "Path under a configured target root"},
                },
                "required": ["proof_id", "target"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(delete_reconstruction_proof),
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
    registry.register(
        descriptor(
            "verify_reconstruction_proof",
            ToolClass::Read,
            "core",
            "Re-check a stored or inline reconstruction proof against the subject \
             and the retained export: per-claim outcomes and an aggregate \
             verdict, computed fresh on every call",
            json!({
                "type": "object",
                "properties": {
                    "claim_ids": {"type": "array", "items": {"type": "string"},
                        "description": "Verify only these claims of the proof"},
                    "detail": {"type": "string", "enum": ["complete", "summary"],
                        "description": "Summary is the default; complete adds the proof body"},
                    "proof": {"type": "object",
                        "description": "An inline proof object (supply this or proof_id)"},
                    "proof_id": {"type": "string",
                        "description": "A stored proof's id (supply this or proof)"},
                    "target": {"type": "string", "description": "Path under a configured target root"},
                },
                "required": ["target"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(verify_reconstruction_proof),
    );
}

fn compare_artifacts(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
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

fn export_evidence_bundle(_: &Registry, _: &Config, args: &Value) -> Result<Value, FathomError> {
    let results = args
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'results' must be an array",
            )
        })?;
    bundle::build_bundle(results)
}

fn verify_evidence_bundle(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let bundle_value = args.get("bundle").ok_or_else(|| {
        FathomError::new(ErrorCode::InvalidRequest, "argument 'bundle' is required")
    })?;
    let evidence = bundle::verify_bundle(config, bundle_value)?;
    Ok(evidence.to_value())
}

/// How much of a ledger result one call projects (SPEC §4.1.8,
/// on S1's terms): the summary is the default; `complete` adds
/// the stored proof body. Any other value is a typed refusal.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Detail {
    Complete,
    Summary,
}

fn parse_detail(args: &Value) -> Result<Detail, FathomError> {
    match args.get("detail") {
        None => Ok(Detail::Summary),
        Some(Value::String(value)) if value == "summary" => Ok(Detail::Summary),
        Some(Value::String(value)) if value == "complete" => Ok(Detail::Complete),
        Some(_) => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'detail' must be \"summary\" or \"complete\"",
        )),
    }
}

/// One claim as the build tool accepts it: the caller's
/// statement and `(inventory, key)` locators. Confidence is
/// assigned from the class table and record digests are
/// computed by the server — a caller asserting either is
/// refused (SPEC §4.1.4, §4.1.8).
struct ClaimRequest {
    claim_id: String,
    class: ClaimClass,
    confidence: Confidence,
    refs: Vec<(String, String)>,
    statement: Value,
}

fn claim_refusal(request_id: &str, reason: String) -> FathomError {
    FathomError::new(
        ErrorCode::InvalidRequest,
        format!("claim '{request_id}' refused: {reason}"),
    )
}

/// Parse and shape-check the build tool's `claims` argument.
/// Runs before any target or store access, so a malformed
/// request is refused before any work (S1's convention).
fn parse_claim_requests(args: &Value) -> Result<Vec<ClaimRequest>, FathomError> {
    let raw_claims = args
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'claims' must be an array of claim objects",
            )
        })?;
    if raw_claims.is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "a ledger needs at least one claim",
        ));
    }
    if raw_claims.len() > PROOF_CLAIMS_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("claims exceed PROOF_CLAIMS_MAX ({PROOF_CLAIMS_MAX})"),
        ));
    }
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut requests = Vec::with_capacity(raw_claims.len());
    for raw in raw_claims {
        requests.push(parse_claim_request(raw, &mut seen)?);
    }
    Ok(requests)
}

fn parse_claim_request(
    raw: &Value,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<ClaimRequest, FathomError> {
    let object = raw.as_object().ok_or_else(|| {
        FathomError::new(ErrorCode::InvalidRequest, "each claim must be an object")
    })?;
    let claim_id = object
        .get("claim_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "each claim needs a non-empty claim_id",
            )
        })?
        .to_string();
    if !seen.insert(claim_id.clone()) {
        return Err(claim_refusal(&claim_id, "duplicate claim_id".to_string()));
    }
    let class_raw = object
        .get("class")
        .and_then(Value::as_str)
        .ok_or_else(|| claim_refusal(&claim_id, "no class".to_string()))?;
    let class = ClaimClass::parse(class_raw)
        .ok_or_else(|| claim_refusal(&claim_id, format!("unknown class '{class_raw}'")))?;
    let statement = object
        .get("statement")
        .cloned()
        .ok_or_else(|| claim_refusal(&claim_id, "no statement".to_string()))?;
    if !statement.is_object() {
        return Err(claim_refusal(
            &claim_id,
            "statement must be an object of facts, not prose".to_string(),
        ));
    }
    if proof::canonical_json(&statement).len() > PROOF_STATEMENT_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "claim '{claim_id}' statement exceeds PROOF_STATEMENT_BYTES_MAX ({PROOF_STATEMENT_BYTES_MAX})"
            ),
        ));
    }
    let raw_refs = object
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| claim_refusal(&claim_id, "evidence must be an array".to_string()))?;
    if raw_refs.is_empty() {
        return Err(claim_refusal(
            &claim_id,
            "cites no evidence; a claim with no locator can never bind".to_string(),
        ));
    }
    if raw_refs.len() > PROOF_EVIDENCE_PER_CLAIM_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "claim '{claim_id}' cites more than PROOF_EVIDENCE_PER_CLAIM_MAX ({PROOF_EVIDENCE_PER_CLAIM_MAX}) references"
            ),
        ));
    }
    let mut refs: Vec<(String, String)> = Vec::with_capacity(raw_refs.len());
    for raw_ref in raw_refs {
        let ref_object = raw_ref.as_object().ok_or_else(|| {
            claim_refusal(
                &claim_id,
                "each evidence reference must be an {inventory, key} object".to_string(),
            )
        })?;
        if ref_object.get("record_digest").is_some() {
            return Err(claim_refusal(
                &claim_id,
                "supplies a record_digest; digests are computed by the server, never the caller"
                    .to_string(),
            ));
        }
        let inventory = ref_object
            .get("inventory")
            .and_then(Value::as_str)
            .ok_or_else(|| claim_refusal(&claim_id, "a reference has no inventory".to_string()))?;
        let key = ref_object
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| claim_refusal(&claim_id, "a reference has no key".to_string()))?;
        refs.push((inventory.to_string(), key.to_string()));
    }
    let inventories: Vec<&str> = refs
        .iter()
        .map(|(inventory, _)| inventory.as_str())
        .collect();
    let confidence = class.confidence(&inventories);
    if let Some(asserted) = object.get("confidence").and_then(Value::as_str)
        && asserted != proof::confidence_str(confidence)
    {
        return Err(claim_refusal(
            &claim_id,
            format!(
                "asserts confidence '{asserted}'; class {} carries '{}', set by the class table",
                class.as_str(),
                proof::confidence_str(confidence)
            ),
        ));
    }
    Ok(ClaimRequest {
        claim_id,
        class,
        confidence,
        refs,
        statement,
    })
}

fn build_reconstruction_obligation_ledger(
    registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let detail = parse_detail(args)?;
    let requests = parse_claim_requests(args)?;
    let function = optional_str(args, "function");
    if function == Some("") {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'function' must not be empty",
        ));
    }
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    // The video lane (YouTube-RE §6.3) binds claims against
    // the retained ingest document instead of a Ghidra
    // export: same ledger, same proof shape, mode
    // `video-ingest`. Any other export_mode value is refused;
    // the Ghidra modes are selected by 'function' as before.
    let video_mode = match optional_str(args, "export_mode") {
        None => false,
        Some("video-ingest") => true,
        Some(other) => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("unknown export_mode '{other}'; the only named mode is 'video-ingest'"),
            ));
        }
    };
    if video_mode && function.is_some() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'function' does not apply to export_mode 'video-ingest'",
        ));
    }
    let (mode, mode_key) = if video_mode {
        ("video-ingest", "video-ingest".to_string())
    } else {
        match function {
            Some(name) => (
                "function",
                format!("function-{}", &sha256_hex(name.as_bytes())[..12]),
            ),
            None => ("overview", "overview".to_string()),
        }
    };
    let document: Value = if video_mode {
        // No provider runs here: the ingest document is
        // already retained evidence, produced by
        // ingest_youtube_video.
        proof::find_video_ingest_document(config, &subject.sha256).ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "no retained video ingest document for this subject; \
                 run ingest_youtube_video on the source video first",
            )
        })?
    } else {
        // Build is the composition point (SPEC §4.1.8): the
        // one ledger tool that may run a provider, and only
        // when the retained store holds no export for this
        // subject/mode.
        let export_file = proof::retained_export_path(config, &subject.sha256, &mode_key);
        if !export_file.exists() {
            fathom_native::engine::run_export(config, &path, &subject.sha256, mode, function)?;
            let after = subject_for_file(&path)?;
            if after.sha256 != subject.sha256 {
                return Err(FathomError::new(
                    ErrorCode::ArtifactChanged,
                    "the target changed while Ghidra analyzed it; results discarded",
                )
                .with_target(path.display().to_string()));
            }
        }
        let export_bytes = std::fs::read(&export_file).map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot read retained export: {error}"),
            )
        })?;
        serde_json::from_slice(&export_bytes).map_err(|error| {
            FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                format!("retained export is not the expected JSON document: {error}"),
            )
        })?
    };
    let dossier = mode == "function";
    let mut bound_claims: Vec<Value> = Vec::with_capacity(requests.len());
    let mut claims_by_class: BTreeMap<&str, usize> = BTreeMap::new();
    for request in &requests {
        let mut evidence = Vec::with_capacity(request.refs.len());
        for (inventory, key) in &request.refs {
            // Build-time honesty (§4.1.8): a locator that does
            // not resolve now is refused, never stored as if
            // bound.
            let resolution = if video_mode {
                proof::resolve_record_for_mode(&document, "video-ingest", inventory, key)
            } else {
                proof::resolve_record(&document, dossier, inventory, key)
            };
            let record = match resolution {
                Resolution::Record(record) => record,
                Resolution::BeyondCeiling => {
                    return Err(claim_refusal(
                        &request.claim_id,
                        format!(
                            "{inventory}/{key} is beyond the retained ceiling of a truncated inventory"
                        ),
                    ));
                }
                Resolution::Absent => {
                    return Err(claim_refusal(
                        &request.claim_id,
                        format!("the retained export carries no record at {inventory}/{key}"),
                    ));
                }
                Resolution::NotApplicable => {
                    return Err(claim_refusal(
                        &request.claim_id,
                        format!("inventory '{inventory}' is not part of the {mode} export"),
                    ));
                }
            };
            evidence.push(json!({
                "inventory": inventory,
                "key": key,
                "record_digest": proof::value_digest(&record),
            }));
        }
        *claims_by_class.entry(request.class.as_str()).or_insert(0) += 1;
        bound_claims.push(json!({
            "claim_id": request.claim_id,
            "class": request.class.as_str(),
            "confidence": proof::confidence_str(request.confidence),
            "evidence": evidence,
            "statement": request.statement,
        }));
    }
    let export_digest = if video_mode {
        proof::video_ingest_digest(&document)
    } else {
        proof::value_digest(&document)
    };
    let mut proof_value = json!({
        "claims": bound_claims,
        "export": {"digest": export_digest, "mode": mode_key},
        "producer": proof::producer_identity(registry),
        "proof_version": proof::PROOF_VERSION,
        "subject": {
            "path": subject.path.clone(),
            "sha256": subject.sha256.clone(),
            "size_bytes": subject.size_bytes,
        },
    });
    let digest = proof::compute_proof_digest(&proof_value);
    let proof_id = digest[..32].to_string();
    proof_value["proof_digest"] = json!(digest);
    proof_value["proof_id"] = json!(proof_id.clone());
    let canonical = proof::canonical_json(&proof_value);
    if canonical.len() > PROOF_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("the bound proof exceeds PROOF_BYTES_MAX ({PROOF_BYTES_MAX})"),
        ));
    }
    let already_stored = proof::proof_path(config, &subject.sha256, &proof_id).exists();
    if !already_stored
        && proof::count_stored_proofs(config, &subject.sha256) >= PROOF_PER_SUBJECT_MAX
    {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "the subject already retains PROOF_PER_SUBJECT_MAX ({PROOF_PER_SUBJECT_MAX}) proofs; delete one before building another"
            ),
        ));
    }
    proof::store_proof(config, &subject.sha256, &proof_id, &canonical)?;
    let mut evidence = Evidence::new("build_reconstruction_obligation_ledger", "core");
    evidence.subject = Some(subject);
    evidence.coverage.examined = requests.len() as u64;
    evidence.coverage.total = requests.len() as u64;
    evidence.coverage.exhaustive = true;
    evidence.add_finding(Finding::new(
        "ledger",
        Confidence::Derived,
        json!({
            "claim_count": requests.len(),
            "claims_by_class": claims_by_class,
            "export_digest": export_digest,
            "export_mode": mode_key,
            "proof_digest": digest,
            "proof_id": proof_id,
        }),
    ));
    for request in &requests {
        evidence.add_finding(Finding::new(
            "claim_binding",
            Confidence::Observed,
            json!({
                "claim_id": request.claim_id,
                "class": request.class.as_str(),
                "confidence": proof::confidence_str(request.confidence),
                "evidence_count": request.refs.len(),
                "status": "bound",
            }),
        ));
    }
    if detail == Detail::Complete {
        evidence.add_finding(Finding::new("proof", Confidence::Observed, proof_value));
    }
    Ok(evidence.to_value())
}

fn verify_reconstruction_proof(
    registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let detail = parse_detail(args)?;
    let inline = args.get("proof");
    let proof_id_arg = optional_str(args, "proof_id");
    if inline.is_some() && proof_id_arg.is_some() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "supply either 'proof' or 'proof_id', not both",
        ));
    }
    if inline.is_none() && proof_id_arg.is_none() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "supply either 'proof' or 'proof_id'",
        ));
    }
    let claim_ids = parse_claim_ids(args)?;
    // An inline proof is shape-checked before the target is
    // touched (SPEC §4.1.7 rule 1): a malformed proof is
    // refused before any file or store access.
    let inline_parsed = match inline {
        Some(value) => Some((value.clone(), proof::parse_proof(value)?)),
        None => None,
    };
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let (proof_value, parsed) = match inline_parsed {
        Some(pair) => pair,
        None => {
            let proof_id = proof_id_arg.expect("checked above");
            let loaded =
                proof::load_stored_proof(config, &subject.sha256, proof_id)?.ok_or_else(|| {
                    FathomError::new(
                        ErrorCode::InvalidRequest,
                        format!("no stored proof '{proof_id}' for this subject"),
                    )
                })?;
            let parsed = proof::parse_proof(&loaded)?;
            (loaded, parsed)
        }
    };
    // Rule 3, pairing: the proof's own digest first, then the
    // presented target's re-hash. A replayed proof reaches no
    // claim checking at all.
    if proof::compute_proof_digest(&proof_value) != parsed.proof_digest {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "proof_digest does not match the proof's contents",
        ));
    }
    if subject.sha256 != parsed.subject_sha256 {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!(
                "proof is bound to subject {} but the target hashes to {}",
                parsed.subject_sha256, subject.sha256
            ),
        ));
    }
    if let Some(ids) = &claim_ids {
        for id in ids {
            if !parsed.claims.iter().any(|claim| &claim.claim_id == id) {
                return Err(FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("claim_ids names unknown claim '{id}'"),
                ));
            }
        }
    }
    // Rule 4: the bound export, located by subject and mode.
    // A document that does not digest to the bound digest is
    // not the evidence the proof cites — absent, for every
    // claim. Verification never re-exports.
    let bound_export = proof::load_bound_export(
        config,
        &subject.sha256,
        &parsed.export_mode,
        &parsed.export_digest,
    );
    // Rule 5: producer drift is computed only when the bound
    // export is present; it caps the aggregate, never blocks.
    let revision_drift = bound_export.is_some()
        && proof::producer_drifted(&parsed.producer, &proof::producer_identity(registry));
    let outcomes = proof::verify_claims(&parsed, bound_export.as_ref());
    let shown: Vec<proof::ClaimOutcome> = match &claim_ids {
        Some(ids) => outcomes
            .into_iter()
            .filter(|outcome| ids.contains(&outcome.claim_id))
            .collect(),
        None => outcomes,
    };
    let aggregate = proof::aggregate(&shown, revision_drift);
    let gate_critical = proof::gate_critical_unverified(&shown);
    let counts = |wanted: proof::Outcome| {
        shown
            .iter()
            .filter(|outcome| outcome.outcome == wanted)
            .count()
    };
    let mut evidence = Evidence::new("verify_reconstruction_proof", "core");
    evidence.subject = Some(subject);
    let mut verdict = Finding::new(
        "proof_verdict",
        Confidence::Derived,
        json!({
            "aggregate": aggregate.as_str(),
            "bound_export": if bound_export.is_some() { "present" } else { "absent" },
            "claims": {
                "failed": counts(proof::Outcome::Failed),
                "inapplicable": counts(proof::Outcome::Inapplicable),
                "unavailable": counts(proof::Outcome::Unavailable),
                "verified": counts(proof::Outcome::Verified),
            },
            "gate_critical_unverified": gate_critical,
            "revision_drift": revision_drift,
        }),
    );
    if revision_drift {
        let current = proof::producer_identity(registry);
        verdict = verdict.with_limitation(format!(
            "revision drift: the proof was produced by {} {} (catalog {}, revision {}); \
             this server is {} {} (catalog {}, revision {}); outcomes are computed \
             against the bound export and the aggregate is capped at partial",
            producer_field(&parsed.producer, "server"),
            producer_field(&parsed.producer, "version"),
            producer_field(&parsed.producer, "catalog_digest"),
            producer_field(&parsed.producer, "source_revision"),
            producer_field(&current, "server"),
            producer_field(&current, "version"),
            producer_field(&current, "catalog_digest"),
            producer_field(&current, "source_revision"),
        ));
    }
    evidence.add_finding(verdict);
    for outcome in &shown {
        evidence.add_finding(Finding::new(
            "claim_outcome",
            outcome.confidence,
            json!({
                "claim_id": outcome.claim_id,
                "class": outcome.class.as_str(),
                "confidence": proof::confidence_str(outcome.confidence),
                "diagnostic": outcome.diagnostic,
                "outcome": outcome.outcome.as_str(),
            }),
        ));
    }
    if detail == Detail::Complete {
        evidence.add_finding(Finding::new("proof", Confidence::Observed, proof_value));
    }
    evidence.coverage.examined = shown.len() as u64;
    evidence.coverage.total = parsed.claims.len() as u64;
    evidence.coverage.exhaustive =
        aggregate == proof::Aggregate::Verified && shown.len() == parsed.claims.len();
    if bound_export.is_none() {
        evidence.add_unknown(
            "bound export",
            "the retained export this proof cites is not present in this host's store",
        );
    }
    if aggregate != proof::Aggregate::Verified {
        evidence.status = Completeness::Partial;
    }
    Ok(evidence.to_value())
}

/// One string field of a producer identity, for drift
/// diagnostics.
fn producer_field<'a>(producer: &'a Value, field: &str) -> &'a str {
    producer[field].as_str().unwrap_or("")
}

/// Parse the optional `claim_ids` subset argument.
fn parse_claim_ids(args: &Value) -> Result<Option<Vec<String>>, FathomError> {
    match args.get("claim_ids") {
        None => Ok(None),
        Some(value) => {
            let ids = value.as_array().ok_or_else(|| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    "argument 'claim_ids' must be an array of strings",
                )
            })?;
            if ids.is_empty() {
                return Err(FathomError::new(
                    ErrorCode::InvalidRequest,
                    "argument 'claim_ids' must not be empty when supplied",
                ));
            }
            let mut parsed = Vec::with_capacity(ids.len());
            for id in ids {
                let id = id.as_str().ok_or_else(|| {
                    FathomError::new(
                        ErrorCode::InvalidRequest,
                        "argument 'claim_ids' must be an array of strings",
                    )
                })?;
                parsed.push(id.to_string());
            }
            Ok(Some(parsed))
        }
    }
}

fn delete_reconstruction_proof(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let proof_id = require_str(args, "proof_id")?;
    proof::validate_proof_id(proof_id)?;
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let file = proof::proof_path(config, &subject.sha256, proof_id);
    if !file.exists() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("no stored proof '{proof_id}' for this subject"),
        ));
    }
    std::fs::remove_file(&file).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot delete proof {}: {error}", file.display()),
        )
    })?;
    let mut evidence = Evidence::new("delete_reconstruction_proof", "core");
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    evidence.add_finding(Finding::new(
        "proof_deletion",
        Confidence::Observed,
        json!({
            "deleted": true,
            "proof_id": proof_id,
            "subject_sha256": subject.sha256,
        }),
    ));
    evidence.subject = Some(subject);
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A target file plus a state dir whose Ghidra cache
    /// already holds the given export documents, so the
    /// ledger tools read the retained store and never spawn
    /// the engine (SPEC §4.1.11, obligation 7's shape).
    struct SeededTarget {
        root: PathBuf,
        state_dir: PathBuf,
        subject_sha256: String,
        target: PathBuf,
    }

    impl SeededTarget {
        fn cleanup(&self) {
            std::fs::remove_dir_all(&self.root).ok();
        }

        fn config(&self) -> Config {
            self.config_with_tools(&[])
        }

        fn config_with_tools(&self, tools: &[&str]) -> Config {
            Config {
                allow_programs: Vec::new(),
                allow_tools: tools.iter().map(ToString::to_string).collect(),
                ghidra_headless: None,
                http_bind: "127.0.0.1:8731".parse().unwrap(),
                signing_key_file: None,
                state_dir: self.state_dir.clone(),
                target_roots: vec![self.root.canonicalize().unwrap()],
                video: fathom_core::config::VideoConfig::default(),
            }
        }

        fn target_arg(&self) -> String {
            self.target.display().to_string()
        }
    }

    fn seeded_target(tag: &str, exports: &[(&str, String)]) -> SeededTarget {
        let root =
            std::env::temp_dir().join(format!("fathom-ledger-s2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let state_dir = root.join("state");
        let target = root.join("target.bin");
        std::fs::create_dir_all(&state_dir).unwrap();
        let target_bytes = format!("s2-fixture-{tag}").into_bytes();
        std::fs::write(&target, &target_bytes).unwrap();
        let subject_sha256 = sha256_hex(&target_bytes);
        if !exports.is_empty() {
            let cache_dir = state_dir.join("ghidra").join(&subject_sha256[..32]);
            std::fs::create_dir_all(&cache_dir).unwrap();
            for (name, document) in exports {
                std::fs::write(cache_dir.join(name), document).unwrap();
            }
        }
        SeededTarget {
            root,
            state_dir,
            subject_sha256,
            target,
        }
    }

    fn registry() -> Registry {
        crate::composition::build_registry()
    }

    fn overview_export() -> String {
        overview_export_truncated(false)
    }

    /// An overview export: 3 functions, 2 strings (one an
    /// uncited payload marker), 1 data string, 1 symbol.
    /// Optionally truncated on the functions inventory
    /// (3 retained of 10).
    fn overview_export_truncated(truncated: bool) -> String {
        json!({
            "data_strings": [{"address": "00403000", "value": "data-str-0"}],
            "data_strings_scan_capped": false,
            "data_strings_total": 1,
            "data_strings_truncated": false,
            "functions": [
                {"address": "00401000", "body_size": 16, "calling_convention": "__fastcall",
                 "classification": "defined", "name": "main_fn", "signature": "int main_fn(void)"},
                {"address": "00401001", "body_size": 24, "calling_convention": "__fastcall",
                 "classification": "defined", "name": "helper_a", "signature": "void helper_a(void)"},
                {"address": "00401002", "body_size": 32, "calling_convention": "__fastcall",
                 "classification": "defined", "name": "helper_b", "signature": "void helper_b(void)"},
            ],
            "functions_total": if truncated { 10 } else { 3 },
            "functions_truncated": truncated,
            "program": {
                "address_size": "64", "compiler_spec": "gcc", "executable_format": "ELF",
                "image_base": "00400000", "language_id": "x86:LE:64:default", "name": "sample",
            },
            "strings": [
                {"address": "00402000", "value": "hello-str"},
                {"address": "00402099", "value": "PAYLOAD_MARKER_S2"},
            ],
            "strings_total": 2,
            "strings_truncated": false,
            "symbols": [
                {"address": "00401000", "name": "main_fn", "source": "DEFAULT", "type": "Function"},
            ],
            "symbols_total": 1,
            "symbols_truncated": false,
        })
        .to_string()
    }

    /// A per-function dossier export for `target_fn`.
    fn function_export() -> String {
        json!({
            "callees": ["helper_a", "helper_b"],
            "callers": ["main"],
            "decompile": {
                "bytes": 55,
                "c": "int target_fn(void) { return DECOMPILE_MARKER_S2; }",
                "truncated": false,
            },
            "function": {
                "address": "00401000", "body_size": 42, "calling_convention": "__fastcall",
                "classification": "defined", "name": "target_fn",
                "signature": "int target_fn(void)",
            },
            "function_found": true,
            "function_match": "exact",
            "listing": [
                {"address": "00401000", "text": "PUSH EBP"},
                {"address": "00401001", "text": "MOV EBP, ESP"},
                {"address": "00401003", "text": "RET"},
            ],
            "listing_truncated": false,
            "program": {
                "address_size": "64", "compiler_spec": "gcc", "executable_format": "ELF",
                "image_base": "00400000", "language_id": "x86:LE:64:default", "name": "sample",
            },
            "references_to": [{"from": "00402000", "type": "DATA"}],
        })
        .to_string()
    }

    fn function_export_file(function: &str) -> String {
        format!(
            "export-function-{}.json",
            &sha256_hex(function.as_bytes())[..12]
        )
    }

    fn honest_claims() -> Value {
        json!([
            {"claim_id": "c-fn", "class": "function_identity",
             "evidence": [{"inventory": "functions", "key": "00401000"}],
             "statement": {"name": "main_fn", "signature": "int main_fn(void)"}},
            {"claim_id": "c-str", "class": "string_assertion",
             "evidence": [{"inventory": "strings", "key": "00402000"}],
             "statement": {"value": "hello-str"}},
            {"claim_id": "c-cov", "class": "coverage",
             "evidence": [{"inventory": "coverage", "key": "functions"}],
             "statement": {"exhaustive": true, "retained": 3, "total": 3}},
        ])
    }

    fn finding<'a>(value: &'a Value, kind: &str) -> &'a Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} finding in {value}"))
    }

    fn verdict_facts(value: &Value) -> &Value {
        &finding(value, "proof_verdict")["facts"]
    }

    fn outcome_facts<'a>(value: &'a Value, claim_id: &str) -> &'a Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| {
                finding["kind"] == "claim_outcome" && finding["facts"]["claim_id"] == claim_id
            })
            .map(|finding| &finding["facts"])
            .unwrap_or_else(|| panic!("no claim_outcome for {claim_id} in {value}"))
    }

    fn build_ok(fixture: &SeededTarget, registry: &Registry, claims: Value) -> Value {
        registry
            .call(
                &fixture.config(),
                "build_reconstruction_obligation_ledger",
                &json!({"claims": claims, "target": fixture.target_arg()}),
            )
            .unwrap()
    }

    fn proof_id_of(build_result: &Value) -> String {
        finding(build_result, "ledger")["facts"]["proof_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn stored_proof(fixture: &SeededTarget, proof_id: &str) -> Value {
        let file = proof::proof_path(&fixture.config(), &fixture.subject_sha256, proof_id);
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    }

    fn verify_by_id(fixture: &SeededTarget, registry: &Registry, proof_id: &str) -> Value {
        registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({"proof_id": proof_id, "target": fixture.target_arg()}),
            )
            .unwrap()
    }

    fn verify_inline(fixture: &SeededTarget, registry: &Registry, proof: Value) -> Value {
        registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({"proof": proof, "target": fixture.target_arg()}),
            )
            .unwrap()
    }

    /// A minimal hand-made proof over the fixture's subject,
    /// digested honestly; the export digest is the caller's to
    /// choose (bound or not).
    fn hand_proof(fixture: &SeededTarget, registry: &Registry, export_digest: String) -> Value {
        let mut proof = json!({
            "claims": [{
                "claim_id": "c1", "class": "function_identity", "confidence": "observed",
                "evidence": [{"inventory": "functions", "key": "00401000",
                              "record_digest": sha256_hex(b"record")}],
                "statement": {"name": "main_fn"},
            }],
            "export": {"digest": export_digest, "mode": "overview"},
            "producer": proof::producer_identity(registry),
            "proof_version": 1,
            "subject": {"path": fixture.target_arg(), "sha256": fixture.subject_sha256,
                        "size_bytes": 0},
        });
        let digest = proof::compute_proof_digest(&proof);
        proof["proof_digest"] = json!(digest);
        proof["proof_id"] = json!(digest[..32].to_string());
        proof
    }

    // Obligation 10: the honest path verifies end-to-end, and
    // the summary view carries no evidence payload bytes.
    #[test]
    fn validation_honest_path_builds_and_verifies_end_to_end() {
        let fixture = seeded_target("honest", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let built = build_ok(&fixture, &registry, honest_claims());
        let ledger = &finding(&built, "ledger")["facts"];
        assert_eq!(ledger["claim_count"], 3);
        assert_eq!(ledger["claims_by_class"]["coverage"], 1);
        assert_eq!(ledger["claims_by_class"]["function_identity"], 1);
        assert_eq!(ledger["claims_by_class"]["string_assertion"], 1);
        let proof_id = proof_id_of(&built);
        // The proof is stored under proofs/<subject prefix>/.
        let file = proof::proof_path(&fixture.config(), &fixture.subject_sha256, &proof_id);
        assert!(file.exists(), "proof stored at {}", file.display());

        let by_id = verify_by_id(&fixture, &registry, &proof_id);
        assert_eq!(by_id["status"], "complete");
        let verdict = verdict_facts(&by_id);
        assert_eq!(verdict["aggregate"], "verified");
        assert_eq!(verdict["bound_export"], "present");
        assert_eq!(verdict["claims"]["verified"], 3);
        assert_eq!(
            verdict["gate_critical_unverified"],
            json!([]),
            "coverage verified, so the gate-critical list is empty"
        );
        for claim_id in ["c-fn", "c-str", "c-cov"] {
            assert_eq!(outcome_facts(&by_id, claim_id)["outcome"], "verified");
        }
        // No evidence payload leaks into the summary view: the
        // uncited marker string lives only in the export.
        assert!(
            !by_id.to_string().contains("PAYLOAD_MARKER_S2"),
            "summary verify view must not carry export payload bytes"
        );

        // The same proof, presented inline, verifies identically.
        let inline = verify_inline(&fixture, &registry, stored_proof(&fixture, &proof_id));
        assert_eq!(verdict_facts(&inline)["aggregate"], "verified");
        fixture.cleanup();
    }

    // Obligation 8 (validation half): a fully bound
    // function_purpose claim verifies — at `inferred`, never
    // presented as `observed`.
    #[test]
    fn validation_function_purpose_verifies_at_inferred_confidence() {
        let fixture = seeded_target(
            "purpose",
            &[(&function_export_file("target_fn"), function_export())],
        );
        let registry = registry();
        let built = registry
            .call(
                &fixture.config(),
                "build_reconstruction_obligation_ledger",
                &json!({
                    "claims": [
                        {"claim_id": "c-id", "class": "function_identity",
                         "evidence": [{"inventory": "function", "key": "00401000"}],
                         "statement": {"name": "target_fn"}},
                        {"claim_id": "c-purpose", "class": "function_purpose",
                         "evidence": [{"inventory": "call_graph", "key": "00401000"}],
                         "statement": {"callees": ["helper_a", "helper_b"]}},
                    ],
                    "function": "target_fn",
                    "target": fixture.target_arg(),
                }),
            )
            .unwrap();
        let proof_id = proof_id_of(&built);
        let verified = verify_by_id(&fixture, &registry, &proof_id);
        assert_eq!(verdict_facts(&verified)["aggregate"], "verified");
        let purpose = outcome_facts(&verified, "c-purpose");
        assert_eq!(purpose["outcome"], "verified");
        assert_eq!(purpose["confidence"], "inferred");
        // D-092 Q2: function_purpose is not gate-critical; the
        // verified coverage-free proof names nothing.
        assert_eq!(
            verdict_facts(&verified)["gate_critical_unverified"],
            json!([])
        );
        fixture.cleanup();
    }

    #[test]
    fn validation_verify_subset_reports_only_the_named_claims() {
        let fixture = seeded_target("subset", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let verified = registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({
                    "claim_ids": ["c-fn"],
                    "proof_id": proof_id,
                    "target": fixture.target_arg(),
                }),
            )
            .unwrap();
        assert_eq!(verdict_facts(&verified)["aggregate"], "verified");
        assert_eq!(verdict_facts(&verified)["claims"]["verified"], 1);
        assert_eq!(verified["coverage"]["examined"], 1);
        assert_eq!(verified["coverage"]["total"], 3);
        fixture.cleanup();
    }

    // Q4 (D-092): the operator deletion verb removes a stored
    // proof; afterwards it no longer verifies by id.
    #[test]
    fn validation_delete_removes_a_stored_proof() {
        let fixture = seeded_target("delete", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let config = fixture.config_with_tools(&["delete_reconstruction_proof"]);
        let deleted = registry
            .call(
                &config,
                "delete_reconstruction_proof",
                &json!({"proof_id": proof_id, "target": fixture.target_arg()}),
            )
            .unwrap();
        assert_eq!(
            finding(&deleted, "proof_deletion")["facts"]["deleted"],
            true
        );
        let file = proof::proof_path(&fixture.config(), &fixture.subject_sha256, &proof_id);
        assert!(!file.exists());
        let error = registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({"proof_id": proof_id, "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        fixture.cleanup();
    }

    // Obligation 1: an ID-array-only proof verifies nothing —
    // every claim fails as unbound_evidence, aggregate failed.
    #[test]
    fn adversarial_id_array_only_proof_fails_every_claim() {
        let fixture = seeded_target("idarray", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let mut proof = stored_proof(&fixture, &proof_id);
        for claim in proof["claims"].as_array_mut().unwrap() {
            claim["evidence"] = json!(["00401000"]);
        }
        proof["proof_digest"] = json!(proof::compute_proof_digest(&proof));
        let verified = verify_inline(&fixture, &registry, proof);
        let verdict = verdict_facts(&verified);
        assert_eq!(verdict["aggregate"], "failed");
        assert_eq!(verdict["claims"]["failed"], 3);
        assert_eq!(verdict["claims"]["verified"], 0);
        for claim_id in ["c-fn", "c-str", "c-cov"] {
            let outcome = outcome_facts(&verified, claim_id);
            assert_eq!(outcome["outcome"], "failed");
            assert!(
                outcome["diagnostic"]
                    .as_str()
                    .unwrap()
                    .contains("unbound_evidence"),
                "diagnostic names the failure class: {outcome}"
            );
        }
        fixture.cleanup();
    }

    // Obligation 2: a proof replayed against a different
    // subject is refused under rule 3 — no claim is checked.
    #[test]
    fn adversarial_cross_subject_replay_is_refused() {
        let fixture = seeded_target("replay", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let proof = stored_proof(&fixture, &proof_id);
        let other = fixture.root.join("target-b.bin");
        std::fs::write(&other, b"s2-fixture-different-bytes").unwrap();
        let error = registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({"proof": proof, "target": other.display().to_string()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
        fixture.cleanup();
    }

    // Obligation 3a: mutating a stored proof's statement
    // breaks its digest; verification is refused.
    #[test]
    fn adversarial_tampered_stored_proof_is_refused() {
        let fixture = seeded_target("tamper", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let file = proof::proof_path(&fixture.config(), &fixture.subject_sha256, &proof_id);
        let mut proof: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        proof["claims"][0]["statement"]["name"] = json!("forged_name");
        std::fs::write(&file, proof.to_string()).unwrap();
        let error = registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({"proof_id": proof_id, "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
        fixture.cleanup();
    }

    // Obligation 3b: mutating the retained export's cited
    // record fails that claim on its record digest.
    #[test]
    fn adversarial_mutated_export_record_fails_its_claim() {
        let fixture = seeded_target("mutate", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        // Mutate the cited record in the store; rebind the
        // proof honestly to the mutated document (its own
        // digest recomputed) — the record digest still fails.
        let export_file =
            proof::retained_export_path(&fixture.config(), &fixture.subject_sha256, "overview");
        let mut document: Value =
            serde_json::from_str(&std::fs::read_to_string(&export_file).unwrap()).unwrap();
        document["functions"][0]["name"] = json!("renamed_fn");
        std::fs::write(&export_file, document.to_string()).unwrap();
        let mut proof = stored_proof(&fixture, &proof_id);
        proof["export"]["digest"] = json!(proof::value_digest(&document));
        proof["proof_digest"] = json!(proof::compute_proof_digest(&proof));
        let verified = verify_inline(&fixture, &registry, proof);
        let outcome = outcome_facts(&verified, "c-fn");
        assert_eq!(outcome["outcome"], "failed");
        assert!(
            outcome["diagnostic"]
                .as_str()
                .unwrap()
                .contains("record_digest_mismatch")
        );
        assert_eq!(verdict_facts(&verified)["aggregate"], "failed");
        fixture.cleanup();
    }

    // Obligation 4: truncated evidence downgrades, never
    // verifies — a coverage overclaim fails, a citation past
    // the ceiling is unavailable.
    #[test]
    fn adversarial_truncated_evidence_downgrades_never_verifies() {
        let fixture = seeded_target(
            "truncated",
            &[("export-overview.json", overview_export_truncated(true))],
        );
        let registry = registry();
        let built = build_ok(
            &fixture,
            &registry,
            json!([{"claim_id": "c-cov", "class": "coverage",
                    "evidence": [{"inventory": "coverage", "key": "functions"}],
                    "statement": {"exhaustive": true, "retained": 3, "total": 10}}]),
        );
        let verified = verify_by_id(&fixture, &registry, &proof_id_of(&built));
        let outcome = outcome_facts(&verified, "c-cov");
        assert_eq!(outcome["outcome"], "failed");
        assert_eq!(verdict_facts(&verified)["aggregate"], "failed");
        // Coverage is gate-critical (D-092 Q2): its failure is
        // named in the verdict block.
        assert_eq!(
            verdict_facts(&verified)["gate_critical_unverified"],
            json!(["c-cov"])
        );

        // A citation past the retained ceiling is unavailable.
        let document: Value = serde_json::from_str(&overview_export_truncated(true)).unwrap();
        let mut proof = hand_proof(&fixture, &registry, proof::value_digest(&document));
        proof["claims"][0]["evidence"] = json!([{
            "inventory": "functions", "key": "00401999",
            "record_digest": sha256_hex(b"ghost"),
        }]);
        proof["claims"][0]["statement"] = json!({"name": "ghost_fn"});
        proof["proof_digest"] = json!(proof::compute_proof_digest(&proof));
        let verified = verify_inline(&fixture, &registry, proof);
        assert_eq!(outcome_facts(&verified, "c1")["outcome"], "unavailable");
        assert_eq!(verdict_facts(&verified)["aggregate"], "partial");
        fixture.cleanup();
    }

    // Obligation 5: revision drift caps at partial with the
    // bound export present; absent export, all unavailable.
    #[test]
    fn adversarial_drift_caps_at_partial_and_absent_export_unavailable() {
        let fixture = seeded_target("drift", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));

        // A second registry whose catalog differs (one extra
        // tool) drifts the producer binding.
        let mut drifted = crate::composition::build_registry();
        drifted.register(
            descriptor(
                "zz_extra_tool",
                ToolClass::Read,
                "test",
                "drift fixture",
                json!({"type": "object"}),
            ),
            Arc::new(|_, _, _| Ok(json!({}))),
        );
        let verified = verify_by_id(&fixture, &drifted, &proof_id);
        let verdict = verdict_facts(&verified);
        assert_eq!(verdict["revision_drift"], true);
        assert_eq!(verdict["aggregate"], "partial");
        assert_eq!(verdict["claims"]["verified"], 3);
        assert!(
            finding(&verified, "proof_verdict")["limitations"][0]
                .as_str()
                .unwrap()
                .contains("revision drift")
        );

        // Bound export evicted: every claim unavailable.
        std::fs::remove_file(proof::retained_export_path(
            &fixture.config(),
            &fixture.subject_sha256,
            "overview",
        ))
        .unwrap();
        let verified = verify_by_id(&fixture, &registry, &proof_id);
        let verdict = verdict_facts(&verified);
        assert_eq!(verdict["bound_export"], "absent");
        assert_eq!(verdict["claims"]["unavailable"], 3);
        assert_eq!(verdict["aggregate"], "partial");
        fixture.cleanup();
    }

    // Obligation 6: malformed proofs are refused before the
    // target is read — the target here does not exist, so any
    // target access would fail with a different code.
    #[test]
    fn adversarial_malformed_proofs_refused_before_any_target_access() {
        let fixture = seeded_target("malformed", &[]);
        let registry = registry();
        let base = hand_proof(&fixture, &registry, sha256_hex(b"export"));
        let ghost = fixture
            .root
            .join("does-not-exist.bin")
            .display()
            .to_string();
        let mut variants: Vec<Value> = Vec::new();
        let mut duplicate = base.clone();
        let claim = duplicate["claims"][0].clone();
        duplicate["claims"].as_array_mut().unwrap().push(claim);
        variants.push(duplicate);
        let mut unknown_class = base.clone();
        unknown_class["claims"][0]["class"] = json!("nonsense_class");
        variants.push(unknown_class);
        let mut unknown_version = base.clone();
        unknown_version["proof_version"] = json!(99);
        variants.push(unknown_version);
        let mut prose_statement = base.clone();
        prose_statement["claims"][0]["statement"] = json!("just prose");
        variants.push(prose_statement);
        for mut variant in variants {
            variant["proof_digest"] = json!(proof::compute_proof_digest(&variant));
            let error = registry
                .call(
                    &fixture.config(),
                    "verify_reconstruction_proof",
                    &json!({"proof": variant, "target": ghost}),
                )
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidRequest, "{error}");
        }
        fixture.cleanup();
    }

    // Obligation 7: verify spawns nothing and creates
    // nothing — an empty state dir stays empty.
    #[test]
    fn adversarial_verify_in_empty_state_creates_nothing() {
        let fixture = seeded_target("empty", &[]);
        let registry = registry();
        let proof = hand_proof(&fixture, &registry, sha256_hex(b"export"));
        let verified = verify_inline(&fixture, &registry, proof);
        assert_eq!(outcome_facts(&verified, "c1")["outcome"], "unavailable");
        assert_eq!(verdict_facts(&verified)["bound_export"], "absent");
        assert!(
            !fixture.state_dir.join("ghidra").exists(),
            "verify must not create a Ghidra cache"
        );
        assert!(
            !fixture.state_dir.join("proofs").exists(),
            "verify must not create a proof store"
        );
        fixture.cleanup();
    }

    // Obligation 9: the named bounds hold under attack.
    #[test]
    fn adversarial_bounds_refuse_oversize_requests() {
        let fixture = seeded_target("bounds", &[("export-overview.json", overview_export())]);
        let registry = registry();
        // PROOF_CLAIMS_MAX + 1 claims at build.
        let claims: Vec<Value> = (0..=PROOF_CLAIMS_MAX)
            .map(|index| {
                json!({"claim_id": format!("c{index}"), "class": "function_identity",
                       "evidence": [{"inventory": "functions", "key": "00401000"}],
                       "statement": {"name": "main_fn"}})
            })
            .collect();
        let error = registry
            .call(
                &fixture.config(),
                "build_reconstruction_obligation_ledger",
                &json!({"claims": claims, "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceConstraint);
        // A statement past PROOF_STATEMENT_BYTES_MAX at build.
        let error = registry
            .call(
                &fixture.config(),
                "build_reconstruction_obligation_ledger",
                &json!({
                    "claims": [{"claim_id": "c-big", "class": "function_identity",
                                "evidence": [{"inventory": "functions", "key": "00401000"}],
                                "statement": {"pad": "x".repeat(PROOF_STATEMENT_BYTES_MAX + 1)}}],
                    "target": fixture.target_arg(),
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceConstraint);
        // An inline proof past PROOF_BYTES_MAX: 256 claims
        // each carrying a near-maximal statement.
        let claims: Vec<Value> = (0..PROOF_CLAIMS_MAX)
            .map(|index| {
                json!({"claim_id": format!("c{index}"), "class": "function_identity",
                       "confidence": "observed",
                       "evidence": [{"inventory": "functions", "key": "00401000",
                                     "record_digest": sha256_hex(b"record")}],
                       "statement": {"pad": "y".repeat(16_000)}})
            })
            .collect();
        let mut proof = hand_proof(&fixture, &registry, sha256_hex(b"export"));
        proof["claims"] = json!(claims);
        proof["proof_digest"] = json!(proof::compute_proof_digest(&proof));
        assert!(proof::canonical_json(&proof).len() > PROOF_BYTES_MAX);
        let error = registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({"proof": proof, "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        fixture.cleanup();
    }

    // Build-time honesty (§4.1.8): unresolvable locators,
    // caller-supplied digests, empty evidence, and asserted
    // confidence are all refused before anything is stored.
    #[test]
    fn adversarial_build_refuses_unbound_or_caller_computed_claims() {
        let fixture = seeded_target(
            "buildrefuse",
            &[("export-overview.json", overview_export())],
        );
        let registry = registry();
        let cases: Vec<Value> = vec![
            // Locator that resolves to nothing.
            json!([{"claim_id": "c-x", "class": "function_identity",
                    "evidence": [{"inventory": "functions", "key": "00409999"}],
                    "statement": {"name": "ghost"}}]),
            // Caller-computed record digest.
            json!([{"claim_id": "c-x", "class": "function_identity",
                    "evidence": [{"inventory": "functions", "key": "00401000",
                                  "record_digest": sha256_hex(b"forged")}],
                    "statement": {"name": "main_fn"}}]),
            // No evidence at all.
            json!([{"claim_id": "c-x", "class": "function_identity",
                    "evidence": [], "statement": {"name": "main_fn"}}]),
            // Confidence asserted above the class table.
            json!([{"claim_id": "c-x", "class": "function_purpose", "confidence": "observed",
                    "evidence": [{"inventory": "functions", "key": "00401000"}],
                    "statement": {"name": "main_fn"}}]),
        ];
        for claims in cases {
            let error = registry
                .call(
                    &fixture.config(),
                    "build_reconstruction_obligation_ledger",
                    &json!({"claims": claims, "target": fixture.target_arg()}),
                )
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidRequest, "{error}");
            assert!(
                error.message.contains("c-x"),
                "the refusal names the claim: {error}"
            );
        }
        // Nothing was stored by any refused build.
        assert_eq!(
            proof::count_stored_proofs(&fixture.config(), &fixture.subject_sha256),
            0
        );
        fixture.cleanup();
    }

    // The deletion verb is execute-class: default-deny
    // without an allowlist entry, and a missing proof is a
    // typed refusal, never a silent success.
    #[test]
    fn adversarial_delete_is_default_deny_and_missing_is_refused() {
        let fixture = seeded_target(
            "deleterefuse",
            &[("export-overview.json", overview_export())],
        );
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let error = registry
            .call(
                &fixture.config(),
                "delete_reconstruction_proof",
                &json!({"proof_id": proof_id, "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::AccessDenied);
        let config = fixture.config_with_tools(&["delete_reconstruction_proof"]);
        let error = registry
            .call(
                &config,
                "delete_reconstruction_proof",
                &json!({"proof_id": "0".repeat(32), "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        let error = registry
            .call(
                &config,
                "delete_reconstruction_proof",
                &json!({"proof_id": "../escape", "target": fixture.target_arg()}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        // The real proof survived every refused delete.
        assert_eq!(
            verdict_facts(&verify_by_id(&fixture, &registry, &proof_id))["aggregate"],
            "verified"
        );
        fixture.cleanup();
    }

    #[test]
    fn adversarial_unknown_claim_ids_subset_is_refused() {
        let fixture = seeded_target("badsubset", &[("export-overview.json", overview_export())]);
        let registry = registry();
        let proof_id = proof_id_of(&build_ok(&fixture, &registry, honest_claims()));
        let error = registry
            .call(
                &fixture.config(),
                "verify_reconstruction_proof",
                &json!({
                    "claim_ids": ["no-such-claim"],
                    "proof_id": proof_id,
                    "target": fixture.target_arg(),
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        fixture.cleanup();
    }
}
