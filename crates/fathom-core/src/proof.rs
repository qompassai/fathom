//! The reconstruction-proof ledger (SPEC §4.1).
//!
//! A proof binds caller-authored claims to one subject
//! (SHA-256), one retained export (digest), and one producing
//! implementation (version, catalog digest, source revision).
//! Outcomes are never stored in the proof: verification is a
//! pure function of (proof, subject hash, retained store) that
//! recomputes every outcome on every call, runs no provider,
//! spawns no process, and writes nothing — so a `verified`
//! mark can never be replayed from storage.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::config::Config;
use crate::error::{ErrorCode, FathomError};
use crate::evidence::{Confidence, sha256_hex};
use crate::limits::{
    PROOF_BYTES_MAX, PROOF_CLAIMS_MAX, PROOF_DIAGNOSTIC_CHARS_MAX, PROOF_EVIDENCE_PER_CLAIM_MAX,
    PROOF_STATEMENT_BYTES_MAX,
};
use crate::paths;
use crate::registry::Registry;

/// The one proof serialization this build reads and writes.
/// An unknown version is refused, never defaulted or migrated
/// silently (SPEC §4.1.5).
pub const PROOF_VERSION: u64 = 1;

/// The provider whose retained exports proofs bind in v1: the
/// §9.1 Ghidra store is the retained-evidence store S1 opened.
pub const PROOF_PROVIDER: &str = "ghidra";

/// The canonical form every digest in this module is computed
/// over: compact JSON with object keys sorted, recursively —
/// §6's digest rule, written out so it does not depend on a
/// map implementation detail.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
        _ => out.push_str(&serde_json::to_string(value).unwrap_or_default()),
    }
}

/// SHA-256 over a value's canonical form.
pub fn value_digest(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

/// The digest a proof carries: over its canonical form with
/// the `proof_digest` field itself removed, and with the
/// server-assigned `proof_id` removed — the id is an
/// assignment (derived from this digest), not a binding.
pub fn compute_proof_digest(proof: &Value) -> String {
    let mut material = proof.clone();
    if let Some(object) = material.as_object_mut() {
        object.remove("proof_digest");
        object.remove("proof_id");
    }
    value_digest(&material)
}

/// The producing implementation's identity, exactly as
/// `session_info` reports it (SPEC §4.1.5) with the build-time
/// source revision joined per D-092 Q3.
pub fn producer_identity(registry: &Registry) -> Value {
    json!({
        "catalog_digest": registry.catalog_digest(),
        "provider": PROOF_PROVIDER,
        "server": crate::PRODUCT_NAME,
        "source_revision": crate::SOURCE_REVISION,
        "version": crate::VERSION,
    })
}

/// Whether the proof's producer binding differs from the
/// current server's (SPEC §4.1.7 rule 5): version, catalog
/// digest, or source revision.
pub fn producer_drifted(bound: &Value, current: &Value) -> bool {
    ["catalog_digest", "source_revision", "version"]
        .iter()
        .any(|field| bound.get(field) != current.get(field))
}

/// The wire form of a [`Confidence`].
pub fn confidence_str(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Derived => "derived",
        Confidence::Inferred => "inferred",
        Confidence::Observed => "observed",
    }
}

fn parse_confidence(raw: &str) -> Option<Confidence> {
    match raw {
        "derived" => Some(Confidence::Derived),
        "inferred" => Some(Confidence::Inferred),
        "observed" => Some(Confidence::Observed),
        _ => None,
    }
}

/// One claim class of SPEC §4.1.4. A class outside this table
/// is refused at parse time; the table grows by SPEC
/// amendment, not by caller invention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimClass {
    ArtifactClassification,
    CallRelationship,
    Coverage,
    FunctionIdentity,
    FunctionPurpose,
    StringAssertion,
}

impl ClaimClass {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "artifact_classification" => Some(ClaimClass::ArtifactClassification),
            "call_relationship" => Some(ClaimClass::CallRelationship),
            "coverage" => Some(ClaimClass::Coverage),
            "function_identity" => Some(ClaimClass::FunctionIdentity),
            "function_purpose" => Some(ClaimClass::FunctionPurpose),
            "string_assertion" => Some(ClaimClass::StringAssertion),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ClaimClass::ArtifactClassification => "artifact_classification",
            ClaimClass::CallRelationship => "call_relationship",
            ClaimClass::Coverage => "coverage",
            ClaimClass::FunctionIdentity => "function_identity",
            ClaimClass::FunctionPurpose => "function_purpose",
            ClaimClass::StringAssertion => "string_assertion",
        }
    }

    /// The confidence the class table fixes, set at build and
    /// never raised by verification. `string_assertion` is the
    /// one class whose confidence follows the citation:
    /// defined strings are `observed`, data strings `derived`.
    pub fn confidence(self, inventories: &[&str]) -> Confidence {
        match self {
            ClaimClass::ArtifactClassification => Confidence::Observed,
            ClaimClass::CallRelationship => Confidence::Derived,
            ClaimClass::Coverage => Confidence::Observed,
            ClaimClass::FunctionIdentity => Confidence::Observed,
            ClaimClass::FunctionPurpose => Confidence::Inferred,
            ClaimClass::StringAssertion => {
                if inventories.contains(&"data_strings") {
                    Confidence::Derived
                } else {
                    Confidence::Observed
                }
            }
        }
    }

    /// Gate-critical classes (SPEC §4.1.4, D-092 Q2): a
    /// non-verified outcome is named in the verdict block.
    /// `coverage` alone is gate-critical in v1.
    pub fn gate_critical(self) -> bool {
        matches!(self, ClaimClass::Coverage)
    }
}

/// One evidence reference as a proof carries it. A reference
/// that is not an object with an `(inventory, key)` locator
/// and a server-computed `record_digest` is `Unbound` — the
/// bare-identifier shape of SPEC §4.1.7 rule 2.
#[derive(Clone, Debug)]
pub enum EvidenceRef {
    Bound {
        inventory: String,
        key: String,
        record_digest: String,
    },
    Unbound,
}

/// One claim of a parsed proof.
#[derive(Clone, Debug)]
pub struct Claim {
    pub claim_id: String,
    pub class: ClaimClass,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceRef>,
    pub statement: Value,
}

/// A proof that passed shape validation (SPEC §4.1.7 rule 1).
/// Shape runs before any file or store access, so a malformed
/// proof is refused before any work.
#[derive(Clone, Debug)]
pub struct Proof {
    pub claims: Vec<Claim>,
    pub export_digest: String,
    pub export_mode: String,
    pub producer: Value,
    pub proof_digest: String,
    pub subject_sha256: String,
    /// The proof as presented, retained for `detail:
    /// "complete"` views; outcomes are never read from it.
    pub value: Value,
}

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message)
}

fn is_digest(raw: &str) -> bool {
    raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit())
}

/// Shape-validate a proof value (SPEC §4.1.7 rule 1): version,
/// classes, unique claim ids, bounds, object statements.
/// Evidence references are *classified* here, not judged —
/// an unbound reference is a claim outcome (rule 2), not a
/// shape refusal.
pub fn parse_proof(value: &Value) -> Result<Proof, FathomError> {
    if canonical_json(value).len() > PROOF_BYTES_MAX {
        return Err(invalid(format!(
            "proof exceeds PROOF_BYTES_MAX ({PROOF_BYTES_MAX}) serialized bytes"
        )));
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid("proof must be a JSON object"))?;
    let version = object.get("proof_version").and_then(Value::as_u64);
    if version != Some(PROOF_VERSION) {
        return Err(invalid(format!(
            "proof_version must be {PROOF_VERSION}; unknown versions are refused, never migrated"
        )));
    }
    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("proof has no subject object"))?;
    let subject_sha256 = subject
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|sha| is_digest(sha))
        .ok_or_else(|| invalid("proof subject.sha256 must be a SHA-256 hex digest"))?
        .to_string();
    let export = object
        .get("export")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("proof has no export binding"))?;
    let export_digest = export
        .get("digest")
        .and_then(Value::as_str)
        .filter(|digest| is_digest(digest))
        .ok_or_else(|| invalid("proof export.digest must be a SHA-256 hex digest"))?
        .to_string();
    let export_mode = export
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("proof export.mode must be a string"))?
        .to_string();
    let producer = object
        .get("producer")
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| invalid("proof has no producer binding"))?;
    let proof_digest = object
        .get("proof_digest")
        .and_then(Value::as_str)
        .filter(|digest| is_digest(digest))
        .ok_or_else(|| invalid("proof has no proof_digest"))?
        .to_string();
    let raw_claims = object
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("proof claims must be an array"))?;
    if raw_claims.is_empty() {
        return Err(invalid("a proof needs at least one claim"));
    }
    if raw_claims.len() > PROOF_CLAIMS_MAX {
        return Err(invalid(format!(
            "proof carries {} claims, over PROOF_CLAIMS_MAX ({PROOF_CLAIMS_MAX})",
            raw_claims.len()
        )));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut claims = Vec::with_capacity(raw_claims.len());
    for raw in raw_claims {
        claims.push(parse_claim(raw, &mut seen)?);
    }
    Ok(Proof {
        claims,
        export_digest,
        export_mode,
        producer,
        proof_digest,
        subject_sha256,
        value: value.clone(),
    })
}

fn parse_claim(raw: &Value, seen: &mut BTreeSet<String>) -> Result<Claim, FathomError> {
    let object = raw
        .as_object()
        .ok_or_else(|| invalid("each claim must be an object"))?;
    let claim_id = object
        .get("claim_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("each claim needs a non-empty claim_id"))?
        .to_string();
    if !seen.insert(claim_id.clone()) {
        return Err(invalid(format!("duplicate claim_id '{claim_id}'")));
    }
    let class_raw = object
        .get("class")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("claim '{claim_id}' has no class")))?;
    let class = ClaimClass::parse(class_raw).ok_or_else(|| {
        invalid(format!(
            "claim '{claim_id}' names unknown class '{class_raw}'"
        ))
    })?;
    let confidence_raw = object
        .get("confidence")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("claim '{claim_id}' has no confidence")))?;
    let confidence = parse_confidence(confidence_raw).ok_or_else(|| {
        invalid(format!(
            "claim '{claim_id}' names unknown confidence '{confidence_raw}'"
        ))
    })?;
    let statement = object
        .get("statement")
        .cloned()
        .ok_or_else(|| invalid(format!("claim '{claim_id}' has no statement")))?;
    if !statement.is_object() {
        return Err(invalid(format!(
            "claim '{claim_id}' statement must be an object of facts, not prose"
        )));
    }
    if canonical_json(&statement).len() > PROOF_STATEMENT_BYTES_MAX {
        return Err(invalid(format!(
            "claim '{claim_id}' statement exceeds PROOF_STATEMENT_BYTES_MAX ({PROOF_STATEMENT_BYTES_MAX})"
        )));
    }
    let raw_evidence = object.get("evidence").and_then(Value::as_array);
    let raw_evidence = raw_evidence.cloned().unwrap_or_default();
    if raw_evidence.len() > PROOF_EVIDENCE_PER_CLAIM_MAX {
        return Err(invalid(format!(
            "claim '{claim_id}' cites {} evidence references, over PROOF_EVIDENCE_PER_CLAIM_MAX ({PROOF_EVIDENCE_PER_CLAIM_MAX})",
            raw_evidence.len()
        )));
    }
    let evidence = raw_evidence.iter().map(parse_ref).collect();
    Ok(Claim {
        claim_id,
        class,
        confidence,
        evidence,
        statement,
    })
}

fn parse_ref(raw: &Value) -> EvidenceRef {
    let object = match raw.as_object() {
        Some(object) => object,
        None => return EvidenceRef::Unbound,
    };
    let inventory = object.get("inventory").and_then(Value::as_str);
    let key = object.get("key").and_then(Value::as_str);
    let record_digest = object
        .get("record_digest")
        .and_then(Value::as_str)
        .filter(|digest| is_digest(digest));
    match (inventory, key, record_digest) {
        (Some(inventory), Some(key), Some(record_digest)) => EvidenceRef::Bound {
            inventory: inventory.to_string(),
            key: key.to_string(),
            record_digest: record_digest.to_string(),
        },
        _ => EvidenceRef::Unbound,
    }
}

/// How one `(inventory, key)` locator resolves in a retained
/// export document.
#[derive(Clone, Debug)]
pub enum Resolution {
    /// The inventory exists but is truncated, and the key is
    /// not among the retained rows.
    BeyondCeiling,
    /// The inventory is whole and carries no such record.
    Absent,
    /// The inventory is not part of this export document.
    NotApplicable,
    /// The retained record.
    Record(Value),
}

/// The inventories one export document carries. An `overview`
/// document inventories the program; a `function` document is
/// one function's dossier. Records are the export's own rows,
/// in the shapes the S1 reads project.
pub fn resolve_record(document: &Value, dossier: bool, inventory: &str, key: &str) -> Resolution {
    if dossier {
        resolve_dossier(document, inventory, key)
    } else {
        resolve_overview(document, inventory, key)
    }
}

fn find_by_address(document: &Value, field: &str, truncated_field: &str, key: &str) -> Resolution {
    let rows = document.get(field).and_then(Value::as_array);
    if let Some(rows) = rows {
        for row in rows {
            if row.get("address").and_then(Value::as_str) == Some(key) {
                return Resolution::Record(row.clone());
            }
        }
    }
    let truncated = document
        .get(truncated_field)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if truncated {
        Resolution::BeyondCeiling
    } else {
        Resolution::Absent
    }
}

fn resolve_overview(document: &Value, inventory: &str, key: &str) -> Resolution {
    match inventory {
        "coverage" => match coverage_record(document, key) {
            Some(record) => Resolution::Record(record),
            None => Resolution::NotApplicable,
        },
        "data_strings" => find_by_address(document, "data_strings", "data_strings_truncated", key),
        "functions" => find_by_address(document, "functions", "functions_truncated", key),
        "names" => find_by_address(document, "symbols", "symbols_truncated", key),
        "program" => {
            let program = document.get("program");
            match program {
                Some(program) if program.get("name").and_then(Value::as_str) == Some(key) => {
                    Resolution::Record(program.clone())
                }
                Some(_) => Resolution::Absent,
                None => Resolution::Absent,
            }
        }
        "strings" => find_by_address(document, "strings", "strings_truncated", key),
        _ => Resolution::NotApplicable,
    }
}

fn resolve_dossier(document: &Value, inventory: &str, key: &str) -> Resolution {
    let function = document.get("function");
    let function_address = function
        .and_then(|f| f.get("address"))
        .and_then(Value::as_str);
    match inventory {
        "call_graph" => match function_address {
            Some(address) if address == key => Resolution::Record(json!({
                "callees": document.get("callees").cloned().unwrap_or_else(|| json!([])),
                "callers": document.get("callers").cloned().unwrap_or_else(|| json!([])),
            })),
            _ => Resolution::Absent,
        },
        "coverage" => {
            if key != "listing" {
                return Resolution::NotApplicable;
            }
            let truncated = document
                .get("listing_truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let retained = document
                .get("listing")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            Resolution::Record(json!({
                "exhaustive": !truncated,
                "inventory": "listing",
                "retained": retained,
                "truncated": truncated,
            }))
        }
        "decompile" => match (function_address, document.get("decompile")) {
            (Some(address), Some(decompile)) if address == key => {
                Resolution::Record(decompile.clone())
            }
            _ => Resolution::Absent,
        },
        "function" => match function {
            Some(function) if function_address == Some(key) => Resolution::Record(function.clone()),
            _ => Resolution::Absent,
        },
        "listing" => find_by_address(document, "listing", "listing_truncated", key),
        "references_to" => match function_address {
            Some(address) if address == key => {
                let references = document
                    .get("references_to")
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                let count = references.as_array().map_or(0, Vec::len);
                Resolution::Record(json!({"count": count, "references": references}))
            }
            _ => Resolution::Absent,
        },
        _ => Resolution::NotApplicable,
    }
}

/// The synthesized `coverage` record for one overview
/// inventory: retained and total counts and truncation,
/// derived from the export document itself — so a coverage
/// claim's exhaustiveness assertion is checkable against the
/// store, never taken on faith (SPEC §4.1.7 rule 6).
fn coverage_record(document: &Value, inventory: &str) -> Option<Value> {
    let (field, total_field, truncated_field) = match inventory {
        "data_strings" => (
            "data_strings",
            "data_strings_total",
            "data_strings_truncated",
        ),
        "functions" => ("functions", "functions_total", "functions_truncated"),
        "names" => ("symbols", "symbols_total", "symbols_truncated"),
        "strings" => ("strings", "strings_total", "strings_truncated"),
        _ => return None,
    };
    let retained = document
        .get(field)
        .and_then(Value::as_array)
        .map_or(0, Vec::len) as u64;
    let total = document
        .get(total_field)
        .and_then(Value::as_u64)
        .unwrap_or(retained);
    let truncated = document
        .get(truncated_field)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(json!({
        "exhaustive": !truncated && retained == total,
        "inventory": inventory,
        "retained": retained,
        "total": total,
        "truncated": truncated,
    }))
}

/// One claim's verification outcome (SPEC §4.1.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Failed,
    Inapplicable,
    Unavailable,
    Verified,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Failed => "failed",
            Outcome::Inapplicable => "inapplicable",
            Outcome::Unavailable => "unavailable",
            Outcome::Verified => "verified",
        }
    }
}

/// The mechanical aggregate over one verification (SPEC §4.1.8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Aggregate {
    Failed,
    Partial,
    Verified,
}

impl Aggregate {
    pub fn as_str(self) -> &'static str {
        match self {
            Aggregate::Failed => "failed",
            Aggregate::Partial => "partial",
            Aggregate::Verified => "verified",
        }
    }
}

/// One claim's computed outcome. Never stored in a proof;
/// produced fresh by every verification.
#[derive(Clone, Debug)]
pub struct ClaimOutcome {
    pub claim_id: String,
    pub class: ClaimClass,
    pub confidence: Confidence,
    pub diagnostic: String,
    pub outcome: Outcome,
}

fn bounded_diagnostic(text: String) -> String {
    text.chars().take(PROOF_DIAGNOSTIC_CHARS_MAX).collect()
}

fn outcome(claim: &Claim, outcome: Outcome, diagnostic: String) -> ClaimOutcome {
    ClaimOutcome {
        claim_id: claim.claim_id.clone(),
        class: claim.class,
        confidence: claim.confidence,
        diagnostic: bounded_diagnostic(diagnostic),
        outcome,
    }
}

/// Verify every claim of a parsed proof against the bound
/// export (SPEC §4.1.7 rules 2, 4, 6, 7). Pairing (rule 3)
/// and shape (rule 1) are the caller's refusals, already
/// settled; `export` is `Some` only when the retained
/// document on disk digests to the proof's bound digest.
pub fn verify_claims(proof: &Proof, export: Option<&Value>) -> Vec<ClaimOutcome> {
    let Some(document) = export else {
        return proof
            .claims
            .iter()
            .map(|claim| {
                outcome(
                    claim,
                    Outcome::Unavailable,
                    "bound_export_absent: the retained export this proof cites is not \
                     present in this host's store"
                        .to_string(),
                )
            })
            .collect();
    };
    let dossier = proof.export_mode != "overview";
    proof
        .claims
        .iter()
        .map(|claim| check_claim(claim, document, dossier))
        .collect()
}

fn check_claim(claim: &Claim, document: &Value, dossier: bool) -> ClaimOutcome {
    // Rule 2: bound evidence, or the claim fails. This is the
    // contract's center — an ID-array-only claim verifies
    // nothing, however plausible its identifiers look.
    let mut locators: Vec<(&str, &str, &str)> = Vec::with_capacity(claim.evidence.len());
    for reference in &claim.evidence {
        match reference {
            EvidenceRef::Bound {
                inventory,
                key,
                record_digest,
            } => locators.push((inventory, key, record_digest)),
            EvidenceRef::Unbound => {
                return outcome(
                    claim,
                    Outcome::Failed,
                    "unbound_evidence: every reference must carry an (inventory, key) \
                     locator and a server-computed record_digest"
                        .to_string(),
                );
            }
        }
    }
    if locators.is_empty() {
        return outcome(
            claim,
            Outcome::Failed,
            "unbound_evidence: the claim cites no evidence".to_string(),
        );
    }
    // Rule 7's floor: the proof must carry the class table's
    // confidence; anything else was not produced under this
    // contract and establishes nothing at any confidence.
    let inventories: Vec<&str> = locators.iter().map(|(inv, _, _)| *inv).collect();
    let expected = claim.class.confidence(&inventories);
    if claim.confidence != expected {
        return outcome(
            claim,
            Outcome::Failed,
            format!(
                "confidence_mismatch: class {} carries {}; the proof asserts {}",
                claim.class.as_str(),
                confidence_str(expected),
                confidence_str(claim.confidence)
            ),
        );
    }
    // Rule 6: resolve, re-digest, and check the statement
    // field-by-field against the bound records.
    let mut records: Vec<Value> = Vec::with_capacity(locators.len());
    for (inventory, key, record_digest) in &locators {
        match resolve_record(document, dossier, inventory, key) {
            Resolution::Record(record) => {
                if value_digest(&record) != *record_digest {
                    return outcome(
                        claim,
                        Outcome::Failed,
                        format!(
                            "record_digest_mismatch: the retained record at \
                             {inventory}/{key} no longer digests to the bound digest"
                        ),
                    );
                }
                records.push(record);
            }
            Resolution::BeyondCeiling => {
                return outcome(
                    claim,
                    Outcome::Unavailable,
                    format!(
                        "beyond_retained_ceiling: {inventory}/{key} is past the \
                         retained rows of a truncated inventory"
                    ),
                );
            }
            Resolution::Absent => {
                return outcome(
                    claim,
                    Outcome::Failed,
                    format!(
                        "record_absent: the bound export carries no record at \
                         {inventory}/{key}"
                    ),
                );
            }
            Resolution::NotApplicable => {
                return outcome(
                    claim,
                    Outcome::Inapplicable,
                    format!(
                        "inventory_not_applicable: inventory '{inventory}' is not \
                         part of the bound export"
                    ),
                );
            }
        }
    }
    let statement = claim
        .statement
        .as_object()
        .expect("shape validation requires object statements");
    for (field, asserted) in statement {
        let mut carried = false;
        let mut contradicted = false;
        for record in &records {
            if let Some(actual) = record.get(field) {
                carried = true;
                if actual != asserted {
                    contradicted = true;
                }
            }
        }
        if contradicted {
            return outcome(
                claim,
                Outcome::Failed,
                format!(
                    "statement_contradicted: a bound record contradicts the \
                     statement's '{field}'"
                ),
            );
        }
        if !carried {
            return outcome(
                claim,
                Outcome::Failed,
                format!(
                    "statement_key_not_carried: no bound record carries the \
                     statement's '{field}'"
                ),
            );
        }
    }
    outcome(
        claim,
        Outcome::Verified,
        "bound evidence resolves, digests match, and the records state the claim".to_string(),
    )
}

/// The aggregate over a set of outcomes (SPEC §4.1.8):
/// mechanical and total. `revision_drift` caps at `partial`.
/// A set with no verified claim — all inapplicable — is
/// `partial`: nothing was established, and nothing failed.
pub fn aggregate(outcomes: &[ClaimOutcome], revision_drift: bool) -> Aggregate {
    if outcomes.iter().any(|o| o.outcome == Outcome::Failed) {
        return Aggregate::Failed;
    }
    if revision_drift || outcomes.iter().any(|o| o.outcome == Outcome::Unavailable) {
        return Aggregate::Partial;
    }
    if outcomes.iter().any(|o| o.outcome == Outcome::Verified) {
        return Aggregate::Verified;
    }
    Aggregate::Partial
}

/// Gate-critical claims whose outcome is not `verified`
/// (SPEC §4.1.8): in v1, the `coverage` claims (D-092 Q2).
pub fn gate_critical_unverified(outcomes: &[ClaimOutcome]) -> Vec<String> {
    outcomes
        .iter()
        .filter(|o| o.class.gate_critical() && o.outcome != Outcome::Verified)
        .map(|o| o.claim_id.clone())
        .collect()
}

/// The subject key shared with the §9.1 export cache: the
/// first 32 hex chars of the subject SHA-256.
fn subject_key(subject_sha256: &str) -> &str {
    &subject_sha256[..subject_sha256.len().min(32)]
}

/// The cached export document's path for (subject, mode) —
/// the §9.1 cache layout, named here so the ledger and the
/// engine agree on where retained evidence lives.
pub fn retained_export_path(config: &Config, subject_sha256: &str, mode: &str) -> PathBuf {
    config
        .state_dir
        .join("ghidra")
        .join(subject_key(subject_sha256))
        .join(format!("export-{mode}.json"))
}

/// The retained export document for (subject, mode), read
/// without creating anything and without running a provider:
/// `Some` only when the file exists and parses.
pub fn read_retained_export(config: &Config, subject_sha256: &str, mode: &str) -> Option<Value> {
    let bytes = std::fs::read(retained_export_path(config, subject_sha256, mode)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The directory one subject's proofs live in (SPEC §4.1.10).
/// Read paths use this directly, never [`paths::state_subdir`],
/// so verification creates nothing.
pub fn proofs_dir(config: &Config, subject_sha256: &str) -> PathBuf {
    config
        .state_dir
        .join("proofs")
        .join(subject_key(subject_sha256))
}

/// One stored proof's path.
pub fn proof_path(config: &Config, subject_sha256: &str, proof_id: &str) -> PathBuf {
    proofs_dir(config, subject_sha256).join(format!("{proof_id}.json"))
}

/// Validate a caller-supplied `proof_id` before it reaches
/// the filesystem: the ids this server assigns are derived
/// hex, and nothing caller-shaped may become a path.
pub fn validate_proof_id(proof_id: &str) -> Result<(), FathomError> {
    if proof_id.is_empty()
        || proof_id.len() > 64
        || !proof_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(invalid("proof_id must be 1–64 characters of [A-Za-z0-9-]"));
    }
    Ok(())
}

/// How many proofs the store holds for one subject.
pub fn count_stored_proofs(config: &Config, subject_sha256: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(proofs_dir(config, subject_sha256)) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .count()
}

/// Load one stored proof by id. `Ok(None)` is an absent
/// proof; a stored body that does not parse, exceeds the
/// byte bound, or names a different id than its file is an
/// integrity failure, not an absence.
pub fn load_stored_proof(
    config: &Config,
    subject_sha256: &str,
    proof_id: &str,
) -> Result<Option<Value>, FathomError> {
    validate_proof_id(proof_id)?;
    let path = proof_path(config, subject_sha256, proof_id);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot read stored proof {}: {error}", path.display()),
            ));
        }
    };
    if bytes.len() > PROOF_BYTES_MAX {
        return Err(invalid(format!(
            "stored proof '{proof_id}' exceeds PROOF_BYTES_MAX ({PROOF_BYTES_MAX})"
        )));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("stored proof '{proof_id}' is not valid JSON: {error}"),
        )
    })?;
    if value.get("proof_id").and_then(Value::as_str) != Some(proof_id) {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("stored proof file '{proof_id}.json' names a different proof_id in its body"),
        ));
    }
    Ok(Some(value))
}

/// Store one proof under its id, creating the subject's
/// proof directory (which lives under the state dir, like
/// every provider write). Returns the path written.
pub fn store_proof(
    config: &Config,
    subject_sha256: &str,
    proof_id: &str,
    canonical: &str,
) -> Result<PathBuf, FathomError> {
    validate_proof_id(proof_id)?;
    let proofs_root = paths::state_subdir(config, "proofs")?;
    let dir = proofs_root.join(subject_key(subject_sha256));
    std::fs::create_dir_all(&dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create proof dir {}: {error}", dir.display()),
        )
    })?;
    let path = dir.join(format!("{proof_id}.json"));
    std::fs::write(&path, canonical).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot store proof {}: {error}", path.display()),
        )
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small retained overview document: two functions, one
    /// symbol, two defined strings, one data string, whole.
    fn overview_document() -> Value {
        json!({
            "data_strings": [{"address": "00403000", "value": "data-0"}],
            "data_strings_total": 1,
            "data_strings_truncated": false,
            "functions": [
                {"address": "00401000", "body_size": 42, "calling_convention": "__fastcall",
                 "classification": "defined", "name": "fn-0", "signature": "void fn-0(void)"},
                {"address": "00401020", "body_size": 16, "calling_convention": "__fastcall",
                 "classification": "defined", "name": "fn-1", "signature": "void fn-1(void)"},
            ],
            "functions_total": 2,
            "functions_truncated": false,
            "program": {"address_size": "64", "compiler_spec": "gcc",
                "executable_format": "ELF", "image_base": "00400000",
                "language_id": "x86:LE:64:default", "name": "sample"},
            "strings": [
                {"address": "00402000", "value": "str-0"},
                {"address": "00402020", "value": "str-1"},
            ],
            "strings_total": 2,
            "strings_truncated": false,
            "symbols": [
                {"address": "00401000", "name": "fn-0", "source": "DEFAULT", "type": "Function"},
            ],
            "symbols_total": 1,
            "symbols_truncated": false,
        })
    }

    fn bound_claim(
        claim_id: &str,
        class: &str,
        document: &Value,
        dossier: bool,
        inventory: &str,
        key: &str,
        statement: Value,
    ) -> Value {
        let record = match resolve_record(document, dossier, inventory, key) {
            Resolution::Record(record) => record,
            other => panic!("fixture record must resolve, got {other:?}"),
        };
        let class_enum = ClaimClass::parse(class).unwrap();
        let confidence = class_enum.confidence(&[inventory]);
        json!({
            "claim_id": claim_id,
            "class": class,
            "confidence": confidence_str(confidence),
            "evidence": [{
                "inventory": inventory,
                "key": key,
                "record_digest": value_digest(&record),
            }],
            "statement": statement,
        })
    }

    fn proof_around(document: &Value, claims: Vec<Value>) -> Proof {
        let mut value = json!({
            "claims": claims,
            "export": {"digest": value_digest(document), "mode": "overview"},
            "producer": {
                "catalog_digest": "c".repeat(64),
                "provider": "ghidra",
                "server": "fathom",
                "source_revision": "test",
                "version": "0.0.0",
            },
            "proof_version": 1,
            "subject": {"path": "/fixtures/sample", "sha256": "a".repeat(64), "size_bytes": 3},
        });
        let digest = compute_proof_digest(&value);
        value["proof_digest"] = json!(digest);
        parse_proof(&value).expect("fixture proof parses")
    }

    #[test]
    fn validation_canonical_json_is_key_order_independent() {
        let a = json!({"b": 1, "a": {"d": [1, 2], "c": "x"}});
        let b: Value = serde_json::from_str("{\"a\":{\"c\":\"x\",\"d\":[1,2]},\"b\":1}").unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(value_digest(&a), value_digest(&b));
    }

    #[test]
    fn validation_resolve_record_reads_the_overview_inventories() {
        let document = overview_document();
        let function = match resolve_record(&document, false, "functions", "00401000") {
            Resolution::Record(record) => record,
            other => panic!("functions must resolve, got {other:?}"),
        };
        assert_eq!(function["name"], "fn-0");
        assert!(matches!(
            resolve_record(&document, false, "names", "00401000"),
            Resolution::Record(_)
        ));
        assert!(matches!(
            resolve_record(&document, false, "strings", "00402020"),
            Resolution::Record(_)
        ));
        let coverage = match resolve_record(&document, false, "coverage", "functions") {
            Resolution::Record(record) => record,
            other => panic!("coverage must resolve, got {other:?}"),
        };
        assert_eq!(coverage["retained"], 2);
        assert_eq!(coverage["total"], 2);
        assert_eq!(coverage["exhaustive"], true);
        let program = match resolve_record(&document, false, "program", "sample") {
            Resolution::Record(record) => record,
            other => panic!("program must resolve, got {other:?}"),
        };
        assert_eq!(program["executable_format"], "ELF");
    }

    #[test]
    fn validation_class_confidence_table_is_the_contract() {
        assert_eq!(
            ClaimClass::FunctionPurpose.confidence(&["call_graph"]),
            Confidence::Inferred
        );
        assert_eq!(
            ClaimClass::StringAssertion.confidence(&["strings"]),
            Confidence::Observed
        );
        assert_eq!(
            ClaimClass::StringAssertion.confidence(&["data_strings"]),
            Confidence::Derived
        );
        assert!(ClaimClass::Coverage.gate_critical());
        assert!(!ClaimClass::FunctionPurpose.gate_critical());
    }

    #[test]
    fn validation_bound_claim_verifies() {
        let document = overview_document();
        let claim = bound_claim(
            "c1",
            "function_identity",
            &document,
            false,
            "functions",
            "00401000",
            json!({"name": "fn-0", "signature": "void fn-0(void)"}),
        );
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, Outcome::Verified);
        assert_eq!(aggregate(&outcomes, false), Aggregate::Verified);
    }

    #[test]
    fn adversarial_unbound_claim_fails_against_a_perfect_export() {
        // SPEC §4.1.11 test 1, core half: bare identifiers,
        // no locators, no digests — failed, aggregate failed.
        let document = overview_document();
        let claim = json!({
            "claim_id": "c1",
            "class": "function_identity",
            "confidence": "observed",
            "evidence": ["fn-0", "00401000"],
            "statement": {"name": "fn-0"},
        });
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Failed);
        assert!(outcomes[0].diagnostic.starts_with("unbound_evidence"));
        assert_eq!(aggregate(&outcomes, false), Aggregate::Failed);
    }

    #[test]
    fn adversarial_statement_contradiction_fails() {
        let document = overview_document();
        let claim = bound_claim(
            "c1",
            "function_identity",
            &document,
            false,
            "functions",
            "00401000",
            json!({"name": "not-fn-0"}),
        );
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Failed);
        assert!(outcomes[0].diagnostic.starts_with("statement_contradicted"));
    }

    #[test]
    fn adversarial_statement_key_no_record_carries_fails() {
        let document = overview_document();
        let claim = bound_claim(
            "c1",
            "function_identity",
            &document,
            false,
            "functions",
            "00401000",
            json!({"moon_phase": "waxing"}),
        );
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Failed);
        assert!(
            outcomes[0]
                .diagnostic
                .starts_with("statement_key_not_carried")
        );
    }

    #[test]
    fn adversarial_beyond_ceiling_is_unavailable_not_failed() {
        // SPEC §4.1.11 test 4, core half.
        let mut document = overview_document();
        document["functions_truncated"] = json!(true);
        document["functions_total"] = json!(10);
        let claim = json!({
            "claim_id": "c1",
            "class": "function_identity",
            "confidence": "observed",
            "evidence": [{
                "inventory": "functions",
                "key": "00409999",
                "record_digest": "0".repeat(64),
            }],
            "statement": {"name": "ghost"},
        });
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Unavailable);
        assert_eq!(aggregate(&outcomes, false), Aggregate::Partial);
    }

    #[test]
    fn adversarial_coverage_overclaim_over_a_truncated_inventory_fails() {
        // SPEC §4.1.11 test 4, second half: the export states
        // its own counts, so the overclaim is a contradiction.
        let mut document = overview_document();
        document["functions_truncated"] = json!(true);
        document["functions_total"] = json!(10);
        let claim = bound_claim(
            "c1",
            "coverage",
            &document,
            false,
            "coverage",
            "functions",
            json!({"exhaustive": true, "retained": 2, "total": 10}),
        );
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Failed);
        assert_eq!(gate_critical_unverified(&outcomes), vec!["c1".to_string()]);
    }

    #[test]
    fn adversarial_inapplicable_inventory_is_not_a_failure() {
        let document = overview_document();
        let claim = json!({
            "claim_id": "c1",
            "class": "call_relationship",
            "confidence": "derived",
            "evidence": [{
                "inventory": "call_graph",
                "key": "00401000",
                "record_digest": "0".repeat(64),
            }],
            "statement": {"callers": ["main"]},
        });
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Inapplicable);
        // Nothing established, nothing failed: partial.
        assert_eq!(aggregate(&outcomes, false), Aggregate::Partial);
    }

    #[test]
    fn adversarial_drift_caps_the_aggregate_at_partial() {
        // SPEC §4.1.11 test 5, core half.
        let document = overview_document();
        let claim = bound_claim(
            "c1",
            "function_identity",
            &document,
            false,
            "functions",
            "00401000",
            json!({"name": "fn-0"}),
        );
        let proof = proof_around(&document, vec![claim]);
        let outcomes = verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Verified);
        assert_eq!(aggregate(&outcomes, true), Aggregate::Partial);
        assert!(producer_drifted(
            &json!({"catalog_digest": "a", "source_revision": "r1", "version": "1"}),
            &json!({"catalog_digest": "a", "source_revision": "r2", "version": "1"}),
        ));
    }

    #[test]
    fn adversarial_parse_proof_refuses_bad_shapes() {
        let document = overview_document();
        let claim = bound_claim(
            "c1",
            "function_identity",
            &document,
            false,
            "functions",
            "00401000",
            json!({"name": "fn-0"}),
        );
        let base = proof_around(&document, vec![claim]).value;
        // Unknown version.
        let mut bad = base.clone();
        bad["proof_version"] = json!(99);
        assert_eq!(
            parse_proof(&bad).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        // Unknown class.
        let mut bad = base.clone();
        bad["claims"][0]["class"] = json!("telepathy");
        assert_eq!(
            parse_proof(&bad).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        // Duplicate claim ids.
        let mut bad = base.clone();
        bad["claims"] = json!([base["claims"][0].clone(), base["claims"][0].clone()]);
        assert_eq!(
            parse_proof(&bad).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        // Non-object statement.
        let mut bad = base.clone();
        bad["claims"][0]["statement"] = json!("prose, not facts");
        assert_eq!(
            parse_proof(&bad).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
}
