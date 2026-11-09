//! The ledger-bound behaviour-check stage (D-1097).
//!
//! For one remade title, every measured constant and behaviour
//! in its dynamics spec becomes an obligation in a digest-bound
//! ledger. An obligation is discharged only by a fixture run
//! whose retained artifact the evaluator re-resolves and
//! re-checks against the measured claim, or it stands open —
//! with its reason, or as the gate's problem. The stage is a
//! pipeline stage, not a tool: this module models, parses, and
//! evaluates ledgers, and does nothing else. It spawns no
//! process, runs no fixture, and writes nothing — the §4.1
//! verification posture applied to behaviour records.
//!
//! Outcomes are per-obligation, always. No scalar, ratio, or
//! percentage is computed anywhere in this module: a title
//! counts as checked when nothing is silently outstanding,
//! and the verdict block names what blocks it when it is not.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

use crate::error::{ErrorCode, FathomError};
use crate::limits::{
    BEHAVIOUR_BYTES_MAX, BEHAVIOUR_CLAIM_BYTES_MAX, BEHAVIOUR_DIAGNOSTIC_CHARS_MAX,
    BEHAVIOUR_OBLIGATIONS_MAX, BEHAVIOUR_REASON_CHARS_MAX,
};
use crate::proof::{canonical_json, value_digest};

/// The one ledger serialization this build reads and writes.
/// An unknown version is refused, never defaulted or migrated
/// silently (the §4.1.5 discipline, restated for ledgers).
pub const BEHAVIOUR_LEDGER_VERSION: u64 = 1;

/// The one comparison rule this version defines: the
/// discharge's observed facts are checked field-by-field
/// against the claim — every claim key present with an equal
/// value; extra observed keys are not the claim's business
/// (§4.1.7 rule 6). A ledger naming another rule is refused
/// at parse time; the rule set grows by amendment.
pub const COMPARISON_EXACT: &str = "exact";

/// What one obligation binds. The set is closed: a kind
/// outside this table is refused at parse time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationKind {
    /// An observable run outcome of the remake.
    Behaviour,
    /// A tuning value the remake must carry and apply.
    Constant,
    /// Equality of behaviour across runs or platforms.
    Determinism,
}

impl ObligationKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "behaviour" => Some(ObligationKind::Behaviour),
            "constant" => Some(ObligationKind::Constant),
            "determinism" => Some(ObligationKind::Determinism),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ObligationKind::Behaviour => "behaviour",
            ObligationKind::Constant => "constant",
            ObligationKind::Determinism => "determinism",
        }
    }
}

/// The discharge record an obligation may carry: the binding
/// of one fixture run to this claim. The evaluator trusts
/// none of it until it has re-resolved the artifact and
/// re-checked the digest (see [`evaluate`]).
#[derive(Clone, Debug)]
pub struct Discharge {
    /// Id of the retained fixture artifact, resolved against
    /// the artifact set presented at evaluation.
    pub artifact: String,
    /// SHA-256 of the retained artifact's bytes, recorded by
    /// the fixture runner.
    pub artifact_sha256: String,
    /// Facts the fixture run produced, in the same rendering
    /// the claim states its facts.
    pub observed: Value,
    /// The producing runner's identity (implementation,
    /// version, source revision) — the §4.1.5 producer
    /// binding, restated for pipeline runners.
    pub runner: Value,
}

/// One obligation of a parsed ledger.
#[derive(Clone, Debug)]
pub struct Obligation {
    pub claim: Value,
    pub discharge: Option<Discharge>,
    pub fixture_id: String,
    pub fixture_runner: String,
    pub kind: ObligationKind,
    pub obligation_id: String,
    pub open_reason: Option<String>,
    pub spec_document: String,
    pub spec_locator: String,
}

/// A behaviour ledger that passed shape validation. Shape
/// runs before any digest or artifact work, so a malformed
/// ledger is refused before any evaluation.
#[derive(Clone, Debug)]
pub struct BehaviourLedger {
    pub ledger_digest: String,
    pub obligations: Vec<Obligation>,
    pub spec_document: String,
    pub spec_sha256: String,
    pub title: String,
    /// The ledger as presented, retained so evaluation can
    /// recompute the digest over exactly what was authored;
    /// outcomes are never read from it.
    pub value: Value,
}

/// The digest a ledger carries: SHA-256 over its canonical
/// form with the `ledger_digest` field itself removed (the
/// `proof::compute_proof_digest` discipline, restated).
pub fn compute_ledger_digest(ledger: &Value) -> String {
    let mut material = ledger.clone();
    if let Some(object) = material.as_object_mut() {
        object.remove("ledger_digest");
    }
    value_digest(&material)
}

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message)
}

fn is_digest(raw: &str) -> bool {
    raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit())
}

/// One required non-empty string field of an object.
fn required_str(
    object: &serde_json::Map<String, Value>,
    field: &str,
    owner: &str,
) -> Result<String, FathomError> {
    match object.get(field).and_then(Value::as_str) {
        Some(raw) if !raw.is_empty() => Ok(raw.to_string()),
        _ => Err(invalid(format!(
            "{owner}: field '{field}' must be a non-empty string"
        ))),
    }
}

/// One required facts object (`claim` / `observed`): an
/// object, never prose, within the canonical byte bound.
fn facts_object(
    object: &serde_json::Map<String, Value>,
    field: &str,
    owner: &str,
) -> Result<Value, FathomError> {
    let value = object.get(field).cloned().unwrap_or(Value::Null);
    if !value.is_object() {
        return Err(invalid(format!(
            "{owner}: field '{field}' must be an object of structured facts"
        )));
    }
    if canonical_json(&value).len() > BEHAVIOUR_CLAIM_BYTES_MAX {
        return Err(invalid(format!(
            "{owner}: field '{field}' exceeds BEHAVIOUR_CLAIM_BYTES_MAX \
             ({BEHAVIOUR_CLAIM_BYTES_MAX}) canonical bytes"
        )));
    }
    Ok(value)
}

fn parse_discharge(
    object: &serde_json::Map<String, Value>,
    owner: &str,
) -> Result<Option<Discharge>, FathomError> {
    let Some(raw) = object.get("discharge") else {
        return Ok(None);
    };
    let Some(fields) = raw.as_object() else {
        return Err(invalid(format!("{owner}: 'discharge' must be an object")));
    };
    let artifact = required_str(fields, "artifact", owner)?;
    let artifact_sha256 = required_str(fields, "artifact_sha256", owner)?;
    if !is_digest(&artifact_sha256) {
        return Err(invalid(format!(
            "{owner}: 'artifact_sha256' must be a SHA-256 hex digest"
        )));
    }
    let runner = fields.get("runner").cloned().unwrap_or(Value::Null);
    let Some(runner_fields) = runner.as_object() else {
        return Err(invalid(format!(
            "{owner}: discharge 'runner' must be an object"
        )));
    };
    for field in ["implementation", "version", "source_revision"] {
        required_str(runner_fields, field, owner)?;
    }
    let observed = facts_object(fields, "observed", owner)?;
    Ok(Some(Discharge {
        artifact,
        artifact_sha256,
        observed,
        runner,
    }))
}

fn parse_obligation(raw: &Value, index: usize) -> Result<Obligation, FathomError> {
    let owner = format!("obligation {index}");
    let Some(fields) = raw.as_object() else {
        return Err(invalid(format!("{owner}: must be an object")));
    };
    let obligation_id = required_str(fields, "obligation_id", &owner)?;
    let owner = format!("obligation '{obligation_id}'");
    let kind_raw = required_str(fields, "kind", &owner)?;
    let Some(kind) = ObligationKind::parse(&kind_raw) else {
        return Err(invalid(format!("{owner}: unknown kind '{kind_raw}'")));
    };
    let spec_source = fields.get("spec_source").cloned().unwrap_or(Value::Null);
    let Some(spec_fields) = spec_source.as_object() else {
        return Err(invalid(format!("{owner}: 'spec_source' must be an object")));
    };
    let spec_document = required_str(spec_fields, "document", &owner)?;
    let spec_locator = required_str(spec_fields, "locator", &owner)?;
    let claim = facts_object(fields, "claim", &owner)?;
    let fixture = fields.get("fixture").cloned().unwrap_or(Value::Null);
    let Some(fixture_fields) = fixture.as_object() else {
        return Err(invalid(format!("{owner}: 'fixture' must be an object")));
    };
    let fixture_id = required_str(fixture_fields, "fixture_id", &owner)?;
    let fixture_runner = required_str(fixture_fields, "runner", &owner)?;
    let comparison = required_str(fixture_fields, "comparison", &owner)?;
    if comparison != COMPARISON_EXACT {
        return Err(invalid(format!(
            "{owner}: unknown comparison rule '{comparison}'"
        )));
    }
    let open_reason = match fields.get("open_reason") {
        None => None,
        Some(raw) => {
            let Some(text) = raw.as_str().filter(|text| !text.is_empty()) else {
                return Err(invalid(format!(
                    "{owner}: 'open_reason' must be a non-empty string"
                )));
            };
            if text.chars().count() > BEHAVIOUR_REASON_CHARS_MAX {
                return Err(invalid(format!(
                    "{owner}: 'open_reason' exceeds BEHAVIOUR_REASON_CHARS_MAX \
                     ({BEHAVIOUR_REASON_CHARS_MAX}) characters"
                )));
            }
            Some(text.to_string())
        }
    };
    let discharge = parse_discharge(fields, &owner)?;
    if discharge.is_some() && open_reason.is_some() {
        return Err(invalid(format!(
            "{owner}: carries both discharge evidence and an open reason; \
             the record is contradictory"
        )));
    }
    Ok(Obligation {
        claim,
        discharge,
        fixture_id,
        fixture_runner,
        kind,
        obligation_id,
        open_reason,
        spec_document,
        spec_locator,
    })
}

/// Shape-validate a ledger value: version, kinds, unique
/// obligation ids, bounds, object claims, contradictory
/// records. The digest is *not* checked here — that is
/// evaluation's first step, as in §4.1.7.
pub fn parse_ledger(value: &Value) -> Result<BehaviourLedger, FathomError> {
    if canonical_json(value).len() > BEHAVIOUR_BYTES_MAX {
        return Err(invalid(format!(
            "ledger exceeds BEHAVIOUR_BYTES_MAX ({BEHAVIOUR_BYTES_MAX}) serialized bytes"
        )));
    }
    let Some(fields) = value.as_object() else {
        return Err(invalid("ledger must be a JSON object"));
    };
    let version = fields.get("ledger_version").and_then(Value::as_u64);
    if version != Some(BEHAVIOUR_LEDGER_VERSION) {
        return Err(invalid(format!(
            "unknown ledger_version {version:?}; this build reads \
             {BEHAVIOUR_LEDGER_VERSION}"
        )));
    }
    let title = required_str(fields, "title", "ledger")?;
    let spec = fields.get("spec").cloned().unwrap_or(Value::Null);
    let Some(spec_fields) = spec.as_object() else {
        return Err(invalid("ledger: 'spec' must be an object"));
    };
    let spec_document = required_str(spec_fields, "document", "ledger spec")?;
    let spec_sha256 = required_str(spec_fields, "sha256", "ledger spec")?;
    if !is_digest(&spec_sha256) {
        return Err(invalid(
            "ledger spec: 'sha256' must be a SHA-256 hex digest",
        ));
    }
    let ledger_digest = required_str(fields, "ledger_digest", "ledger")?;
    if !is_digest(&ledger_digest) {
        return Err(invalid(
            "ledger: 'ledger_digest' must be a SHA-256 hex digest",
        ));
    }
    let Some(raw_obligations) = fields.get("obligations").and_then(Value::as_array) else {
        return Err(invalid("ledger: 'obligations' must be an array"));
    };
    if raw_obligations.len() > BEHAVIOUR_OBLIGATIONS_MAX {
        return Err(invalid(format!(
            "ledger: {} obligations exceeds BEHAVIOUR_OBLIGATIONS_MAX \
             ({BEHAVIOUR_OBLIGATIONS_MAX})",
            raw_obligations.len()
        )));
    }
    let mut obligations = Vec::with_capacity(raw_obligations.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (index, raw) in raw_obligations.iter().enumerate() {
        let obligation = parse_obligation(raw, index)?;
        if !seen.insert(obligation.obligation_id.clone()) {
            return Err(invalid(format!(
                "ledger: duplicate obligation_id '{}'",
                obligation.obligation_id
            )));
        }
        obligations.push(obligation);
    }
    Ok(BehaviourLedger {
        ledger_digest,
        obligations,
        spec_document,
        spec_sha256,
        title,
        value: value.clone(),
    })
}

/// The one outcome evaluation assigns to one obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationOutcome {
    /// A fixture run's resolved, digest-matched evidence
    /// states every claim fact.
    Discharged,
    /// Discharge evidence is cited but cannot be resolved as
    /// cited: the artifact is absent, or its digest differs.
    EvidenceUnavailable,
    /// Resolved evidence contradicts the claim.
    Failed,
    /// No discharge and no reason: unexplained.
    Open,
    /// No discharge; a reason is recorded.
    OpenWithReason,
}

impl ObligationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            ObligationOutcome::Discharged => "discharged",
            ObligationOutcome::EvidenceUnavailable => "evidence_unavailable",
            ObligationOutcome::Failed => "failed",
            ObligationOutcome::Open => "open",
            ObligationOutcome::OpenWithReason => "open_with_reason",
        }
    }
}

/// One obligation's outcome with its bounded diagnostic.
#[derive(Clone, Debug)]
pub struct ObligationVerdict {
    pub diagnostic: String,
    pub obligation_id: String,
    pub outcome: ObligationOutcome,
}

/// The stage's gate verdict for one title. Mechanical and
/// total: derived from the per-obligation outcomes alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateVerdict {
    /// Something is failed, unexplained, unresolvable, or
    /// nothing was discharged at all.
    Blocked,
    /// Every obligation is discharged or stands open with
    /// its reason, and at least one is discharged.
    Checked,
}

impl GateVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            GateVerdict::Blocked => "blocked",
            GateVerdict::Checked => "checked",
        }
    }
}

/// The evaluation of one ledger: the gate verdict, any gate
/// notes the derivation owes the reader, and one verdict per
/// obligation, in ledger order.
#[derive(Clone, Debug)]
pub struct BehaviourEvaluation {
    pub notes: Vec<String>,
    pub outcomes: Vec<ObligationVerdict>,
    pub verdict: GateVerdict,
}

impl BehaviourEvaluation {
    /// How many obligations carry the given outcome.
    pub fn count(&self, outcome: ObligationOutcome) -> usize {
        self.outcomes
            .iter()
            .filter(|verdict| verdict.outcome == outcome)
            .count()
    }

    /// The ids of the obligations carrying the given outcome,
    /// in ledger order.
    pub fn ids_with(&self, outcome: ObligationOutcome) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|verdict| verdict.outcome == outcome)
            .map(|verdict| verdict.obligation_id.as_str())
            .collect()
    }

    /// The verdict block as canonical JSON: counts as
    /// accounting, blocking ids named by category, and one
    /// outcome record per obligation. No ratio is derived
    /// from the counts anywhere.
    pub fn to_value(&self, title: &str) -> Value {
        let outcomes: Vec<Value> = self
            .outcomes
            .iter()
            .map(|verdict| {
                json!({
                    "diagnostic": verdict.diagnostic,
                    "obligation_id": verdict.obligation_id,
                    "outcome": verdict.outcome.as_str(),
                })
            })
            .collect();
        json!({
            "blocking": {
                "evidence_unavailable": self.ids_with(ObligationOutcome::EvidenceUnavailable),
                "failed": self.ids_with(ObligationOutcome::Failed),
                "open": self.ids_with(ObligationOutcome::Open),
            },
            "counts": {
                "discharged": self.count(ObligationOutcome::Discharged),
                "evidence_unavailable": self.count(ObligationOutcome::EvidenceUnavailable),
                "failed": self.count(ObligationOutcome::Failed),
                "open": self.count(ObligationOutcome::Open),
                "open_with_reason": self.count(ObligationOutcome::OpenWithReason),
            },
            "notes": self.notes,
            "outcomes": outcomes,
            "title": title,
            "verdict": self.verdict.as_str(),
        })
    }
}

fn bounded_diagnostic(message: String) -> String {
    if message.chars().count() > BEHAVIOUR_DIAGNOSTIC_CHARS_MAX {
        message
            .chars()
            .take(BEHAVIOUR_DIAGNOSTIC_CHARS_MAX)
            .collect()
    } else {
        message
    }
}

/// The first claim key the observed facts contradict or do
/// not carry, in sorted key order; `None` when the observed
/// facts state every claim fact (the `exact` rule).
fn first_contradiction(claim: &Value, observed: &Value) -> Option<String> {
    let claim_fields = claim.as_object()?;
    let mut keys: Vec<&String> = claim_fields.keys().collect();
    keys.sort();
    for key in keys {
        if observed.get(key) != claim_fields.get(key) {
            return Some(key.clone());
        }
    }
    None
}

fn evaluate_obligation(
    obligation: &Obligation,
    artifacts: &BTreeMap<String, String>,
) -> ObligationVerdict {
    let verdict = |outcome: ObligationOutcome, diagnostic: String| ObligationVerdict {
        diagnostic: bounded_diagnostic(diagnostic),
        obligation_id: obligation.obligation_id.clone(),
        outcome,
    };
    let Some(discharge) = &obligation.discharge else {
        return match &obligation.open_reason {
            Some(reason) => verdict(ObligationOutcome::OpenWithReason, reason.clone()),
            None => verdict(
                ObligationOutcome::Open,
                "no discharge evidence and no open reason recorded".to_string(),
            ),
        };
    };
    let Some(retained_digest) = artifacts.get(&discharge.artifact) else {
        return verdict(
            ObligationOutcome::EvidenceUnavailable,
            format!(
                "discharge artifact '{}' is not in the retained artifact set",
                discharge.artifact
            ),
        );
    };
    if retained_digest != &discharge.artifact_sha256 {
        return verdict(
            ObligationOutcome::EvidenceUnavailable,
            format!(
                "discharge artifact '{}' digest does not match the retained artifact",
                discharge.artifact
            ),
        );
    }
    match first_contradiction(&obligation.claim, &discharge.observed) {
        None => verdict(
            ObligationOutcome::Discharged,
            "observed states every claim fact".to_string(),
        ),
        Some(key) => verdict(
            ObligationOutcome::Failed,
            format!("observed contradicts the claim at key '{key}'"),
        ),
    }
}

/// Evaluate one ledger against the retained artifact set
/// (artifact id → SHA-256 of its bytes, computed by the
/// caller from the artifact files — this function reads no
/// file and spawns nothing). A ledger whose own digest does
/// not recompute is refused, never evaluated.
pub fn evaluate(
    ledger: &BehaviourLedger,
    artifacts: &BTreeMap<String, String>,
) -> Result<BehaviourEvaluation, FathomError> {
    let recomputed = compute_ledger_digest(&ledger.value);
    if recomputed != ledger.ledger_digest {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!(
                "ledger digest mismatch: the ledger records {} but recomputes to \
                 {recomputed}; a tampered ledger is refused, not evaluated",
                ledger.ledger_digest
            ),
        ));
    }
    let outcomes: Vec<ObligationVerdict> = ledger
        .obligations
        .iter()
        .map(|obligation| evaluate_obligation(obligation, artifacts))
        .collect();
    let discharged = outcomes
        .iter()
        .filter(|verdict| verdict.outcome == ObligationOutcome::Discharged)
        .count();
    let blocking = outcomes.iter().any(|verdict| {
        matches!(
            verdict.outcome,
            ObligationOutcome::EvidenceUnavailable
                | ObligationOutcome::Failed
                | ObligationOutcome::Open
        )
    });
    let mut notes = Vec::new();
    if outcomes.is_empty() {
        notes.push("ledger carries no obligations".to_string());
    } else if discharged == 0 {
        notes.push("no obligation is discharged".to_string());
    }
    let verdict = if blocking || discharged == 0 {
        GateVerdict::Blocked
    } else {
        GateVerdict::Checked
    };
    Ok(BehaviourEvaluation {
        notes,
        outcomes,
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::sha256_hex;

    const ARTIFACT_BYTES: &[u8] = b"fixture run output\n";

    fn artifact_map() -> BTreeMap<String, String> {
        BTreeMap::from([("run.txt".to_string(), sha256_hex(ARTIFACT_BYTES))])
    }

    fn discharge(observed: Value) -> Value {
        json!({
            "artifact": "run.txt",
            "artifact_sha256": sha256_hex(ARTIFACT_BYTES),
            "observed": observed,
            "runner": {
                "implementation": "test runner",
                "source_revision": "test",
                "version": "0",
            },
        })
    }

    fn obligation(id: &str, extra: Value) -> Value {
        let mut base = json!({
            "claim": {"gauge": 219.5479},
            "fixture": {
                "comparison": "exact",
                "fixture_id": "fx",
                "runner": "test",
            },
            "kind": "behaviour",
            "obligation_id": id,
            "spec_source": {"document": "spec.md", "locator": "§1"},
        });
        if let (Some(base_fields), Some(extra_fields)) = (base.as_object_mut(), extra.as_object()) {
            for (key, value) in extra_fields {
                base_fields.insert(key.clone(), value.clone());
            }
        }
        base
    }

    fn ledger_value(obligations: Vec<Value>) -> Value {
        let mut doc = json!({
            "ledger_version": 1,
            "obligations": obligations,
            "spec": {"document": "spec.md", "sha256": "a".repeat(64)},
            "title": "test-title",
        });
        let digest = compute_ledger_digest(&doc);
        doc["ledger_digest"] = json!(digest);
        doc
    }

    fn evaluated(obligations: Vec<Value>) -> BehaviourEvaluation {
        let ledger = parse_ledger(&ledger_value(obligations)).expect("ledger parses");
        evaluate(&ledger, &artifact_map()).expect("ledger evaluates")
    }

    // ---------- validation ----------

    #[test]
    fn validation_discharged_obligation_checks_the_ledger() {
        let evaluation = evaluated(vec![obligation(
            "a.discharged",
            json!({"discharge": discharge(json!({"gauge": 219.5479}))}),
        )]);
        assert_eq!(evaluation.verdict, GateVerdict::Checked);
        assert_eq!(
            evaluation.outcomes[0].outcome,
            ObligationOutcome::Discharged
        );
        assert_eq!(evaluation.count(ObligationOutcome::Discharged), 1);
    }

    #[test]
    fn validation_open_with_reason_travels_without_blocking() {
        let evaluation = evaluated(vec![
            obligation(
                "a.discharged",
                json!({"discharge": discharge(json!({"gauge": 219.5479}))}),
            ),
            obligation(
                "b.waiting",
                json!({"open_reason": "fixture not yet runnable on this host"}),
            ),
        ]);
        assert_eq!(evaluation.verdict, GateVerdict::Checked);
        assert_eq!(
            evaluation.ids_with(ObligationOutcome::OpenWithReason),
            vec!["b.waiting"]
        );
        assert!(evaluation.notes.is_empty());
    }

    #[test]
    fn validation_extra_observed_keys_are_not_the_claims_business() {
        let evaluation = evaluated(vec![obligation(
            "a.discharged",
            json!({"discharge": discharge(json!({
                "extra": "the run also printed this",
                "gauge": 219.5479,
            }))}),
        )]);
        assert_eq!(
            evaluation.outcomes[0].outcome,
            ObligationOutcome::Discharged
        );
    }

    #[test]
    fn validation_key_order_does_not_change_the_digest() {
        let first: Value = serde_json::from_str(
            r#"{"ledger_version": 1, "title": "t", "obligations": [],
                "spec": {"document": "spec.md", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
        )
        .expect("json parses");
        let second: Value = serde_json::from_str(
            r#"{"spec": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "document": "spec.md"},
                "obligations": [], "title": "t", "ledger_version": 1}"#,
        )
        .expect("json parses");
        assert_eq!(
            compute_ledger_digest(&first),
            compute_ledger_digest(&second)
        );
    }

    #[test]
    fn validation_all_open_with_reason_still_blocks() {
        // Gate totality: a ledger that checked nothing has
        // checked nothing, however honest its reasons are.
        let evaluation = evaluated(vec![
            obligation("a.waiting", json!({"open_reason": "reason one"})),
            obligation("b.waiting", json!({"open_reason": "reason two"})),
        ]);
        assert_eq!(evaluation.verdict, GateVerdict::Blocked);
        assert_eq!(evaluation.notes, vec!["no obligation is discharged"]);
    }

    #[test]
    fn validation_empty_ledger_blocks() {
        let evaluation = evaluated(vec![]);
        assert_eq!(evaluation.verdict, GateVerdict::Blocked);
        assert_eq!(evaluation.notes, vec!["ledger carries no obligations"]);
    }

    // ---------- adversarial ----------

    #[test]
    fn adversarial_tampered_ledger_is_refused() {
        let mut doc = ledger_value(vec![obligation(
            "a.discharged",
            json!({"discharge": discharge(json!({"gauge": 219.5479}))}),
        )]);
        doc["obligations"][0]["claim"]["gauge"] = json!(1.0);
        let ledger = parse_ledger(&doc).expect("shape still parses");
        let err = evaluate(&ledger, &artifact_map()).unwrap_err();
        assert_eq!(err.code, ErrorCode::EvidenceIntegrityMismatch);
    }

    #[test]
    fn adversarial_missing_artifact_is_evidence_unavailable() {
        let mut bad = discharge(json!({"gauge": 219.5479}));
        bad["artifact"] = json!("absent.txt");
        let evaluation = evaluated(vec![obligation("a.discharged", json!({"discharge": bad}))]);
        assert_eq!(
            evaluation.outcomes[0].outcome,
            ObligationOutcome::EvidenceUnavailable
        );
        assert_eq!(evaluation.verdict, GateVerdict::Blocked);
    }

    #[test]
    fn adversarial_artifact_digest_mismatch_is_evidence_unavailable() {
        let mut bad = discharge(json!({"gauge": 219.5479}));
        bad["artifact_sha256"] = json!("b".repeat(64));
        let evaluation = evaluated(vec![obligation("a.discharged", json!({"discharge": bad}))]);
        assert_eq!(
            evaluation.outcomes[0].outcome,
            ObligationOutcome::EvidenceUnavailable
        );
        assert_eq!(evaluation.verdict, GateVerdict::Blocked);
    }

    #[test]
    fn adversarial_contradicting_observed_fails_and_names_the_key() {
        let evaluation = evaluated(vec![obligation(
            "a.wrong",
            json!({"discharge": discharge(json!({"gauge": 1.0}))}),
        )]);
        assert_eq!(evaluation.outcomes[0].outcome, ObligationOutcome::Failed);
        assert!(evaluation.outcomes[0].diagnostic.contains("'gauge'"));
        assert_eq!(evaluation.verdict, GateVerdict::Blocked);
    }

    #[test]
    fn adversarial_missing_claim_key_in_observed_fails() {
        let evaluation = evaluated(vec![obligation(
            "a.wrong",
            json!({"discharge": discharge(json!({"other": 219.5479}))}),
        )]);
        assert_eq!(evaluation.outcomes[0].outcome, ObligationOutcome::Failed);
    }

    #[test]
    fn adversarial_unexplained_open_blocks() {
        let evaluation = evaluated(vec![obligation("a.open", json!({}))]);
        assert_eq!(evaluation.outcomes[0].outcome, ObligationOutcome::Open);
        assert_eq!(evaluation.verdict, GateVerdict::Blocked);
        assert_eq!(evaluation.ids_with(ObligationOutcome::Open), vec!["a.open"]);
    }

    #[test]
    fn adversarial_duplicate_obligation_ids_are_refused() {
        let doc = ledger_value(vec![
            obligation("a.same", json!({})),
            obligation("a.same", json!({})),
        ]);
        let err = parse_ledger(&doc).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_reason_and_discharge_together_are_refused() {
        let doc = ledger_value(vec![obligation(
            "a.both",
            json!({
                "discharge": discharge(json!({"gauge": 219.5479})),
                "open_reason": "also open",
            }),
        )]);
        let err = parse_ledger(&doc).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_unknown_shapes_are_refused() {
        // Unknown kind.
        let mut bad_kind = obligation("a.x", json!({}));
        bad_kind["kind"] = json!("vibes");
        assert_eq!(
            parse_ledger(&ledger_value(vec![bad_kind]))
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        // Unknown comparison rule.
        let mut bad_rule = obligation("a.x", json!({}));
        bad_rule["fixture"]["comparison"] = json!("close-enough");
        assert_eq!(
            parse_ledger(&ledger_value(vec![bad_rule]))
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        // Non-object claim (prose is not a claim).
        let mut prose = obligation("a.x", json!({}));
        prose["claim"] = json!("the gauge is about 220");
        assert_eq!(
            parse_ledger(&ledger_value(vec![prose])).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        // Unknown ledger version.
        let mut doc = ledger_value(vec![]);
        doc["ledger_version"] = json!(99);
        assert_eq!(
            parse_ledger(&doc).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn adversarial_oversized_claim_is_refused() {
        let big = "x".repeat(BEHAVIOUR_CLAIM_BYTES_MAX + 1);
        let mut oversized = obligation("a.big", json!({}));
        oversized["claim"] = json!({"blob": big});
        let err = parse_ledger(&ledger_value(vec![oversized])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }
}
