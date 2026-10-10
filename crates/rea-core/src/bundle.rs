//! Evidence bundles (SPEC §6).
//!
//! A bundle packages evidence envelopes with a digest over their
//! canonical concatenation. Verification re-checks the digest and
//! — where a subject file is still reachable under the target
//! roots — re-hashes the subject, because a valid bundle ID alone
//! does not establish that subject identities agree (upstream's
//! rule).

use serde_json::{Value, json};
use std::path::Path;

use crate::config::Config;
use crate::error::{ErrorCode, ReaError};
use crate::evidence::{Confidence, Evidence, Finding, sha256_hex};
use crate::paths;

/// Build a bundle value from evidence envelopes.
pub fn build_bundle(results: &[Value]) -> Result<Value, ReaError> {
    if results.is_empty() {
        return Err(ReaError::new(
            ErrorCode::InvalidRequest,
            "a bundle needs at least one evidence result",
        ));
    }
    for result in results {
        let shaped = result.get("tool").is_some()
            && result.get("provider").is_some()
            && result.get("findings").is_some();
        if !shaped {
            return Err(ReaError::new(
                ErrorCode::InvalidRequest,
                "every bundle member must be an evidence envelope (tool, provider, findings)",
            ));
        }
    }
    let digest = bundle_digest(results);
    Ok(json!({
        "bundle_digest": digest,
        "count": results.len(),
        "results": results,
    }))
}

/// The digest rule: SHA-256 over the canonical (compact, key
/// order as serialized) concatenation of member envelopes.
pub fn bundle_digest(results: &[Value]) -> String {
    let mut material = String::new();
    for result in results {
        material.push_str(&serde_json::to_string(result).unwrap_or_default());
        material.push('\n');
    }
    sha256_hex(material.as_bytes())
}

/// Verify a bundle: digest integrity plus per-subject re-hash
/// where the subject is reachable. Returns an evidence envelope
/// describing the verification itself.
pub fn verify_bundle(config: &Config, bundle: &Value) -> Result<Evidence, ReaError> {
    let results = bundle
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ReaError::new(ErrorCode::InvalidRequest, "bundle has no results array"))?;
    let claimed = bundle
        .get("bundle_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| ReaError::new(ErrorCode::InvalidRequest, "bundle has no bundle_digest"))?;
    if bundle_digest(results) != claimed {
        return Err(ReaError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "bundle digest does not match its contents",
        ));
    }
    let mut evidence = Evidence::new("verify_evidence_bundle", "core");
    evidence.coverage.total = results.len() as u64;
    for result in results {
        let subject = result.get("subject");
        let (path, sha) = match subject {
            Some(subject) => (
                subject.get("path").and_then(Value::as_str),
                subject.get("sha256").and_then(Value::as_str),
            ),
            None => (None, None),
        };
        match (path, sha) {
            (Some(path), Some(sha)) => match paths::validate_target(config, Path::new(path)) {
                Ok(canonical) => match crate::evidence::hash_file(&canonical) {
                    Ok((actual, _)) => {
                        evidence.coverage.examined += 1;
                        evidence.add_finding(Finding::new(
                            "subject_verification",
                            Confidence::Observed,
                            json!({
                                "path": path,
                                "claimed_sha256": sha,
                                "actual_sha256": actual,
                                "match": actual == sha,
                            }),
                        ));
                        if actual != sha {
                            return Err(ReaError::new(
                                ErrorCode::EvidenceIntegrityMismatch,
                                format!("subject {path} no longer hashes to its evidence digest"),
                            ));
                        }
                    }
                    Err(e) => {
                        evidence.add_unknown(format!("subject re-hash: {path}"), e.message.clone());
                    }
                },
                Err(e) => {
                    evidence.add_unknown(format!("subject re-hash: {path}"), e.message.clone());
                }
            },
            _ => {
                evidence.add_unknown(
                    "subject re-hash",
                    "bundle member carries no subject identity to cross-check",
                );
            }
        }
    }
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigFile;

    fn member() -> Value {
        json!({
            "tool": "inspect_artifact",
            "provider": "artifact",
            "findings": [],
        })
    }

    #[test]
    fn adversarial_empty_bundle_is_rejected() {
        assert!(build_bundle(&[]).is_err());
    }

    #[test]
    fn adversarial_unshaped_member_is_rejected() {
        let err = build_bundle(&[json!({"nope": true})]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_tampered_bundle_fails_digest() {
        let mut bundle = build_bundle(&[member()]).unwrap();
        bundle["results"][0]["findings"] = json!([{"kind": "forged"}]);
        let config = Config::restrictive_default();
        let err = verify_bundle(&config, &bundle).unwrap_err();
        assert_eq!(err.code, ErrorCode::EvidenceIntegrityMismatch);
    }

    #[test]
    fn validation_bundle_round_trip() {
        let bundle = build_bundle(&[member()]).unwrap();
        let config = Config::from_file_form(ConfigFile::default()).unwrap();
        let evidence = verify_bundle(&config, &bundle).unwrap();
        // Member has no subject: recorded as unknown, not as a pass.
        assert_eq!(evidence.unknowns.len(), 1);
    }
}
