//! The evidence model (SPEC §6).
//!
//! A finding is evidence, not an answer. Every tool result is an
//! [`Evidence`] envelope: subject identity (SHA-256 of the exact
//! bytes), findings with distinct observed/derived/inferred
//! confidence, unknowns for coverage not established, and coverage
//! counts derived from examined records.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use crate::error::{ErrorCode, ReaError};
use crate::limits::TARGET_BYTES_MAX;

/// How a fact in a finding was established. The three never mix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Derived,
    Inferred,
    Observed,
}

/// Whether a run established everything it set out to establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Partial,
}

/// Identity of the exact bytes a result is about.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Subject {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// One evidence-carrying fact.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub kind: String,
    pub confidence: Confidence,
    pub facts: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

impl Finding {
    pub fn new(kind: impl Into<String>, confidence: Confidence, facts: Value) -> Self {
        Finding {
            kind: kind.into(),
            confidence,
            facts,
            locations: Vec::new(),
            limitations: Vec::new(),
        }
    }

    pub fn with_limitation(mut self, limitation: impl Into<String>) -> Self {
        self.limitations.push(limitation.into());
        self
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.locations.push(location.into());
        self
    }
}

/// Coverage the run did not establish, and why.
#[derive(Clone, Debug, Serialize)]
pub struct Unknown {
    pub aspect: String,
    pub reason: String,
}

/// Examined-record counts. Derived from records, never prose.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Coverage {
    pub examined: u64,
    pub total: u64,
    pub exhaustive: bool,
}

/// One tool result: the evidence envelope of SPEC §6.
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub tool: String,
    pub provider: String,
    pub status: Completeness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    pub findings: Vec<Finding>,
    pub unknowns: Vec<Unknown>,
    pub coverage: Coverage,
}

impl Evidence {
    pub fn new(tool: impl Into<String>, provider: impl Into<String>) -> Self {
        Evidence {
            tool: tool.into(),
            provider: provider.into(),
            status: Completeness::Complete,
            subject: None,
            findings: Vec::new(),
            unknowns: Vec::new(),
            coverage: Coverage::default(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Record an aspect this run did not establish. Calling this
    /// marks the envelope partial: unknown coverage is never
    /// presented as complete.
    pub fn add_unknown(&mut self, aspect: impl Into<String>, reason: impl Into<String>) {
        self.unknowns.push(Unknown {
            aspect: aspect.into(),
            reason: reason.into(),
        });
        self.status = Completeness::Partial;
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    pub fn with_subject(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }
}

/// SHA-256 of a byte slice, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Hash a file by streaming it, enforcing the target size bound.
pub fn hash_file(path: &Path) -> Result<(String, u64), ReaError> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        ReaError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target {}: {e}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            ReaError::new(
                ErrorCode::UnreadableOutput,
                format!("cannot read target {}: {e}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > TARGET_BYTES_MAX {
            return Err(ReaError::new(
                ErrorCode::ResourceConstraint,
                format!("target exceeds {TARGET_BYTES_MAX} bytes"),
            )
            .with_target(path.display().to_string()));
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok((out, total))
}

/// Build the [`Subject`] for a file target.
pub fn subject_for_file(path: &Path) -> Result<Subject, ReaError> {
    let (sha256, size_bytes) = hash_file(path)?;
    Ok(Subject {
        path: path.display().to_string(),
        sha256,
        size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_sha256_matches_known_vector() {
        // SHA-256("abc") from FIPS 180-4 examples.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn validation_unknown_marks_envelope_partial() {
        let mut evidence = Evidence::new("t", "p");
        assert_eq!(evidence.status, Completeness::Complete);
        evidence.add_unknown("cfg", "not collected");
        assert_eq!(evidence.status, Completeness::Partial);
        assert_eq!(evidence.unknowns.len(), 1);
    }

    #[test]
    fn validation_subject_hashes_file_bytes() {
        let dir = std::env::temp_dir().join(format!("rea-core-ev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("subject.bin");
        std::fs::write(&file, b"abc").unwrap();
        let subject = subject_for_file(&file).unwrap();
        assert_eq!(
            subject.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(subject.size_bytes, 3);
        std::fs::remove_dir_all(&dir).ok();
    }
}
