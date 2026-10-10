//! Canonical error contracts (SPEC §7).
//!
//! Codes and categories are adopted verbatim from upstream's
//! `error-contract.schema.json`. Every failure that crosses a tool
//! boundary is a [`FathomError`]; it serializes to the canonical
//! envelope `{"error": {...}}`.

use serde::Serialize;
use serde_json::{Value, json};

/// Error categories, adopted verbatim from upstream's schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Cancelled,
    ExecutionFailure,
    IntegrityMismatch,
    InvalidInput,
    ResourceConstraint,
    Timeout,
    Truncated,
    Unavailable,
    UnsupportedProvider,
    UnsupportedTarget,
}

/// Error codes, adopted verbatim from upstream's schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AccessDenied,
    ArtifactChanged,
    ArtifactIntegrityMismatch,
    ArtifactOperationFailed,
    Cancelled,
    CapabilityUnavailable,
    CleanupIncomplete,
    ConfigurationInvalid,
    EvidenceIntegrityMismatch,
    ExecutionFailure,
    InvalidRequest,
    ProcessCaptureFailed,
    ProviderTimeout,
    ProviderUnavailable,
    ResourceConstraint,
    RevisionConflict,
    TargetUnavailable,
    Truncated,
    UnreadableOutput,
    UnsupportedTarget,
}

impl ErrorCode {
    /// The category this code belongs to (port mapping, SPEC §7).
    pub fn category(self) -> ErrorCategory {
        match self {
            ErrorCode::AccessDenied => ErrorCategory::InvalidInput,
            ErrorCode::ArtifactChanged => ErrorCategory::IntegrityMismatch,
            ErrorCode::ArtifactIntegrityMismatch => ErrorCategory::IntegrityMismatch,
            ErrorCode::ArtifactOperationFailed => ErrorCategory::ExecutionFailure,
            ErrorCode::Cancelled => ErrorCategory::Cancelled,
            ErrorCode::CapabilityUnavailable => ErrorCategory::Unavailable,
            ErrorCode::CleanupIncomplete => ErrorCategory::ExecutionFailure,
            ErrorCode::ConfigurationInvalid => ErrorCategory::InvalidInput,
            ErrorCode::EvidenceIntegrityMismatch => ErrorCategory::IntegrityMismatch,
            ErrorCode::ExecutionFailure => ErrorCategory::ExecutionFailure,
            ErrorCode::InvalidRequest => ErrorCategory::InvalidInput,
            ErrorCode::ProcessCaptureFailed => ErrorCategory::ExecutionFailure,
            ErrorCode::ProviderTimeout => ErrorCategory::Timeout,
            ErrorCode::ProviderUnavailable => ErrorCategory::Unavailable,
            ErrorCode::ResourceConstraint => ErrorCategory::ResourceConstraint,
            ErrorCode::RevisionConflict => ErrorCategory::IntegrityMismatch,
            ErrorCode::TargetUnavailable => ErrorCategory::Unavailable,
            ErrorCode::Truncated => ErrorCategory::Truncated,
            ErrorCode::UnreadableOutput => ErrorCategory::ExecutionFailure,
            ErrorCode::UnsupportedTarget => ErrorCategory::UnsupportedTarget,
        }
    }

    /// The wire form of the code (`snake_case`, as in the schema).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::AccessDenied => "access_denied",
            ErrorCode::ArtifactChanged => "artifact_changed",
            ErrorCode::ArtifactIntegrityMismatch => "artifact_integrity_mismatch",
            ErrorCode::ArtifactOperationFailed => "artifact_operation_failed",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::CapabilityUnavailable => "capability_unavailable",
            ErrorCode::CleanupIncomplete => "cleanup_incomplete",
            ErrorCode::ConfigurationInvalid => "configuration_invalid",
            ErrorCode::EvidenceIntegrityMismatch => "evidence_integrity_mismatch",
            ErrorCode::ExecutionFailure => "execution_failure",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::ProcessCaptureFailed => "process_capture_failed",
            ErrorCode::ProviderTimeout => "provider_timeout",
            ErrorCode::ProviderUnavailable => "provider_unavailable",
            ErrorCode::ResourceConstraint => "resource_constraint",
            ErrorCode::RevisionConflict => "revision_conflict",
            ErrorCode::TargetUnavailable => "target_unavailable",
            ErrorCode::Truncated => "truncated",
            ErrorCode::UnreadableOutput => "unreadable_output",
            ErrorCode::UnsupportedTarget => "unsupported_target",
        }
    }
}

/// A canonical fathom error.
#[derive(Clone, Debug)]
pub struct FathomError {
    pub code: ErrorCode,
    pub message: String,
    pub target: Option<String>,
    pub remediation: Option<String>,
    pub details: Option<Value>,
}

impl FathomError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        FathomError {
            code,
            message: message.into(),
            target: None,
            remediation: None,
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// The honest answer for a scaffolded capability (SPEC §7):
    /// `capability_unavailable` with an explicit `not_implemented`
    /// status and the SPEC section that owns the capability.
    pub fn not_implemented(what: &str, spec_ref: &str) -> Self {
        FathomError::new(
            ErrorCode::CapabilityUnavailable,
            format!("{what} is not implemented in this build"),
        )
        .with_details(json!({"status": "not_implemented", "spec": spec_ref}))
        .with_remediation(format!(
            "See SPEC.md {spec_ref}; the capability is scaffolded, not built."
        ))
    }

    /// The canonical `{"error": {...}}` envelope.
    pub fn to_envelope(&self) -> Value {
        let mut error = serde_json::Map::new();
        error.insert("code".into(), json!(self.code.as_str()));
        error.insert("category".into(), json!(self.code.category()));
        error.insert("message".into(), json!(self.message));
        if let Some(target) = &self.target {
            error.insert("target".into(), json!(target));
        }
        if let Some(remediation) = &self.remediation {
            error.insert("remediation".into(), json!(remediation));
        }
        if let Some(details) = &self.details {
            error.insert("details".into(), details.clone());
        }
        json!({"error": error})
    }
}

impl std::fmt::Display for FathomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for FathomError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_every_code_has_a_distinct_wire_form() {
        let codes = [
            ErrorCode::AccessDenied,
            ErrorCode::ArtifactChanged,
            ErrorCode::ArtifactIntegrityMismatch,
            ErrorCode::ArtifactOperationFailed,
            ErrorCode::Cancelled,
            ErrorCode::CapabilityUnavailable,
            ErrorCode::CleanupIncomplete,
            ErrorCode::ConfigurationInvalid,
            ErrorCode::EvidenceIntegrityMismatch,
            ErrorCode::ExecutionFailure,
            ErrorCode::InvalidRequest,
            ErrorCode::ProcessCaptureFailed,
            ErrorCode::ProviderTimeout,
            ErrorCode::ProviderUnavailable,
            ErrorCode::ResourceConstraint,
            ErrorCode::RevisionConflict,
            ErrorCode::TargetUnavailable,
            ErrorCode::Truncated,
            ErrorCode::UnreadableOutput,
            ErrorCode::UnsupportedTarget,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            assert!(seen.insert(code.as_str()), "duplicate wire form");
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn validation_envelope_carries_code_category_and_message() {
        let err = FathomError::new(ErrorCode::TargetUnavailable, "gone").with_target("/x");
        let envelope = err.to_envelope();
        assert_eq!(envelope["error"]["code"], "target_unavailable");
        assert_eq!(envelope["error"]["category"], "unavailable");
        assert_eq!(envelope["error"]["message"], "gone");
        assert_eq!(envelope["error"]["target"], "/x");
    }

    #[test]
    fn validation_not_implemented_is_explicit() {
        let err = FathomError::not_implemented("browser observation", "§9.4");
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(err.details.as_ref().unwrap()["status"], "not_implemented");
    }
}
