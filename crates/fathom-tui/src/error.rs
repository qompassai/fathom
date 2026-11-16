//! The workflow's typed error: expected failures are values,
//! never panics across a stage boundary.

use std::fmt;

/// An expected workflow failure with bounded context.
#[derive(Debug)]
pub enum WorkflowError {
    /// Run configuration failed validation; nothing was created.
    ConfigInvalid(String),
    /// A fathom-core call failed (census, config build).
    Fathom(String),
    /// A filesystem operation failed; `context` names the act.
    Io {
        /// What was being attempted when the failure hit.
        context: String,
        /// The underlying OS error, as text.
        message: String,
    },
    /// A deterministic stage produced output that violates its
    /// own contract (a bug, reported as a value).
    Internal(String),
}

impl WorkflowError {
    /// Build an `Io` error from a context string and an io error.
    pub fn io(context: impl Into<String>, error: &std::io::Error) -> Self {
        WorkflowError::Io {
            context: context.into(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkflowError::ConfigInvalid(message) => {
                write!(formatter, "invalid run configuration: {message}")
            }
            WorkflowError::Fathom(message) => write!(formatter, "fathom: {message}"),
            WorkflowError::Io { context, message } => {
                write!(formatter, "{context}: {message}")
            }
            WorkflowError::Internal(message) => {
                write!(formatter, "internal contract failure: {message}")
            }
        }
    }
}

impl std::error::Error for WorkflowError {}

impl From<fathom_core::error::FathomError> for WorkflowError {
    fn from(error: fathom_core::error::FathomError) -> Self {
        WorkflowError::Fathom(error.message.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_carries_the_context() {
        let error = WorkflowError::ConfigInvalid("no MCPs selected".to_string());
        assert!(error.to_string().contains("no MCPs selected"));
        let error = WorkflowError::io("read target", &std::io::Error::from_raw_os_error(13));
        assert!(error.to_string().contains("read target"));
    }
}
