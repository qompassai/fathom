//! The deterministic policy engine (SPEC §8).
//!
//! Classes: `read` tools run when their target validates;
//! `observe` and `execute` tools are default-deny and run only
//! when the operator's config names them in `allow_tools`. The
//! decision is a pure function of the config and the tool — no
//! prompts, no ambient authority, no fallback.

use serde::Serialize;

use crate::config::Config;

/// What a tool is allowed to do to the world.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClass {
    Execute,
    Observe,
    Read,
}

impl ToolClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ToolClass::Execute => "execute",
            ToolClass::Observe => "observe",
            ToolClass::Read => "read",
        }
    }
}

/// The outcome of a policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

/// Evaluate whether `tool` (of `class`) may run under `config`.
pub fn decide(config: &Config, class: ToolClass, tool: &str) -> PolicyDecision {
    match class {
        ToolClass::Read => PolicyDecision::Allow,
        ToolClass::Observe | ToolClass::Execute => {
            if config.allow_tools.iter().any(|name| name == tool) {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny {
                    reason: format!(
                        "tool '{tool}' is {}-class and default-deny; the operator must name it in allow_tools",
                        class.as_str()
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigFile;

    fn config(allow: &[&str]) -> Config {
        Config::from_file_form(ConfigFile {
            allow_tools: Some(allow.iter().map(|s| s.to_string()).collect()),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    #[test]
    fn adversarial_execute_is_denied_by_default() {
        let decision = decide(&config(&[]), ToolClass::Execute, "capture_process");
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn adversarial_observe_is_denied_by_default() {
        let decision = decide(&config(&[]), ToolClass::Observe, "observe_browser");
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn adversarial_allowlist_names_tools_not_classes() {
        // Allowing one execute tool must not allow another.
        let decision = decide(
            &config(&["capture_process"]),
            ToolClass::Execute,
            "other_tool",
        );
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn validation_read_is_allowed() {
        let decision = decide(&config(&[]), ToolClass::Read, "binary_overview");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn validation_allowlisted_execute_is_allowed() {
        let decision = decide(
            &config(&["capture_process"]),
            ToolClass::Execute,
            "capture_process",
        );
        assert_eq!(decision, PolicyDecision::Allow);
    }
}
