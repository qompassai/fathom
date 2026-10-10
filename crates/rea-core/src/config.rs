//! Operator configuration (SPEC §8).
//!
//! Loaded from TOML, validated fail-closed: unknown fields are
//! rejected, target roots must exist, and an empty target-root
//! list means the server answers only `session_info`.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::{ErrorCode, ReaError};

/// Default bind for the HTTP transports (loopback only).
pub const DEFAULT_HTTP_BIND: &str = "127.0.0.1:8731";

/// Raw config as written on disk. Unknown fields are denied so a
/// typo is a startup failure, not a silent loss of a safety rule.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Program names `capture_process` may run (bare names).
    pub allow_programs: Option<Vec<String>>,
    /// Tool names (observe/execute class) the operator allows.
    pub allow_tools: Option<Vec<String>>,
    /// Explicit path to Ghidra's `analyzeHeadless`.
    pub ghidra_headless: Option<PathBuf>,
    /// Bind address for the HTTP transports.
    pub http_bind: Option<String>,
    /// File holding the base64 Ed25519 signing seed (32 bytes).
    pub signing_key_file: Option<PathBuf>,
    /// Directory for all analysis state.
    pub state_dir: Option<PathBuf>,
    /// Roots every target path must canonicalize under.
    pub target_roots: Option<Vec<PathBuf>>,
}

/// Validated runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub allow_programs: Vec<String>,
    pub allow_tools: Vec<String>,
    pub ghidra_headless: Option<PathBuf>,
    pub http_bind: SocketAddr,
    pub signing_key_file: Option<PathBuf>,
    pub state_dir: PathBuf,
    pub target_roots: Vec<PathBuf>,
}

impl Config {
    /// Build a validated config from the on-disk form.
    pub fn from_file_form(form: ConfigFile) -> Result<Config, ReaError> {
        let mut allow_programs = form.allow_programs.unwrap_or_default();
        allow_programs.sort();
        allow_programs.dedup();
        for name in &allow_programs {
            if name.is_empty() {
                return Err(ReaError::new(
                    ErrorCode::ConfigurationInvalid,
                    "allow_programs contains an empty program name",
                ));
            }
        }
        let mut allow_tools = form.allow_tools.unwrap_or_default();
        allow_tools.sort();
        allow_tools.dedup();
        for name in &allow_tools {
            if name.is_empty() {
                return Err(ReaError::new(
                    ErrorCode::ConfigurationInvalid,
                    "allow_tools contains an empty tool name",
                ));
            }
        }
        let http_bind: SocketAddr = form
            .http_bind
            .as_deref()
            .unwrap_or(DEFAULT_HTTP_BIND)
            .parse()
            .map_err(|e| {
                ReaError::new(
                    ErrorCode::ConfigurationInvalid,
                    format!("http_bind is not a socket address: {e}"),
                )
            })?;
        let state_dir = match form.state_dir {
            Some(dir) => dir,
            None => default_state_dir(),
        };
        let mut target_roots = Vec::new();
        for root in form.target_roots.unwrap_or_default() {
            let canonical = root.canonicalize().map_err(|e| {
                ReaError::new(
                    ErrorCode::ConfigurationInvalid,
                    format!("target root {} cannot be resolved: {e}", root.display()),
                )
            })?;
            target_roots.push(canonical);
        }
        target_roots.sort();
        target_roots.dedup();
        Ok(Config {
            allow_programs,
            allow_tools,
            ghidra_headless: form.ghidra_headless,
            http_bind,
            signing_key_file: form.signing_key_file,
            state_dir,
            target_roots,
        })
    }

    /// Parse and validate a TOML config document.
    pub fn from_toml_str(text: &str) -> Result<Config, ReaError> {
        let form: ConfigFile = toml::from_str(text).map_err(|e| {
            ReaError::new(
                ErrorCode::ConfigurationInvalid,
                format!("config does not parse: {e}"),
            )
        })?;
        Config::from_file_form(form)
    }

    /// Load a config file; a missing path is a configuration
    /// error (fail-closed), never a silent default.
    pub fn load(path: &std::path::Path) -> Result<Config, ReaError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ReaError::new(
                ErrorCode::ConfigurationInvalid,
                format!("cannot read config {}: {e}", path.display()),
            )
        })?;
        Config::from_toml_str(&text)
    }

    /// Defaults for one-shot CLI use without a config file: no
    /// target roots (nothing is analyzable until the operator
    /// declares roots), no observe/execute tools allowed.
    pub fn restrictive_default() -> Config {
        Config {
            allow_programs: Vec::new(),
            allow_tools: Vec::new(),
            ghidra_headless: None,
            http_bind: DEFAULT_HTTP_BIND.parse().expect("constant binds"),
            signing_key_file: None,
            state_dir: default_state_dir(),
            target_roots: Vec::new(),
        }
    }

    /// Whether the HTTP bind stays on loopback (SPEC §8: a
    /// non-loopback bind must be a deliberate config act, which
    /// it is by construction here; this reports the fact).
    pub fn http_bind_is_loopback(&self) -> bool {
        self.http_bind.ip().is_loopback()
    }
}

/// `$XDG_STATE_HOME/rea-rust`, else `$HOME/.local/state/rea-rust`,
/// else a temp-dir fallback that is always writable.
pub fn default_state_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("rea-rust");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("rea-rust");
        }
    }
    std::env::temp_dir().join("rea-rust-state")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_unknown_field_is_rejected() {
        let err = Config::from_toml_str("target_rootz = []\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigurationInvalid);
    }

    #[test]
    fn adversarial_missing_target_root_is_rejected() {
        let err =
            Config::from_toml_str("target_roots = [\"/nonexistent-rea-root-xyz\"]\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigurationInvalid);
    }

    #[test]
    fn adversarial_bad_bind_is_rejected() {
        let err = Config::from_toml_str("http_bind = \"not-an-address\"\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigurationInvalid);
    }

    #[test]
    fn validation_defaults_are_restrictive() {
        let config = Config::from_toml_str("").unwrap();
        assert!(config.allow_programs.is_empty());
        assert!(config.allow_tools.is_empty());
        assert!(config.target_roots.is_empty());
        assert!(config.http_bind_is_loopback());
    }

    #[test]
    fn validation_allow_programs_are_sorted_and_deduped() {
        let config =
            Config::from_toml_str("allow_programs = [\"echo\", \"true\", \"echo\"]\n").unwrap();
        assert_eq!(
            config.allow_programs,
            vec!["echo".to_string(), "true".to_string()]
        );
    }

    #[test]
    fn adversarial_empty_program_name_is_rejected() {
        let err = Config::from_toml_str("allow_programs = [\"\"]\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigurationInvalid);
    }

    #[test]
    fn validation_allow_tools_are_sorted_and_deduped() {
        let config =
            Config::from_toml_str("allow_tools = [\"capture_process\", \"capture_process\"]\n")
                .unwrap();
        assert_eq!(config.allow_tools, vec!["capture_process".to_string()]);
    }
}
