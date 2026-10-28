//! Operator configuration (SPEC §8).
//!
//! Loaded from TOML, validated fail-closed: unknown fields are
//! rejected, target roots must exist, and an empty target-root
//! list means the server answers only `session_info`.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::{ErrorCode, FathomError};

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
    /// Per-provider configuration blocks (SPEC §8 pattern:
    /// a provider exists for a build only when the operator
    /// configures it).
    pub providers: Option<ProvidersFile>,
    /// File holding the base64 Ed25519 signing seed (32 bytes).
    pub signing_key_file: Option<PathBuf>,
    /// Directory for all analysis state.
    pub state_dir: Option<PathBuf>,
    /// Roots every target path must canonicalize under.
    pub target_roots: Option<Vec<PathBuf>>,
}

/// The `[providers]` table of the on-disk form.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersFile {
    /// The YouTube ingest lane's provider block (YouTube-RE
    /// SPEC §4.3/§4.4: rendition and ASR are configuration,
    /// never per-call arguments).
    pub video: Option<VideoProviderFile>,
}

/// The `[providers.video]` block, on-disk form.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoProviderFile {
    /// Model file the local-ASR program consumes (YouTube-RE
    /// §4.4 path 3).
    pub asr_model: Option<PathBuf>,
    /// Local-ASR engine program (YouTube-RE §5 verdict:
    /// whisper.cpp via an operator wrapper). Absent means
    /// the local-ASR leg is unavailable and an ingest with
    /// no caption track proceeds partial, honestly.
    pub asr_program: Option<PathBuf>,
    /// Caption language tried after the video's original
    /// language (default `en`).
    pub caption_fallback_language: Option<String>,
    /// Fetcher program (default `yt-dlp`).
    pub fetcher_program: Option<PathBuf>,
    /// Whole format-string override for the fetch template.
    /// Test-only in spirit: obligation 2's hash reproduction
    /// runs under the estate corpus's archival string
    /// (YouTube-RE §14); production policy is `max_height`.
    pub format_override: Option<String>,
    /// Rendition cap in lines (default 1080; YouTube-RE
    /// §4.3 analysis rendition policy).
    pub max_height: Option<u32>,
    /// Frame sampler program (default `ffmpeg`).
    pub sampler_program: Option<PathBuf>,
}

/// Validated video-lane configuration.
#[derive(Clone, Debug)]
pub struct VideoConfig {
    pub asr_model: Option<PathBuf>,
    pub asr_program: Option<PathBuf>,
    pub caption_fallback_language: String,
    pub fetcher_program: PathBuf,
    pub format_override: Option<String>,
    pub max_height: u32,
    pub sampler_program: PathBuf,
}

impl Default for VideoConfig {
    fn default() -> Self {
        VideoConfig {
            asr_model: None,
            asr_program: None,
            caption_fallback_language: "en".to_string(),
            fetcher_program: PathBuf::from("yt-dlp"),
            format_override: None,
            max_height: 1080,
            sampler_program: PathBuf::from("ffmpeg"),
        }
    }
}

impl VideoConfig {
    fn from_file_form(form: VideoProviderFile) -> Result<VideoConfig, FathomError> {
        let caption_fallback_language = form
            .caption_fallback_language
            .unwrap_or_else(|| "en".to_string());
        if caption_fallback_language.is_empty()
            || !caption_fallback_language
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(FathomError::new(
                ErrorCode::ConfigurationInvalid,
                "providers.video.caption_fallback_language must be a language tag",
            ));
        }
        let max_height = form.max_height.unwrap_or(1080);
        if max_height == 0 || max_height > 4320 {
            return Err(FathomError::new(
                ErrorCode::ConfigurationInvalid,
                "providers.video.max_height must be within 1..=4320",
            ));
        }
        if let Some(format) = &form.format_override
            && format.is_empty()
        {
            return Err(FathomError::new(
                ErrorCode::ConfigurationInvalid,
                "providers.video.format_override must not be empty",
            ));
        }
        Ok(VideoConfig {
            asr_model: form.asr_model,
            asr_program: form.asr_program,
            caption_fallback_language,
            fetcher_program: form
                .fetcher_program
                .unwrap_or_else(|| PathBuf::from("yt-dlp")),
            format_override: form.format_override,
            max_height,
            sampler_program: form
                .sampler_program
                .unwrap_or_else(|| PathBuf::from("ffmpeg")),
        })
    }
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
    pub video: VideoConfig,
}

impl Config {
    /// Build a validated config from the on-disk form.
    pub fn from_file_form(form: ConfigFile) -> Result<Config, FathomError> {
        let mut allow_programs = form.allow_programs.unwrap_or_default();
        allow_programs.sort();
        allow_programs.dedup();
        for name in &allow_programs {
            if name.is_empty() {
                return Err(FathomError::new(
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
                return Err(FathomError::new(
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
                FathomError::new(
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
                FathomError::new(
                    ErrorCode::ConfigurationInvalid,
                    format!("target root {} cannot be resolved: {e}", root.display()),
                )
            })?;
            target_roots.push(canonical);
        }
        target_roots.sort();
        target_roots.dedup();
        let video = match form.providers.and_then(|providers| providers.video) {
            Some(video_form) => VideoConfig::from_file_form(video_form)?,
            None => VideoConfig::default(),
        };
        Ok(Config {
            allow_programs,
            allow_tools,
            ghidra_headless: form.ghidra_headless,
            http_bind,
            signing_key_file: form.signing_key_file,
            state_dir,
            target_roots,
            video,
        })
    }

    /// Parse and validate a TOML config document.
    pub fn from_toml_str(text: &str) -> Result<Config, FathomError> {
        let form: ConfigFile = toml::from_str(text).map_err(|e| {
            FathomError::new(
                ErrorCode::ConfigurationInvalid,
                format!("config does not parse: {e}"),
            )
        })?;
        Config::from_file_form(form)
    }

    /// Load a config file; a missing path is a configuration
    /// error (fail-closed), never a silent default.
    pub fn load(path: &std::path::Path) -> Result<Config, FathomError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            FathomError::new(
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
            video: VideoConfig::default(),
        }
    }

    /// Whether the HTTP bind stays on loopback (SPEC §8: a
    /// non-loopback bind must be a deliberate config act, which
    /// it is by construction here; this reports the fact).
    pub fn http_bind_is_loopback(&self) -> bool {
        self.http_bind.ip().is_loopback()
    }
}

/// `$XDG_STATE_HOME/fathom`, else `$HOME/.local/state/fathom`,
/// else a temp-dir fallback that is always writable.
pub fn default_state_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("fathom");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("fathom");
    }
    std::env::temp_dir().join("fathom-state")
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
        let err = Config::from_toml_str("target_roots = [\"/nonexistent-fathom-root-xyz\"]\n")
            .unwrap_err();
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
