//! Run configuration: the validated contract every stage runs
//! under. Validation happens before the run directory exists —
//! an invalid configuration creates nothing.

use crate::error::WorkflowError;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The build's target language, fixed by the commission
/// (D-1559). Displayed in the TUI; not a choice.
pub const TARGET_LANGUAGE: &str = "Rust";

/// MCP servers the run must include: fathom's own tool catalog
/// is the workflow's instrument and is not optional.
pub const REQUIRED_MCPS: [&str; 1] = ["fathom"];

/// MCP servers an operator may select for a run, alphabetical.
/// Rung 1 records names in a run-scoped registry; rung 2 hands
/// the selected set to model-executed stages as their allowed
/// tool set.
pub const KNOWN_MCPS: [&str; 5] = ["bloch", "fathom", "lumen", "phlow", "theodolite"];

/// Pre-checked MCPs on the configuration screen.
pub const DEFAULT_MCPS: [&str; 3] = ["bloch", "fathom", "theodolite"];

/// Which model route a run's model-executed stages use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    /// Fan-out: per-stage assignment between local and cloud,
    /// printed into the plan for approval.
    Both,
    /// A commercial cloud AI provider, behind a typed API seam
    /// (rung 3; no cloud call exists in rung 1).
    Cloud,
    /// Local models through the estate runtime (phlow / rose).
    Local,
}

impl Provider {
    /// All choices, in display order.
    pub const ALL: [Provider; 3] = [Provider::Cloud, Provider::Local, Provider::Both];

    /// Display name.
    pub fn label(self) -> &'static str {
        match self {
            Provider::Both => "Both (per-stage assignment)",
            Provider::Cloud => "Cloud AI provider",
            Provider::Local => "Local models (phlow / rose)",
        }
    }

    /// Machine name, used in artifacts.
    pub fn name(self) -> &'static str {
        match self {
            Provider::Both => "both",
            Provider::Cloud => "cloud",
            Provider::Local => "local",
        }
    }
}

/// How the run treats the Plan boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunMode {
    /// Run through every stage that can execute; no pause.
    Auto,
    /// Pause after the Plan stage for approve / note / abort.
    Plan,
}

impl RunMode {
    /// All choices, in display order.
    pub const ALL: [RunMode; 2] = [RunMode::Plan, RunMode::Auto];

    /// Display name.
    pub fn label(self) -> &'static str {
        match self {
            RunMode::Auto => "Auto (run through)",
            RunMode::Plan => "Plan (approve before build)",
        }
    }

    /// Machine name, used in artifacts.
    pub fn name(self) -> &'static str {
        match self {
            RunMode::Auto => "auto",
            RunMode::Plan => "plan",
        }
    }
}

/// A natural language the translation stage can source from
/// (D-1560), plus English as the passthrough.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Language {
    /// Arabic (right-to-left).
    Arabic,
    /// Chinese.
    Chinese,
    /// English — the build language; strings pass through.
    English,
    /// Italian.
    Italian,
    /// Japanese.
    Japanese,
    /// Korean.
    Korean,
    /// Spanish.
    Spanish,
}

impl Language {
    /// All languages, alphabetical.
    pub const ALL: [Language; 7] = [
        Language::Arabic,
        Language::Chinese,
        Language::English,
        Language::Italian,
        Language::Japanese,
        Language::Korean,
        Language::Spanish,
    ];

    /// Text direction of the language's script.
    pub fn direction(self) -> TextDirection {
        match self {
            Language::Arabic => TextDirection::Rtl,
            _ => TextDirection::Ltr,
        }
    }

    /// Machine name, used in the translation manifest.
    pub fn name(self) -> &'static str {
        match self {
            Language::Arabic => "arabic",
            Language::Chinese => "chinese",
            Language::English => "english",
            Language::Italian => "italian",
            Language::Japanese => "japanese",
            Language::Korean => "korean",
            Language::Spanish => "spanish",
        }
    }
}

/// Script direction, recorded per string in the manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextDirection {
    /// Left-to-right.
    Ltr,
    /// Right-to-left (Arabic).
    Rtl,
}

impl TextDirection {
    /// Machine name, used in the translation manifest.
    pub fn name(self) -> &'static str {
        match self {
            TextDirection::Ltr => "ltr",
            TextDirection::Rtl => "rtl",
        }
    }
}

/// How the translation stage assigns a language to strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceLanguageMode {
    /// Detect per string (script-first heuristics).
    Auto,
    /// The operator declares the source language; detection
    /// still runs and any disagreement stays on the record.
    Fixed(Language),
}

impl SourceLanguageMode {
    /// Display name.
    pub fn label(self) -> String {
        match self {
            SourceLanguageMode::Auto => "Auto-detect".to_string(),
            SourceLanguageMode::Fixed(language) => format!("Fixed: {}", language.name()),
        }
    }

    /// Machine name, used in the translation manifest.
    pub fn name(self) -> String {
        match self {
            SourceLanguageMode::Auto => "auto".to_string(),
            SourceLanguageMode::Fixed(language) => format!("fixed:{}", language.name()),
        }
    }
}

/// Translation stage settings (D-1560).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslateConfig {
    /// When false the stage is skipped cleanly.
    pub enabled: bool,
    /// Detection behaviour.
    pub mode: SourceLanguageMode,
}

impl Default for TranslateConfig {
    fn default() -> Self {
        TranslateConfig {
            enabled: true,
            mode: SourceLanguageMode::Auto,
        }
    }
}

/// A fully specified run. Build one, `validate` it, then hand
/// it to the engine.
#[derive(Clone, Debug)]
pub struct RunConfig {
    /// MCP set for the run (validated against `KNOWN_MCPS`).
    pub mcps: BTreeSet<String>,
    /// Plan or auto.
    pub mode: RunMode,
    /// Root under which the timestamped run directory is made.
    /// Never inside the target tree: the target is evidence.
    pub output_root: PathBuf,
    /// Provider route for model-executed stages.
    pub provider: Provider,
    /// The directory holding the app/game to reverse.
    pub target_dir: PathBuf,
    /// Translation settings.
    pub translate: TranslateConfig,
}

impl RunConfig {
    /// A configuration with the commission's defaults: local
    /// provider, plan mode, default MCPs, translation on with
    /// auto-detection, output under `./fathom-runs`.
    pub fn new(target_dir: PathBuf) -> RunConfig {
        RunConfig {
            mcps: DEFAULT_MCPS.iter().map(|name| name.to_string()).collect(),
            mode: RunMode::Plan,
            output_root: PathBuf::from("fathom-runs"),
            provider: Provider::Local,
            target_dir,
            translate: TranslateConfig::default(),
        }
    }

    /// Validate every field. On failure nothing has been
    /// created and the error names the broken rule.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        let metadata = std::fs::metadata(&self.target_dir).map_err(|error| {
            WorkflowError::ConfigInvalid(format!(
                "target {} cannot be stat'ed: {error}",
                self.target_dir.display()
            ))
        })?;
        if !metadata.is_dir() {
            return Err(WorkflowError::ConfigInvalid(format!(
                "target {} is not a directory",
                self.target_dir.display()
            )));
        }
        std::fs::read_dir(&self.target_dir).map_err(|error| {
            WorkflowError::ConfigInvalid(format!(
                "target {} is not readable: {error}",
                self.target_dir.display()
            ))
        })?;
        if self.mcps.is_empty() {
            return Err(WorkflowError::ConfigInvalid(
                "no MCPs selected; a run needs at least the fathom tool catalog".to_string(),
            ));
        }
        for name in &self.mcps {
            if !KNOWN_MCPS.contains(&name.as_str()) {
                return Err(WorkflowError::ConfigInvalid(format!(
                    "unknown MCP '{name}'; known set: {}",
                    KNOWN_MCPS.join(", ")
                )));
            }
        }
        for required in REQUIRED_MCPS {
            if !self.mcps.contains(required) {
                return Err(WorkflowError::ConfigInvalid(format!(
                    "required MCP '{required}' is not selected"
                )));
            }
        }
        if let Ok(output_meta) = std::fs::metadata(&self.output_root)
            && !output_meta.is_dir()
        {
            return Err(WorkflowError::ConfigInvalid(format!(
                "output root {} exists and is not a directory",
                self.output_root.display()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fathom-tui-config-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    #[test]
    fn defaults_validate_against_a_real_directory() {
        let dir = fixture_dir("ok");
        let config = RunConfig::new(dir.clone());
        assert!(config.validate().is_ok());
        assert_eq!(config.provider, Provider::Local);
        assert_eq!(config.mode, RunMode::Plan);
        assert!(config.translate.enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonexistent_target_is_rejected() {
        let config = RunConfig::new(PathBuf::from("/nonexistent-fathom-target-xyz"));
        let error = config.validate().expect_err("must reject");
        assert!(error.to_string().contains("target"), "{error}");
    }

    #[test]
    fn file_target_is_rejected() {
        let dir = fixture_dir("file");
        let file = dir.join("game.exe");
        std::fs::write(&file, b"MZ").expect("fixture file");
        let config = RunConfig::new(file);
        assert!(config.validate().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_mcp_selection_is_rejected() {
        let dir = fixture_dir("nomcp");
        let mut config = RunConfig::new(dir.clone());
        config.mcps.clear();
        let error = config.validate().expect_err("must reject");
        assert!(error.to_string().contains("no MCPs"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_required_mcp_is_rejected() {
        let dir = fixture_dir("reqmcp");
        let mut config = RunConfig::new(dir.clone());
        config.mcps.remove("fathom");
        assert!(!config.mcps.is_empty());
        let error = config.validate().expect_err("must reject");
        assert!(error.to_string().contains("fathom"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_mcp_is_rejected() {
        let dir = fixture_dir("badmcp");
        let mut config = RunConfig::new(dir.clone());
        config.mcps.insert("definitely-not-an-mcp".to_string());
        let error = config.validate().expect_err("must reject");
        assert!(error.to_string().contains("unknown MCP"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn output_root_that_is_a_file_is_rejected() {
        let dir = fixture_dir("outroot");
        let file = dir.join("occupied");
        std::fs::write(&file, b"x").expect("fixture file");
        let mut config = RunConfig::new(dir.clone());
        config.output_root = file;
        assert!(config.validate().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_arabic_is_rtl() {
        for language in Language::ALL {
            let expected = if language == Language::Arabic {
                TextDirection::Rtl
            } else {
                TextDirection::Ltr
            };
            assert_eq!(language.direction(), expected, "{language:?}");
        }
    }

    #[test]
    fn target_language_is_rust() {
        assert_eq!(TARGET_LANGUAGE, "Rust");
    }
}
