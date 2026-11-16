//! The deterministic document renderers: the Spec stage's
//! draft and the Plan stage's approval artifact.
//!
//! Both render from observed facts only (the census summary,
//! the translation inventory, the run configuration). Rows in
//! long tables are bounded; the full facts live in the JSON
//! artifacts, and the documents say so where they truncate.

use crate::census::CensusSummary;
use crate::config::{Provider, RunConfig, TARGET_LANGUAGE};
use crate::stages::Stage;
use crate::translate::TranslationManifest;
use std::fmt::Write as _;

/// Most rows printed in any one document table.
pub const TABLE_ROWS_MAX: usize = 50;

/// Render `spec-draft.md`: the clean-room spec skeleton built
/// from the census. Sections that need model work or human
/// judgement are marked as obligations, never filled with
/// invented content.
pub fn render_spec_draft(config: &RunConfig, census: &CensusSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Clean-room spec draft — {}", census.root_name);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Drafted deterministically by the Spec stage from the Census stage's\n\
         evidence. Confidence labels follow fathom's evidence model: facts\n\
         below are **observed** unless a section says otherwise. Sections\n\
         marked OBLIGATION are work for the Build stage and the operator —\n\
         this draft invents nothing to fill them."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Target identity (observed)");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Target directory: `{}`", config.target_dir.display());
    let _ = writeln!(
        out,
        "- Engine fingerprint: **{}** (variant: {})",
        census.engine, census.engine_variant
    );
    let _ = writeln!(
        out,
        "- Files: {} ({})",
        census.files_total,
        human_bytes(census.bytes_total)
    );
    let _ = writeln!(out, "- Containers found: {}", census.containers);
    if census.frameworks.is_empty() {
        let _ = writeln!(out, "- Frameworks: none detected");
    } else {
        let _ = writeln!(out, "- Frameworks: {}", census.frameworks.join(", "));
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Asset inventory (observed)");
    let _ = writeln!(out);
    if census.asset_classes.is_empty() {
        let _ = writeln!(out, "No asset classes were recorded.");
    } else {
        let _ = writeln!(out, "| Class | Files | Bytes |");
        let _ = writeln!(out, "|---|---|---|");
        for (class, count, bytes) in census.asset_classes.iter().take(TABLE_ROWS_MAX) {
            let _ = writeln!(out, "| {class} | {count} | {bytes} |");
        }
        if census.asset_classes.len() > TABLE_ROWS_MAX {
            let _ = writeln!(
                out,
                "\n… and {} more classes; the full table is in `census.json`.",
                census.asset_classes.len() - TABLE_ROWS_MAX
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Unknowns (not examined / unresolved)");
    let _ = writeln!(out);
    if census.unknowns.is_empty() {
        let _ = writeln!(out, "The census recorded no unknowns.");
    } else {
        for (aspect, reason) in &census.unknowns {
            let _ = writeln!(out, "- **{aspect}**: {reason}");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Clean-room obligations (OBLIGATION)");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Behaviour inventory: enumerate the target's observable behaviours\n\
         before implementing any of them (fathom's per-engine providers and\n\
         the behaviour-check stage supply the deep evidence in rung 2+).\n\
         - Implementation language: {TARGET_LANGUAGE} (fixed by the commission).\n\
         - Shipped text is English only; original-language strings are RE\n\
         material (see `translation-manifest.json`).\n\
         - No original assets, code, or text ship in the build."
    );
    out
}

/// Render `plan.md`: the run's approval artifact. In plan
/// mode the operator approves exactly this document.
pub fn render_plan(
    config: &RunConfig,
    census: &CensusSummary,
    translate: &TranslationManifest,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Run plan — clean-room rebuild of {}",
        census.root_name
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Run configuration");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Target: `{}`", config.target_dir.display());
    let _ = writeln!(out, "- Provider: {}", config.provider.label());
    let _ = writeln!(out, "- Mode: {}", config.mode.label());
    let _ = writeln!(out, "- Build language: {TARGET_LANGUAGE} (fixed)");
    let mcps: Vec<&str> = config.mcps.iter().map(String::as_str).collect();
    let _ = writeln!(out, "- MCP set: {}", mcps.join(", "));
    let _ = writeln!(
        out,
        "- Translation: {}",
        if config.translate.enabled {
            format!("on, source language {}", config.translate.mode.label())
        } else {
            "off".to_string()
        }
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Census summary (observed)");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Engine: {} (variant {}); files {}; size {}; containers {}",
        census.engine,
        census.engine_variant,
        census.files_total,
        human_bytes(census.bytes_total),
        census.containers
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Translation workload (observed inventory)");
    let _ = writeln!(out);
    if !translate.enabled {
        let _ = writeln!(
            out,
            "Translation is off for this run; the stage is skipped."
        );
    } else {
        let _ = writeln!(
            out,
            "- Strings inventoried: {} across {} files ({} undecoded)",
            translate.summary.strings_total,
            translate.summary.files_scanned,
            translate.summary.files_undecoded
        );
        for (language, count) in &translate.summary.by_language {
            let _ = writeln!(out, "- {language}: {count}");
        }
        let _ = writeln!(
            out,
            "- Translation itself is model-executed through the run's provider\n\
             routing and lands in rung 2; entries wait in\n\
             `translation-manifest.json` with `english: null`."
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Stages");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Stage | Kind | Rung 1 behaviour |");
    let _ = writeln!(out, "|---|---|---|");
    for stage in Stage::SEQUENCE {
        let kind = if stage.is_model_executed() {
            "model-executed"
        } else {
            "deterministic"
        };
        let behaviour = match stage {
            Stage::Build | Stage::Gates => "reports Unavailable; the run stops at this boundary",
            Stage::Translate => "inventory + manifest skeleton (execution: rung 2)",
            _ => "executes",
        };
        let _ = writeln!(out, "| {} | {kind} | {behaviour} |", stage.title());
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Provider routing for model-executed stages");
    let _ = writeln!(out);
    match config.provider {
        Provider::Local => {
            let _ = writeln!(
                out,
                "All model-executed stages route to local models through the\n\
                 estate runtime (phlow / rose). No external service is called."
            );
        }
        Provider::Cloud => {
            let _ = writeln!(
                out,
                "All model-executed stages route to the cloud AI provider\n\
                 (typed API seam; implemented in rung 3)."
            );
        }
        Provider::Both => {
            let _ = writeln!(
                out,
                "Per-stage assignment: translation execution and build iteration\n\
                 route local (phlow / rose); plan review and hard reasoning\n\
                 route cloud. A stage never falls back across routes silently:\n\
                 a failed route is a failed stage with the route named."
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Operator notes");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "(Notes appended at the plan-approval pause land here and in the run log.)"
    );
    out
}

/// Render a byte count with a binary unit, one decimal.
pub fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = KIB * 1_024;
    const GIB: u64 = MIB * 1_024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunConfig;
    use std::path::PathBuf;

    fn sample_census() -> CensusSummary {
        CensusSummary {
            asset_classes: vec![("script".to_string(), 12, 4096)],
            bytes_total: 8192,
            containers: 2,
            engine: "renpy".to_string(),
            engine_variant: "unknown".to_string(),
            files_total: 20,
            frameworks: vec!["renpy".to_string()],
            root_name: "demo-game".to_string(),
            unknowns: vec![("engine".to_string(), "partial match".to_string())],
        }
    }

    #[test]
    fn spec_draft_carries_census_facts_and_obligations() {
        let config = RunConfig::new(PathBuf::from("/games/demo"));
        let text = render_spec_draft(&config, &sample_census());
        assert!(text.contains("renpy"), "{text}");
        assert!(text.contains("| script | 12 | 4096 |"), "{text}");
        assert!(text.contains("OBLIGATION"), "{text}");
        assert!(text.contains("partial match"), "{text}");
    }

    #[test]
    fn plan_carries_config_workload_and_boundary() {
        let config = RunConfig::new(PathBuf::from("/games/demo"));
        let mut manifest = TranslationManifest::disabled(config.translate.mode);
        manifest.enabled = true;
        manifest.summary.strings_total = 3;
        manifest
            .summary
            .by_language
            .insert("japanese".to_string(), 3);
        let text = render_plan(&config, &sample_census(), &manifest);
        assert!(text.contains("japanese: 3"), "{text}");
        assert!(text.contains("theodolite"), "{text}");
        assert!(text.contains("Unavailable"), "{text}");
        assert!(text.contains("Rust (fixed)"), "{text}");
    }

    #[test]
    fn plan_records_translation_off() {
        let mut config = RunConfig::new(PathBuf::from("/games/demo"));
        config.translate.enabled = false;
        let manifest = TranslationManifest::disabled(config.translate.mode);
        let text = render_plan(&config, &sample_census(), &manifest);
        assert!(text.contains("Translation: off"), "{text}");
        assert!(text.contains("skipped"), "{text}");
    }

    #[test]
    fn human_bytes_uses_binary_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }
}
