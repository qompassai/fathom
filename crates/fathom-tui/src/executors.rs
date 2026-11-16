//! Stage executors: one struct per stage behind the
//! `StageExecutor` trait.
//!
//! Rung 1: Census, Spec, Translate (inventory), and Plan are
//! real and deterministic. Build and Gates are model-executed
//! stages; their executor reports the typed `Unavailable`
//! outcome — the estate's evidence-honesty rule: a scaffolded
//! capability says so, never a fabricated success.

use crate::census::{self, CensusSummary};
use crate::config::RunConfig;
use crate::documents;
use crate::error::WorkflowError;
use crate::events::WorkflowEvent;
use crate::run_dir;
use crate::stages::Stage;
use crate::translate::{self, TranslationManifest};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Cross-stage artifacts: each executor reads what earlier
/// stages produced and publishes its own output here.
#[derive(Default)]
pub struct Artifacts {
    /// The extracted census summary.
    pub census: Option<CensusSummary>,
    /// The census evidence envelope, verbatim.
    pub census_value: Option<Value>,
    /// The translation manifest.
    pub translate: Option<TranslationManifest>,
}

/// What an executor is given to work with.
pub struct ExecCtx<'a> {
    /// Set by the operator's abort key; executors check it at
    /// their checkpoints.
    pub abort: &'a AtomicBool,
    /// Cross-stage artifacts.
    pub artifacts: &'a mut Artifacts,
    /// The validated run configuration.
    pub config: &'a RunConfig,
    /// Event sink (the engine's forwarding closure).
    pub emit: &'a dyn Fn(WorkflowEvent),
    /// The run directory artifacts are written into.
    pub run_dir: &'a Path,
}

impl ExecCtx<'_> {
    /// Emit a log line attributed to a stage.
    pub fn log(&self, stage: Stage, line: impl Into<String>) {
        (self.emit)(WorkflowEvent::Log {
            line: line.into(),
            stage: Some(stage),
        });
    }

    /// Emit a progress update for a stage.
    pub fn progress(&self, stage: Stage, message: impl Into<String>) {
        (self.emit)(WorkflowEvent::StageProgress {
            done: None,
            message: message.into(),
            stage,
            total: None,
        });
    }

    /// Whether the operator has asked to abort.
    pub fn abort_requested(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}

/// A stage's terminal outcome, short of failure (failures are
/// `WorkflowError`s).
pub enum StageOutcome {
    /// The stage did its rung's full work.
    Done(String),
    /// The stage was disabled by configuration.
    Skipped(String),
    /// The stage cannot execute in this rung.
    Unavailable(String),
}

/// One pipeline stage's implementation.
pub trait StageExecutor {
    /// Execute the stage.
    fn execute(&self, ctx: &mut ExecCtx<'_>) -> Result<StageOutcome, WorkflowError>;
    /// Which stage this executor implements.
    fn stage(&self) -> Stage;
}

/// The executor set for a run, in pipeline order.
pub fn executors_for_run() -> Vec<Box<dyn StageExecutor>> {
    vec![
        Box::new(CensusExecutor),
        Box::new(SpecExecutor),
        Box::new(TranslateExecutor),
        Box::new(PlanExecutor),
        Box::new(SeamedExecutor {
            stage: Stage::Build,
        }),
        Box::new(SeamedExecutor {
            stage: Stage::Gates,
        }),
    ]
}

/// Census: run fathom's game-tree census over the target and
/// write the evidence envelope to `census.json`.
pub struct CensusExecutor;

impl StageExecutor for CensusExecutor {
    fn execute(&self, ctx: &mut ExecCtx<'_>) -> Result<StageOutcome, WorkflowError> {
        ctx.progress(Stage::Census, "running fathom census_game_tree");
        let state_dir: PathBuf = ctx.run_dir.join("fathom-state");
        let (evidence, summary) = census::run_census(&ctx.config.target_dir, &state_dir)?;
        let text = serde_json::to_string_pretty(&evidence)
            .map_err(|error| WorkflowError::Internal(format!("census encode: {error}")))?;
        run_dir::write_atomic(&ctx.run_dir.join("census.json"), text.as_bytes())?;
        let line = format!(
            "{} files, {}, engine {} (variant {}), {} containers",
            summary.files_total,
            documents::human_bytes(summary.bytes_total),
            summary.engine,
            summary.engine_variant,
            summary.containers
        );
        ctx.log(Stage::Census, line.clone());
        ctx.artifacts.census_value = Some(evidence);
        ctx.artifacts.census = Some(summary);
        Ok(StageOutcome::Done(line))
    }

    fn stage(&self) -> Stage {
        Stage::Census
    }
}

/// Spec: draft `spec-draft.md` from the census summary.
pub struct SpecExecutor;

impl StageExecutor for SpecExecutor {
    fn execute(&self, ctx: &mut ExecCtx<'_>) -> Result<StageOutcome, WorkflowError> {
        let census =
            ctx.artifacts.census.as_ref().ok_or_else(|| {
                WorkflowError::Internal("spec stage ran before census".to_string())
            })?;
        let text = documents::render_spec_draft(ctx.config, census);
        run_dir::write_atomic(&ctx.run_dir.join("spec-draft.md"), text.as_bytes())?;
        Ok(StageOutcome::Done(
            "spec-draft.md drafted from census evidence".to_string(),
        ))
    }

    fn stage(&self) -> Stage {
        Stage::Spec
    }
}

/// Translate: the deterministic inventory + manifest
/// skeleton. Translation itself is rung 2.
pub struct TranslateExecutor;

impl StageExecutor for TranslateExecutor {
    fn execute(&self, ctx: &mut ExecCtx<'_>) -> Result<StageOutcome, WorkflowError> {
        if !ctx.config.translate.enabled {
            let manifest = TranslationManifest::disabled(ctx.config.translate.mode);
            write_manifest(ctx, &manifest)?;
            ctx.artifacts.translate = Some(manifest);
            return Ok(StageOutcome::Skipped(
                "translation disabled by configuration".to_string(),
            ));
        }
        ctx.progress(Stage::Translate, "inventorying text-bearing files");
        let manifest = translate::run_inventory(&ctx.config.target_dir, &ctx.config.translate)?;
        let line = format!(
            "{} strings inventoried across {} files ({} undecoded); \
             translation execution lands in rung 2",
            manifest.summary.strings_total,
            manifest.summary.files_scanned,
            manifest.summary.files_undecoded
        );
        ctx.log(Stage::Translate, line.clone());
        write_manifest(ctx, &manifest)?;
        ctx.artifacts.translate = Some(manifest);
        Ok(StageOutcome::Done(line))
    }

    fn stage(&self) -> Stage {
        Stage::Translate
    }
}

fn write_manifest(ctx: &ExecCtx<'_>, manifest: &TranslationManifest) -> Result<(), WorkflowError> {
    let text = serde_json::to_string_pretty(manifest)
        .map_err(|error| WorkflowError::Internal(format!("manifest encode: {error}")))?;
    run_dir::write_atomic(
        &ctx.run_dir.join("translation-manifest.json"),
        text.as_bytes(),
    )
}

/// Plan: render `plan.md` from config + census + inventory.
pub struct PlanExecutor;

impl StageExecutor for PlanExecutor {
    fn execute(&self, ctx: &mut ExecCtx<'_>) -> Result<StageOutcome, WorkflowError> {
        let census =
            ctx.artifacts.census.as_ref().ok_or_else(|| {
                WorkflowError::Internal("plan stage ran before census".to_string())
            })?;
        let manifest = ctx.artifacts.translate.as_ref().ok_or_else(|| {
            WorkflowError::Internal("plan stage ran before translate".to_string())
        })?;
        let text = documents::render_plan(ctx.config, census, manifest);
        run_dir::write_atomic(&ctx.run_dir.join("plan.md"), text.as_bytes())?;
        Ok(StageOutcome::Done(
            "plan.md written (approval artifact)".to_string(),
        ))
    }

    fn stage(&self) -> Stage {
        Stage::Plan
    }
}

/// Build / Gates in rung 1: a typed seam. The executor states
/// plainly that the stage is model-executed and lands in
/// rung 2, with the run's chosen provider named.
pub struct SeamedExecutor {
    /// Stage::Build or Stage::Gates.
    pub stage: Stage,
}

impl StageExecutor for SeamedExecutor {
    fn execute(&self, ctx: &mut ExecCtx<'_>) -> Result<StageOutcome, WorkflowError> {
        let line = format!(
            "stage {} is model-executed (provider: {}) and lands in rung 2; \
             rung 1 stops here honestly",
            self.stage.name(),
            ctx.config.provider.name()
        );
        ctx.log(self.stage, line.clone());
        Ok(StageOutcome::Unavailable(line))
    }

    fn stage(&self) -> Stage {
        self.stage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn scratch_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fathom-tui-executor-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        root
    }

    #[test]
    fn seamed_executor_reports_unavailable_and_names_provider() {
        let root = scratch_root("seam");
        let config = RunConfig::new(root.clone());
        let mut artifacts = Artifacts::default();
        let abort = AtomicBool::new(false);
        let events: Mutex<Vec<WorkflowEvent>> = Mutex::new(Vec::new());
        let emit = |event: WorkflowEvent| events.lock().expect("lock").push(event);
        let mut ctx = ExecCtx {
            abort: &abort,
            artifacts: &mut artifacts,
            config: &config,
            emit: &emit,
            run_dir: &root,
        };
        let executor = SeamedExecutor {
            stage: Stage::Build,
        };
        let outcome = executor.execute(&mut ctx).expect("seam executes");
        match outcome {
            StageOutcome::Unavailable(summary) => {
                assert!(summary.contains("rung 2"), "{summary}");
                assert!(summary.contains("local"), "{summary}");
            }
            _ => panic!("seamed stage must be Unavailable"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn spec_before_census_is_a_typed_internal_error() {
        let root = scratch_root("order");
        let config = RunConfig::new(root.clone());
        let mut artifacts = Artifacts::default();
        let abort = AtomicBool::new(false);
        let events: Mutex<Vec<WorkflowEvent>> = Mutex::new(Vec::new());
        let emit = |event: WorkflowEvent| events.lock().expect("lock").push(event);
        let mut ctx = ExecCtx {
            abort: &abort,
            artifacts: &mut artifacts,
            config: &config,
            emit: &emit,
            run_dir: &root,
        };
        let result = SpecExecutor.execute(&mut ctx);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
