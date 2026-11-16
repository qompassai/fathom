//! The workflow engine: a typed stage machine over the
//! pipeline sequence.
//!
//! The engine owns no UI state and the frontend owns no engine
//! state. The engine runs (typically on a worker thread),
//! emits `WorkflowEvent`s, and — in plan mode only — blocks at
//! the Plan boundary until the frontend answers with an
//! `ApprovalDecision`. Every exit path that has a run
//! directory writes `run-log.txt`
//! from the same event stream the frontend rendered.

use crate::config::{RunConfig, RunMode};
use crate::error::WorkflowError;
use crate::events::{ApprovalDecision, RunOutcome, WorkflowEvent};
use crate::executors::{Artifacts, ExecCtx, StageExecutor, StageOutcome, executors_for_run};
use crate::run_dir;
use crate::stages::{Stage, StageStatus};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};

/// A validated run, ready to execute.
pub struct Engine {
    config: RunConfig,
}

impl Engine {
    /// Validate the configuration; an invalid one builds
    /// nothing and creates nothing.
    pub fn new(config: RunConfig) -> Result<Engine, WorkflowError> {
        config.validate()?;
        Ok(Engine { config })
    }

    /// Execute the run, emitting events on `events` and (in
    /// plan mode) waiting for one approval decision on
    /// `approvals`. `abort` is polled at every stage boundary.
    /// Returns the terminal outcome; the same outcome is the
    /// payload of the final `RunFinished` event.
    pub fn run(
        self,
        events: Sender<WorkflowEvent>,
        approvals: Receiver<ApprovalDecision>,
        abort: Arc<AtomicBool>,
    ) -> RunOutcome {
        let log_lines: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let run_dir_slot: RefCell<Option<PathBuf>> = RefCell::new(None);
        let emit = |event: WorkflowEvent| {
            log_lines.borrow_mut().push(format_event(&event));
            let _ = events.send(event);
        };
        let outcome = self.run_inner(&emit, &approvals, &abort, &run_dir_slot);
        // The run log is written from the same stream the
        // frontend rendered, outcome line included, before
        // RunFinished is emitted.
        let finished = WorkflowEvent::RunFinished {
            outcome: outcome.clone(),
        };
        log_lines.borrow_mut().push(format_event(&finished));
        if let Some(run_dir) = run_dir_slot.borrow().as_ref() {
            let body = log_lines.borrow().join("\n") + "\n";
            let _ = run_dir::write_atomic(&run_dir.join("run-log.txt"), body.as_bytes());
        }
        let _ = events.send(finished);
        outcome
    }

    fn run_inner(
        &self,
        emit: &dyn Fn(WorkflowEvent),
        approvals: &Receiver<ApprovalDecision>,
        abort: &AtomicBool,
        run_dir_slot: &RefCell<Option<PathBuf>>,
    ) -> RunOutcome {
        let run_dir =
            match run_dir::create_run_dir(&self.config.output_root, run_dir::now_unix_secs()) {
                Ok(dir) => dir,
                Err(error) => {
                    return RunOutcome::Failed {
                        error: error.to_string(),
                        stage: Stage::Census,
                    };
                }
            };
        *run_dir_slot.borrow_mut() = Some(run_dir.clone());
        emit(WorkflowEvent::RunStarted {
            mode: self.config.mode,
            provider: self.config.provider,
            run_dir: run_dir.clone(),
            target: self.config.target_dir.clone(),
        });
        let mut artifacts = Artifacts::default();
        let executors = executors_for_run();
        let mut outcome: Option<RunOutcome> = None;
        let mut index = 0;
        while index < executors.len() {
            let executor = &executors[index];
            let stage = executor.stage();
            if abort.load(Ordering::SeqCst) {
                outcome = Some(RunOutcome::Aborted { stage });
                skip_remaining(emit, &executors, index);
                break;
            }
            emit(WorkflowEvent::StageStarted { stage });
            let result = {
                let mut ctx = ExecCtx {
                    abort,
                    artifacts: &mut artifacts,
                    config: &self.config,
                    emit,
                    run_dir: &run_dir,
                };
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    executor.execute(&mut ctx)
                }))
            };
            match result {
                Ok(Ok(StageOutcome::Done(summary))) => {
                    emit(WorkflowEvent::StageFinished {
                        stage,
                        status: StageStatus::Done,
                        summary,
                    });
                    if stage == Stage::Plan && self.config.mode == RunMode::Plan {
                        match self.await_approval(emit, approvals, &run_dir) {
                            ApprovalStep::Approved => {}
                            ApprovalStep::Rejected => {
                                outcome = Some(RunOutcome::PlanRejected);
                                skip_remaining(emit, &executors, index + 1);
                                break;
                            }
                        }
                    }
                }
                Ok(Ok(StageOutcome::Skipped(summary))) => {
                    emit(WorkflowEvent::StageFinished {
                        stage,
                        status: StageStatus::Skipped,
                        summary,
                    });
                }
                Ok(Ok(StageOutcome::Unavailable(summary))) => {
                    emit(WorkflowEvent::StageFinished {
                        stage,
                        status: StageStatus::Unavailable,
                        summary,
                    });
                    outcome = Some(RunOutcome::StoppedAtRungBoundary { stage });
                    skip_remaining(emit, &executors, index + 1);
                    break;
                }
                Ok(Err(error)) => {
                    emit(WorkflowEvent::StageFinished {
                        stage,
                        status: StageStatus::Failed,
                        summary: error.to_string(),
                    });
                    outcome = Some(RunOutcome::Failed {
                        error: error.to_string(),
                        stage,
                    });
                    skip_remaining(emit, &executors, index + 1);
                    break;
                }
                Err(_panic) => {
                    let error = WorkflowError::Internal(format!(
                        "stage {} panicked; reported as a failure, not hidden",
                        stage.name()
                    ));
                    emit(WorkflowEvent::StageFinished {
                        stage,
                        status: StageStatus::Failed,
                        summary: error.to_string(),
                    });
                    outcome = Some(RunOutcome::Failed {
                        error: error.to_string(),
                        stage,
                    });
                    skip_remaining(emit, &executors, index + 1);
                    break;
                }
            }
            index += 1;
        }
        outcome.unwrap_or(RunOutcome::Completed)
    }

    /// Block at the Plan boundary until the frontend answers.
    /// A note is appended to the plan and logged before the
    /// run proceeds, so the approved plan is the edited plan.
    fn await_approval(
        &self,
        emit: &dyn Fn(WorkflowEvent),
        approvals: &Receiver<ApprovalDecision>,
        run_dir: &Path,
    ) -> ApprovalStep {
        let plan_path = run_dir.join("plan.md");
        emit(WorkflowEvent::ApprovalRequested {
            plan_path: plan_path.clone(),
            stage: Stage::Plan,
        });
        match approvals.recv() {
            Ok(ApprovalDecision::Approve) => {
                emit(WorkflowEvent::Log {
                    line: "plan approved by operator".to_string(),
                    stage: Some(Stage::Plan),
                });
                ApprovalStep::Approved
            }
            Ok(ApprovalDecision::ApproveWithNote(note)) => {
                let block = format!("\n## Operator note (at approval)\n\n{note}\n");
                match run_dir::append_text(&plan_path, &block) {
                    Ok(()) => emit(WorkflowEvent::Log {
                        line: format!("plan approved with operator note: {note}"),
                        stage: Some(Stage::Plan),
                    }),
                    Err(error) => emit(WorkflowEvent::Log {
                        line: format!("operator note could not be appended: {error}"),
                        stage: Some(Stage::Plan),
                    }),
                }
                ApprovalStep::Approved
            }
            Ok(ApprovalDecision::Abort) => {
                emit(WorkflowEvent::Log {
                    line: "plan rejected by operator".to_string(),
                    stage: Some(Stage::Plan),
                });
                ApprovalStep::Rejected
            }
            Err(_closed) => {
                emit(WorkflowEvent::Log {
                    line: "approval channel closed; treating as rejection".to_string(),
                    stage: Some(Stage::Plan),
                });
                ApprovalStep::Rejected
            }
        }
    }
}

enum ApprovalStep {
    Approved,
    Rejected,
}

/// Emit `Skipped` finishes for every executor from `from`
/// onward, so a frontend's stage list is always complete.
fn skip_remaining(emit: &dyn Fn(WorkflowEvent), executors: &[Box<dyn StageExecutor>], from: usize) {
    for executor in &executors[from..] {
        emit(WorkflowEvent::StageFinished {
            stage: executor.stage(),
            status: StageStatus::Skipped,
            summary: "not reached".to_string(),
        });
    }
}

/// Render one event as a run-log line.
pub fn format_event(event: &WorkflowEvent) -> String {
    match event {
        WorkflowEvent::ApprovalRequested { plan_path, .. } => {
            format!("approval requested: plan at {}", plan_path.display())
        }
        WorkflowEvent::Log { line, stage } => match stage {
            Some(stage) => format!("[{}] {line}", stage.name()),
            None => line.clone(),
        },
        WorkflowEvent::RunFinished { outcome } => {
            format!("run finished: {}", outcome.describe())
        }
        WorkflowEvent::RunStarted {
            mode,
            provider,
            run_dir,
            target,
        } => format!(
            "run started: target={} provider={} mode={} run_dir={}",
            target.display(),
            provider.name(),
            mode.name(),
            run_dir.display()
        ),
        WorkflowEvent::StageFinished {
            stage,
            status,
            summary,
        } => format!(
            "stage {} finished: {} — {summary}",
            stage.name(),
            status.name()
        ),
        WorkflowEvent::StageStarted { stage } => format!("stage {} started", stage.name()),
        WorkflowEvent::StageProgress {
            done,
            message,
            stage,
            total,
        } => match (done, total) {
            (Some(done), Some(total)) => {
                format!("[{}] {message} ({done}/{total})", stage.name())
            }
            _ => format!("[{}] {message}", stage.name()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Provider, TranslateConfig};
    use std::sync::mpsc::channel;
    use std::time::Duration;

    fn fixture_game(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "fathom-tui-engine-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let game = base.join("game");
        std::fs::create_dir_all(game.join("data")).expect("game dirs");
        std::fs::write(game.join("game.exe"), b"MZ fake").expect("exe");
        std::fs::write(
            game.join("data").join("script.rpy"),
            "label start:\n    \"ゲームを開始します\"\n",
        )
        .expect("rpy");
        (base, game)
    }

    struct DrivenRun {
        events: Vec<WorkflowEvent>,
        outcome: RunOutcome,
        run_dir: PathBuf,
    }

    /// Run the engine on a thread, collecting events; answer
    /// approvals with `decision` (None = never asked / drop).
    fn drive(config: RunConfig, decision: Option<ApprovalDecision>, pre_abort: bool) -> DrivenRun {
        let engine = Engine::new(config).expect("config validates");
        let (event_tx, event_rx) = channel::<WorkflowEvent>();
        let (approval_tx, approval_rx) = channel::<ApprovalDecision>();
        let abort = Arc::new(AtomicBool::new(pre_abort));
        let abort_for_thread = abort.clone();
        let handle =
            std::thread::spawn(move || engine.run(event_tx, approval_rx, abort_for_thread));
        let mut events = Vec::new();
        let mut run_dir = PathBuf::new();
        let mut answered = false;
        loop {
            match event_rx.recv_timeout(Duration::from_secs(60)) {
                Ok(event) => {
                    if let WorkflowEvent::RunStarted { run_dir: dir, .. } = &event {
                        run_dir = dir.clone();
                    }
                    if let WorkflowEvent::ApprovalRequested { .. } = &event
                        && let Some(decision) = &decision
                    {
                        let _ = approval_tx.send(decision.clone());
                        answered = true;
                    }
                    let finished = matches!(event, WorkflowEvent::RunFinished { .. });
                    events.push(event);
                    if finished {
                        break;
                    }
                }
                Err(_) => panic!("engine did not finish in time; events: {events:?}"),
            }
        }
        let outcome = handle.join().expect("engine thread");
        if decision.is_some() {
            assert!(
                answered,
                "an approval decision was scripted but never requested"
            );
        }
        DrivenRun {
            events,
            outcome,
            run_dir,
        }
    }

    fn stage_statuses(events: &[WorkflowEvent]) -> Vec<(Stage, StageStatus)> {
        events
            .iter()
            .filter_map(|event| match event {
                WorkflowEvent::StageFinished { stage, status, .. } => Some((*stage, *status)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn auto_mode_runs_to_the_rung_boundary_with_all_artifacts() {
        let (base, game) = fixture_game("auto");
        let mut config = RunConfig::new(game);
        config.mode = RunMode::Auto;
        config.output_root = base.join("runs");
        let driven = drive(config, None, false);
        assert_eq!(
            driven.outcome,
            RunOutcome::StoppedAtRungBoundary {
                stage: Stage::Build
            }
        );
        let statuses = stage_statuses(&driven.events);
        assert_eq!(
            statuses,
            vec![
                (Stage::Census, StageStatus::Done),
                (Stage::Spec, StageStatus::Done),
                (Stage::Translate, StageStatus::Done),
                (Stage::Plan, StageStatus::Done),
                (Stage::Build, StageStatus::Unavailable),
                (Stage::Gates, StageStatus::Skipped),
            ]
        );
        for artifact in [
            "census.json",
            "spec-draft.md",
            "translation-manifest.json",
            "plan.md",
            "run-log.txt",
        ] {
            assert!(
                driven.run_dir.join(artifact).exists(),
                "missing artifact {artifact}"
            );
        }
        let log = std::fs::read_to_string(driven.run_dir.join("run-log.txt")).expect("log");
        assert!(log.contains("run finished"), "{log}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn plan_mode_pauses_and_approval_reaches_the_boundary() {
        let (base, game) = fixture_game("approve");
        let mut config = RunConfig::new(game);
        config.output_root = base.join("runs");
        let driven = drive(config, Some(ApprovalDecision::Approve), false);
        assert_eq!(
            driven.outcome,
            RunOutcome::StoppedAtRungBoundary {
                stage: Stage::Build
            }
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn plan_mode_rejection_stops_before_build() {
        let (base, game) = fixture_game("reject");
        let mut config = RunConfig::new(game);
        config.output_root = base.join("runs");
        let driven = drive(config, Some(ApprovalDecision::Abort), false);
        assert_eq!(driven.outcome, RunOutcome::PlanRejected);
        let statuses = stage_statuses(&driven.events);
        assert!(statuses.contains(&(Stage::Build, StageStatus::Skipped)));
        assert!(statuses.contains(&(Stage::Gates, StageStatus::Skipped)));
        assert!(driven.run_dir.join("plan.md").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn plan_mode_note_is_appended_to_the_plan() {
        let (base, game) = fixture_game("note");
        let mut config = RunConfig::new(game);
        config.output_root = base.join("runs");
        let driven = drive(
            config,
            Some(ApprovalDecision::ApproveWithNote(
                "prioritise the battle system".to_string(),
            )),
            false,
        );
        assert_eq!(
            driven.outcome,
            RunOutcome::StoppedAtRungBoundary {
                stage: Stage::Build
            }
        );
        let plan = std::fs::read_to_string(driven.run_dir.join("plan.md")).expect("plan");
        assert!(plan.contains("prioritise the battle system"), "{plan}");
        assert!(plan.contains("Operator note"), "{plan}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn abort_before_the_run_aborts_at_census() {
        let (base, game) = fixture_game("abort");
        let mut config = RunConfig::new(game);
        config.mode = RunMode::Auto;
        config.output_root = base.join("runs");
        let driven = drive(config, None, true);
        assert_eq!(
            driven.outcome,
            RunOutcome::Aborted {
                stage: Stage::Census
            }
        );
        assert!(!driven.run_dir.join("census.json").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn translate_off_skips_the_stage_and_still_plans() {
        let (base, game) = fixture_game("notranslate");
        let mut config = RunConfig::new(game);
        config.mode = RunMode::Auto;
        config.output_root = base.join("runs");
        config.translate = TranslateConfig {
            enabled: false,
            ..TranslateConfig::default()
        };
        let driven = drive(config, None, false);
        let statuses = stage_statuses(&driven.events);
        assert!(statuses.contains(&(Stage::Translate, StageStatus::Skipped)));
        let manifest = std::fs::read_to_string(driven.run_dir.join("translation-manifest.json"))
            .expect("manifest");
        assert!(manifest.contains("\"enabled\": false"), "{manifest}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn event_order_is_run_started_first_and_run_finished_last() {
        let (base, game) = fixture_game("order");
        let mut config = RunConfig::new(game);
        config.mode = RunMode::Auto;
        config.output_root = base.join("runs");
        config.provider = Provider::Cloud;
        let driven = drive(config, None, false);
        assert!(matches!(
            driven.events.first(),
            Some(WorkflowEvent::RunStarted { .. })
        ));
        assert!(matches!(
            driven.events.last(),
            Some(WorkflowEvent::RunFinished { .. })
        ));
        // Stage starts and finishes strictly alternate in
        // pipeline sequence order. The one honest exception:
        // a stage skipped without ever starting (the tail
        // after a rung boundary or an abort) finishes with
        // `Skipped` and no start — it never ran.
        let mut last_started: Option<Stage> = None;
        for event in &driven.events {
            match event {
                WorkflowEvent::StageStarted { stage } => {
                    assert!(last_started.is_none(), "nested stage start");
                    last_started = Some(*stage);
                }
                WorkflowEvent::StageFinished {
                    stage,
                    status: StageStatus::Skipped,
                    ..
                } if last_started != Some(*stage) => {
                    assert!(last_started.is_none(), "skip inside a running stage");
                }
                WorkflowEvent::StageFinished { stage, .. } => {
                    assert_eq!(last_started, Some(*stage), "finish without start");
                    last_started = None;
                }
                _ => {}
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn invalid_config_builds_no_engine() {
        let config = RunConfig::new(PathBuf::from("/nonexistent-fathom-engine-target"));
        assert!(Engine::new(config).is_err());
    }
}
