//! The typed event stream between the engine and any frontend.
//!
//! The engine emits `WorkflowEvent`s; the frontend renders
//! them and answers approval requests with `ApprovalDecision`.
//! The run log is written from this same stream, so what the
//! operator saw is what the run record says.

use crate::config::{Provider, RunMode};
use crate::stages::{Stage, StageStatus};
use std::path::PathBuf;

/// The operator's answer to a plan-approval request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    /// Abort the run at the plan boundary.
    Abort,
    /// Approve the plan as written.
    Approve,
    /// Approve with an operator note; the note is appended to
    /// the plan document and the run log before the run goes on.
    ApproveWithNote(String),
}

/// How a run ended. The frontend renders this verbatim; it
/// never upgrades an outcome in wording.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    /// Aborted by the operator (or by the frontend going away)
    /// while `stage` was next or running.
    Aborted {
        /// The stage at which the abort took effect.
        stage: Stage,
    },
    /// Every stage finished. Not reachable in rung 1, where
    /// Build is an honest seam; kept so rung 2 needs no new
    /// outcome type.
    Completed,
    /// A stage failed; the run stopped.
    Failed {
        /// The typed error's text.
        error: String,
        /// The failing stage.
        stage: Stage,
    },
    /// The operator rejected the plan at the approval pause.
    PlanRejected,
    /// The run reached a stage that cannot execute in this
    /// rung and stopped cleanly at that boundary.
    StoppedAtRungBoundary {
        /// The stage that reported `Unavailable`.
        stage: Stage,
    },
}

impl RunOutcome {
    /// One-line human rendering for the run view and run log.
    pub fn describe(&self) -> String {
        match self {
            RunOutcome::Aborted { stage } => {
                format!("aborted at stage {}", stage.name())
            }
            RunOutcome::Completed => "completed".to_string(),
            RunOutcome::Failed { stage, error } => {
                format!("failed at stage {}: {error}", stage.name())
            }
            RunOutcome::PlanRejected => "plan rejected by operator".to_string(),
            RunOutcome::StoppedAtRungBoundary { stage } => format!(
                "stopped at the rung boundary: stage {} is model-executed \
                 and lands in rung 2",
                stage.name()
            ),
        }
    }
}

/// One event from the engine to the frontend.
#[derive(Clone, Debug)]
pub enum WorkflowEvent {
    /// The engine is blocked at the Plan boundary until the
    /// frontend answers with an `ApprovalDecision`.
    ApprovalRequested {
        /// The plan document to review.
        plan_path: PathBuf,
        /// Always `Stage::Plan` in this design.
        stage: Stage,
    },
    /// A free-form log line (also written to the run log).
    Log {
        /// The line.
        line: String,
        /// The emitting stage, if any.
        stage: Option<Stage>,
    },
    /// The run is over; carries the terminal outcome.
    RunFinished {
        /// The outcome.
        outcome: RunOutcome,
    },
    /// The run directory exists and the pipeline is starting.
    RunStarted {
        /// Plan or auto.
        mode: RunMode,
        /// Provider route.
        provider: Provider,
        /// Where the run's artifacts are being written.
        run_dir: PathBuf,
        /// The target directory under analysis.
        target: PathBuf,
    },
    /// A stage reached its terminal status for this run.
    StageFinished {
        /// The stage.
        stage: Stage,
        /// Its terminal status.
        status: StageStatus,
        /// One-line summary (counts, artifact name, or reason).
        summary: String,
    },
    /// A stage began executing.
    StageStarted {
        /// The stage.
        stage: Stage,
    },
    /// Progress inside a stage; `done`/`total` are counts in
    /// the unit the stage's message names.
    StageProgress {
        /// Units completed, when countable.
        done: Option<u64>,
        /// The progress line.
        message: String,
        /// The stage.
        stage: Stage,
        /// Units total, when known.
        total: Option<u64>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rung_boundary_outcome_names_the_stage_and_rung() {
        let outcome = RunOutcome::StoppedAtRungBoundary {
            stage: Stage::Build,
        };
        let text = outcome.describe();
        assert!(text.contains("build"), "{text}");
        assert!(text.contains("rung 2"), "{text}");
    }

    #[test]
    fn failed_outcome_carries_stage_and_error() {
        let outcome = RunOutcome::Failed {
            stage: Stage::Census,
            error: "boom".to_string(),
        };
        assert_eq!(outcome.describe(), "failed at stage census: boom");
    }
}
