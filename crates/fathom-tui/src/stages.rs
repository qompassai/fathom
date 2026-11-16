//! The workflow's stages and their statuses.
//!
//! Variants are declared alphabetically (the repository rule);
//! the execution order lives in `Stage::SEQUENCE`, because the
//! pipeline order is a semantic contract, not a sort order.

/// One stage of the clean-room rebuild pipeline.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Stage {
    /// Model-executed clean-room implementation in Rust.
    Build,
    /// Deterministic census of the target directory.
    Census,
    /// Verification of the build against the spec.
    Gates,
    /// Deterministic run plan; the plan-mode approval artifact.
    Plan,
    /// Deterministic spec draft from the census.
    Spec,
    /// Text inventory + translation (inventory is deterministic).
    Translate,
}

impl Stage {
    /// The pipeline execution order: Census → Spec → Translate
    /// → Plan → Build → Gates (D-1559 as amended by D-1560).
    pub const SEQUENCE: [Stage; 6] = [
        Stage::Census,
        Stage::Spec,
        Stage::Translate,
        Stage::Plan,
        Stage::Build,
        Stage::Gates,
    ];

    /// Machine name, used in logs and artifacts.
    pub fn name(self) -> &'static str {
        match self {
            Stage::Build => "build",
            Stage::Census => "census",
            Stage::Gates => "gates",
            Stage::Plan => "plan",
            Stage::Spec => "spec",
            Stage::Translate => "translate",
        }
    }

    /// Display title for the run view.
    pub fn title(self) -> &'static str {
        match self {
            Stage::Build => "Build",
            Stage::Census => "Census",
            Stage::Gates => "Gates",
            Stage::Plan => "Plan",
            Stage::Spec => "Spec",
            Stage::Translate => "Translate",
        }
    }

    /// Whether the stage calls a model when fully implemented.
    /// Deterministic stages never route through a provider.
    pub fn is_model_executed(self) -> bool {
        matches!(self, Stage::Build | Stage::Gates)
    }
}

/// Lifecycle status of one stage within a run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageStatus {
    /// Finished with its rung's full contract.
    Done,
    /// Finished by failing; the run stops.
    Failed,
    /// Not yet started.
    Pending,
    /// Currently executing.
    Running,
    /// Never ran: an earlier stage stopped the run, or the
    /// stage was disabled by configuration.
    Skipped,
    /// The stage exists but cannot execute in this rung; the
    /// run stops at this boundary without pretending otherwise.
    Unavailable,
}

impl StageStatus {
    /// Single-glyph rendering for the run view's stage list.
    pub fn glyph(self) -> &'static str {
        match self {
            StageStatus::Done => "✓",
            StageStatus::Failed => "✗",
            StageStatus::Pending => "·",
            StageStatus::Running => "▶",
            StageStatus::Skipped => "–",
            StageStatus::Unavailable => "○",
        }
    }

    /// Machine name, used in the run log.
    pub fn name(self) -> &'static str {
        match self {
            StageStatus::Done => "done",
            StageStatus::Failed => "failed",
            StageStatus::Pending => "pending",
            StageStatus::Running => "running",
            StageStatus::Skipped => "skipped",
            StageStatus::Unavailable => "unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_the_pipeline_order() {
        assert_eq!(
            Stage::SEQUENCE.map(|stage| stage.name()),
            ["census", "spec", "translate", "plan", "build", "gates"]
        );
    }

    #[test]
    fn sequence_covers_every_stage_once() {
        let mut seen = std::collections::BTreeSet::new();
        for stage in Stage::SEQUENCE {
            assert!(seen.insert(stage), "duplicate stage {stage:?}");
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn only_build_and_gates_are_model_executed() {
        assert!(Stage::Build.is_model_executed());
        assert!(Stage::Gates.is_model_executed());
        for stage in [Stage::Census, Stage::Spec, Stage::Translate, Stage::Plan] {
            assert!(!stage.is_model_executed(), "{stage:?}");
        }
    }
}
