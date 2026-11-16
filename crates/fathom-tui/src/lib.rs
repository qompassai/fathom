//! fathom-tui: the clean-room rebuild workflow for fathom.
//!
//! The library half is the workflow engine — typed run
//! configuration, a staged pipeline (Census → Spec → Translate
//! → Plan → Build → Gates) behind a `StageExecutor` trait, and
//! a typed event stream. It has no terminal dependency: the
//! ratatui TUI in `tui` is one view over it, and a headless
//! runner or a `fathom workflow` subcommand can drive the same
//! engine later (the phlow one-runtime-many-frontends shape).
//!
//! Rung 1 scope: Census, Spec, Translate (inventory), and Plan
//! are real and deterministic. Build and Gates are
//! model-executed stages and report the typed `Unavailable`
//! status rather than pretending to run — see `executors`.
#![forbid(unsafe_code)]

pub mod census;
pub mod config;
pub mod documents;
pub mod engine;
pub mod error;
pub mod events;
pub mod executors;
pub mod run_dir;
pub mod stages;
pub mod translate;
pub mod tui;
