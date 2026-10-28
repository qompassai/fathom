//! fathom-core: the shared foundation of the fathom port.
//!
//! Config (fail-closed), canonical error contracts, the evidence
//! model, the deterministic policy engine, the tool registry,
//! target confinement, and bounded child processes. Providers
//! build on this crate and never bypass it.
#![forbid(unsafe_code)]

pub mod bundle;
pub mod config;
pub mod error;
pub mod evidence;
pub mod limits;
pub mod paths;
pub mod policy;
pub mod process;
pub mod proof;
pub mod registry;

/// The port's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The source revision this build was compiled from (SPEC
/// §4.1.5): the git HEAD at build time, suffixed `-dirty` when
/// the tree carried uncommitted changes, or `"unknown"` when
/// built outside a checkout. Embedded by `build.rs`; part of
/// the producer identity `session_info` reports.
pub const SOURCE_REVISION: &str = env!("FATHOM_SOURCE_REVISION");

/// The port's product name, used in protocol surfaces.
pub const PRODUCT_NAME: &str = "fathom";
