//! rea-core: the shared foundation of the rea-rust port.
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
pub mod registry;

/// The port's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The port's product name, used in protocol surfaces.
pub const PRODUCT_NAME: &str = "rea-rust";
