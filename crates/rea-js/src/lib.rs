//! JavaScript/Electron provider (SPEC §9.2).
//!
//! oxc parses each module; facts are imports, exports, the
//! module graph, and the Electron boundary (IPC channels,
//! `contextBridge` exposures, window preferences). ASAR archives
//! are read by a hand-implemented reader for the pickle-framed
//! format, cross-validated against archives produced by the real
//! `@electron/asar` tool (fixture test).

#![forbid(unsafe_code)]

pub mod analyzer;
pub mod app;
pub mod asar;

use std::sync::Arc;

use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, target_schema};

/// Register the JavaScript provider's tools, all implemented.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "analyze_javascript_application",
            ToolClass::Read,
            "javascript",
            "Static analysis of a JS/Electron application: modules, graph, IPC boundaries",
            target_schema(),
        ),
        Arc::new(app::analyze_javascript_application),
    );
    registry.register(
        descriptor(
            "inspect_asar",
            ToolClass::Read,
            "asar",
            "ASAR archive inventory: entries, sizes, offsets, unpacked flags",
            target_schema(),
        ),
        Arc::new(asar::inspect_asar),
    );
}
