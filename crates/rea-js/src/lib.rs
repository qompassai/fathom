//! rea-js: JavaScript / Electron static analysis.
//!
//! oxc parses; the module graph resolves relative specifiers;
//! Electron IPC boundaries are AST-derived; ASAR archives are
//! read by an in-tree implementation of the format (SPEC §9.2).
//! Stage 1 registers the catalog as scaffolds; stage 2 builds
//! the handlers.
#![forbid(unsafe_code)]

use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, target_schema};

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register_not_implemented(
        descriptor(
            "analyze_javascript_application",
            ToolClass::Read,
            "js",
            "Module graph, imports/exports, and Electron boundaries of an app directory or ASAR",
            target_schema(),
        ),
        "§9.2",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_asar",
            ToolClass::Read,
            "js",
            "ASAR archive inventory: entries, sizes, offsets, unpacked flags",
            target_schema(),
        ),
        "§9.2",
    );
}
