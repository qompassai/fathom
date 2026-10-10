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
pub mod sourcemap;

use std::sync::Arc;

use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, target_schema};
use serde_json::json;

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
    registry.register(
        descriptor(
            "inspect_source_map",
            ToolClass::Read,
            "javascript",
            "Source-map v3 parsing: sources, sourcesContent presence, segments, and generated-to-original position mapping",
            json!({
                "type": "object",
                "properties": {
                    "generated_column": {"type": "integer", "minimum": 0},
                    "generated_line": {"type": "integer", "minimum": 0},
                    "target": {"type": "string", "description": "Path to a .map file under a configured target root"},
                },
                "required": ["target"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(sourcemap::inspect_source_map),
    );
}
