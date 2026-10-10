//! Native-binary provider (SPEC §9.1, §9.4).
//!
//! Ghidra 12 runs headless as the analysis engine (the estate
//! pattern from diver's `security.ghidra`); layout and artifact
//! facts are read directly with goblin. IDA is not ported: no
//! license exists on Matt's machines, so claiming it would fake
//! coverage.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod engine;
pub mod ghidra;
pub mod layout;

pub use engine::locate_headless;

use serde_json::json;
use std::sync::Arc;

use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, target_schema};

/// Register the native provider's tools, all implemented.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "analyze_function",
            ToolClass::Read,
            "ghidra",
            "Function dossier: listing, bounded decompile, callers, callees",
            json!({
                "type": "object",
                "properties": {
                    "function": {"type": "string"},
                    "target": {"type": "string"},
                },
                "required": ["function", "target"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(ghidra::analyze_function),
    );
    registry.register(
        descriptor(
            "binary_overview",
            ToolClass::Read,
            "ghidra",
            "Program identity, memory map, and inventory counts",
            target_schema(),
        ),
        Arc::new(ghidra::binary_overview),
    );
    registry.register(
        descriptor(
            "inspect_artifact",
            ToolClass::Read,
            "artifact",
            "File identity and classification, or a bounded directory inventory",
            target_schema(),
        ),
        Arc::new(artifact::inspect_artifact),
    );
    registry.register(
        descriptor(
            "inspect_binary_layout",
            ToolClass::Read,
            "native-layout",
            "Container layout and mitigation candidates, read directly (no engine)",
            target_schema(),
        ),
        Arc::new(layout::inspect_binary_layout),
    );
    registry.register(
        descriptor(
            "list_functions",
            ToolClass::Read,
            "ghidra",
            "Function inventory with classifications and signatures",
            target_schema(),
        ),
        Arc::new(ghidra::list_functions),
    );
    registry.register(
        descriptor(
            "list_names",
            ToolClass::Read,
            "ghidra",
            "Symbol inventory: addresses, names, types",
            target_schema(),
        ),
        Arc::new(ghidra::list_names),
    );
    registry.register(
        descriptor(
            "list_strings",
            ToolClass::Read,
            "ghidra",
            "Defined-string inventory with addresses",
            target_schema(),
        ),
        Arc::new(ghidra::list_strings),
    );
    registry.register(
        descriptor(
            "search_inventory",
            ToolClass::Read,
            "ghidra",
            "Substring search across functions, symbols, and strings",
            json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "target": {"type": "string"},
                },
                "required": ["query", "target"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(ghidra::search_inventory),
    );
}
