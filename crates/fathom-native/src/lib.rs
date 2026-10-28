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
pub mod il2cpp;
pub mod layout;

pub use engine::locate_headless;

use serde_json::json;
use std::sync::Arc;

use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, target_schema};

/// The `{target}` schema plus the paging arguments the retained
/// inventory reads accept (SPEC §9.1 read pattern).
fn inventory_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1,
                "description": "Rows in this page; capped at the inventory's count bound"},
            "offset": {"type": "integer", "minimum": 0,
                "description": "Retained rows to skip before this page"},
            "target": {"type": "string", "description": "Path under a configured target root"},
        },
        "required": ["target"],
        "additionalProperties": false,
    })
}

/// Register the native provider's tools, all implemented.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "analyze_function",
            ToolClass::Read,
            "ghidra",
            "Function dossier: identity, counts, and call-graph size by default; \
             detail \"complete\" adds the listing, bounded decompile, callers, and callees",
            json!({
                "type": "object",
                "properties": {
                    "detail": {"type": "string", "enum": ["complete", "summary"],
                        "description": "View over the retained export; summary is the default"},
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
            "il2cpp_apply",
            ToolClass::Execute,
            "ghidra-il2cpp",
            "Apply a script.json method/string map to a Ghidra project (headless, idempotent)",
            json!({
                "type": "object",
                "properties": {
                    "map": {"type": "string"},
                    "program": {"type": "string"},
                    "project": {"type": "string"},
                    "project_name": {"type": "string"},
                },
                "required": ["map", "project", "project_name"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(il2cpp::il2cpp_apply),
    );
    registry.register(
        descriptor(
            "il2cpp_decompile",
            ToolClass::Read,
            "ghidra-il2cpp",
            "Decompile one IL2CPP method (by name or 0x RVA) with depth-1 callees",
            json!({
                "type": "object",
                "properties": {
                    "game_namespaces": {"type": "array", "items": {"type": "string"}},
                    "map": {"type": "string"},
                    "method": {"type": "string"},
                    "program": {"type": "string"},
                    "project": {"type": "string"},
                    "project_name": {"type": "string"},
                },
                "required": ["method", "project", "project_name"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(il2cpp::il2cpp_decompile),
    );
    registry.register(
        descriptor(
            "il2cpp_xrefs",
            ToolClass::Read,
            "ghidra-il2cpp",
            "Reference census for IL2CPP addresses, callers grouped and namespace-classified",
            json!({
                "type": "object",
                "properties": {
                    "game_namespaces": {"type": "array", "items": {"type": "string"}},
                    "map": {"type": "string"},
                    "program": {"type": "string"},
                    "project": {"type": "string"},
                    "project_name": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["project", "project_name", "targets"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(il2cpp::il2cpp_xrefs),
    );
    registry.register(
        descriptor(
            "list_functions",
            ToolClass::Read,
            "ghidra",
            "Function inventory with classifications and signatures; \
             offset/limit page the retained rows",
            inventory_schema(),
        ),
        Arc::new(ghidra::list_functions),
    );
    registry.register(
        descriptor(
            "list_names",
            ToolClass::Read,
            "ghidra",
            "Symbol inventory: addresses, names, types; \
             offset/limit page the retained rows",
            inventory_schema(),
        ),
        Arc::new(ghidra::list_names),
    );
    registry.register(
        descriptor(
            "list_strings",
            ToolClass::Read,
            "ghidra",
            "Defined-string inventory with addresses; \
             offset/limit page the retained rows",
            inventory_schema(),
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
