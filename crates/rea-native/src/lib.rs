//! rea-native: the native-binary provider.
//!
//! Deep analysis drives Ghidra headless as a child process with
//! a bundled Java export script (SPEC §9.1); layout diagnostics
//! use goblin with no engine dependency; artifact inventory
//! covers files and packages. Stage 1 registers the catalog as
//! scaffolds; stage 2 builds the handlers.
#![forbid(unsafe_code)]

use rea_core::config::Config;
use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, target_schema};
use serde_json::json;
use std::path::PathBuf;

/// Locate Ghidra's `analyzeHeadless`: explicit config first,
/// then `REA_GHIDRA_HEADLESS`, then `$PATH`, then the Arch
/// package location. Returns the first candidate that exists.
pub fn locate_headless(config: &Config) -> Option<PathBuf> {
    if let Some(path) = &config.ghidra_headless {
        if path.exists() {
            return Some(path.clone());
        }
    }
    if let Ok(path) = std::env::var("REA_GHIDRA_HEADLESS") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in ["ghidra-analyzeHeadless", "analyzeHeadless"] {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }
    let packaged = PathBuf::from("/opt/ghidra/support/analyzeHeadless");
    if packaged.exists() {
        return Some(packaged);
    }
    None
}

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register_not_implemented(
        descriptor(
            "analyze_function",
            ToolClass::Read,
            "ghidra",
            "Function dossier: assembly, decompiled output, callers, callees, references",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "function": {"type": "string", "description": "Function name or entry address"},
                },
                "required": ["target", "function"],
                "additionalProperties": false,
            }),
        ),
        "§9.1",
    );
    registry.register_not_implemented(
        descriptor(
            "binary_overview",
            ToolClass::Read,
            "ghidra",
            "Program inventory: identity, memory blocks, functions, symbols, strings",
            target_schema(),
        ),
        "§9.1",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_artifact",
            ToolClass::Read,
            "artifact",
            "File or directory inventory: digests, sizes, classification, plist facts",
            target_schema(),
        ),
        "§9.4",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_binary_layout",
            ToolClass::Read,
            "native-layout",
            "Offline layout diagnostics: sections, segments, symbols, relocations, mitigations",
            target_schema(),
        ),
        "§9.1",
    );
    registry.register_not_implemented(
        descriptor(
            "list_functions",
            ToolClass::Read,
            "ghidra",
            "Every function in the target program, with classification",
            target_schema(),
        ),
        "§9.1",
    );
    registry.register_not_implemented(
        descriptor(
            "list_names",
            ToolClass::Read,
            "ghidra",
            "Every address-bearing symbol in the target program",
            target_schema(),
        ),
        "§9.1",
    );
    registry.register_not_implemented(
        descriptor(
            "list_strings",
            ToolClass::Read,
            "ghidra",
            "Every defined string in the target program, with charset facts",
            target_schema(),
        ),
        "§9.1",
    );
    registry.register_not_implemented(
        descriptor(
            "search_inventory",
            ToolClass::Read,
            "ghidra",
            "Literal search across function, symbol, and string inventories",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "query": {"type": "string"},
                },
                "required": ["target", "query"],
                "additionalProperties": false,
            }),
        ),
        "§9.1",
    );
}
