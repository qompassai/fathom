//! Native-binary provider (SPEC §9.1, §9.4).
//!
//! Ghidra 12 runs headless as the analysis engine (the estate
//! pattern from diver's `security.ghidra`); layout and artifact
//! facts are read directly with goblin. IDA is not ported: no
//! license exists on Matt's machines, so claiming it would fake
//! coverage.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod beam;
pub mod engine;
pub mod ghidra;
pub mod godot;
pub mod gpu;
pub mod il2cpp;
pub mod layout;
pub mod python;
pub mod renpy;
pub mod unity;
pub mod unreal;

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
            "inspect_beam_module",
            ToolClass::Read,
            "beam",
            "BEAM module census: IFF chunk inventory, atom table, imports, \
             exports, locals, and lambdas resolved through the atom table, \
             Code header cross-checked against the function tables, literal \
             table walked as external terms; the opcode stream is \
             inventoried, never decoded",
            target_schema(),
        ),
        Arc::new(beam::inspect_beam_module),
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
            "inspect_godot_pck",
            ToolClass::Read,
            "godot",
            "Godot PCK archive inventory: header, directory entries with \
             content hashes and MD5 cross-checks; encrypted, sparse, and \
             unreadable entries are explicit unknowns",
            target_schema(),
        ),
        Arc::new(godot::inspect_godot_pck),
    );
    registry.register(
        descriptor(
            "inspect_gpu_code_object",
            ToolClass::Read,
            "gpu",
            "GPU code-object census: a standalone AMDGPU ELF (target from \
             e_flags, kernel symbols with descriptor presence, NT_AMDGPU_METADATA \
             note decoded from MessagePack or YAML), a Clang offload bundle, or \
             a host binary with bundles embedded; instruction streams are \
             inventoried, never disassembled",
            target_schema(),
        ),
        Arc::new(gpu::inspect_gpu_code_object),
    );
    registry.register(
        descriptor(
            "inspect_python_artifact",
            ToolClass::Read,
            "python",
            "Python artifact census: a .pyc (PEP 552 header facts and the \
             code-object tree — functions, classes, lambdas, names, string \
             constants — read with a bounded marshal reader) or a PyInstaller \
             archive (CArchive TOC with stored-byte SHA-256 per entry and the \
             nested PYZ module census); bytecode instructions are not decoded",
            target_schema(),
        ),
        Arc::new(python::inspect_python_artifact),
    );
    registry.register(
        descriptor(
            "inspect_renpy_archive",
            ToolClass::Read,
            "renpy",
            "Ren'Py RPA archive census (RPA-3.0 and RPA-2.0): header and key facts, \
             a restricted data-only pickle interpreter for the index (never a real \
             unpickler), and SHA-256 of every segment's stored bytes; the format \
             carries no content anchor and the census says so",
            target_schema(),
        ),
        Arc::new(renpy::inspect_renpy_archive),
    );
    registry.register(
        descriptor(
            "inspect_unity_bundle",
            ToolClass::Read,
            "unity",
            "Unity UnityFS bundle (formats 6-8) or standalone SerializedFile \
             (versions 9-22) census: blocks-info directory (LZ4; LZMA reported, \
             never decoded), per-file type/object summaries with type trees \
             skipped, and the data hash recorded as an unverified fact",
            target_schema(),
        ),
        Arc::new(unity::inspect_unity_bundle),
    );
    registry.register(
        descriptor(
            "inspect_unreal_pak",
            ToolClass::Read,
            "unreal",
            "Unreal Engine pak (version 11) census: footer and index SHA-1 \
             verification, full-directory paths, encoded-entry decode cross-checked \
             against data-area headers, stored-byte SHA-1 verification for every \
             entry; encrypted entries are reported, never decrypted",
            target_schema(),
        ),
        Arc::new(unreal::inspect_unreal_pak),
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
