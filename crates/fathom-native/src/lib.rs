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
pub mod sections;
pub mod unity;
pub mod unreal;

pub use engine::locate_headless;

use serde_json::{Value, json};
use std::sync::Arc;

use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, target_schema};

/// SPEC anchor for read-core rows that would mutate the cached
/// Ghidra project: the batch-export cache is keyed by subject
/// SHA-256, not project revision, so a write would silently stale
/// every cached export. The transactional mutation path is G2.
const SPEC_MUTATION_PATH: &str = "§9.1 (mutation path: Ghidra G2)";

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

/// The `{target, ...}` schema: `properties` plus the target path,
/// `required` plus `target`, no additional properties.
fn target_and(properties: Value, required: &[&str]) -> Value {
    let mut merged = properties.as_object().cloned().unwrap_or_default();
    merged.insert(
        "target".into(),
        json!({"type": "string", "description": "Path under a configured target root"}),
    );
    let mut required: Vec<&str> = required.to_vec();
    required.push("target");
    required.sort_unstable();
    json!({
        "type": "object",
        "properties": merged,
        "required": required,
        "additionalProperties": false,
    })
}

/// `properties` plus the paged-listing `offset`/`limit` pair.
fn with_page(properties: Value) -> Value {
    let mut merged = properties.as_object().cloned().unwrap_or_default();
    if let Some(page) = ghidra::query::page_properties().as_object() {
        merged.extend(page.clone());
    }
    Value::Object(merged)
}

/// Register the native provider's tools. Read-core rows that
/// would write are registered not-implemented with their reason.
pub fn register(registry: &mut Registry) {
    registry.register_not_implemented(
        descriptor(
            "add_memory_reference",
            ToolClass::Execute,
            "ghidra",
            "Add a memory reference — not implemented: writes to the cached project \
             await the G2 mutation path",
            target_and(
                json!({
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "type": {"type": "string"},
                }),
                &["from", "to"],
            ),
        ),
        SPEC_MUTATION_PATH,
    );
    registry.register(
        descriptor(
            "analysis_status",
            ToolClass::Read,
            "ghidra",
            "Whether the cached program is auto-analyzed, and analyzer enablement counts",
            target_schema(),
        ),
        Arc::new(ghidra::program::analysis_status),
    );
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
            "find_next_undefined_function",
            ToolClass::Read,
            "ghidra",
            "Next instructions (at or after 'start') that no function body covers",
            target_and(json!({"start": {"type": "string"}}), &[]),
        ),
        Arc::new(ghidra::functions::find_next_undefined_function),
    );
    registry.register(
        descriptor(
            "get_bulk_xrefs",
            ToolClass::Read,
            "ghidra",
            "References to and from up to 32 addresses in one engine run",
            target_and(
                json!({"addresses": {"type": "array", "items": {"type": "string"},
                    "minItems": 1, "maxItems": fathom_core::limits::ADDRESS_QUERY_COUNT_MAX}}),
                &["addresses"],
            ),
        ),
        Arc::new(ghidra::xrefs::get_bulk_xrefs),
    );
    registry.register(
        descriptor(
            "get_comment",
            ToolClass::Read,
            "ghidra",
            "Stored comments at one address, optionally of one type",
            target_and(
                json!({
                    "address": {"type": "string"},
                    "type": {"type": "string",
                        "enum": ["eol", "plate", "post", "pre", "repeatable"]},
                }),
                &["address"],
            ),
        ),
        Arc::new(ghidra::program::get_comment),
    );
    registry.register(
        descriptor(
            "get_data_type_size",
            ToolClass::Read,
            "ghidra",
            "Length Ghidra records for one named data type (name or /category/path)",
            target_and(json!({"name": {"type": "string"}}), &["name"]),
        ),
        Arc::new(ghidra::types::get_data_type_size),
    );
    registry.register(
        descriptor(
            "get_entry_points",
            ToolClass::Read,
            "ghidra",
            "External entry points (exports and the program entry; paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::get_entry_points),
    );
    registry.register(
        descriptor(
            "get_enum_values",
            ToolClass::Read,
            "ghidra",
            "Names and values of one enum data type",
            target_and(json!({"name": {"type": "string"}}), &["name"]),
        ),
        Arc::new(ghidra::types::get_enum_values),
    );
    registry.register(
        descriptor(
            "get_external_location",
            ToolClass::Read,
            "ghidra",
            "External (imported) locations matching one name or address",
            target_and(
                json!({"address": {"type": "string"}, "name": {"type": "string"}}),
                &[],
            ),
        ),
        Arc::new(ghidra::program::get_external_location),
    );
    registry.register(
        descriptor(
            "get_full_call_graph",
            ToolClass::Read,
            "ghidra",
            "Every resolved call edge in the program (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::functions::get_full_call_graph),
    );
    registry.register(
        descriptor(
            "get_function_call_graph",
            ToolClass::Read,
            "ghidra",
            "Call-graph neighborhood of one function to a bounded depth",
            target_and(
                json!({
                    "depth": {"type": "integer", "minimum": 1,
                        "maximum": fathom_core::limits::CALL_GRAPH_DEPTH_MAX},
                    "direction": {"type": "string", "enum": ["both", "callees", "callers"]},
                    "function": {"type": "string"},
                }),
                &["function"],
            ),
        ),
        Arc::new(ghidra::functions::get_function_call_graph),
    );
    registry.register(
        descriptor(
            "get_function_jump_targets",
            ToolClass::Read,
            "ghidra",
            "Jump instructions in a function and their resolved targets",
            target_and(json!({"function": {"type": "string"}}), &["function"]),
        ),
        Arc::new(ghidra::functions::get_function_jump_targets),
    );
    registry.register(
        descriptor(
            "get_function_labels",
            ToolClass::Read,
            "ghidra",
            "Label symbols stored inside a function body",
            target_and(json!({"function": {"type": "string"}}), &["function"]),
        ),
        Arc::new(ghidra::functions::get_function_labels),
    );
    registry.register(
        descriptor(
            "get_function_pcode",
            ToolClass::Read,
            "ghidra",
            "Raw p-code per instruction, or the decompiler's high p-code (paged)",
            target_and(
                with_page(json!({
                    "function": {"type": "string"},
                    "high": {"type": "boolean"},
                })),
                &["function"],
            ),
        ),
        Arc::new(ghidra::functions::get_function_pcode),
    );
    registry.register(
        descriptor(
            "get_function_tags",
            ToolClass::Read,
            "ghidra",
            "Function tags applied to one function",
            target_and(json!({"function": {"type": "string"}}), &["function"]),
        ),
        Arc::new(ghidra::functions::get_function_tags),
    );
    registry.register(
        descriptor(
            "get_function_variables",
            ToolClass::Read,
            "ghidra",
            "Listing parameters and locals, plus the decompiler's variables",
            target_and(json!({"function": {"type": "string"}}), &["function"]),
        ),
        Arc::new(ghidra::functions::get_function_variables),
    );
    registry.register(
        descriptor(
            "get_function_xrefs",
            ToolClass::Read,
            "ghidra",
            "References into a function's entry and out of its instructions",
            target_and(json!({"function": {"type": "string"}}), &["function"]),
        ),
        Arc::new(ghidra::xrefs::get_function_xrefs),
    );
    registry.register(
        descriptor(
            "get_plate_comment",
            ToolClass::Read,
            "ghidra",
            "Stored plate comment at an address or a function's entry",
            target_and(
                json!({"address": {"type": "string"}, "function": {"type": "string"}}),
                &[],
            ),
        ),
        Arc::new(ghidra::program::get_plate_comment),
    );
    registry.register(
        descriptor(
            "get_program_options",
            ToolClass::Read,
            "ghidra",
            "Program options with types and values, optionally one group (paged)",
            target_and(with_page(json!({"group": {"type": "string"}})), &[]),
        ),
        Arc::new(ghidra::program::get_program_options),
    );
    registry.register(
        descriptor(
            "get_project_info",
            ToolClass::Read,
            "ghidra",
            "Fathom's cached Ghidra project for the target, read from the state dir",
            target_schema(),
        ),
        Arc::new(ghidra::program::get_project_info),
    );
    registry.register(
        descriptor(
            "get_property",
            ToolClass::Read,
            "ghidra",
            "Value of one user property map at one address",
            target_and(
                json!({"address": {"type": "string"}, "map": {"type": "string"}}),
                &["address", "map"],
            ),
        ),
        Arc::new(ghidra::program::get_property),
    );
    registry.register(
        descriptor(
            "get_struct_layout",
            ToolClass::Read,
            "ghidra",
            "Defined components of a structure or union, with undefined regions",
            target_and(json!({"name": {"type": "string"}}), &["name"]),
        ),
        Arc::new(ghidra::types::get_struct_layout),
    );
    registry.register(
        descriptor(
            "get_type_size",
            ToolClass::Read,
            "ghidra",
            "Size a type expression denotes ('char *', 'uint[16]'), derived by a stated grammar",
            target_and(json!({"type": {"type": "string"}}), &["type"]),
        ),
        Arc::new(ghidra::types::get_type_size),
    );
    registry.register(
        descriptor(
            "get_valid_data_types",
            ToolClass::Read,
            "ghidra",
            "Built-in and program-defined data type names (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::types::get_valid_data_types),
    );
    registry.register(
        descriptor(
            "get_xrefs_from",
            ToolClass::Read,
            "ghidra",
            "References recorded from one address (paged)",
            target_and(
                with_page(json!({"address": {"type": "string"}})),
                &["address"],
            ),
        ),
        Arc::new(ghidra::xrefs::get_xrefs_from),
    );
    registry.register(
        descriptor(
            "get_xrefs_to",
            ToolClass::Read,
            "ghidra",
            "References to one address, with referencing functions (paged)",
            target_and(
                with_page(json!({"address": {"type": "string"}})),
                &["address"],
            ),
        ),
        Arc::new(ghidra::xrefs::get_xrefs_to),
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
            "list_analyzers",
            ToolClass::Read,
            "ghidra",
            "Auto-analysis analyzers recorded in the program, with enablement (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_analyzers),
    );
    registry.register(
        descriptor(
            "list_bookmarks",
            ToolClass::Read,
            "ghidra",
            "Bookmarks, optionally filtered by type or category (paged)",
            target_and(
                with_page(json!({
                    "category": {"type": "string"},
                    "type": {"type": "string"},
                })),
                &[],
            ),
        ),
        Arc::new(ghidra::program::list_bookmarks),
    );
    registry.register(
        descriptor(
            "list_calling_conventions",
            ToolClass::Read,
            "ghidra",
            "Calling conventions the program's compiler spec defines",
            target_schema(),
        ),
        Arc::new(ghidra::program::list_calling_conventions),
    );
    registry.register(
        descriptor(
            "list_class_members",
            ToolClass::Read,
            "ghidra",
            "Symbols inside one class namespace (paged)",
            target_and(with_page(json!({"class": {"type": "string"}})), &["class"]),
        ),
        Arc::new(ghidra::program::list_class_members),
    );
    registry.register(
        descriptor(
            "list_classes",
            ToolClass::Read,
            "ghidra",
            "Class namespaces with member counts (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_classes),
    );
    registry.register(
        descriptor(
            "list_data_items",
            ToolClass::Read,
            "ghidra",
            "Defined data items with types, values, and reference counts (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_data_items),
    );
    registry.register(
        descriptor(
            "list_data_items_by_xrefs",
            ToolClass::Read,
            "ghidra",
            "Defined data items ranked by references to them (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_data_items_by_xrefs),
    );
    registry.register(
        descriptor(
            "list_data_type_categories",
            ToolClass::Read,
            "ghidra",
            "Data type categories with type and subcategory counts (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::types::list_data_type_categories),
    );
    registry.register(
        descriptor(
            "list_data_types",
            ToolClass::Read,
            "ghidra",
            "Program data types, optionally filtered by category or kind (paged)",
            target_and(
                with_page(json!({
                    "category": {"type": "string"},
                    "kind": {"type": "string", "enum": ["array", "builtin", "enum",
                        "function_definition", "other", "pointer", "structure", "typedef",
                        "union"]},
                })),
                &[],
            ),
        ),
        Arc::new(ghidra::types::list_data_types),
    );
    registry.register(
        descriptor(
            "list_external_locations",
            ToolClass::Read,
            "ghidra",
            "External (imported) locations, optionally one library (paged)",
            target_and(with_page(json!({"library": {"type": "string"}})), &[]),
        ),
        Arc::new(ghidra::program::list_external_locations),
    );
    registry.register(
        descriptor(
            "list_function_tags",
            ToolClass::Read,
            "ghidra",
            "Function tags defined in the program, with use counts (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::functions::list_function_tags),
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
            "list_namespaces",
            ToolClass::Read,
            "ghidra",
            "Namespace, class, and library symbols with member counts (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_namespaces),
    );
    registry.register_not_implemented(
        descriptor(
            "list_open_programs",
            ToolClass::Read,
            "ghidra",
            "Open programs — not implemented: fathom is stateless per call and holds no \
             open-program session (SPEC §4); see list_projects",
            json!({"type": "object", "properties": {}, "additionalProperties": false}),
        ),
        "§4 (stateless per-call tools; session binding not implemented)",
    );
    registry.register(
        descriptor(
            "list_option_groups",
            ToolClass::Read,
            "ghidra",
            "Program option groups with option counts (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_option_groups),
    );
    registry.register(
        descriptor(
            "list_project_files",
            ToolClass::Read,
            "ghidra",
            "Domain files in the target's cached Ghidra project (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_project_files),
    );
    registry.register(
        descriptor(
            "list_projects",
            ToolClass::Read,
            "ghidra",
            "Fathom's per-subject Ghidra project caches in the state dir (paged)",
            json!({
                "type": "object",
                "properties": ghidra::query::page_properties(),
                "additionalProperties": false,
            }),
        ),
        Arc::new(ghidra::program::list_projects),
    );
    registry.register(
        descriptor(
            "list_properties",
            ToolClass::Read,
            "ghidra",
            "User property map entries, optionally one map (paged)",
            target_and(with_page(json!({"map": {"type": "string"}})), &[]),
        ),
        Arc::new(ghidra::program::list_properties),
    );
    registry.register(
        descriptor(
            "list_property_maps",
            ToolClass::Read,
            "ghidra",
            "User property maps with value classes and sizes (paged)",
            target_and(with_page(json!({})), &[]),
        ),
        Arc::new(ghidra::program::list_property_maps),
    );
    registry.register(
        descriptor(
            "list_scripts",
            ToolClass::Read,
            "ghidra",
            "Scripts in fathom's provider script dir, with digests",
            fathom_core::registry::empty_schema(),
        ),
        Arc::new(ghidra::program::list_scripts),
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
            "project_info",
            ToolClass::Read,
            "ghidra",
            "The target's cached Ghidra project as Ghidra reports it",
            target_schema(),
        ),
        Arc::new(ghidra::program::project_info),
    );
    registry.register_not_implemented(
        descriptor(
            "remove_reference",
            ToolClass::Execute,
            "ghidra",
            "Remove a reference — not implemented: writes to the cached project \
             await the G2 mutation path",
            target_and(
                json!({"from": {"type": "string"}, "to": {"type": "string"}}),
                &["from", "to"],
            ),
        ),
        SPEC_MUTATION_PATH,
    );
    registry.register(
        descriptor(
            "search_data_types",
            ToolClass::Read,
            "ghidra",
            "Case-insensitive substring search over data type paths (paged)",
            target_and(with_page(json!({"query": {"type": "string"}})), &["query"]),
        ),
        Arc::new(ghidra::types::search_data_types),
    );
    registry.register(
        descriptor(
            "search_functions_by_tag",
            ToolClass::Read,
            "ghidra",
            "Functions carrying one tag (exact, case-sensitive; paged)",
            target_and(with_page(json!({"tag": {"type": "string"}})), &["tag"]),
        ),
        Arc::new(ghidra::functions::search_functions_by_tag),
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
    registry.register(
        descriptor(
            "validate_data_type",
            ToolClass::Read,
            "ghidra",
            "Whether a type expression parses and resolves, with the reason if not",
            target_and(json!({"type": {"type": "string"}}), &["type"]),
        ),
        Arc::new(ghidra::types::validate_data_type),
    );
    registry.register(
        descriptor(
            "validate_data_type_exists",
            ToolClass::Read,
            "ghidra",
            "Whether a data type name exists in the program or Ghidra's built-ins",
            target_and(json!({"name": {"type": "string"}}), &["name"]),
        ),
        Arc::new(ghidra::types::validate_data_type_exists),
    );
    registry.register(
        descriptor(
            "validate_function_prototype",
            ToolClass::Read,
            "ghidra",
            "Whether a C prototype's return and parameter types resolve in the program",
            target_and(json!({"prototype": {"type": "string"}}), &["prototype"]),
        ),
        Arc::new(ghidra::types::validate_function_prototype),
    );
}
