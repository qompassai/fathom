# Fathom ↔ Ghidra parity matrix (G0)

**STATUS: COMPLETE — rebuilt on v6.0.0 per Pax count ruling (inbox 2026-10-20 09:52).**
Fathom baseline unchanged: `main @ 0ea7b20`.

## Count reconciliation (every number sourced)

| Figure | Count | Source |
|-------|------:|--------|
| Study headline (recon-time README) | **209** | Pax STUDY.md; dated erratum now on the study — documentation drifted; figure kept visible |
| v6.0.0 README headline | **272** | [README @ v6.0.0](https://raw.githubusercontent.com/bethington/ghidra-mcp/v6.0.0/README.md) (`**272 MCP tools**`); sha256 `a193861c307947a4674ba0c53121e108fa62912cf4499d2de9819323acfc563b` |
| v6.0.0 `tests/endpoints.json` `total_endpoints` | **272** | tagged release manifest (HTTP/plugin endpoints); sha256 `e5067594ff2a545b7d3a9ce6bf53ca0648ee88865b394a60a76f6294bcbcf85b`; `version: 6.0.0` |
| v6.0.0 README API-reference bullets | **280** | generated block between BEGIN/END GENERATED API REFERENCE (includes duplicate `import_file`) |
| v6.0.0 README API-reference **distinct** names | **279** | same block, `import_file` counted once |
| Bridge-only tools in README, absent from endpoints.json | **7** | `check_tools`, `connect_instance`, `list_instances`, `list_tool_groups`, `load_tool_group`, `search_tools`, `unload_tool_group` |
| **Authoritative matrix row count** | **279** | distinct documented MCP tool names on the v6.0.0 surface = 272 endpoints.json + 7 bridge static; `import_file` once |

**Upstream listing defect (flagged):** `import_file` appears **twice** in the v6.0.0 README API reference
(under Program & Session Management and again under Bridge Static Tools). It appears **once** in
`endpoints.json`. The matrix counts it once.

**Why 272 ≠ 279:** 272 is the plugin/HTTP endpoint catalog (`endpoints.json` + README headline).
279 is that catalog plus the 7 Python-bridge static tools documented in the README but not in
`endpoints.json`. Both are real enumerations of the release; the matrix uses distinct MCP tool
names (279) as the row set per Pax ruling.

## Sources

- Pax study + erratum: `~/workspace/fathom-ghidra-mcp-port-20261020/STUDY.md`
- Pax count ruling: inbox 2026-10-20 09:52 — baseline = v6.0.0 as installed on primo;
  authoritative rows = distinct tool names; import_file once.
- Prior answers (09:48): HAVE = working fathom implementation only; `observe_browser` ≠ HAVE.
- Primo install (study): Ghidra 12.1.2 + bethington bridge **v6.0.0**.
- Box copies: `/workspace/g0/README-v6.0.0.md`, `/workspace/g0/endpoints-v6.json`.

## Summary

| Status | Count |
|--------|------:|
| HAVE | 89 |
| BUILD | 113 |
| DEFER | 77 |
| **TOTAL rows** | **279** |

BUILD by study stage: G1=76, G2=35, G3=0, G4=2.

**G3 adjudications (live differential vs the bethington bridge, FxDiff3, 2026-10-29):**
function-hash VALUES differ between the implementations (bridge anchor hash
`d15155a6…` vs fathom `2f79e258…` for the same function) — the hash disciplines
are implementation-specific; each is internally consistent (source hash equals
target hash for identical code within each implementation) and both matched the
same 11/11 function pairs on the fixture pair, so this is a recorded legitimate
difference, not a defect. Fathom's discipline is documented on its tools:
SHA-256 over the concatenated instruction bytes in address order. The bridge's
`get_function_documentation` surfaces neither bookmarks nor tags; those families
were verified AGREE through the bridge's own `list_bookmarks` /
`get_function_tags` read-backs after its `merge_program_documentation`
(bookmarks planned/applied 1/1, tags 1/1, names 11/11, signatures 5/5, plate
comments 2/2, instruction comments 1/1). The bridge merge also reported
`errors: 49` internally and applied globals/data definitions beyond the
function-documentation scope fathom transfers — bridge scope, recorded, not
matched. Signature equality in fathom's transfer and diff is up to
calling-convention rendering (`__stdcall` may render on an imported signature
and not on the same prototype applied in another program).

`observe_browser` remains a fathom NotImplemented scaffold and is **not** cited as HAVE
(conformance drift for the gate).

## Matrix

| # | Ghidra-MCP tool | Category | Status | Fathom tool | Stage | Note / defer reason |
|--:|-----------------|----------|--------|-------------|-------|---------------------|
| 1 | `add_function_tag` | Function Tags, Variables & Attributes | HAVE | `add_function_tag` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 2 | `add_memory_reference` | Cross-References | HAVE | `add_memory_reference` | G1 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 3 | `add_struct_field` | Data Types & Structures | HAVE | `add_struct_field` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 4 | `analysis_status` | Program & Session Management | BUILD | — | G1 | — |
| 5 | `analyze_api_call_chains` | Analysis | BUILD | — | G1 | — |
| 6 | `analyze_call_graph` | Analysis | BUILD | — | G1 | — |
| 7 | `analyze_control_flow` | Analysis | BUILD | — | G1 | — |
| 8 | `analyze_data_region` | Analysis | BUILD | — | G1 | — |
| 9 | `analyze_dataflow` | Analysis | BUILD | — | G1 | — |
| 10 | `analyze_for_documentation` | Analysis | BUILD | — | G1 | — |
| 11 | `analyze_function_complete` | Analysis | HAVE | `analyze_function` | — | partial — closest single-call dossier |
| 12 | `analyze_function_completeness` | Analysis | BUILD | — | G1 | — |
| 13 | `analyze_global_completeness` | Data Types & Structures | BUILD | — | G2 | — |
| 14 | `analyze_struct_field_usage` | Analysis | BUILD | — | G1 | — |
| 15 | `apply_data_classification` | Analysis | BUILD | — | G2 | — |
| 16 | `apply_data_type` | Data Types & Structures | HAVE | `apply_data_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 17 | `apply_function_documentation` | Utility & Documentation Transfer | HAVE | `apply_function_documentation` | G3 | landed G3 — hash-verified single-function transfer (Execute-class, G2 transactional path, read-back verified) |
| 18 | `archive_ingest_function` | Cross-Binary Documentation & Archive | DEFER | — | — | deferred with reason (G3): fathom keeps no archive store — documentation lives in the subject's evidence bundle and moves between programs through the G3 transfer tools directly; an offline doc store is a separate commission |
| 19 | `archive_ingest_program` | Cross-Binary Documentation & Archive | DEFER | — | — | deferred with reason (G3): fathom keeps no archive store — documentation lives in the subject's evidence bundle and moves between programs through the G3 transfer tools directly; an offline doc store is a separate commission |
| 20 | `archive_project` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 21 | `audit_global` | Data Types & Structures | BUILD | — | G2 | — |
| 22 | `audit_globals_in_function` | Data Types & Structures | BUILD | — | G2 | — |
| 23 | `batch_add_function_tags` | Function Tags, Variables & Attributes | HAVE | `batch_add_function_tags` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 24 | `batch_analyze_completeness` | Analysis | BUILD | — | G1 | — |
| 25 | `batch_apply_documentation` | Analysis | BUILD | — | G1 | — |
| 26 | `batch_create_labels` | Renaming & Labels | HAVE | `batch_create_labels` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 27 | `batch_decompile` | Analysis | BUILD | — | G1 | — |
| 28 | `batch_delete_labels` | Renaming & Labels | HAVE | `batch_delete_labels` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 29 | `batch_remove_function_tags` | Function Tags, Variables & Attributes | HAVE | `batch_remove_function_tags` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 30 | `batch_rename_function_components` | Renaming & Labels | BUILD | — | G2 | — |
| 31 | `batch_set_comments` | Comments & Bookmarks | HAVE | `batch_set_comments` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 32 | `batch_set_variable_types` | Data Types & Structures | BUILD | — | G2 | — |
| 33 | `batch_string_anchor_report` | Cross-Binary Documentation & Archive | DEFER | — | — | deferred with reason (G3): string-anchor reporting belongs to the archive lane; no estate consumer; the transfer gate does not depend on it |
| 34 | `bulk_fuzzy_match` | Cross-Binary Documentation & Archive | DEFER | — | — | deferred with reason (G3): fuzzy matching is similarity-scored and version-sensitive; fathom's matching discipline is exact-hash only, by design (deterministic gates) |
| 35 | `can_rename_at_address` | Analysis | BUILD | — | G1 | — |
| 36 | `check_connection` | Utility & Documentation Transfer | HAVE | `session_info` | — | — |
| 37 | `check_tools` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 38 | `checkin_program` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 39 | `clear_flow_and_repair` | Function Tags, Variables & Attributes | BUILD | — | G2 | — |
| 40 | `clear_function_comments` | Comments & Bookmarks | HAVE | `clear_function_comments` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 41 | `clear_instruction_flow_override` | Analysis | BUILD | — | G2 | — |
| 42 | `clone_data_type` | Data Types & Structures | HAVE | `clone_data_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 43 | `close_program` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 44 | `close_project` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 45 | `compare_programs_documentation` | Utility & Documentation Transfer | HAVE | `compare_programs_documentation` | G3 | landed G3 — hash-match plan + measured completeness for both programs |
| 46 | `configure_analyzer` | Analysis | BUILD | — | G2 | — |
| 47 | `connect_instance` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 48 | `convert_number` | Utility & Documentation Transfer | BUILD | — | G1 | — |
| 49 | `create_array_type` | Data Types & Structures | HAVE | `create_array_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 50 | `create_data_type_category` | Data Types & Structures | HAVE | `create_data_type_category` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 51 | `create_enum` | Data Types & Structures | HAVE | `create_enum` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 52 | `create_folder` | Project Organization | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 53 | `create_function` | Analysis | HAVE | `create_function` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 54 | `create_function_signature` | Data Types & Structures | HAVE | `create_function_signature` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 55 | `create_function_tag` | Function Tags, Variables & Attributes | HAVE | `create_function_tag` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 56 | `create_label` | Renaming & Labels | HAVE | `create_label` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 57 | `create_memory_block` | Analysis | BUILD | — | G2 | — |
| 58 | `create_pointer_type` | Data Types & Structures | HAVE | `create_pointer_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 59 | `create_project` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 60 | `create_property_map` | Program & Session Management | BUILD | — | G2 | — |
| 61 | `create_struct` | Data Types & Structures | HAVE | `create_struct` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 62 | `create_typedef` | Data Types & Structures | HAVE | `create_typedef` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 63 | `create_union` | Data Types & Structures | HAVE | `create_union` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 64 | `debugger_dynamic_to_static` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 65 | `debugger_interrupt` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 66 | `debugger_launch` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 67 | `debugger_launch_offers` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 68 | `debugger_list_breakpoints` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 69 | `debugger_modules` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 70 | `debugger_read_memory` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 71 | `debugger_registers` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 72 | `debugger_remove_breakpoint` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 73 | `debugger_resume` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 74 | `debugger_set_breakpoint` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 75 | `debugger_stack_trace` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 76 | `debugger_static_to_dynamic` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 77 | `debugger_status` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 78 | `debugger_step_into` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 79 | `debugger_step_out` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 80 | `debugger_step_over` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 81 | `debugger_traces` | Debugger (Ghidra TraceRmi — GUI only) | DEFER | — | — | TraceRmi live debugging — outside fathom headless posture (study §Staging) |
| 82 | `decompile_function` | Decompilation & Disassembly | HAVE | `analyze_function` | — | partial — bounded decompile inside analyze_function dossier |
| 83 | `delete_bookmark` | Comments & Bookmarks | HAVE | `delete_bookmark` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 84 | `delete_data_type` | Data Types & Structures | HAVE | `delete_data_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 85 | `delete_file` | Project Organization | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 86 | `delete_function` | Analysis | HAVE | `delete_function` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 87 | `delete_function_tag` | Function Tags, Variables & Attributes | BUILD | — | G2 | deferred with reason (G2): Ghidra 12.1.2 `FunctionTagManager` has no delete operation — the bridge's tool has no public-API counterpart |
| 88 | `delete_label` | Renaming & Labels | HAVE | `delete_label` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 89 | `delete_project` | Project Organization | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 90 | `delete_property_map` | Program & Session Management | BUILD | — | G2 | — |
| 91 | `detect_array_bounds` | Analysis | BUILD | — | G1 | — |
| 92 | `detect_crypto_constants` | Analysis | BUILD | — | G1 | — |
| 93 | `detect_malware_behaviors` | Analysis | BUILD | — | G1 | — |
| 94 | `diff_functions` | Utility & Documentation Transfer | HAVE | `diff_functions` | G3 | landed G3 — hash equality + documentation field differences (signature compared up to calling-convention rendering) |
| 95 | `disassemble_bytes` | Decompilation & Disassembly | BUILD | — | G1 | — |
| 96 | `disassemble_function` | Decompilation & Disassembly | HAVE | `analyze_function` | — | partial — listing inside dossier |
| 97 | `embed_struct_field` | Data Types & Structures | BUILD | — | G2 | — |
| 98 | `emulate_function` | Emulation | BUILD | — | G4 | — |
| 99 | `emulate_hash_batch` | Emulation | BUILD | — | G4 | — |
| 100 | `exit_ghidra` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 101 | `export_program` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 102 | `extract_iocs_with_context` | Analysis | BUILD | — | G1 | — |
| 103 | `find_anti_analysis_techniques` | Analysis | BUILD | — | G1 | — |
| 104 | `find_code_gaps` | Analysis | BUILD | — | G1 | — |
| 105 | `find_dead_code` | Analysis | BUILD | — | G1 | — |
| 106 | `find_next_undefined_function` | Analysis | BUILD | — | G1 | — |
| 107 | `find_similar_functions` | Search | HAVE | `find_similar_functions` | G3 | landed G3 — exact-hash form; ambiguity flagged, never guessed (fuzzy-threshold form is the separate `find_similar_functions_fuzzy` row) |
| 108 | `find_similar_functions_fuzzy` | Cross-Binary Documentation & Archive | DEFER | — | — | deferred with reason (G3): fuzzy matching is similarity-scored and version-sensitive; fathom's matching discipline is exact-hash only, by design (deterministic gates) |
| 109 | `find_undocumented_by_string` | Utility & Documentation Transfer | DEFER | — | — | deferred with reason (G3): depends on the string-anchor machinery deferred with `batch_string_anchor_report` |
| 110 | `force_decompile` | Decompilation & Disassembly | HAVE | `analyze_function` | — | partial — force-fresh path unconfirmed |
| 111 | `get_address_spaces` | Program & Session Management | HAVE | `binary_overview` | — | partial |
| 112 | `get_assembly_context` | Analysis | BUILD | — | G1 | — |
| 113 | `get_bulk_function_hashes` | Utility & Documentation Transfer | HAVE | `get_bulk_function_hashes` | G3 | landed G3 — SHA-256 over concatenated instruction bytes in address order |
| 114 | `get_bulk_xrefs` | Cross-References | BUILD | — | G1 | — |
| 115 | `get_comment` | Comments & Bookmarks | BUILD | — | G1 | — |
| 116 | `get_current_address` | Context & Lookups | DEFER | — | — | GUI-only tool; fathom is headless |
| 117 | `get_current_function` | Context & Lookups | DEFER | — | — | GUI-only tool; fathom is headless |
| 118 | `get_current_program_info` | Program & Session Management | HAVE | `binary_overview` | — | — |
| 119 | `get_current_selection` | Context & Lookups | DEFER | — | — | GUI-only tool; fathom is headless |
| 120 | `get_data_type_size` | Data Types & Structures | BUILD | — | G1 | — |
| 121 | `get_entry_points` | Context & Lookups | BUILD | — | G1 | — |
| 122 | `get_enum_values` | Context & Lookups | BUILD | — | G1 | — |
| 123 | `get_external_location` | Context & Lookups | BUILD | — | G1 | — |
| 124 | `get_field_access_context` | Analysis | BUILD | — | G1 | — |
| 125 | `get_full_call_graph` | Context & Lookups | BUILD | — | G1 | — |
| 126 | `get_function_by_address` | Context & Lookups | HAVE | `analyze_function` | — | — |
| 127 | `get_function_call_graph` | Context & Lookups | BUILD | — | G1 | — |
| 128 | `get_function_callees` | Context & Lookups | HAVE | `analyze_function` | — | partial — callees in dossier |
| 129 | `get_function_callers` | Context & Lookups | HAVE | `analyze_function` | — | partial — callers in dossier |
| 130 | `get_function_count` | Context & Lookups | HAVE | `binary_overview` | — | partial — inventory counts |
| 131 | `get_function_documentation` | Utility & Documentation Transfer | HAVE | `get_function_documentation` | G3 | landed G3 — full documentation set per function |
| 132 | `get_function_hash` | Utility & Documentation Transfer | HAVE | `get_function_hash` | G3 | landed G3 — SHA-256 over concatenated instruction bytes in address order |
| 133 | `get_function_jump_targets` | Context & Lookups | BUILD | — | G1 | — |
| 134 | `get_function_labels` | Context & Lookups | BUILD | — | G1 | — |
| 135 | `get_function_pcode` | Analysis | BUILD | — | G1 | — |
| 136 | `get_function_signature` | Utility & Documentation Transfer | HAVE | `get_function_signature` | G3 | landed G3 |
| 137 | `get_function_tags` | Function Tags, Variables & Attributes | BUILD | — | G1 | — |
| 138 | `get_function_variables` | Context & Lookups | BUILD | — | G1 | — |
| 139 | `get_function_xrefs` | Cross-References | BUILD | — | G1 | — |
| 140 | `get_language_metadata` | Program & Session Management | HAVE | `binary_overview` | — | partial |
| 141 | `get_metadata` | Utility & Documentation Transfer | HAVE | `binary_overview` | — | — |
| 142 | `get_plate_comment` | Comments & Bookmarks | BUILD | — | G1 | — |
| 143 | `get_program_options` | Program & Session Management | BUILD | — | G1 | — |
| 144 | `get_project_info` | Headless Project & Program Lifecycle | BUILD | — | G1 | — |
| 145 | `get_property` | Program & Session Management | BUILD | — | G1 | — |
| 146 | `get_struct_layout` | Context & Lookups | BUILD | — | G1 | — |
| 147 | `get_type_size` | Data Types & Structures | BUILD | — | G1 | — |
| 148 | `get_valid_data_types` | Context & Lookups | BUILD | — | G1 | — |
| 149 | `get_version` | Utility & Documentation Transfer | HAVE | `session_info` | — | — |
| 150 | `get_xrefs_from` | Cross-References | BUILD | — | G1 | — |
| 151 | `get_xrefs_to` | Cross-References | BUILD | — | G1 | — |
| 152 | `health` | Utility & Documentation Transfer | HAVE | `session_info` | — | — |
| 153 | `import_data_types` | Data Types & Structures | BUILD | — | G2 | — |
| 154 | `import_file` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 155 | `import_program` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 156 | `inspect_memory_content` | Analysis | HAVE | `inspect_binary_layout` | — | partial |
| 157 | `list_analyzers` | Analysis | BUILD | — | G1 | — |
| 158 | `list_bookmarks` | Listing & Enumeration | BUILD | — | G1 | — |
| 159 | `list_calling_conventions` | Listing & Enumeration | BUILD | — | G1 | — |
| 160 | `list_class_members` | Function Tags, Variables & Attributes | BUILD | — | G1 | — |
| 161 | `list_classes` | Listing & Enumeration | BUILD | — | G1 | — |
| 162 | `list_data_items` | Listing & Enumeration | BUILD | — | G1 | — |
| 163 | `list_data_items_by_xrefs` | Listing & Enumeration | BUILD | — | G1 | — |
| 164 | `list_data_type_categories` | Data Types & Structures | BUILD | — | G1 | — |
| 165 | `list_data_types` | Data Types & Structures | BUILD | — | G1 | — |
| 166 | `list_exports` | Listing & Enumeration | HAVE | `list_names` | — | partial |
| 167 | `list_external_locations` | Listing & Enumeration | BUILD | — | G1 | — |
| 168 | `list_function_tags` | Function Tags, Variables & Attributes | BUILD | — | G1 | — |
| 169 | `list_functions` | Listing & Enumeration | HAVE | `list_functions` | — | — |
| 170 | `list_functions_enhanced` | Listing & Enumeration | HAVE | `list_functions` | — | partial — classifications/signatures present; enhanced metadata field parity unconfirmed |
| 171 | `list_globals` | Listing & Enumeration | HAVE | `list_names` | — | partial — symbol inventory covers globals |
| 172 | `list_imports` | Listing & Enumeration | HAVE | `list_names` | — | partial |
| 173 | `list_instances` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 174 | `list_methods` | Listing & Enumeration | HAVE | `list_functions` | — | partial — name listing covered |
| 175 | `list_namespaces` | Listing & Enumeration | BUILD | — | G1 | — |
| 176 | `list_open_programs` | Program & Session Management | BUILD | — | G1 | keeps its named reason (SPEC §4): fathom is stateless per call — no session-held open programs to list |
| 177 | `list_option_groups` | Program & Session Management | BUILD | — | G1 | — |
| 178 | `list_project_files` | Program & Session Management | BUILD | — | G1 | — |
| 179 | `list_projects` | Project Organization | BUILD | — | G1 | — |
| 180 | `list_properties` | Program & Session Management | BUILD | — | G1 | — |
| 181 | `list_property_maps` | Program & Session Management | BUILD | — | G1 | — |
| 182 | `list_scripts` | Listing & Enumeration | BUILD | — | G1 | — |
| 183 | `list_segments` | Listing & Enumeration | HAVE | `binary_overview` | — | partial — memory map in overview |
| 184 | `list_strings` | Listing & Enumeration | HAVE | `list_strings` | — | — |
| 185 | `list_tool_groups` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 186 | `load_program` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 187 | `load_program_from_project` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 188 | `load_tool_group` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 189 | `mcp_health` | Utility & Documentation Transfer | HAVE | `session_info` | — | partial — pool/uptime fields not in fathom |
| 190 | `mcp_schema` | Utility & Documentation Transfer | HAVE | `session_info` | — | partial — catalog via tools/list + session_info |
| 191 | `merge_program_documentation` | Cross-Binary Documentation & Archive | HAVE | `merge_program_documentation` | G3 | landed G3 — whole-program hash-matched transfer in one transaction; unmatched and ambiguous functions reported exactly |
| 192 | `modify_struct_field` | Data Types & Structures | HAVE | `modify_struct_field` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 193 | `modify_struct_field_type` | Data Types & Structures | BUILD | — | G2 | — |
| 194 | `move_data_type_to_category` | Data Types & Structures | HAVE | `move_data_type_to_category` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 195 | `move_file` | Project Organization | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 196 | `move_folder` | Project Organization | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 197 | `open_program` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 198 | `open_project` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 199 | `project_info` | Project Organization | BUILD | — | G1 | — |
| 200 | `prompt_policy` | System | DEFER | — | — | prompt_policy is bridge automation UX; outside fathom policy surface |
| 201 | `read_memory` | Analysis | HAVE | `inspect_binary_layout` | — | partial — layout/mitigations; not arbitrary address read |
| 202 | `reanalyze` | Program & Session Management | BUILD | — | G2 | — |
| 203 | `recreate_struct` | Data Types & Structures | BUILD | — | G2 | — |
| 204 | `remove_function_tag` | Function Tags, Variables & Attributes | HAVE | `remove_function_tag` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 205 | `remove_program_option` | Program & Session Management | BUILD | — | G2 | — |
| 206 | `remove_property` | Program & Session Management | BUILD | — | G2 | — |
| 207 | `remove_reference` | Cross-References | HAVE | `remove_reference` | G1 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 208 | `remove_struct_field` | Data Types & Structures | HAVE | `remove_struct_field` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 209 | `rename_data` | Renaming & Labels | HAVE | `rename_data` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 210 | `rename_data_type` | Data Types & Structures | HAVE | `rename_data_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 211 | `rename_external_location` | Renaming & Labels | BUILD | — | G2 | — |
| 212 | `rename_function` | Renaming & Labels | HAVE | `rename_function` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 213 | `rename_function_by_address` | Renaming & Labels | HAVE | `rename_function_by_address` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 214 | `rename_global_variable` | Renaming & Labels | HAVE | `rename_global_variable` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 215 | `rename_label` | Renaming & Labels | HAVE | `rename_label` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 216 | `rename_or_label` | Renaming & Labels | BUILD | — | G2 | — |
| 217 | `rename_variable` | Renaming & Labels | HAVE | `rename_variable` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 218 | `rename_variables` | Renaming & Labels | BUILD | — | G2 | — |
| 219 | `resize_struct` | Data Types & Structures | BUILD | — | G2 | deferred with reason (G2): no direct Composite length setter in the 12.1.2 API surface used by the mutation script |
| 220 | `resolve_duplicate_type` | Data Types & Structures | BUILD | — | G2 | — |
| 221 | `restore_project` | Headless Project & Program Lifecycle | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 222 | `run_analysis` | Analysis | BUILD | — | G2 | — |
| 223 | `run_ghidra_script` | Scripting | BUILD | — | G2 | deferred with reason (G2): unbounded execute surface, contrary to the bounded G2 tool surface |
| 224 | `run_script_inline` | Scripting | BUILD | — | G2 | deferred with reason (G2): unbounded execute surface, contrary to the bounded G2 tool surface |
| 225 | `save_all_programs` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 226 | `save_program` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 227 | `search_byte_patterns` | Search | BUILD | — | G1 | — |
| 228 | `search_data_types` | Search | BUILD | — | G1 | — |
| 229 | `search_functions` | Search | HAVE | `search_inventory` | — | partial — substring across functions |
| 230 | `search_functions_by_tag` | Function Tags, Variables & Attributes | BUILD | — | G1 | — |
| 231 | `search_functions_enhanced` | Search | HAVE | `search_inventory` | — | partial — advanced filters unconfirmed |
| 232 | `search_instructions` | Analysis | BUILD | — | G1 | — |
| 233 | `search_strings` | Search | HAVE | `search_inventory` | — | partial — substring across strings; regex dialect unconfirmed |
| 234 | `search_tools` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 235 | `server_admin_set_permissions` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 236 | `server_admin_terminate_all_checkouts` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 237 | `server_admin_terminate_checkout` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 238 | `server_admin_users` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 239 | `server_authenticate` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 240 | `server_checkouts` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 241 | `server_connect` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 242 | `server_disconnect` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 243 | `server_repositories` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 244 | `server_repository_create` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 245 | `server_repository_file` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 246 | `server_repository_files` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 247 | `server_status` | Headless Project & Program Lifecycle | HAVE | `session_info` | — | partial — headless connection status vs fathom session_info |
| 248 | `server_version_control_add` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 249 | `server_version_control_checkin` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 250 | `server_version_control_checkout` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 251 | `server_version_control_undo_checkout` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 252 | `server_version_history` | Ghidra Server & Version Control | DEFER | — | — | Ghidra Server collaboration — no estate Ghidra Server (study §Staging) |
| 253 | `set_bookmark` | Comments & Bookmarks | HAVE | `set_bookmark` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 254 | `set_comment` | Comments & Bookmarks | HAVE | `set_comment` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 255 | `set_decompiler_comment` | Comments & Bookmarks | HAVE | `set_decompiler_comment` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 256 | `set_decompiler_variable_type` | Function Tags, Variables & Attributes | HAVE | `set_decompiler_variable_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 257 | `set_disassembly_comment` | Comments & Bookmarks | HAVE | `set_disassembly_comment` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 258 | `set_function_no_return` | Function Tags, Variables & Attributes | HAVE | `set_function_no_return` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 259 | `set_function_prototype` | Data Types & Structures | HAVE | `set_function_prototype` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 260 | `set_function_tag_comment` | Function Tags, Variables & Attributes | HAVE | `set_function_tag_comment` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 261 | `set_function_this_type` | Function Tags, Variables & Attributes | BUILD | — | G2 | — |
| 262 | `set_global` | Data Types & Structures | BUILD | — | G2 | — |
| 263 | `set_image_base` | Program & Session Management | BUILD | — | G2 | — |
| 264 | `set_local_variable_type` | Data Types & Structures | HAVE | `set_local_variable_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 265 | `set_parameter_type` | Data Types & Structures | HAVE | `set_parameter_type` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 266 | `set_plate_comment` | Comments & Bookmarks | HAVE | `set_plate_comment` | G2 | landed G2 — transactional mutation path (Execute-class, flowguard decide()) |
| 267 | `set_program_option` | Program & Session Management | BUILD | — | G2 | — |
| 268 | `set_property` | Program & Session Management | BUILD | — | G2 | — |
| 269 | `set_variable_storage` | Data Types & Structures | BUILD | — | G2 | — |
| 270 | `set_variables` | Function Tags, Variables & Attributes | BUILD | — | G2 | — |
| 271 | `suggest_field_names` | Analysis | BUILD | — | G1 | — |
| 272 | `switch_program` | Program & Session Management | DEFER | — | — | Stateful project/session lifecycle — fathom uses its own per-subject SHA-256 project cache via analyzeHeadless (study §Where fathom already stands) |
| 273 | `tool_goto_address` | Utility & Documentation Transfer | DEFER | — | — | GUI tool-window control; fathom is headless |
| 274 | `tool_launch_codebrowser` | Utility & Documentation Transfer | DEFER | — | — | GUI tool-window control; fathom is headless |
| 275 | `tool_running_tools` | Utility & Documentation Transfer | DEFER | — | — | GUI tool-window control; fathom is headless |
| 276 | `unload_tool_group` | Bridge Static Tools | DEFER | — | — | Bridge-instance tooling for bethington Python bridge; fathom is its own MCP server (no-second-engine) |
| 277 | `validate_data_type` | Data Types & Structures | BUILD | — | G1 | — |
| 278 | `validate_data_type_exists` | Data Types & Structures | BUILD | — | G1 | — |
| 279 | `validate_function_prototype` | Data Types & Structures | BUILD | — | G1 | — |

## Findings for Pax

- Count ruling applied: v6.0.0 baseline, 279 distinct rows, import_file duplication flagged.
- Q-G0-5/Q-G0-6 from the prior 209-row matrix are **superseded** by this ruling.
- Partial HAVEs: most HAVE rows note dossier/coarser-tool coverage; G1 decides split vs keep.
- Lifecycle DEFER cluster: open/close/save/import project tools — fathom owns per-subject
  SHA-256 project cache via analyzeHeadless (no-second-engine).
- Bridge 7 + TraceRmi 18 + Ghidra Server 17 + GUI-only + prompt_policy = DEFER cluster.

## Appendix — fathom inventory @ 0ea7b20

25 registered MCP tools; 24 Available; `observe_browser` NotImplemented. Ghidra-provider (6):
`analyze_function`, `binary_overview`, `list_functions`, `list_names`, `list_strings`,
`search_inventory`. Adjacent: `inspect_binary_layout`, `inspect_artifact`, `session_info`.

## G1 differential gate — 2026-10-29 (curative run, D-315/D-316/D-317)

Branch `pax/fathom-ghidra-g1` @ `8f8d157` (clippy fix on top of the
reconciled `993529e`). Harness: primo stage dir
`~/.local/share/fathom-ghidra-g1/harness/run_differential.py`, run
`--with-gui`; captures in `harness/out/` (runs 1–3 preserved as
`out-gui-run1/2/3`). Bridge reached ONLY via the shim
(`~/ghidra-bridge-venv/bin/python /usr/bin/bridge-mcp-ghidra`),
read-only. Ghidra GUI 12.1.2 ran on primo under Xvfb (display :77,
virtual display — Owner off-desktop per D-317); project `FxDiff`
at `~/fathom-gui-proj`, fixtures imported headlessly, `fx_hello`
opened in CodeBrowser after enabling GhidraMCPPlugin in the tool's
plugin configuration (first-launch dialog). Bridge transport was
UDS (`/run/user/1000/ghidra-mcp/ghidra-<pid>.sock`); the plugin's
TCP port measured **8089** (bridge default; the 8093 figure in the
dispatch was not what the machine bound). Fixtures (gcc 16.2.1,
`-O0 -g`): `fx_hello` sha256
`0b71a9b93247ca373152e45744ba247ed71f8a0320b872e66af3a833ca4c96b6`,
`fx_struct` sha256
`175d7658f9dfbfa0ba4f96f6b7b717aa38db73aa3c83f3428be14b231b165adc`,
`fx_stripped` sha256
`279fd6b2e572408ddeaa831d7ab3320151dc220fe63f0677b028f6a2c3de8256`.

**Verdict: DIFFERENTIAL PASS — zero unresolved discrepancies.**
Per family (fathom tool ↔ bridge tool, same fixture, same calls):

| Family | Verdict | Evidence |
|---|---|---|
| program_info (`binary_overview` ↔ `get_current_program_info`) | AGREE | name `fx_hello`, address_size 64, ELF format agree; bridge adds overlay-space warning, fathom adds language/compiler/image_base — complementary, no contradiction |
| list_functions | AGREE (exact) | 21/21 (name, address) pairs identical, incl. `compute_loop` @ `0010115d` both sides. Fathom `total=28` counts Ghidra's external placeholders (bridge `analysis_status.function_count=28` agrees); retained rows are the 21 defined functions |
| list_strings | AGREE with adjudicated diffs | 86 (value, address) pairs identical. Fathom-only 7: `.eh_frame`/DWARF residue strings the headless export retains (`align(1)` ×3 spaces, `align(64)`, `align(8)`, `zR`) — fathom superset, honestly reported. Bridge-only 2: `result=%d\\n` = same string as fathom's `result=%d\n` with the bridge double-escaping the backslash (bridge rendering quirk), and `"00102004"` @ `00104020`, a pointer-slot value the bridge renders as a string where fathom defines none |
| list_data_types | AGREE (exact) | 64/64 type-name sets identical |
| entry_points (`get_entry_points`) | AGREE with adjudicated diff | Fathom's 14 ⊂ bridge's 21. Bridge-only rows are ELF alias names for addresses fathom already reports (`__DT_INIT`/`__DT_FINI` for `_init`/`_fini`, `__data_start` for `data_start`, `__bss_start`/`__TMC_END__`/`_edata` for `completed.0`/`_end` region) plus `entry` @ image base `00100000` (bridge convention). Legitimate definition difference, recorded |
| analysis_status | AGREE | `analyzed=true` both sides; fathom adds analyzer enablement 30/35, bridge adds function_count 28 — complementary |
| function_xrefs (`get_function_xrefs`, anchor `compute_loop`) | AGREE with adjudicated diff | Inbound set identical 4/4 (EXTERNAL Entry Point; INDIRECTION `00102048`; DATA `001020e0`; UNCONDITIONAL_CALL `001011c3` in `main`). Fathom additionally reports 13 outbound references from the function body (stack writes, loop back-edge jump `00101176`→`0010118e`, calls) — verified real in the listing; the bridge tool returns the inbound set only (narrower scope, not a fathom defect) |
| xrefs_to (`get_xrefs_to` @ `0010115d`) | AGREE (exact) | 4/4 references identical incl. types and referencing function |
| xrefs_from (`get_xrefs_from` @ `0010115d`) | AGREE (exact) | 0 references both sides (entry address itself originates none) |
| struct_layout (`get_struct_layout` `Rect` on `fx_struct`) | AGREE (exact) | 24 bytes, alignment 4, components identical: `origin` Point 16 @0, `width` int 4 @16, `height` int 4 @20 |

Live smoke (same session, fathom MCP surface vs Ghidra 12.1.2
headless, dot-free state dir `~/fathom-state`): all ten tools above
answered with real fixture data — PASS (brief minimum was
`binary_overview` + `list_functions`).


## G2 landing + live differential (2026-10-29)

49 write/documentation tools landed on the transactional mutation path
(copy-on-write project swap; one Ghidra transaction per batch; per-op
verified postconditions; commit only on the script's `committed`
result; any failure discards the copy and the cached project is
re-hashed — mismatch escalates to `ArtifactIntegrityMismatch`). All 49
are Execute-class: `decide()` default-deny, per-session `allow_tools`
enable, typed refusals. The 2 G1-stage rows `add_memory_reference` /
`remove_reference` resolve here; `list_open_programs` keeps its named
stateless reason. Unlanded with reasons: `delete_function_tag`,
`resize_struct`, `run_ghidra_script`, `run_script_inline` (row notes).

**Verdict: DIFFERENTIAL PASS — zero unresolved discrepancies.**
Throwaway bridge project `FxDiff2` (same fixtures, bridge writes are
its normal GUI operation on that project only); fathom writes on its
own cached copies; post-write read-backs compared per family:

| Family | Verdict | Evidence / adjudication |
|---|---|---|
| comment (`set_comment`) | AGREE | both read back `g2 differential comment` (EOL) at `0010115d` |
| plate_comment | AGREE | both read back `g2 plate` |
| rename_function | AGREE | `compute_loop` → `compute_loop_g2` both sides |
| rename_variable | AGREE | bridge param renamed to `g2_param`, read-back `['g2_param', 'step']` matches fathom end state |
| prototype (`set_function_prototype`) | AGREE | bridge decompile head `long compute_loop_g2(int count,long step)` matches fathom's applied prototype |
| label (`create_label`) | AGREE | `g2_loop_entry` @ `0010115d`, USER_DEFINED |
| bookmark (`set_bookmark`) | AGREE with adjudicated diff | bridge tool has no `type` field (Note implied); category `g2cat` + comment agree |
| function_tag (create + add) | AGREE | tag `g2tag` read back on the function both sides |
| memory_reference (add + remove) | AGREE | add from `main`, xrefs read-back, remove reports `removed: 1` |
| struct create + add field | AGREE with adjudicated diff | layout agrees (x int@0, y int@4, z long@8, size 16). Bridge-side "strict naming enforcement" renames fields `x→nX`, `y→nY`, `z→nZ` — bridge convention, not a semantic difference. Bridge `create_struct.fields` is a string holding a JSON array (its error text is the spec) |
| struct modify field type | AGREE with adjudicated diff | addressed as `nZ` after the bridge's rename: field at offset 8 becomes `short` (size 2) both sides; the bridge drops the field name to `(unnamed)` and keeps struct size 16, as does Ghidra's replaceComponent on the fathom side |
| apply_data_type | AGREE | `int` applied at `00100000` both sides, value `0x464c457f` |

Fathom-side harness: 40 PASS / 0 FAIL, including adversarial rows —
mid-batch failure rolls back with the project tree hash identical
before/after, a held mutation lock yields typed `revision_conflict`
with the project unchanged, and a deny-config server refuses with
`access_denied` before any project exists. Comment-class mapping note:
Ghidra's `CommentType` has no decompiler/disassembly kinds; fathom's
`set_decompiler_comment` / `set_disassembly_comment` map to EOL in the
mutation script (documented in-tool).
