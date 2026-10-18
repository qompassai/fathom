# Fathom RE testing program + phlow integration + art style provider (2026-10-18)

Branch `pax/fathom-re-testing-20261018` (unpushed; landing is Matt's word).
Corpus + drivers + results: primo `~/fathom-re-corpus-20261018/`.
Calibration: primo `~/fathom-art-calibration-20261018/`.

## Defects found by testing and fixed (one commit each)

- D1 `0de9a4a` — `inspect_evm_bytecode` panicked on bytecode ending in a
  complete PUSH4 (EQ peek one byte past the end).
- D2 `ae77d5c` — Ghidra runs past the 330 s bound returned
  `execution_failure` with no evidence and left a half-imported project
  that later calls silently reused (cache poisoning). Now: timeout keeps
  a completed export, else discards the partial project and returns
  `provider_timeout`. Tradeoff: a large binary under load may need
  several attempts, each re-importing from clean.
- D3 `a2623c6` — `inspect_binary_layout` reported ELF symbol counts
  only; SPEC §9.1 names symbols. Now emits bounded name rows.
- D4+D5 `8f08a01` — `analyze_function` matched exact Ghidra names only
  (now a unique-match ladder: exact, qualified suffix, demangled,
  case-insensitive, entry address; ambiguity exports candidates);
  `list_strings` missed unterminated literals (now a derived
  `data_strings` byte-run harvest). Narrative correction in `1308321`:
  the Go sample itself exports `CorpusFnv1aHash` wrappers — Ghidra was
  faithful; nothing title-cases names.
- D6 `81a4253` — fathom-managed never read the #US heap; C# string
  literals (incl. the corpus marker) were invisible. Now parsed per
  ECMA-335 with caps and an observed `user_strings` finding.
- D7 `1c076bd` — layout rows were a prefix of raw symtab order; on the
  Go (2,530 syms) and Zig (871) binaries every ground-truth name fell
  past the 256 cap. Rows are now name-sorted, a deterministic stride
  sample over the whole table, cap 1024.
- D8 `901602a` — `search_inventory` was blind past the export's 5,000
  row cap and past 200 chars inside long byte-runs (the Go marker sits
  at offset 882 of a 1,273-char run, string ~15k of 15,491). Export now
  retains 50k rows/array under a 1.5 MiB byte budget; byte-run values
  retain 4,096 chars; the provider caps returned rows at the core
  listing bounds and returns context snippets for deep matches.

Corpus-side defects fixed in the corpus (not fathom): the Rust sample's
hash fn was dead-code eliminated by rustc (rewritten `#[no_mangle]`);
manifest v2 verified symbols by substring (false ground truth) —
v3 parses nm exactly with recorded surface forms; scorer v2 matches
surface forms exactly.

Known behavior worth remembering: Ghidra export caches are keyed by
subject+mode only, not by export-script version — after changing
`FathomExportAnalysis.java`, clear the state dir or stale exports are
served.

## Phase E — phlow integration

phlow checkout branch `pax/fathom-integration-20261018`, commit
`a8e5cba` (unpushed): phlow-mcp gains a bounded NDJSON stdio MCP
client (it was server-only), a fathom demo profile fixture + example,
and an env-gated integration test. Live proof: negotiated 2025-06-18
(fathom's version is in phlow's SUPPORTED_PROTOCOL_VERSIONS — no
drift), 3 tools answered with consistent subject hashes. Transcript:
corpus dir `phlow_demo_transcript.txt`.

## Phase F — art/animation style (commit `f24a2b5`, SPEC §9.5)

New crate fathom-art (25 tools total): `analyze_art_style` (measured
style spec — median-cut palette, HSL grade stats, rule-classified
shading, hand-walked GIF timing, gutter-based sheet geometry),
`remap_palette` (native deterministic transform), and
`apply_style_via_lumen` (Execute; grading is lumen's — fathom builds
the .lumen.json doc, drives lumen stdio MCP style_list/style_apply,
re-measures the output, verifies vs a reference under stated
tolerances). Watch out: adding serde_json `preserve_order` in this
crate broke workspace clippy via feature unification (grew
serde_json::Value → FathomError past result_large_err) — dropped.

Calibration (real assets, ground truth): POV GIF timing recovered
exactly ([140,420,460,460,620,520,260,200] ms, loop infinite);
synthwave hue shift recovered +20.97° vs +20 nominal; ukiyo_e
lightness ratio 1.045 vs 1.05, posterize signature 224→8 populated
levels (direct output: 5, classed cel); closed loops vs real lumen
pass all checks (ukiyo_e, demo_toon) when the reference shares the
input's pixel population — a flattened-on-black reference against a
transparent-sprite output fails lightness/palette for frame reasons,
which the envelope correctly reports as out-of-tolerance.

## Honest remainder

No deep providers for JVM/Python/Lua/WASM artifacts (inspect_artifact
complete, layout partial). IDA/Hopper remain declared-not-implemented.
solc absent on primo (EVM corpus hand-assembled). Lumen preset numeric
parameters are not exposed by style_list (names/descriptions only) —
the bridge declares them lumen-internal unknowns.
