# EFLO — fathom 1.0.0 tools/list measurement

Measured 2026-10-29 on primo, against the landed 1.0.0 binary.

## Method

The witness-bundle SPEC section 6 form (the fleet's canonical
EFLO method): the complete `tools/list` result payload as
served — every tool object with name, description, inputSchema,
outputSchema, and annotations, nothing stripped — serialized
as compact, key-sorted JSON and tokenized whole with a real
BPE tokenizer (tiktoken). The payload was captured from a live
stdio session against the 1.0.0 binary (the G-F4 utilization
run); the session's `server/discover` reported fathom 1.0.0.

## Numbers

- Tools: **158**
- Canonical payload: **88,715 bytes**
- **cl100k_base: 19,072 tokens**
- o200k_base: 20,276 tokens (reported alongside, per SPEC)
- Per-tool sum (cl100k_base, each tool object counted
  separately): 19,211 — the small delta vs the whole-payload
  count is tokenizer boundary behavior, stated for honesty.
- Heaviest tools (cl100k_base): `build_video_guide` 299,
  `build_reconstruction_obligation_ledger` 261,
  `apply_style_via_lumen` 230, `verify_reconstruction_proof`
  202, `remap_palette` 195, `read_video_ingest` 165,
  `inspect_python_artifact` 162, `list_data_types` 156,
  `inspect_renpy_archive` 153, `apply_function_documentation`
  150. The cost is breadth (158 tools), not a few bloated
  schemas: the median tool is roughly 100 tokens.

## Disposition vs the fleet budget (<= 2,500 tokens)

**OVER — 19,072 vs 2,500 (7.6x). Not shrunk, not hidden.**

The <=2,500 budget was written for single-surface servers.
Fathom is a multi-provider server (core, native/Ghidra, JS,
managed, observe, video, art, A2A) whose 158-tool surface is
its commissioned scope (the Ghidra parity ladder alone is 89
HAVE rows). No description-trimming pass can close a 7.6x gap
without falsifying the surface, so none was attempted.

Recommendation, for the Owner/Pax gate:

1. **A D-147-class EFLO waiver for fathom at 1.0.0**, with the
   measured number (19,072 cl100k_base) stated as the waived
   figure — the same instrument that carried neemu (4,201,
   cap 4,600), scaled to a server whose scope is an order of
   magnitude larger.
2. **Trigger-scoped group loading as the structural fix on
   the 1.x track**: provider-grouped surfaces (core+readers,
   ghidra, video, art, observe) loaded per task trigger, so a
   consumer session pays only for the group it uses — the
   estate's trigger-scoped loading doctrine applied to the
   server that needs it most. Until that lands, the waiver in
   (1) is the honest posture and this file is its record.
