# Current Work

fathom: Rust port of REA (morluto/rea), commissioned
2026-10-10. Spec-led from upstream's public docs and contracts;
no TypeScript transliterated.

## Status (2026-10-12)

- Stages 0–4 committed and gated (see SPEC §11).
- Renamed in-tree from rea-rust to fathom (crates, binary, docs)
  on 2026-10-10; OpenAPPA worker profile added the same day.
- Stage 5 built (2026-10-11): browser observation (Chromium
  headless DOM inventory), firmware inspection, Android APK
  inventory, Mach-O dylib projection, source-map position
  mapping. All 22 port tools are built; no tool is registered
  not-implemented.
- Named walls remain, exactly as SPEC states them: PTY capture,
  decoded-CIL instruction listings, EVM interface inference
  beyond selectors, ZIP64 + DEX/arsc decode in APK inspection,
  firmware extraction, the browser session/scenario engine,
  mitmproxy native captures, and the IDA/Hopper providers
  (host tools absent — a stated unknown, not a gap to fake).

## Standing rules

- Dual license: AGPL-3.0-only OR Apache-2.0 for first-party code.
- Evidence honesty is the product: observed / derived / inferred
  stay distinct; scaffolds return `capability_unavailable`.
- Policy is deterministic and fail-closed; execute/observe tools
  are default-deny.
