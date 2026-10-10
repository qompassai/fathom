# Current Work

fathom: clean-room Rust port of REA (morluto/rea), commissioned
2026-10-10. Spec-led from upstream's public docs and contracts;
no TypeScript transliterated.

## Status (2026-10-10)

- Stage 0 (SPEC.md) committed.
- Stage 1 (scaffolding + core crates) committed.
- Stage 2 (native Ghidra/goblin, JS/Electron oxc/ASAR) committed.
- Stage 3 built: fathom-managed .NET inventory (manual ECMA-335;
  CIL decode scaffolded) and fathom-observe capture_process
  (allow_programs-gated), HAR reading, EVM selector scan.
  Browser, firmware, Android stay scaffolded per SPEC 9.4.
- Pushed to github.com/qompassai/fathom; renamed in-tree from
  rea-rust to fathom (crates, binary, docs) on 2026-10-10.

## Standing rules

- Dual license: AGPL-3.0-only OR Apache-2.0 for first-party code.
- Evidence honesty is the product: observed / derived / inferred
  stay distinct; scaffolds return `capability_unavailable`.
- Policy is deterministic and fail-closed; execute/observe tools
  are default-deny.
