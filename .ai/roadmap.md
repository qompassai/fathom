# Roadmap — fathom (mcp) — v0.1 → v1.0
<!-- bloch:roadmap schema=1 kind=mcp lane=general baseline=0.1.0 target=1.0.0 -->

How to work this roadmap (any agent): run `bloch task start R-xxx --agent <you>` before working a task, `bloch task done R-xxx` when you believe it is complete — done runs every `verify:` command and flips the task green only if all pass; there is no override. `bloch task fail R-xxx --error "..."` records a failure. Fixes learned the hard way land in `.ai/memory/lessons.md` via the inbox/promote flow and are surfaced in every HANDOFF.

## What 1.0 means here (curated 2026-10-29 — G1 curative landing)

1.0 = the Ghidra parity ladder (STUDY: fathom-ghidra-mcp-port,
2026-10-20) carried through G3 — read-core parity live-gated
against Ghidra 12.1.2, the transactional mutation path for
documentation/write tools, and cross-binary documentation
transfer — with the MCP conformance manifest green at every
stage. G4 (P-code emulation) proceeds only if G1–G3 gates
justify it. Deferred by design, with reasons in the parity
matrix: TraceRmi live debugging and Ghidra Server collaboration.

## Phase 1 — Baseline truth
- [x] R-101 Build is green from a clean checkout
  - verify: cargo build
  - evidence: 1 verify commands, all exit 0 at 2026-10-29T08:26:53Z
- [x] R-102 Existing tests pass at the baseline
  - verify: cargo test
  - evidence: 1 verify commands, all exit 0 at 2026-10-29T08:27:00Z
- [x] R-103 Repo identity, baseline version, and this roadmap are recorded
  - verify: test -f .ai/roadmap.md
  - evidence: 1 verify commands, all exit 0 at 2026-10-29T08:27:00Z

## Phase 2 — Ghidra parity ladder (STUDY staging G0–G4)
- [x] R-201 G0 — parity matrix: every documented bethington v6.0.0 tool enumerated (279 distinct rows), fathom status per row
  - verify: test -f docs/fathom-ghidra-parity-matrix.md
  - evidence: 1 verify commands, all exit 0 at 2026-10-29T08:27:00Z
- [x] R-202 G1 — read-core parity: listing & enumeration, xrefs & call graphs, data types & structures (read), strings/memory search, imports/exports via export-schema extension; live-gated on Ghidra 12.1.2 against fixture binaries, differential vs the bethington bridge
  - verify: cargo test
  - verify: cargo clippy --all-targets -- -D warnings
  - evidence: 2 verify commands, all exit 0 at 2026-10-29T08:27:06Z
- [x] R-203 G2 — documentation & write tools: rename, labels, comments, prototypes, variables, structure creation via the transactional mutation path (Execute-class, flowguard-gated); the 3 G1 not-implemented rows (add_memory_reference, remove_reference, list_open_programs per SPEC §4) resolve here or keep their named reasons
  - verify: cargo test
  - evidence: 1 verify commands, all exit 0 at 2026-10-29T09:46:59Z
- [ ] R-204 G3 — cross-binary documentation transfer: function-hash matching and documentation propagation, composing with fathom's evidence bundles; completeness scoring as a measured finding
  - verify: cargo test
  - evidence:
- [ ] R-205 G4 — emulation (P-code), only if G1–G3 gates justify it
  - verify: cargo test
  - evidence:

## Phase 3 — Tests and gates
- [ ] R-301 Validation tests cover the happy path end to end (half the test split)
  - verify: cargo test
  - evidence:
- [ ] R-302 Adversarial tests cover malformed, oversized, and hostile inputs (half the test split)
  - verify: cargo test
  - evidence:
- [ ] R-303 Refusal and typed-error behaviour is covered by tests, including oversized payloads
  - verify: cargo test
  - evidence:

## Phase 4 — Hardening
- [ ] R-401 MCP Inspector conformance pass is recorded as evidence
  - verify: cargo test
  - evidence:
- [ ] R-402 Client matrix is verified with at least two real clients
  - verify: cargo test
  - evidence:
- [ ] R-403 Declared-vs-detected access (EFLO) check passes: no tool exceeds its annotations
  - verify: cargo clippy -- -D warnings
  - evidence:
- [ ] R-404 Registry/release packaging builds from a clean checkout
  - verify: cargo build
  - evidence:

## Phase 5 — Docs
- [ ] R-501 README documents install, usage, and verification
  - verify: test -f README.md
  - evidence:
- [ ] R-502 CHANGELOG records every user-facing change
  - verify: test -f CHANGELOG.md
  - evidence:
- [ ] R-503 Tool reference documents every tool, schema, annotation, and error kind
  - verify: test -f README.md
  - evidence:

## Phase 6 — Release v1
- [ ] R-601 Version is bumped to 1.0.0 and the changelog records the release
  - verify: grep -q 'version = "1.0.0"' Cargo.toml
  - evidence:
- [ ] R-602 Clean-environment install and run is verified
  - verify: cargo build
  - evidence:
- [ ] R-603 Release artefacts are built from a clean checkout and checksummed
  - verify: cargo build
  - evidence:
