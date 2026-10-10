# Architectural Decisions

## Clean-room, spec-led port (2026-10-10)

**Decision**: Reimplement REA in Rust from its published docs and
contracts (tool catalog, tool-design guide, error schema,
provider guides). No upstream code copied or transliterated.

**Rationale** (Matt): the Node/npm supply chain is a shifting
vulnerability surface; the estate is Rust-first; whole ports are
prioritized proactively, not reactionary. Upstream is MIT, so this
is a supply-chain and coherence choice, not a licensing need.

## Stateless per-call tools (2026-10-10)

**Decision**: No bound binary session in v1; every tool call names
its target and is independently policy-checked. Provider state
(Ghidra projects) is cached in the state dir keyed by subject
SHA-256.

**Consequence**: Session-binding optimizations are deferred;
upstream workflow composites are deferred with them (SPEC §4).

## Ghidra via batch headless export (2026-10-10)

**Decision**: Drive `analyzeHeadless` with an original Java
`-postScript` that exports bounded JSON, following diver's
DiverExportAnalysis precedent. No persistent bridge process, no
nested third-party MCP server.

## Hand-rolled MCP/A2A/JCS (2026-10-10)

**Decision**: JSON-RPC, the A2A card, and RFC 8785
canonicalization are implemented in-repo (estate pattern from
volta/vongola) rather than depending on `rmcp`, `a2a`, or
`serde_jcs`.
