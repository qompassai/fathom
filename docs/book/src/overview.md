# Overview

`rea-rust` is a clean-room Rust port of REA (Reverse Engineer
Anything). It gives agents and operators reverse-engineering tools
over MCP (stdio and streamable HTTP) and advertises them with a
signed A2A agent card.

Design source: [morluto/rea](https://github.com/morluto/rea) (MIT),
via Matt's fork `qompassai/rea`. No upstream TypeScript is copied;
the contracts, tool catalog, and evidence model are reimplemented
from the fork's public documentation. The full contract lives in
the repository's `SPEC.md`; this book is the operator's tour.

<details>
<summary>Why a Rust port</summary>

Matt's reasoning, recorded 2026-10-10: given the shifting
security-vulnerability landscape (Node/npm supply-chain risk) and
his Rust-first stack, whole Rust ports of tools he depends on are
prioritized proactively rather than as reactionary ports later —
and building them is how he learns Rust for when it really
matters. Upstream REA stays available in parallel as a pinned,
policy-gated MCP server; this port is the long-term home.

</details>

<details>
<summary>The evidence rule</summary>

Every tool returns an evidence envelope: findings, each with a
confidence class (`observed`, `derived`, `inferred`), the subject's
SHA-256 and size, coverage accounting, and named unknowns. A tool
that cannot do its work says so in the envelope or in the canonical
error contract — it never fabricates coverage.

</details>
