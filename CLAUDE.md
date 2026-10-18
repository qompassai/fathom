# CLAUDE.md — fathom

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

Read `AGENTS.md` first (operating discipline), then `SPEC.md`
(design contract), then `.ai/memory/current.md` (state).

Quick facts:

- Rust workspace, edition 2024, toolchain pinned in
  `rust-toolchain.toml` (nightly-2026-09-25 via fenix in the
  flake).
- MCP server (stdio + streamable HTTP) and signed A2A card over
  one tool registry in `fathom-core`; providers never bypass the
  policy engine.
- Native deep analysis drives Ghidra headless as a child process
  with a bundled Java export script; nothing is linked against
  Ghidra.
- All analysis state lives under the configured state dir; target
  paths must canonicalize under a configured target root.
