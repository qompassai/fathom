# Agent configuration for fathom

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

OpenCode reads the root `opencode.json` and the shared skills under
`.agents/skills/` (and `.claude/skills/` directly). Per the
established estate pattern there is no `.opencode/skills/` duplicate
tree. The root `opencode.json` follows the shape of the estate's one
per-project exemplar, adapted to Rust.
