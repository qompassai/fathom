# Agent configuration for rea-rust

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

Skills live in `.claude/skills/` (Claude Code) and `.agents/skills/`
(cross-tool path read by OpenCode, Codex, Cursor, Copilot, Gemini
CLI). OpenCode also reads `.claude/skills/` directly.

This repo carries no `.claude/settings.json` — matching the
established estate pattern (phlow, light-show): repo `.claude/`
holds the README and vendored skills only; machine settings stay in
the operator's home configuration.

Vendored here: `tiger-style-rust` (SKILL.md only; the full reference
guide lives in the Qompass workspace skills tree).
