# AGENTS.md — fathom

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

Working rules for agents in this repository. `SPEC.md` is the
design contract; this file is the operating discipline.

## Non-negotiables

- Tiger Style Rust: safety > performance > developer experience;
  explicit contracts; bounded work; no hidden behavior.
  Assertions on invariants; errors are values (`FathomError`), never
  panics across a tool boundary.
- `#![forbid(unsafe_code)]` in every crate. There is no FFI in
  this codebase; engines (Ghidra) are driven as child processes.
- Alphabetical order everywhere it can apply: modules, files,
  functions, constants, enum variants, tool names, dependency
  lists. Dependency order wins only where the language requires.
- Evidence honesty: a result states what was observed, derived,
  inferred, and not examined. A scaffolded capability returns
  `capability_unavailable` with `not_implemented` — never a
  fabricated empty success. Faking coverage is the one
  unforgivable failure mode.
- ~50/50 validation/adversarial tests. Adversarial cases think
  like an attacker: path escapes, malformed formats, oversized
  inputs, poisoned archives, mid-run target mutation.

## Process

- Test and validate in this tree; gates are `cargo test`,
  `cargo clippy --all-targets -- -D warnings`, `cargo fmt
  --check`, the IDE gate (headless nvim with the live diver
  config), `nix build`, `nix flake check`, and `mdbook build`.
- Commits are local until Matt authorizes a push. Stage explicit
  pathspecs; run `git diff --cached --stat` before every commit;
  never sweep foreign changes.
- Findings and decisions go to `.ai/memory/` (inbox first,
  promote when validated).
