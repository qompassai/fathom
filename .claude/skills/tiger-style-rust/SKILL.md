---
name: "tiger-style-rust"
description: "Write or review Rust code in Matt's Tiger Style: safety-first Rust standard with explicit contracts, assertions, bounded work, and disciplined ownership. Use when writing, regenerating, refactoring, or reviewing Rust — especially services, CLI tools, the phlow agent runtime, and Neovim helpers. See references/TIGER_STYLE_RUST.md for the full guide."
---

# Tiger Style Rust

## Purpose

Apply Matt's Tiger Style standard to Rust code. Priority order, always:
**Safety > Performance > Developer Experience.** The full guide lives in
[references/TIGER_STYLE_RUST.md](references/TIGER_STYLE_RUST.md); this file
is the operational core. When the two disagree, the full guide wins.

## Workflow

1. Pin the toolchain in the project's `rust-toolchain.toml` (an exact,
   reviewed nightly date), not only in editor config. Record the active
   toolchain when terminal, editor, and CI disagree.
2. Lay the crate out top-to-bottom: crate docs/purpose, public contract
   (types, constructors, key functions), then private machinery. Private
   first, then `pub(crate)`, then `pub` only for a real external API.
3. Validate external input with ordinary control flow returning a typed
   error; assert facts a correct implementation already established
   (`assert!` for invariants, `debug_assert!` for expensive dev checks).
4. Bound everything with named constants carrying units: input bytes,
   iterations, retries, queue capacity, memory, output, deadlines.
5. Review against the checklist below before calling the code done.

## Operating Rules

- **Contracts first.** Every substantial operation answers: accepted and
  rejected inputs, trust boundary, max work/memory/output/time, owner of
  every allocation/handle/task/subprocess, failure and cancellation
  behavior, cleanup obligations.
- **Errors vs assertions.** Invalid input/config/protocol data → typed
  error with bounded context. Corrupt internal relationship → `assert!`.
  Never `unwrap()`/`expect()` on external data, I/O, locks, or
  subprocess results. Never put required mutation inside an assertion.
  Propagate with `?` where the caller owns recovery; match explicitly
  where failure changes cleanup, retry, or state. Never `let _ =` a
  `Result` unless the loss is recorded or justified as best-effort.
- **Bound everything.** No unbounded loops, retries, queues, or growth.
  Name limits with units (`output_bytes_max`, `retry_count`,
  `queue_capacity`, `deadline`). Validate index ranges with checked
  arithmetic (`checked_sub`/`checked_add`) before computing an end.
  Use fixed-width integers for wire/disk formats; `usize` for native
  indexing only after checked conversion (`TryFrom`, never unchecked
  `as` on external sizes).
- **Ownership discipline.** Borrow for inspection (`&str`, `&[T]`);
  take ownership when retaining or transferring is the contract.
  Treat `.clone()` as an explicit cost decision — cloning an `Arc`
  differs from cloning a buffer. RAII for ordinary resources; name the
  owner when work escapes a scope (task, callback, `Arc`, subprocess).
- **Unsafe policy.** Default to `#![forbid(unsafe_code)]`. Where unsafe
  is genuinely required: isolate the boundary, document every safety
  obligation locally (allocation, provenance, alignment, init, bounds,
  aliasing, lifetime, thread access), consider
  `#![deny(unsafe_op_in_unsafe_fn)]`, and add adversarial tests to the
  safe wrapper. Never unwind across an FFI boundary.
- **Concurrency.** Bounded queues with a documented full-queue policy
  (reject, block-to-deadline, replace-obsolete). Document lock ordering
  and the protected invariant; never hold a blocking mutex across
  `.await`. Own task handles; cancellation follows a documented policy.
  Use generation tokens so stale completions cannot publish.
- **Control flow:** early returns, shallow branches, no recursion over
  attacker-controlled depth (explicit stack with a depth cap instead).
  Retries need a retryable error class, bounded attempts, a total
  deadline, and an idempotency argument.
- **Names carry domain meaning and units:** `snake_case` for
  items/locals, `UpperCamelCase` for types/traits,
  `SCREAMING_SNAKE_CASE` for constants. No `n`, `sz`, `tmp2`, `stuff`.
  Prefer options structs over positional booleans.
- **Formatting:** rustfmt is the mechanical authority — 4-space indent,
  100 columns, edition 2024. Ordinary functions stay near or below 70
  physical lines; split at meaningful contracts. Explicit imports; no
  wildcard imports in production modules.
- **Types and state:** distinct types for distinct concepts (byte offset
  vs element count, validated vs raw config). Enums for mutually
  exclusive states. State transitions follow
  validate → prepare → commit → observe; rejected validation leaves
  published state unchanged.
- **OS boundaries.** Paths are requests, not authorization — no string
  prefix checks for containment. `std::process::Command` with separate
  argv values (no implicit shell); bound and drain stdout/stderr,
  enforce deadlines, reap children. Atomic writes via temp-file +
  rename. Never log tokens or credential-bearing URLs; no secrets in
  argv.
- **Determinism:** sort map keys before serializing; never depend on
  hash-map iteration order; make float-tolerance decisions explicit
  with units and a reason.
- **Comments explain why**, not what. Keep rustdoc on public items
  focused on contract, bounds, and failure behavior.
- **Neovim:** use the project's pinned toolchain for rust-analyzer,
  checks, formatting, and debugging alike. Helpers feeding diagnostics
  use a versioned schema with bounded records, explicit byte/char and
  indexing conventions, and buffer identity + input version to reject
  stale results.

## Output Contract

Rust you produce for Matt must: compile on the pinned nightly with
warnings denied, carry doc comments on public items stating contract
and bounds, return typed errors on expected failures, assert internal
invariants, bound all work/queues/retries/memory, stay within 100
columns and ~70 lines per function, and pass the review checklist.

## Review Checklist

- [ ] External input validated before allocation, indexing, and mutation.
- [ ] Types distinguish domain concepts; invalid states hard to construct.
- [ ] Work, queues, memory, output, retries, and time have explicit budgets.
- [ ] Arithmetic and conversions preserve sizes and protocol meanings.
- [ ] Errors preserve failure and cause; assertions enforce established invariants.
- [ ] Every resource (allocation, handle, task, subprocess) has one owner and a cleanup path.
- [ ] Cancellation cannot publish stale results or duplicate effects silently.
- [ ] Unsafe/FFI contracts are local, reviewed, and adversarially tested where possible.
- [ ] Logs, argv, and subprocess environments expose no secrets.
- [ ] Toolchain and dependency changes received execution-trust review.
- [ ] Boundary tests and the actual supported target/feature matrix are recorded.
- [ ] Performance claims include measurements and their environment.
