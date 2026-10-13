# fathom

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

Rust port of REA (Reverse Engineer Anything): one
provider-neutral MCP server for reverse engineering — native
binaries, JavaScript/Electron applications, .NET assemblies, web
captures, EVM bytecode, and process behavior — where every result
is an evidence envelope that states what was observed, what was
derived, what was not examined, and what the provider cannot
establish.

The design is specified in [SPEC.md](SPEC.md): capability
inventory mapped from upstream's public contracts, per-capability
Rust strategy, evidence and error models, a deterministic
fail-closed policy engine, and the staging plan. Design source:
morluto/rea (MIT), credited in [NOTICE](NOTICE); no upstream code
is used.

## Why a Rust port

Upstream REA is TypeScript/Node distributed through npm. This port
exists to keep the capability on a Rust-first, pinned, auditable
supply chain — the estate's standing direction (SPEC §1).

## Shape

- `fathom-core` — config, error contracts, evidence model, policy,
  tool registry, confinement, bounded processes.
- `fathom-mcp` — MCP stdio + streamable HTTP transports.
- `fathom-a2a` — signed A2A agent card (JCS + Ed25519).
- `fathom-native` — Ghidra headless provider + binary layout (goblin).
- `fathom-js` — JavaScript/Electron static analysis (oxc) + ASAR.
- `fathom-managed` — .NET PE/CLI metadata (manual ECMA-335).
- `fathom-observe` — process capture, HAR reading, EVM selectors.
- `fathom-cli` — the `fathom` binary (`serve`, `card`, `doctor`,
  one-shot analysis).

## Build

```sh
nix build          # or: nix develop, then cargo build --workspace
cargo test --workspace
```

## License

Dual-licensed AGPL-3.0-only OR Apache-2.0; see `LICENSE`,
`LICENSE-AGPL`, and `NOTICE`.
