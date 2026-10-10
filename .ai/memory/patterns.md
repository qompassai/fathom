# Patterns

## Gates before a stage counts as done

`cargo test --workspace`, `cargo clippy --all-targets -- -D
warnings`, `cargo fmt --check`, IDE gate (headless nvim + live
diver config, rust-analyzer/bacon-ls/crates-lsp, 0 errors),
`nix build`, `nix flake check`, `mdbook build` (final tree).

## Ghidra runs

- Provider locates `analyzeHeadless` via `REA_GHIDRA_HEADLESS`,
  then `$PATH` (`ghidra-analyzeHeadless`), then
  `/opt/ghidra/support/analyzeHeadless`.
- Projects live under `<state_dir>/ghidra/<sha256-prefix>/`;
  never in the target's directory.
- The subject is hashed before and after the run; a change is
  `artifact_changed`, never a silent mixed result.

## Repomap (codebase map for agents)

One-shot generation:

```
nix run github:qompassai/nix?dir=repomap -- /path/to/repo --budget 15000 --out .repomap.txt
```

`.repomap.txt` is a derived artifact — gitignore it, never commit it.
