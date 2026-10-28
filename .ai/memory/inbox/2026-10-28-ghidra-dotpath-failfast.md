# Ghidra provider: dot-path fail-fast (2026-10-28)

Finding: the Ghidra provider died on every default-config run.
Ghidra 12.1.2's project locator rejects any project path with a
dot-prefixed element (`NamingUtilities.checkName`), and the XDG
state default (`~/.local/state/fathom`) always contains `.local`.
Because `run_export` places the project under the state dir, the
provider failed with the misleading "Ghidra run produced no
export (exit Some(1))" — the failure the phlow C2 gate report
recorded against the `provider == "ghidra"` assertion. This is
the 2026-10-18 G1-4 failure mode; the fail-fast ordered then had
not landed in this tree.

Fix (crates/fathom-native/src/engine.rs): `run_export` now checks
the project path before launching and returns
`configuration_invalid` naming the offending element, with a
remediation pointing `state_dir` at a dot-free path. Five tests
(3 adversarial, 2 validation) cover the XDG default, dot elements
in leaf/early positions, `..`, and clean/dot-containing names.

Verified on primo: default config reproduces the old error
against the pre-fix binary; a clean `state_dir` serves all six
ghidra tools through the MCP surface. Separately measured:
first-import analysis of large Rust debug ELFs exceeds the 330 s
provider bound on primo (205 MB debug binary unfinished at
772 s under load) — a bound/headroom question, not this fix.
