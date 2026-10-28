# Ghidra provider: first-import timeout bound (2026-10-28)

Finding (D2 of the 2026-10-28 Ghidra repair run): first-import
full auto-analysis of a large Rust debug ELF exceeds the 330 s
provider bound on primo — the exact 76 MB phlow test binary took
1128 s (Probe D, under load) — so the phlow `fathom_integration`
assertion `provider == "ghidra"` failed with `provider_timeout`
even though the provider itself was healthy. Repeat calls are
cache-served or re-export-only and stay fast; the single bound
was calibrated for them, not for a first import.

Fix (Owner ruling D-241: "raise the bound, test the heap"):
`run_export` already distinguishes the two run shapes — a
subject whose cached project has no `fathom.gpr` is launched
with `-import` (full analysis), otherwise `-process
-noanalysis`. That distinction now selects the bound via
`provider_timeout_secs`: `GHIDRA_FIRST_IMPORT_TIMEOUT_SECS`
(1800 s) for a first import, `GHIDRA_TIMEOUT_SECS` (330 s)
otherwise (crates/fathom-core/src/limits.rs, SPEC §8).
`finish_timed_out_run` reports the bound that actually applied.
Four tests (2 adversarial, 2 validation) pin the split, the
strict ordering, and the error naming the applied bound.

Heap: `GHIDRA_HEADLESS_MAXMEM` remains an operator env lever on
the fathom process (the runner passes its environment through
to Ghidra); measured effect on first-import time is recorded in
~/workspace/ghidra-repair-20261028/REPORT-D2.md.
