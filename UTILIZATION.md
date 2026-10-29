# Utilization — fathom 1.0.0 (G-F4, D-116 evidence)

Scripted modern-era stdio sessions against the landed 1.0.0
binary (`target/debug/fathom`, built from this tree), run on
primo 2026-10-29. Driver: `fathom_util_driver.py` and the full
transcript `fathom-co-util-output.txt`, both filed in the night
workspace (`~/workspace/night-20261028/`). Every session opened
with `server/discover` (supportedVersions = ["2026-07-28"];
serverInfo = fathom **1.0.0**) and a `tools/list` of **158
tools**. Result: **14/14 steps PASS.**

## S1 — Archive family (S5-class readers)

- `inspect_asar` on the tree corpus fixture
  `crates/fathom-js/tests/fixtures/sample.asar` — envelope
  status `complete`, 2 findings.
- `inspect_python_artifact` on
  `crates/fathom-native/tests/fixtures/sample_pyinstaller.bin`
  — status `partial` (the reader's honest coverage statement
  for this fixture), 3 findings.

## S2 — Process family (S6/S7-class)

- `inspect_beam_module` on `demo_mod.beam`, a BEAM file in the
  exact format of the crate's own test-corpus builder
  (`crates/fathom-native/src/beam.rs` tests) — status
  `partial`, 8 findings (chunk inventory, atom table, ExpT/ImpT
  resolved, Code header).
- Adversarial leg: the same tool on a beam compiled by primo's
  erlc (OTP 28, emulator 17.1) is refused with the typed error
  `unsupported_target` ("atom count ... exceeds the census
  bound") — OTP 28 changed the AtU8 atom-chunk layout and the
  reader refuses rather than fabricating a census. Recorded
  here as a finding: the S6 reader does not parse OTP-28 BEAM
  files; the COMPLIANCE BEAM partial (opcode decode
  NOT-IMPLEMENTED) is a separate, additional limitation.
- `inspect_gpu_code_object` on
  `crates/fathom-native/tests/fixtures/amdgpu_kernel.elf`
  (S7) — status `partial`, 1 finding.
- `capture_process` (Execute class, operator-allowlisted for
  this run) running `sha256sum` over the S1 ASAR fixture,
  confined — status `partial`, 1 finding (exit/output/hash
  capture envelope).

## S3 — Video family (fathom-video, YouTube-RE Y1/Y2)

- `ingest_youtube_video` on a real public video ("Me at the
  zoo", 19 s, youtube.com/watch?v=jNQXAC9IVRw) — status
  `complete`, 17 findings; retained ingest `vi_dc5beffb7795d10c`
  (media 474,478 bytes, manual-en caption track, coverage
  19/19 exhaustive in the retained document).
- `read_video_ingest` (summary view) over that ingest —
  `complete`, 1 finding.
- `build_video_guide` with `operation: compose, derive: true`
  (rule-derived steps, Y2) — `complete`, 1 finding.

## S4 — Ghidra engine (fresh session, post-bridge-removal)

Fixture: `fx_hello` from the G3 harness corpus
(`~/.local/share/fathom-ghidra-g3/fixtures/`).

- `binary_overview` — `complete`, 3 findings.
- `list_functions` — `complete`, 1 finding.
- `analyze_function` on `compute_loop` — `complete`, 5
  findings (fresh function analysis through fathom's own
  headless Ghidra provider; the bethington bridge was removed
  in G3/D-295 and no part of this session touches it).

No audio was produced or played in any session.
