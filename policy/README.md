# Fathom's OpenAPPA worker policy

This directory holds fathom's OpenAPPA (APPA) policy profile: the
deterministic, second gate for a dispatched Claude worker building
and analyzing in this repository, after the estate pilot at
`~/openappa-pilot` (2026-10-01). It is policy only — no code reads it
yet; it is checked offline, and wiring a launcher to run workers
under it is separate, later work.

The profile includes upstream's claude-code battery and adds root
rules (root rules run first; the first matching rule wins) for this
repo:

- **Workflows allowed** — `cargo build` / `test` / `clippy` / `fmt`,
  `nix build` / `nix flake check`, `mdbook build`, and read-only git
  inspection (`status`, `diff`, `log`).
- **Hard denies** — the pilot's destructive set (`rm -rf`, `rm -fr`,
  `git reset`, `git clean`, `git push`, `gh`, `sudo`) with
  `attention = ["blocked"]`: no authority can permit them.
- **Fathom's tool tiers** — SPEC classes mapped to tiers: `read`
  tools run; `observe_browser` needs the human at this layer too,
  mirroring SPEC §8 (the engine default-denies observe/execute
  without a config allowlist — Owner's ruling 2026-10-10);
  `capture_process`,
  the catalog's only `execute` tool, is a hard deny — its SPEC
  default-deny preserved in policy form. The upstream
  mutate-provider-state class was not ported, so it has no rules;
  a tool with no rule is undeclared here and refused.
- **Data labels** — analysis artifacts (decompiled output, HAR
  captures, process captures, Ghidra project data) live under the
  fathom state dir, `$XDG_STATE_HOME/fathom`, and may carry target
  secrets. Reading one — through Read, Grep, or a Bash spelling —
  narrows the session audience to `self`. While narrowed, network
  destinations (`curl`, `wget`, `nc`, `scp`, `sftp`, `rsync`, …)
  are refused, and writes land only in cleared destinations: the
  state dir and this repo's tree, both contained sinks whose exits
  are separately gated. Selector segments are exact — a lookalike
  such as `.local/state/fathom-evil` is not cleared.

Because the bare Write/Edit root rules would otherwise shadow the
battery's own protections, the battery's six ask-tier selectors per
tool are mirrored above them, and the bare gates require a `trusted`
session — the same requirement the battery's trust-gated selectors
carry — so the root gate is never weaker than the rule it precedes.

## Validating

Pinned checker: upstream **appa 0.30.0 at commit
`5060566a0d9fed034a5e68ec782a1b00714c7014`** (the pilot's pin; the
estate does not track upstream main), built at
`~/openappa-pilot/src/target/debug/appa`. The battery include in
`appa.toml` is relative to the config file and expects the pilot
tree at `~/openappa-pilot` beside a checkout under
`~/workspace/repos/`.

```sh
APPA=~/openappa-pilot/src/target/debug/appa
$APPA --version    # appa 0.30.0
$APPA describe --config policy/appa.toml --check
$APPA replay --config policy/appa.toml policy/replay/
```

`describe --check` must exit 0 and every replay scenario must be
`ok` (34 steps: 19 allow, 13 deny, 2 authority). The scenarios cover
the allowed workflows and tool tiers, the hard-deny set, the
capture-process refusal, the ask-tier config edits, and the lumen
design's adversarial classes: exfiltration, label confusion, and
sink spoofing.

## Changing this policy

Policy changes are **proposal → replay → Owner's approval**: no
worker widens its own policy. A change lands with its replay
scenarios updated in the same commit, gates green, and the approval
recorded in `.ai/memory/`.

## Known limits

- Bash selectors are substring matches without full-recall
  guarantees (an upstream caveat the pilot also recorded): a network
  send spelled to dodge every selector reaches the battery's
  annotator, not these rules. The hard-deny set is Bash-spelled,
  matching the pilot; PowerShell is not a primo worker surface.
- APPA is not an OS sandbox. This profile is the deterministic
  information-flow layer beside the harness's own permissions and
  fathom's own policy engine (SPEC §8), not a replacement for
  either.
