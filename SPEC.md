# fathom — Specification

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

Rust port of REA (Reverse Engineer Anything). This document
is the contract the implementation is built and gated against: the
capability inventory, the per-capability Rust strategy, the evidence
and error models, the policy and confinement rules, the MCP and A2A
surfaces, and the honest staging plan.

## 1. Why this port exists

Commissioned by Matt, 2026-10-10, in his words and reasoning:

- Upstream REA is a TypeScript/Node program distributed through npm.
  The Node/npm supply chain is a shifting security-vulnerability
  surface: a large transitive dependency tree, install-time scripts,
  and a registry whose compromise modes are well documented. Matt's
  stack (diver, phlow, rose, volta, vongola) is Rust-first precisely
  so that surface is small, pinned, and auditable.
- The estate's pattern is therefore to prioritize **whole Rust ports
  proactively** — while the design is understood and the work is
  calm — instead of reactionary ports later, under pressure, when an
  upstream incident or a breaking change forces the issue.
- Building the port is also the training ground: it teaches Rust in
  the domain where Matt most needs fluency (his own security
  tooling), on a codebase whose behavior is fully specified in
  advance by upstream's public contracts.

Porting rule: nothing here is a transliteration. Designs, contracts,
and behavior specifications carry over from upstream's published
documentation; every line of Rust is original. Upstream is MIT, so
this is a choice about supply chain and stack coherence, not a
licensing necessity; NOTICE credits morluto/rea as the design source.

## 2. Design source

Read from Matt's fork `qompassai/rea` (upstream `morluto/rea`,
v6.3.0), public surfaces only:

- `docs/mcp-contracts.md` — identity/discovery, progress and
  cancellation, provider binding, the generated tool catalog.
- `docs/tool-design.md` — tool shapes (inspect, search/list, trace,
  compare, workflow, observe/capture), contract rules.
- `docs/error-contract.schema.json` — the canonical error codes and
  categories (adopted verbatim in §7).
- `docs/architecture.mermaid` — upstream layering (composition,
  adapters, application, providers, contracts, domain).
- Provider and capability guides: `ghidra-provider.md`,
  `ida-provider.md`, `native-investigation.md`,
  `javascript-application-workflows.md`,
  `javascript-artifact-reconstruction.md`,
  `managed-code-analysis.md`, `browser-observation.md`,
  `process-capture.md`, `web-network-captures.md`,
  `evm-bytecode.md`, `firmware-analysis.md`, `android-analysis.md`,
  `apple-application-analysis.md`, `binary-diagnostics.md`,
  `recorded-crashes.md`, `reconstruction-obligation-ledgers.md`.

## 3. Capability inventory (upstream → port)

Upstream returns, per target class: native pseudocode/assembly/
strings/symbols/calls/references; offline ELF layout diagnostics;
EVM dispatch selectors; recorded-crash registers; JavaScript/Electron
module graphs with IPC and native add-on relationships; website
structure, scripts, and network observation; HAR/mitmproxy capture
reading; .NET metadata, CIL, and build comparisons; Android APK
manifest/classes/methods; firmware regions and extraction; package
and Apple-bundle inventories; process behavior capture and
comparison. The port maps every one of these to a tool in §4 or a
named scaffold in §11. Nothing is silently dropped.

## 4. Tool catalog (port)

Design decisions that shape the whole catalog:

- **Stateless per-call tools.** Upstream binds one immutable deep
  provider per target in a session (`open_binary`/`binary_session`).
  The port takes an explicit `target` path on every call instead:
  no hidden session state, every call independently policy-checked
  and reproducible, and an MCP consumer can audit exactly what was
  asked. The provider cache (§9.1) recovers the performance the
  session model was buying. Session binding may return later as an
  optimization layer; it is NOT-IMPLEMENTED in v1.
- **Provider-neutral names, admitted per-provider semantics.**
  Tools are named for the analyst question; the result states which
  provider produced it and what that provider does and does not
  establish (upstream's core contract rule, kept).
- **Complete catalog, honest availability.** `tools/list` returns
  every tool, including unavailable and not-implemented ones, each
  with availability and the reason. Missing coverage is reported as
  unknown, never presented as absence.
- **Classes.** Every tool is classified `read`, `observe`, or
  `execute` (§8). The class is part of the tool descriptor and is
  enforced by the policy engine before the handler runs.

Tools (alphabetical; status = this run):

| Tool | Class | Provider | Status |
| --- | --- | --- | --- |
| `analyze_art_style` | read | art | built |
| `analyze_function` | read | ghidra | built |
| `analyze_javascript_application` | read | js | built |
| `apply_style_via_lumen` | execute | art | built (bridge to lumen stdio MCP) |
| `binary_overview` | read | ghidra | built |
| `capture_process` | execute | process | built (pipes; PTY scaffolded) |
| `compare_artifacts` | read | core | built |
| `export_evidence_bundle` | read | core | built |
| `inspect_android_apk` | read | android | built (ZIP64 + DEX/arsc decode are named walls) |
| `inspect_artifact` | read | artifact | built |
| `inspect_asar` | read | js | built |
| `inspect_binary_layout` | read | native-layout | built |
| `inspect_evm_bytecode` | read | evm | built (interface inference scaffolded) |
| `inspect_firmware` | read | firmware | built (signature scan; no extraction) |
| `inspect_managed_assembly` | read | managed | built (CIL decode scaffolded) |
| `inspect_source_map` | read | js | built |
| `inspect_web_capture` | read | web | built |
| `list_functions` | read | ghidra | built |
| `list_names` | read | ghidra | built |
| `list_strings` | read | ghidra | built |
| `observe_browser` | observe | browser | built (Chromium headless DOM inventory) |
| `remap_palette` | execute | art | built |
| `search_inventory` | read | ghidra | built |
| `session_info` | read | core | built |
| `verify_evidence_bundle` | read | core | built |

Upstream tools with no separate port tool, and where they went:
`open_binary`/`close_binary`/`binary_session` → stateless design +
`session_info` (identity, catalog digest, availability). CLI
one-shots (`rea doctor`, setup, update) are operator tooling, not
MCP surface; the CLI ships `doctor` (§10). Workflow composites
(`trace_application_feature`, `compare_application_versions`,
`build_reconstruction_obligation_ledger`, and kin) are compositions
over the primitives above; per upstream's own tool-design rule
("compose when repeated use demonstrates a multi-source outcome"),
they are deferred until the primitives have real use — recorded
here so the omission is a decision, not a gap.

## 5. Per-capability Rust strategy

Crates verified against crates.io on 2026-10-10 (name, version,
verdict). "Adopt" means a workspace dependency; every adoption is
pinned in `Cargo.lock` and built offline thereafter.

| Capability | Candidates | Verdict |
| --- | --- | --- |
| JS parsing | oxc_parser/oxc_ast/oxc_ast_visit 0.153.0; swc (heavy); boa parser (engine-grade, wrong layer) | **Adopt oxc.** A real Rust JS toolchain (parser + AST + visitor) at production scale; replaces upstream's Babel dependency one-for-one in role. |
| Binary formats (layout) | goblin 0.10.7; object 0.40.0; pelite 0.10.0 | **Adopt goblin.** ELF/Mach-O/PE parsing in one crate; object is the better *writer's* library and we only read; pelite is PE-only and cannot serve ELF/Mach-O paths. |
| Deep native analysis | Ghidra 12.1.2 headless (host); Hopper (no Linux automation story); IDA (licensed, GUI-bound) | **Drive Ghidra headless** (§9.1). Reimplementing a decompiler is not a port; upstream itself is a provider shell over engines. |
| Browser observation | chromiumoxide 0.9.1; raw CDP over websocket by hand | chromiumoxide is viable and maintained; the scenario/session engine around it is a program of its own → **scaffold in this run**, adopt chromiumoxide when the stage is built. Stage 5 built the provider on the Chromium headless CLI (`--dump-dom` under the bounded process runner) rather than chromiumoxide; the session/scenario surface remains unbuilt. |
| MCP transport | rmcp 3.5.1 (official Rust SDK); hand-rolled JSON-RPC | **Hand-roll.** The wire surface fathom needs (initialize, tools/list, tools/call, ping over stdio + one HTTP POST route) is small; hand-rolling keeps the transport auditable and immune to SDK churn. Trade-off named: protocol upgrades are our work. |
| A2A card | a2a 0.1.0 (985 downloads, placeholder); hand-rolled per estate pattern | **Hand-roll**, following the volta/vongola pattern: JCS-canonicalized card, Ed25519 signature. |
| JCS canonicalization | serde_jcs 0.2.0; hand-rolled RFC 8785 | **Hand-roll** with the RFC 8785 test vectors as unit tests; one less dependency for ~100 lines with a public test suite. |
| .NET metadata | pelite (PE only, no CLI tables); a dedicated ECMA-335 crate (none mature found) | **Manual ECMA-335 parsing** over goblin's PE headers: metadata root, streams, table row geometry, TypeDef/MethodDef/ImplMap reads. The format is a published standard (ECMA-335); the parser is bounded and testable against fixtures. |
| ASAR | @electron/asar (JS); the format itself | **Implement directly.** ASAR is a pickle-framed JSON header plus concatenated payloads; a reader is ~150 lines and is cross-validated against archives produced by the real `@electron/asar`. |
| Process capture | portable-pty (PTY); std::process pipes | **Pipes in this run** (output, exit, timing, hashes). PTY support is scaffolded; upstream's interactive PTY scenarios are named NOT-IMPLEMENTED until portable-pty is adopted. |
| HAR reading | serde_json over the HAR 1.2 schema | **Implement directly**; no crate needed. |
| EVM | EVMole as WASM (upstream's route); hand analysis | **Hand analysis** for the dispatcher/selector slice, findings marked `inferred`. Interface reconstruction beyond selectors is scaffolded. |
| Signing / hashing | ed25519-dalek 2; sha2 0.11 | **Adopt both** (estate-standard crates). |
| HTTP transport | axum 0.8 on tokio 1 | **Adopt** (estate standard). Stdio transport stays synchronous and tokio-free. |

## 6. Evidence model

The design idea carried over from upstream, stated once and applied
everywhere: **a finding is evidence, not an answer.** Every tool
result is an evidence envelope:

```json
{
  "tool": "binary_overview",
  "provider": "ghidra",
  "status": "complete | partial",
  "subject": { "path": "...", "sha256": "...", "size_bytes": 0 },
  "findings": [ { "kind": "function", "confidence": "observed",
                  "facts": { "...": "..." },
                  "locations": ["0x1010"],
                  "limitations": ["..."] } ],
  "unknowns": [ { "aspect": "p-code value flow",
                  "reason": "not collected by this provider run" } ],
  "coverage": { "examined": 0, "total": 0, "exhaustive": true }
}
```

Rules:

- `confidence` is one of `observed` (the provider saw it),
  `derived` (computed from observations by a stated rule), or
  `inferred` (a heuristic guess). The three never mix silently;
  upstream's "observed, derived, and inferred relationships stay
  distinct" is a hard rule here.
- Every finding may carry `limitations`; every envelope carries
  `unknowns` for coverage the run did not establish and `coverage`
  counts derived from examined records, never from prose.
- Subject identity is the SHA-256 of the exact bytes analyzed.
  Evidence bundles (§4, `export_evidence_bundle`) are envelopes
  plus a bundle digest over their canonical form;
  `verify_evidence_bundle` re-checks digests and subject agreement
  (upstream's rule: a valid evidence ID alone does not establish
  that subject identities agree).
- Truncation is data, not silence: bounded collections report
  retained counts and known omitted counts (upstream's p-code
  dossier rule, generalized).

## 7. Error contracts

Errors are the canonical envelope `{"error": {...}}` with `code`,
`category`, `message`, and optional `target`, `remediation`,
`partial_observation`, `details`. Codes and categories are adopted
verbatim from upstream's `error-contract.schema.json`:

- Categories: `cancelled`, `execution_failure`, `integrity_mismatch`,
  `invalid_input`, `resource_constraint`, `timeout`, `truncated`,
  `unavailable`, `unsupported_provider`, `unsupported_target`.
- Codes: `access_denied`, `artifact_changed`,
  `artifact_integrity_mismatch`, `artifact_operation_failed`,
  `cancelled`, `capability_unavailable`, `cleanup_incomplete`,
  `configuration_invalid`, `evidence_integrity_mismatch`,
  `execution_failure`, `invalid_request`, `process_capture_failed`,
  `provider_timeout`, `provider_unavailable`, `resource_constraint`,
  `revision_conflict`, `target_unavailable`, `truncated`,
  `unreadable_output`, `unsupported_target`.

Port additions, kept distinct from upstream's set: a scaffolded tool
returns `capability_unavailable` with `details.status =
"not_implemented"` and the SPEC section that owns it — never a
fabricated empty success. MCP failures return `isError: true` with
the canonical error JSON as the text content and no
`structuredContent`, matching upstream's rule.

## 8. Policy and confinement

Deterministic, fail-closed, evaluated before every handler:

- **Classes.** `read` tools run when the target validates.
  `observe` and `execute` tools are **default-deny**: the config
  must name the tool in an allowlist before it can run at all.
  There is no prompt, no ambient authority, no fallback.
- **Target roots.** The operator declares `target_roots` in config.
  Every target path must canonicalize to a location under a root;
  symlink escapes and `..` escapes are rejected with
  `access_denied`. A config with no target roots serves only
  `session_info`.
- **State directory.** All analysis state (Ghidra projects,
  extraction, caches) lives under one state dir
  (`$XDG_STATE_HOME/fathom` or config). Providers write nowhere
  else; extraction targets are created under it with generated
  names, never from target-supplied paths.
- **Bounds.** Named constants, enforced before the costly step:
  max target bytes, max file count per inventory, max decompile
  bytes, max captured output bytes, provider timeout (default
  330 s for Ghidra, matching upstream's startup deadline scale),
  max ASAR entries. A bound hit is `resource_constraint` or a
  reported truncation — never an unbounded retry.
- **Processes.** Providers run only owned child processes, in
  their own process groups, killed on timeout or cancellation.
  Nothing kills a process it cannot prove it owns (upstream's
  rule, kept verbatim in spirit).
- **Network.** `read`/`execute` tools make no network calls. The
  HTTP transports bind loopback by default; a non-loopback bind
  requires the config to say so explicitly.

## 9. Provider designs

### 9.1 Native (Ghidra headless, batch export)

Route decision, with reasons:

1. **Estate precedent.** Diver already drives Ghidra this way on
   this machine: `analyzeHeadless` with a Java `-postScript`
   (DiverExportAnalysis.java) writing bounded exports. The pattern
   is proven against Ghidra 12.1.2 on primo.
2. **No resident bridge.** Upstream keeps a persistent bridge
   process and socket per target. A batch export has no lifecycle
   to supervise, no socket protocol to version, and its failure
   modes are a process exit code and a log — the deterministic
   shape this estate prefers.
3. **No nested third-party MCP.** The bethington ghidra-mcp bridge
   already exists on primo, but embedding another project's MCP
   server inside this one would route calls around our policy
   engine and evidence model. It stays a sibling tool in diver,
   not a dependency here.
4. **Named cost, mitigated.** Batch import repeats analysis per
   target. Mitigation: the Ghidra project is cached in the state
   dir keyed by the subject's SHA-256; the first call imports and
   analyzes, later calls re-open the project read-only and only
   run the export script. A changed byte means a new digest and a
   fresh import (`artifact_changed` guards mid-run mutation: the
   subject is re-hashed after the run).

The port's own script, `FathomExportAnalysis.java`, exports one JSON
document: program identity (name, format, language, image base),
memory blocks, functions (entry, name, signature, external/thunk
classification), symbols, defined strings, and — for one requested
function — assembly listing, decompiled C (bounded), callers,
callees, and typed references. Caps mirror the estate's existing
ones (5,000 functions/strings class bounds, decompile byte cap,
30 s per-function decompile timeout). `inspect_binary_layout` does
not use Ghidra at all: goblin reads ELF/PE/Mach-O sections,
segments, symbols, relocations, and static mitigation candidates
(upstream's offline-diagnostics slice) with no engine dependency.

Provider honesty: pseudocode and assembly are Ghidra observations,
never "the source"; cross-provider text comparison is not a
semantic fact. Hopper and IDA providers are NOT-IMPLEMENTED
scaffolds — IDA is an upstream-contract adaptation over a licensed
GUI product and Hopper's automation is macOS-centric; both are
named here so their absence is a decision.

### 9.2 JavaScript / Electron (oxc)

`analyze_javascript_application` accepts a directory or an `.asar`
file. Per module: oxc parses (parse errors are findings, not
failures of the run), imports/exports are read from the AST,
relative specifiers resolve against the module set to build the
graph (unresolved specifiers are unknowns, not errors). Electron
boundaries are AST-derived: `electron` imports, `ipcMain.handle`/
`ipcMain.on` channels, `ipcRenderer.invoke`/`send`, `contextBridge`
exposures, `BrowserWindow` construction, `nodeIntegration`/
`contextIsolation` webPreferences facts (a security-relevant
observation set for this operator). Source maps are inventoried
(presence + sources count) and parsed: `inspect_source_map`
decodes source-map v3 documents (sources, `sourcesContent`
presence, name and segment counts) and maps generated positions
to original positions with greatest-lower-bound segment
semantics. Runtime observation (V8 inspector, Electron live
observation) is NOT-IMPLEMENTED in v1.

### 9.3 Managed (.NET, manual ECMA-335)

`inspect_managed_assembly` reads the PE via goblin, locates the
CLI header and metadata root, and walks the `#~`, `#Strings`,
`#GUID`, and `#Blob` streams: assembly/module identity (MVID kept
as exact GUID bytes; ECMA-335 does not impose RFC 4122 bit
patterns), TypeDef/Field/MethodDef inventories with row offsets
and signatures as blob references, ImplMap (P/Invoke) entries as
declared native dependencies, and per-method IL byte digests.
Decoded-CIL instruction listings are scaffolded; the IL digest is
the build-comparison fingerprint input in v1 (upstream's
decoded-CIL fingerprint is the stage that follows).

### 9.4 Observe set

- `capture_process` (execute): runs an allowlisted command in a
  confined working directory under the state dir, pipes only,
  bounded output, records exit/signal, duration, and SHA-256 of
  stdout/stderr so a report can be hashed independently of
  terminal output (upstream's rule). PTY and filesystem-diff
  observation are scaffolded.
- `inspect_web_capture` (read): parses HAR 1.2 — entries,
  request/response inventories, payload exposure flags, source
  locations. mitmproxy native captures are scaffolded (they need
  an external `mitmdump` reader).
- `inspect_evm_bytecode` (read): offline hex/raw bytecode —
  dispatcher scan for `PUSH4` selector candidates with byte
  offsets, findings `inferred`; argument/mutability inference is
  scaffolded.
- `observe_browser` (observe): built. Chromium headless
  (`--headless=new --dump-dom`) runs under the bounded process
  runner (20 s, 2 MiB DOM cap, per-run profile); the serialized
  DOM is inventoried — title, meta, scripts, link elements,
  anchors, forms — with strict data minimization (http/https
  only, userinfo rejected, fragments stripped). Network logs,
  final HTTP status, and screenshots are declared unknowns:
  the dump-dom surface does not expose them.
- `inspect_firmware` (read): built without an external engine:
  header/format detection (incl. uImage header fields), a
  magic-byte signature scan for embedded filesystems/archives,
  and a Shannon entropy profile over a bounded 64 MiB prefix.
  No extraction is performed.
- `inspect_android_apk` (read): built without a JADX/JDK
  engine: a bounded ZIP reader (stored + deflate) and a binary
  AXML parser for the manifest — package/version, uses-sdk,
  permissions, features, application, and components with
  intent filters. Named walls: ZIP64 and multi-disk archives
  are unsupported; DEX and `resources.arsc` contents are
  inventoried by name only; signature verification is not
  performed.
- Apple: bundle anatomy rides on `inspect_artifact` (file
  inventory, digests, plist parsing); the dylib load-resolution
  projection is built in `inspect_binary_layout` — named load
  commands, linked dylibs, rpaths, install name, segments,
  UUID, and exports/imports where present, per architecture
  for fat binaries. The projection does not resolve the load
  graph against any filesystem.

### 9.5 Art / animation style (fathom-art)

Style reverse engineering under the same evidence discipline:
every descriptor is a measurement on the decoded asset —
observed, derived (with the classification rule stated as a
limitation), or an explicit unknown. Nothing is inferred from
filenames, metadata, or priors.

- `analyze_art_style` (read): PNG/JPEG/GIF. Palette by
  deterministic median-cut over opaque pixels (alpha >= 128),
  sampled on a fixed stride past the sample bound; HSL grade
  statistics (saturation-weighted circular mean hue, lightness
  percentiles, populated-level count); a rule-classified
  shading model (flat / cel / soft / mixed — the rule ships in
  the finding's limitations); per-neighbour gradient and edge
  fractions. For GIF: the timing grammar is read by walking
  the block stream directly (graphic-control delays, the
  NETSCAPE2.0 loop extension) — frame durations, holds,
  total, loop behavior — plus a motion curve over decoded
  frames and an easing classification. Sprite-sheet geometry
  is claimed only when fully transparent gutter bands divide
  both axes into uniform cells; otherwise it is an unknown.
- `remap_palette` (execute): the native transform. Exact or
  nearest (RGB distance) remap to a caller palette or to
  another asset's measured palette; outputs are PNG files
  under the state dir, addressed by bare file name. This is
  the deterministic end of the conversion line: arithmetic
  on measured values, no rendering judgment.
- `apply_style_via_lumen` (execute): the conversion bridge.
  Grading/rendering is lumen's work, never a second engine
  here. Fathom wraps the image in a single-layer lumen
  document (stored form, layers as base64 PNG), spawns the
  allowlisted lumen program as a stdio MCP server in a
  scratch project root under the state dir, requires the
  preset to appear in lumen's own `style_list`, and calls
  `style_apply`. The graded document is composited and
  re-measured; with a reference target, the output spec is
  verified against the reference spec under stated tolerances
  (hue 12 degrees, lightness/saturation 0.08, coverage-weighted
  palette distance 24 RGB units) — out-of-tolerance checks are
  unknowns, not silent passes. Without a reference, closeness
  is an explicit unknown, and preset numeric parameters are
  declared lumen-internal (`style_list` reports names and
  descriptions only).

## 10. Surfaces

- **CLI** (`fathom` binary): `serve` (MCP), `card`, `doctor`
  (host/engine inventory: Ghidra discovery, versions, config
  validity — facts, not fixes), and one-shot forms of the read
  tools for terminal use, emitting the same evidence envelopes.
- **MCP stdio**: newline-delimited JSON-RPC; `initialize`, `ping`,
  `tools/list`, `tools/call`. Advertised schemas are complete;
  the compact input-schema profile upstream added for size-capped
  clients is NOT-IMPLEMENTED (named, with its 13,312-byte budget
  recorded for when it is built).
- **MCP streamable HTTP**: `POST /mcp` on the same JSON-RPC core,
  loopback by default. Stateless per request, matching the
  stateless tool design.
- **A2A**: `GET /.well-known/agent-card.json` serves the agent
  card: name, description, URL, skills derived from the tool
  registry (id, name, description, tags per tool class), and an
  Ed25519 signature over the JCS (RFC 8785) canonicalization of
  the card without the signature field. The signing key is an
  operator-supplied seed file (0600); without one, the card is
  served unsigned and says so — a deployment without a key gets a
  visible fact, not a silent forgery.

## 11. Staging plan

- **Stage 0** — this SPEC. Commit gate: SPEC complete.
- **Stage 1** — scaffolding (estate `.ai`/`.claude`/`.opencode`/
  `.openshell`, licenses, flake, book) and core crates:
  `fathom-core` (config, errors, evidence, policy, registry,
  confinement, bounded processes), `fathom-mcp`, `fathom-a2a`,
  `fathom-cli`. Gate: core test suite green.
- **Stage 2** — first providers working: `fathom-native` (Ghidra
  batch export + goblin layout) and `fathom-js` (oxc + ASAR), with
  live smokes on `/usr/bin/true` and a fixture Electron app.
- **Stage 3** — `fathom-managed` (.NET inventory) and `fathom-observe`
  (process capture, HAR, EVM selectors) built; browser, firmware,
  Android, Apple-deep, CIL decode, PTY, source-map mapping, IDA/
  Hopper providers scaffolded with contracts and
  `not_implemented` behavior.
- **Stage 4** — full gates: workspace tests, clippy `-D warnings`,
  fmt, IDE gate (headless nvim, live diver config), `nix build`,
  `nix flake check`, mdBook build.
- **Stage 5** — the stage-2 providers built: browser observation,
  firmware inspection, Android APK inventory, the Mach-O dylib
  projection (Apple-deep), and source-map position mapping.
  IDA/Hopper remain scaffolded: their host tools are absent,
  which stays a stated unknown.

Anything marked scaffold/NOT-IMPLEMENTED returns
`capability_unavailable` in-band. Faking coverage is the one
unforgivable failure mode in a reverse-engineering tool: an
analyst acts on what the tool claims it saw.

## 12. Licensing

First-party code: Apache-2.0 (SPDX `Apache-2.0`), aligned
2026-10-17 per Matt's ruling; originally dual-licensed
AGPL-3.0-only OR Apache-2.0 per the estate pattern of 2026-10-10. Design source credited in NOTICE (morluto/rea, MIT).
The Ghidra export script is original Java written against
Ghidra's public script API, following the estate's existing
diver precedent.
