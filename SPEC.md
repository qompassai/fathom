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
| `build_reconstruction_obligation_ledger` | read | core | built (§4.1) |
| `capture_process` | execute | process | built (pipes; PTY scaffolded) |
| `compare_artifacts` | read | core | built |
| `delete_reconstruction_proof` | execute | core | built (§4.1) |
| `export_evidence_bundle` | read | core | built |
| `inspect_android_apk` | read | android | built (ZIP64 + DEX/arsc decode are named walls) |
| `inspect_artifact` | read | artifact | built |
| `inspect_asar` | read | js | built |
| `inspect_beam_module` | read | beam | built (opcode decode NOT-IMPLEMENTED; inventory is chunk/table-level) |
| `inspect_binary_layout` | read | native-layout | built |
| `inspect_evm_bytecode` | read | evm | built (interface inference scaffolded) |
| `inspect_firmware` | read | firmware | built (signature scan; no extraction) |
| `inspect_godot_pck` | read | godot | built (decryption NOT-IMPLEMENTED; encrypted entries are unknowns) |
| `inspect_gpu_code_object` | read | gpu | built (GPU ISA disassembly NOT-IMPLEMENTED; kernels and metadata are inventoried) |
| `inspect_managed_assembly` | read | managed | built (CIL decode scaffolded; NativeAOT screen built — marker-derived classification, NativeFormat graph NOT-IMPLEMENTED) |
| `inspect_python_artifact` | read | python | built (bytecode instruction decode NOT-IMPLEMENTED; .pyc code-tree and PyInstaller/PYZ censuses are built) |
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
| `verify_reconstruction_proof` | read | core | built (§4.1) |

Upstream tools with no separate port tool, and where they went:
`open_binary`/`close_binary`/`binary_session` → stateless design +
`session_info` (identity, catalog digest, availability). CLI
one-shots (`rea doctor`, setup, update) are operator tooling, not
MCP surface; the CLI ships `doctor` (§10). Workflow composites
(`trace_application_feature`, `compare_application_versions`,
and kin) are compositions over the primitives above; per upstream's
own tool-design rule ("compose when repeated use demonstrates a
multi-source outcome"), they are deferred until the primitives have
real use — recorded here so the omission is a decision, not a gap.
One composite has since graduated on a named consumer:
`build_reconstruction_obligation_ledger`, with
`verify_reconstruction_proof` and the operator verb
`delete_reconstruction_proof`, is built as the
reconstruction-proof ledger of §4.1.

## 4.1 Reconstruction-proof ledger

*Status: **built** (S2, 2026-10-27), on the consumer named
below; the open questions the draft carried are decided in
§4.1.13 (D-092). Requirements sources: the Stage 0 audit's
§A2 (the ledger was absent; §4 deferred it as a workflow
composite), §§4/6/7/8/9.1/10 of this SPEC, and the upstream
6.8 tightening taken at requirements level only: a proof
requires implementation/revision bindings and individual
claim outcomes (including inapplicable / unavailable /
failed); an ID-array proof record does not establish a
verified ledger.*

### 4.1.1 Why the deferral ends here

SPEC §4 deferred workflow composites "until the primitives
have real use." The use now exists and is named: phlow drives
fathom as an MCP server in its planner → coder → verification →
reviewer loop, and its reviewer judges the coder's
reverse-engineering conclusions. Today those conclusions are
prose in a run report next to raw tool dumps; nothing binds a
conclusion to the evidence that supposedly supports it, to the
binary it is about, or to the fathom build that produced the
evidence. The ledger is the composite that makes that binding
mechanical. It is built on the retained-evidence store S1
opened up (§9.1's subject-keyed export cache, read through the
summary/complete views), not beside it: a proof cites the
retained export, it does not duplicate it.

### 4.1.2 Terms

- **Claim** — one assertion about a subject, stated as
  structured facts (never free prose), in one of the classes
  of §4.1.4, at one §6 confidence (`observed`, `derived`,
  `inferred`).
- **Obligation** — a claim a reconstruction depends on: the
  analyst asserts it, and the reconstruction is only as good
  as its discharge. The ledger is the set of obligations for
  one subject.
- **Proof** — the stored record binding a set of claims to
  (a) one subject, by SHA-256; (b) one retained export, by
  digest; (c) one producing implementation, by version,
  catalog digest, and source revision; and (d) per claim, evidence references into
  that export with server-computed record digests.
- **Verification** — the pure re-check of a proof against the
  subject file and the retained store. Verification produces
  per-claim outcomes (§4.1.6). It runs no provider, spawns no
  process, and writes nothing.

A proof is evidence about claims, in §6's sense: it states
what was bound, what was checked, and what could not be
checked. It is not a certificate that a reconstruction is
correct; §4.1.6's confidence rule is the hard boundary.

### 4.1.3 The consumer's shape (phlow, as it exists)

The contract is written against phlow's real mechanics, not
an imagined client:

- **Roles.** phlow's runtime runs `planner`, `coder`,
  `reviewer` over one shared safe runtime. The coder is the
  analyst: it calls fathom's read tools through phlow's MCP
  stdio client (`[[servers]]` profiles, bounded frames and
  timeouts) and assembles claims. The reviewer is the gate
  this SPEC serves.
- **Host-computed evidence.** Phlow's verification is
  host-run (checks plus a static-analysis coverage gate);
  its standing rule is that reviewer approval never
  substitutes for host verification, and drift observed after
  review marks verification `"stale"` with `verified: false`.
  A fathom proof verdict enters that machinery as one more
  host-computed evidence object — produced by a deterministic
  server-side check, not by the reviewer's reading.
- **`decide()`.** Phlow's approval crate decides a
  `Scope { tool, risk, paths, endpoints }` under a versioned,
  fail-closed policy: the most restrictive matching rule wins
  (`deny` > `approval` > `allow`), a missing policy denies
  everything, and the decision carries its scope unchanged.
  An `approval` verdict routes to the operator approval
  queue. §4.1.8 maps proof verdicts onto this flow; the
  mapping is the consumer contract, and phlow-side policy
  remains phlow's.
- **Payload bound.** Phlow caps a tool result at 40,000
  characters. Proof responses are summary-by-default in S1's
  spirit (§4.1.5, §4.1.7) so a maximal proof's verdict still
  fits that cap.

### 4.1.4 Claim model

Seven classes, each grounded in finding kinds fathom
already emits and in what phlow's RE runs actually assert. A claim
class not in this table is refused at parse time (§4.1.7);
the table grows by SPEC amendment, not by caller invention.

| Class | The assertion | Evidence it binds | Confidence |
| --- | --- | --- | --- |
| `archive_entry` | An entry with the stated per-format fields exists in the named archive container | One entry record from the matching `*_entries` inventory of the retained `archive_census` export (game-archive readers amendment, 2026-10-27) | `observed` |
| `artifact_classification` | The subject is of format/layout F, with stated properties | `inspect_artifact` / `inspect_binary_layout` findings | `observed` |
| `call_relationship` | Function A calls / is called by / references B | `call_graph` and `references_to` findings of `analyze_function` | `derived` |
| `coverage` | The run examined N of M inventory items; the retained inventory is or is not exhaustive, as stated | The envelope `coverage` block and retained-inventory counts of the cited list reads | `observed` |
| `function_identity` | A function exists at address A with the stated name, signature, classification | `function` findings (`binary_overview`, `analyze_function`) | `observed` |
| `function_purpose` | Function A serves purpose P, stated as structured facts (e.g. callees it orchestrates, strings it consumes, classification it refines) | The dossier spans (listing / decompile) and findings the purpose rests on | `inferred` |
| `string_assertion` | A string/data item with stated content exists at a stated location | `list_strings` inventories (defined strings `observed`, data strings `derived`) | as cited |

Rules:

- **Statements are facts, not prose.** A claim's statement is
  a JSON object in the shape of the finding facts it cites.
  The verifier checks the claim field-by-field against the
  bound record (§4.1.7, rule 6); extra record fields are not
  the claim's business, and a statement key the record does
  not carry is a contradiction, not an omission.
- **Confidence is the claim's ceiling, set at build.**
  `function_purpose` is `inferred` by construction; the
  class table fixes each class's confidence, and a build
  request asserting a higher one is refused. Verification
  never raises confidence (§4.1.7, rule 7).
- **`coverage` is gate-critical.** It is the class that
  stops a proof from claiming beyond the retained ceiling:
  a reconstruction whose coverage claim is unverified is a
  reconstruction over a partially seen program, and
  §4.1.8's mapping treats that verdict accordingly.
- Claims are authored by the caller (phlow's coder, from the
  findings it gathered). The server never invents claim
  statements; it binds, digests, and checks them. Whether
  authorship should be narrowed further is §4.1.13, Q1.

### 4.1.5 Proof object

Canonical JSON, digested by §6's existing rule (SHA-256 over
the canonical — compact, key-sorted — form, as
`bundle_digest` computes for evidence bundles). Fields,
alphabetical as the codebase keeps them:

```json
{
  "claims": [
    {
      "claim_id": "c1",
      "class": "function_identity",
      "confidence": "observed",
      "evidence": [
        { "inventory": "functions",
          "key": "0x1a40",
          "record_digest": "<sha256 of the canonical record>" }
      ],
      "statement": { "name": "...", "signature": "..." }
    }
  ],
  "export": { "digest": "<sha256 of the retained export document>",
              "mode": "overview" },
  "producer": { "catalog_digest": "...", "provider": "ghidra",
                "server": "fathom", "source_revision": "...",
                "version": "..." },
  "proof_digest": "<sha256, over the canonical form sans this field and proof_id>",
  "proof_id": "<server-assigned>",
  "proof_version": 1,
  "subject": { "path": "...", "sha256": "...", "size_bytes": 0 }
}
```

Binding rules:

- **Subject.** The §6 `Subject` shape, byte-identical in
  meaning: SHA-256 of the exact bytes analyzed. Verification
  re-hashes the presented target (§4.1.7, rule 3).
- **Export.** The digest of the one retained export document
  every evidence reference resolves into, plus its mode.
  Evidence references are `(inventory, key)` locators into
  that document — the same inventories S1's paged reads serve
  (`functions`, `names`, `strings`, and the per-function
  dossier) — each carrying the `record_digest` the **server**
  computed at build time over the referenced record's
  canonical form. Callers supply locators only, never
  digests: a digest the caller computed proves nothing, which
  is the host-computed-evidence principle applied on this
  side of the wire.
- **Producer.** Server name and version, catalog digest,
  and the build-time embedded source revision (exactly what
  `session_info` reports), plus the provider name. This is
  the implementation binding (§4.1.13, Q3: the source
  revision joins version + catalog digest). It carries no
  provider *version*: the port has no provider-version
  probe, and §4.1.7 rule 5 governs drift against the three
  fields carried.
- **No outcomes in the proof.** Outcomes are the verifier's
  output, recorded in the verification envelope (§4.1.8),
  never asserted by the producer and never stored as part of
  the proof. A stored proof is claims + bindings + digest;
  verification is a pure function of (proof, subject file,
  retained store). This keeps the stateless per-call design
  of §4: any fathom instance with the same store can verify
  any proof, and a "verified" mark can never be replayed
  from storage without the check being re-run.
- **`proof_version`** is an integer, versioned like the
  consumer's policy schema: an unknown version is refused,
  never defaulted or migrated silently.

### 4.1.6 Per-claim outcomes

Verification assigns exactly one outcome per claim:

- `verified` — every evidence reference resolved in the
  bound export, every record digest matched, and the record
  states what the claim states, at the claim's confidence.
- `failed` — the evidence resolved and contradicts the
  claim: a record digest mismatch, a statement field the
  record contradicts or does not carry, an unbound claim
  (§4.1.7, rule 2), or a `coverage` claim asserting
  exhaustiveness the retained inventory does not support.
- `inapplicable` — the claim class does not apply to this
  subject or provider (e.g. a managed-lane claim against a
  native subject). Inapplicability is a fact about fit, not
  a defect; it is reported, never folded into `failed`.
- `unavailable` — the evidence could not be resolved from
  the retained store: the bound export is absent (evicted,
  or never retained on this host), the referenced record is
  beyond the retained ceiling of a truncated inventory, or
  the producer binding drifted and the bound export is not
  the one on disk. Unavailable is a downgrade with a stated
  reason — never a silent pass, never a failure of the
  claim.

Each outcome carries a bounded diagnostic string (§4.1.9).
The aggregate verdict derives mechanically (§4.1.8); no
outcome is ever upgraded by aggregation.

### 4.1.7 Verification rules

In order; the first failing rule decides. Parse and shape
checks run **before** any file or store access — S1's
parse-before-the-seam convention, so a malformed proof is
refused before any work and the refusal is provably cheap.

1. **Shape.** Unknown `proof_version`, unknown claim class,
   duplicate `claim_id`s, a claim count or byte size over
   §4.1.9's bounds, or a non-object statement →
   `invalid_request` (category `invalid_input`), naming the
   offending field.
2. **Bound evidence, or the claim fails.** A claim whose
   evidence array is empty, or whose references are bare
   identifiers without a server-computed `record_digest`
   and a resolvable `(inventory, key)` locator, is `failed`
   with the diagnostic class `unbound_evidence`. An
   ID-array-only proof therefore verifies nothing: every
   such claim fails and the aggregate is `failed`
   (§4.1.8). This rule is the contract's center; §4.1.11
   test 1 exists for it.
3. **Pairing.** The proof's own `proof_digest` is recomputed
   first; a mismatch is refused as
   `evidence_integrity_mismatch` (`integrity_mismatch`). The
   presented target is then re-hashed; if it does not hash
   to `subject.sha256`, the request is refused with
   `evidence_integrity_mismatch` naming both digests — the
   §6 bundle rule ("a valid evidence ID alone does not
   establish that subject identities agree") applied to
   proofs. A proof replayed against a different subject
   therefore does not verify; it does not reach claim
   checking at all. A subject that changed since build is
   the same refusal (the `artifact_changed` situation,
   reported through the integrity code because the pairing,
   not the run, is what failed).
4. **Export binding.** The retained export for the subject
   is located by subject key (§4.1.10). If its digest is not
   the proof's bound `export.digest`, the on-disk export is
   not the evidence the proof cites: every claim's outcome
   is `unavailable` (reason: bound export not present), and
   no claim verifies. Verification never re-exports and
   never substitutes a fresher export silently.
5. **Producer drift.** If the bound export *is* present but
   the current server's version, catalog digest, or
   source revision differs from `producer`, verification proceeds against the bound
   export, the verification envelope carries a
   `revision_drift` limitation naming both bindings, and the
   aggregate is capped at `partial` (§4.1.8). Drift with the
   bound export absent is rule 4. A proof never verifies
   silently across an implementation change.
6. **Per-claim check.** Each reference resolves into the
   bound export; the record's canonical digest is recomputed
   and compared; the claim's statement is checked
   field-by-field against the record. Resolution beyond a
   truncated inventory's retained ceiling is `unavailable`,
   in S1's terms: a proof can never claim coverage beyond
   the retained ceiling, and a `coverage` claim that tries
   is `failed`, not `unavailable` — the export states its
   own retained/total counts, so the contradiction is
   checkable, not missing.
7. **Confidence ceiling.** A `verified` outcome certifies
   that the bound evidence exists, matches its digest, and
   states what the claim states — at the claim's class
   confidence. For an `inferred` `function_purpose` claim,
   verification certifies the cited observations, not the
   inference. Outcome records carry the confidence through,
   so no downstream reader can mistake a verified inference
   for an observed fact (§6's hard rule, enforced at this
   boundary too).

### 4.1.8 The reviewer-gate contract

Three tools join the §4 catalog. The two ledger tools are
class `read` (they compose and check stored state; the build
tool writes only inside the state dir, as
`export_evidence_bundle` does); the operator deletion verb
of §4.1.13 Q4 is class `execute`, default-deny unless named
in the allowlist (§8):

| Tool | Class | Provider | Status |
| --- | --- | --- | --- |
| `build_reconstruction_obligation_ledger` | read | core | built |
| `delete_reconstruction_proof` | execute | core | built |
| `verify_reconstruction_proof` | read | core | built |

**Build.** Input: `{target, claims: [{claim_id, class,
statement, evidence: [{inventory, key}]}]}`. An optional
`function` argument selects the subject's per-function
dossier export instead of the overview export, mirroring
`analyze_function`. The server
resolves each locator against the subject's retained export
(running the §9.1 export path first if none exists — build
is the composition point, and this is the only one of the
two tools that may run a provider), computes record
digests, binds subject, export, and producer, stores the
proof (§4.1.10), and returns a **summary view**: `proof_id`,
subject identity, claim count by class, and per-claim
binding status (`bound` / refused with reason). A claim
whose locator does not resolve at build is refused with
`invalid_request` naming the claim — build-time honesty,
so an unbound claim is never stored as if bound. (A forged
proof arriving at verify is still rule 2's problem; build
refusing is not what makes verify safe.) `detail:
"complete"` returns the stored proof body; evidence
*payloads* are never in either view — they stay in the
retained export, reachable through S1's views.

**Verify.** Input: `{target, proof_id}` or `{target,
proof}` (inline, bounded by §4.1.9), plus an optional
`claim_ids` subset and the `detail` parameter on the same
terms as S1. Output: a §6 evidence envelope whose findings
are one outcome record per claim (`kind:
"claim_outcome"`, facts: claim_id, class, confidence,
outcome, diagnostic) and whose headline finding is the
aggregate verdict block:

```json
{ "aggregate": "verified | partial | failed",
  "bound_export": "present | absent",
  "claims": { "verified": 0, "failed": 0,
              "inapplicable": 0, "unavailable": 0 },
  "gate_critical_unverified": ["<claim_id>", "..."],
  "revision_drift": false }
```

Aggregate derivation, mechanical and total:

- `failed` — at least one claim `failed`.
- `partial` — no claim `failed`, and at least one claim
  `unavailable`, or `revision_drift` is true.
- `verified` — every claim `verified` or `inapplicable`,
  at least one claim `verified`, no drift.
- A set in which no claim verified and none failed (every
  claim `inapplicable`) is `partial`: nothing was
  established, and nothing failed.
- Refusals (§4.1.7 rules 1 and 3) return the §7 error
  envelope instead of an aggregate; there is no aggregate
  for a proof that was never checked.

**Delete.** Input: `{target, proof_id}`. Removes the one
stored proof file for the subject; a missing proof is
`invalid_request`, never a silent success. Retention is
otherwise indefinite (§4.1.13, Q4): no eviction, and the
per-subject cap refuses new builds rather than evicting.

**Mapping onto phlow's flow** (the consumer contract;
phlow's policy files remain phlow's to write):

- The verify envelope is host-computed evidence in phlow's
  run report, beside its checks and coverage gate. The
  reviewer reads it; the reviewer's own approval is never
  the evidence.
- A downstream step whose justification is a reconstruction
  presents its `Scope` to `decide()` with the proof's
  aggregate attached to the request, and the recommended
  policy posture is: `verified` — eligible for an `allow`
  rule; `partial` — at best `approval` (a human decides,
  with the per-claim outcomes in front of them); `failed`,
  refused, or no proof — `deny` for any step that would act
  on the reconstruction as if established. Escalation *is*
  the `approval` verdict: it routes to phlow's operator
  approval queue unchanged.
- Verdicts are bound to `(subject.sha256, export.digest)`.
  If either drifts between review and a later execute-class
  step — the situation phlow's runtime already names
  `"stale"` — the verdict is stale on its face and the step
  re-verifies or stops. Fathom's side of that promise is
  rules 3–5: drift can never produce a silent `verified`.

### 4.1.9 Bounds

Named constants for `crates/fathom-core/src/limits.rs`,
alphabetical, in the file's doc style; every one is checked
before the costly step, and a hit is `resource_constraint`
or a reported outcome — never an unbounded retry (§8).

| Constant | Value | Bounds |
| --- | --- | --- |
| `PROOF_BYTES_MAX` | 1,048,576 | Serialized bytes of one proof, stored or inline. Proofs ride MCP payloads; the ceiling keeps one proof inside the class of DECOMPILE_BYTES_MAX, and the summary views keep ordinary traffic far below the consumer's 40,000-char tool-result cap. |
| `PROOF_CLAIMS_MAX` | 256 | Claims in one proof. At this count the summary verify view (one terse outcome record per claim) still fits the consumer's tool-result cap. |
| `PROOF_DIAGNOSTIC_CHARS_MAX` | 512 | Characters of one per-claim diagnostic. |
| `PROOF_EVIDENCE_PER_CLAIM_MAX` | 32 | Evidence references bound to one claim. |
| `PROOF_PER_SUBJECT_MAX` | 64 | Proofs stored for one subject; a build past the cap is `resource_constraint`, never a silent eviction of an older proof. |
| `PROOF_STATEMENT_BYTES_MAX` | 16,384 | Canonical bytes of one claim's statement facts. |

Verification cost is bounded by construction: it reads the
subject file (already capped by `TARGET_BYTES_MAX`), the
bound export, and the proof. It spawns no process and is
subject to no provider timeout because there is no provider.

### 4.1.10 Persistence and interaction

- **Store.** Proofs live in the state dir (§8) under
  `state_subdir("proofs")/<subject sha256 prefix>/`, the
  same subject keying as the §9.1 Ghidra cache (`ghidra/`
  sibling), one file per proof, named by `proof_id`. The
  ledger for a subject is the directory's contents; there
  is no second index to keep honest.
- **Lifetime follows the export, honestly.** A proof whose
  bound export is evicted does not break and does not
  silently rebind: it verifies to `unavailable` outcomes
  (rule 4) until an export with the bound digest is present
  again. Eviction policy for proofs themselves is §4.1.13, Q4.
- **S1 views.** Claims cite the same retained export the
  summary/complete views project; the views and the proof
  are three reads of one store, and a claim's evidence can
  always be inspected by a human through `analyze_function`
  / the paged list reads at the cited locator. The summary
  view's projection limitations and the proof's diagnostics
  use the same wording discipline: a reduced or missing
  payload states itself.
- **Evidence bundles.** A proof is an ordinary result for
  packaging purposes: `export_evidence_bundle` may include
  one, and the bundle digest then covers it. The two
  verifiers stay distinct — `verify_evidence_bundle` checks
  packaging integrity and subject agreement of a bundle;
  `verify_reconstruction_proof` checks claim-to-evidence
  binding. Neither substitutes for the other.

### 4.1.11 Adversarial test obligations

The build stage is not done until each of these passes, at
the repo's ~50/50 validation/adversarial split (AGENTS.md).
They are stated here, before implementation, because
several of them are the design (rules 2, 3, and 6 exist so
these tests can pass):

1. **ID-array-only proof must NOT verify.** A proof whose
   claims cite bare identifiers — no locators, no
   server-computed record digests — yields `failed` on
   every such claim and aggregate `failed`, against a
   subject and export that would verify a properly bound
   proof.
2. **Replay across subjects must NOT verify.** A proof
   built for subject A, presented against subject B (one
   byte different), is refused under rule 3; no claim is
   checked and no aggregate is emitted.
3. **Tamper must NOT verify.** Mutating a claim statement,
   a record digest, or the subject path inside a stored
   proof breaks `proof_digest` and is refused; mutating
   the retained export's cited record (statement intact,
   export re-digested honestly is impossible without the
   record digest changing) yields that claim `failed`.
4. **Truncated evidence downgrades, never verifies.** A
   claim citing a record beyond a truncated inventory's
   retained ceiling is `unavailable`, aggregate at most
   `partial`; a `coverage` claim asserting exhaustiveness
   over that inventory is `failed`.
5. **Revision drift never silently verifies.** With the
   bound export present and the server's version/catalog
   changed, outcomes are computed but the aggregate is
   capped at `partial` and the envelope carries the drift
   limitation; with the bound export absent, all claims
   are `unavailable`.
6. **Malformed proofs are refused before work.**
   Duplicate claim IDs, an unknown class, an unknown
   `proof_version`, an oversized proof — all
   `invalid_request` with no subject file read and no
   store access (asserted by running against an empty
   state dir and a nonexistent target).
7. **Verify spawns nothing.** Against an empty state dir,
   verify returns `unavailable` outcomes and creates no
   Ghidra project, no export, and no child process.
8. **Confidence is never upgraded.** An `inferred`
   `function_purpose` claim with fully bound, matching
   evidence verifies — and its outcome record and the
   aggregate block still carry `inferred`; no field
   anywhere in the envelope presents it as `observed`.
9. **Bounds hold under attack.** `PROOF_CLAIMS_MAX + 1`
   claims, a statement at `PROOF_STATEMENT_BYTES_MAX + 1`,
   and a proof at `PROOF_BYTES_MAX + 1` are refused or
   outcome-reported per §4.1.9 — never a panic, a partial
   parse, or a truncated-but-accepted proof.
10. **The honest path verifies.** A proof built by the
    build tool over a seeded retained export verifies
    end-to-end: aggregate `verified`, per-claim outcomes
    present, and the summary verify view contains no
    evidence payload bytes (the S1 no-payload-leak rule,
    applied to outcomes).

### 4.1.12 What this section does not build

- No session binding (§4's stateless design stands; proofs
  are how state crosses calls, explicitly).
- No proof of *absence* class in v1: "no function does X"
  is a coverage-shaped assertion the retained store cannot
  currently discharge honestly; it waits for a SPEC
  amendment with its own evidence rule.
- No cross-host proof portability guarantees: a proof
  verifies where its bound export is retained (§4.1.13, Q5).
- No changes to the §10 compact input-schema profile; the
  two new tools' schemas are complete, like the rest of the
  catalog.

### 4.1.13 Decisions (Owner, 2026-10-27 — D-092)

The draft of this section carried five open questions; the
Owner decided all five, adopting the recommendations as
presented:

- **Q1 — Claim authorship: as specced.** Phlow's coder
  authors claim statements; the server binds and checks
  them. The check is the gate. Server-minted-only claims
  are not required in v1.
- **Q2 — Gate-critical classes: `coverage` alone.**
  `function_purpose` is NOT gate-critical by default.
  `coverage` alone carries the gate; purpose outcomes
  remain visible in the verdict block without driving the
  `approval` mapping.
- **Q3 — Revision binding: embedded source revision.**
  Fathom gains a build-time embedded source revision,
  which joins the producer binding (version + catalog
  digest + source revision).
- **Q4 — Proof retention: indefinite, deletion verb in
  scope.** No eviction in v1 (per-subject cap stands); an
  operator deletion verb IS in v1 scope
  (`delete_reconstruction_proof`, §4.1.8).
- **Q5 — Portability: phlow-only v1, self-describing
  serialization.** No second reader in the first build;
  the serialization stays self-describing so a second
  reader later is an addition, not a migration.


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
| MCP transport | rmcp 3.5.1 (official Rust SDK); hand-rolled JSON-RPC | **Hand-roll** (original verdict). The wire surface fathom needs (initialize, tools/list, tools/call, ping over stdio + one HTTP POST route) is small; hand-rolling keeps the transport auditable and immune to SDK churn. Trade-off named: protocol upgrades are our work. **Superseded 2026-10-27 (D-113, fleet standardization WS2 W3): adopt rmcp 3.8.0, modern era (2026-07-28) only.** The registry, policy, and every tool handler are unchanged; a byte-level era guard owns stdio framing (the baseline's error texts, the designed `-32022` legacy refusal, a 4 MiB line bound), rmcp owns the envelope behind it, and streamable HTTP carries the same handler with legacy sessions off. Parity against the hand-rolled baseline is recorded in the WS2 W3 gate report. |
| A2A card | a2a 0.1.0 (985 downloads, placeholder); hand-rolled per estate pattern | **Hand-roll**, following the volta/vongola pattern: JCS-canonicalized card, Ed25519 signature. |
| JCS canonicalization | serde_jcs 0.2.0; hand-rolled RFC 8785 | **Hand-roll** with the RFC 8785 test vectors as unit tests; one less dependency for ~100 lines with a public test suite. |
| .NET metadata | pelite (PE only, no CLI tables); a dedicated ECMA-335 crate (none mature found) | **Manual ECMA-335 parsing** over goblin's PE headers: metadata root, streams, table row geometry, TypeDef/MethodDef/ImplMap reads. The format is a published standard (ECMA-335); the parser is bounded and testable against fixtures. |
| ASAR | @electron/asar (JS); the format itself | **Implement directly.** ASAR is a pickle-framed JSON header plus concatenated payloads; a reader is ~150 lines and is cross-validated against archives produced by the real `@electron/asar`. |
| LZ4 block (Unity) | lz4_flex (pure Rust); lz4-sys (FFI) | **Adopt lz4_flex** for `fathom-native` (game-archive readers, 2026-10-27). Pure-Rust block-format decoder matching Unity's raw-block usage; no FFI. The frame format is not used. |
| LZMA | xz2 (FFI); pure-Rust decoders (unaudited) | **Do not adopt.** LZMA-compressed Unity metadata is reported, not decoded. Revisit only with a named consumer whose bundles are LZMA. |
| Pickle (Ren'Py index) | serde-pickle and general unpicklers | **Hand-roll a restricted interpreter** (game-archive readers SPEC §5.4): an allowlist of data-only opcodes over a closed value domain. A general unpickler is an execution surface — pickle from an untrusted archive is never deserialised by one. |
| SHA-1 (Unreal pak anchors) | sha1 0.11 (RustCrypto); hand-rolled | **Adopt sha1 0.11** as a workspace dependency for `fathom-native`. The tree already trusts this family (`sha2` 0.11); hand-rolling a second hash invites divergence. |
| Zlib (RPA index; pak blocks) | flate2 (already a workspace dependency) | **Reuse flate2** — add to `fathom-native`'s manifest. Already adopted and locked; decompression is always bounded-output. |
| Godot PCK | the format itself (Godot engine reader layout) | **Implement directly.** GDPC header + directory parse for format versions 1–3; every readable entry is SHA-256-hashed and cross-checked against the MD5 the directory declares (hand-rolled RFC 1321 implementation, public test vectors). Decryption is NOT-IMPLEMENTED: encrypted directories and entries are reported as unknowns, never skipped. |
| Python .pyc + PyInstaller (S5) | the formats themselves (PEP 552; CPython marshal; PyInstaller CArchive/PYZ) | **Implement directly.** .pyc: header facts plus the code-object tree via a bounded hand-rolled marshal reader (marshal writes code-object scalars as raw i32s — readers that treat them as tagged values desynchronise; the reader is field-kind-aware per version layout, 2.7/3.0–3.7/3.8–3.10/3.11–3.13, unknown magics refused by name). PyInstaller: cookie located at EOF or by bounded tail scan, TOC census with stored-byte SHA-256, nested PYZ module census (both TOC shapes read: dict and list-of-pairs). Fixtures are genuine: a CPython 3.12-compiled module and an archive written by PyInstaller 6.22's own writers. Instruction decode is NOT-IMPLEMENTED. |
| BEAM (S6) | the format itself (IFF/ERTS beam file format) | **Implement directly.** Chunk inventory; Atom/AtU8 atom table; ImpT/ExpT/LocT/FunT function tables resolved through the atom table (unresolved indexes are kept rows, never dropped); Code header cross-checked against the tables; LitT decompressed and walked with a bounded external-term reader (atoms censused, terms counted, never materialised). Opcode-stream decode is NOT-IMPLEMENTED: opcode tables are instruction-set-versioned and a wrong table would fabricate facts. |
| GPU code objects (S7) | the formats themselves (ELF/AMDGPU ABI; Clang offload bundle) | **Implement directly** over goblin's ELF reader. Standalone AMDGPU code objects (target from e_flags, kernel symbols + `.kd` descriptor presence, NT_AMDGPU_METADATA note decoded with a bounded hand-rolled MessagePack reader; YAML v2 metadata reduced to kernel names), standalone offload bundles, and host binaries with bundles embedded (bounded magic scan). GPU ISA disassembly is NOT-IMPLEMENTED. |
| NativeAOT (S8) | the PE format + NativeAOT runtime traces | **Screen, honestly labelled.** No ECMA-335 metadata exists to parse: classification is marker-derived (≥2 distinct System.Private.* component strings plus a runtime-helper export or a third component; Derived confidence), with section/export inventories and a dotted-string census. The NativeFormat metadata graph reader is NOT-IMPLEMENTED, gated on a real NativeAOT fixture (no .NET SDK exists on estate machines to produce one). |
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
  max ASAR entries, max PCK entries. A bound hit is
  `resource_constraint` or a reported truncation — never an
  unbounded retry.
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
- **MCP stdio**: newline-delimited JSON-RPC via rmcp behind a
  byte-level era guard (modern era only, 2026-07-28, since the
  2026-10-27 D-113 migration); sessions open with
  `server/discover`, legacy `initialize` is refused `-32022`,
  and the guard preserves the hand-rolled baseline's framing
  error texts. Advertised schemas are complete; the compact
  input-schema profile upstream added for size-capped clients
  is NOT-IMPLEMENTED (named, with its 13,312-byte budget
  recorded for when it is built).
- **MCP streamable HTTP**: `POST /mcp` served by rmcp's
  streamable-HTTP service with the same handler, loopback by
  default; legacy session mode off and modern per-request
  protocol metadata required. Stateless per request, matching
  the stateless tool design.
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
