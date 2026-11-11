# Fathom — TRIS submission checklist

One line per requirement on the TRIS form (Technology Request Information Sheet) for this product's submission.

**Where each answer is entered.** Every requestor answer is entered on the TRIS form itself, in the section named in each heading below; row numbers are the TRIS template's. Under the TRIS Approval Process: the Requestor completes the form (step 1) and sends it to DLT-IT TRIS Request (step 2); the TRIS Administrator verifies completeness and routes it for initial approvals — IT Solution Architecture, Data Management, and Security Engineering — and then to the IT & DM&S Leadership Team; after full approval the Administrator creates the AIR entry and sends the final communication, and the Requestor submits a Procurement Engagement Request (PER).

**Status key.** **Completed** — the answer is in [WORKSHEET.md](WORKSHEET.md) or the cited evidence in this folder. **Pending** — waiting on the exact input named on the line; nothing is guessed. **IT** — a reviewer field (template rows 66–91), completed by IT; no requestor input.

**Scope.** The requested deployment is local and analyst-run: stdio transport, on the analyst's workstation, inside the Enterprise network. The codebase's streamable-HTTP transport is not part of this request unless Security Engineering separately approves it. Several answers below are written for that scope and cross-refer to the scope confirmation.

## Before submission

- [ ] **Requested-scope confirmation.** Pending — input needed: confirm (a) local, stdio-transport deployment only, with the codebase's streamable-HTTP transport excluded unless Security Engineering separately approves it; (b) whether the Ghidra headless provider is in scope (it carries a JDK requirement — row 33); (c) the approved artifact classes for TDS use (e.g., vendor binaries, firmware images, malware samples in a lab); (d) no telemetry in the submitted build. Slot: [WORKSHEET.md](WORKSHEET.md), scope note in the product answers.

## General — TRIS form, General section

- [x] **Row 3 — Requestor.** Completed — [WORKSHEET.md](WORKSHEET.md) (shared submitter fields).
- [ ] **Row 4 — Requestor's Manager.** Pending — input needed: your manager's name. Slot: [WORKSHEET.md](WORKSHEET.md) (shared submitter fields).
- [ ] **Row 5 — PAT Manager.** Pending — input needed: PAT Manager name. Slot: [WORKSHEET.md](WORKSHEET.md) (shared submitter fields).
- [ ] **Row 6 — CoE Director.** Pending — input needed: CoE Director for the accountable Agile team (if left blank, the TRIS Administrator determines the accountable team, AM, and AD per the process document). Slot: [WORKSHEET.md](WORKSHEET.md) (shared submitter fields).
- [x] **Row 8 — Technology Name.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 9 — Technology Version.** Completed — 1.0.0 (release dated 2026-10-29). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 10 — Vendor Name.** Completed — [WORKSHEET.md](WORKSHEET.md) (shared vendor fields).
- [x] **Row 11 — Website.** Completed — [WORKSHEET.md](WORKSHEET.md) (shared vendor fields).

## Technology Details — TRIS form, Technology Details section

- [x] **Row 14 — Description.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 15 — How used at TDS.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers); business case: [BUSINESS-USE.md](BUSINESS-USE.md) and [RE-LANDSCAPE.md](RE-LANDSCAPE.md).
- [x] **Row 16 — Who will use it.** Completed — developers and security engineering staff (analysts); a small, named user group. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 17 — Technology replaced/removed.** Completed — nothing approved is removed; replaces ad-hoc, unrecorded analysis. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 18 — Direct customer impact.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 19 — Supported internally or by vendor.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [ ] **Row 20 — Production or test/development.** Pending — input needed: confirm the wording (requested as internal production *use* as an analysis tool — it runs during real security work, but no TDS production system depends on it). Slot: [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 21 — Impact if discontinued.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 22 — Backout plan/cost.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [ ] **Row 23 — Similar technologies at TDS.** Pending — input needed: whether TDS already has Ghidra or commercial RE tooling (IDA-class) approved or in use. Slot: [WORKSHEET.md](WORKSHEET.md) (product answers); landscape: [RE-LANDSCAPE.md](RE-LANDSCAPE.md).
- [ ] **Row 24 — Alternatives considered.** Pending — input needed: confirm the alternatives statement (candidates from the design record: Ghidra used directly; adapting an existing open RE agent). Slot: [WORKSHEET.md](WORKSHEET.md) (product answers).

## Technical Security — TRIS form, Technical Security section

- [ ] **Row 26 — AI component.** Pending — input needed: confirm the final Yes/No wording. The substantive answer is stated: Fathom is an MCP server built to be called by AI assistants, bundles no model of its own, and AI Policy 710 is treated as applicable. Slot: [WORKSHEET.md](WORKSHEET.md) (product answers).
- **Row 27 — See AI Policy 710.** Template instruction row; applies — see the row 26 answer.
- [x] **Row 28 — Internet access.** Completed — none required in the requested local/stdio scope (see the scope confirmation above). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 29 — Hosted internal/external.** Completed — internal, on the analyst's workstation. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 30 — Uploads data outside the Enterprise network.** Completed — no, in the requested scope. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 31 — Inbound access to the Enterprise network.** Completed — no; the HTTP transport is out of scope (see the scope confirmation above). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 32 — Data collected.** Completed — exactly what an analyst points it at; the approved artifact classes are scope-confirmation item (c). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 33 — Java required.** Completed — none for Fathom itself; a JDK is required only if the Ghidra provider is in scope (scope-confirmation item (b)). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 34 — Microsoft 365 integration.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 35 — Security risk assessment required.** Completed — yes; required and requested (dual-use capability; the checklist is written to make the assessment easy). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 36 — Cardholder/banking data.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).

## Licensing — TRIS form, Licensing section

- [x] **Row 38 — How licensed.** Completed — Apache License 2.0 (repo LICENSE). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 39 — License model.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 40 — License fees and quantity.** Completed — no fees; one install per analyst workstation in the named user group. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 41 — Support/maintenance fees.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [ ] **Row 42 — Company's financial resources.** Pending — input needed: the vendor financial-resources statement you want on record for Qompass AI. Slot: [WORKSHEET.md](WORKSHEET.md) (shared vendor fields).
- [x] **Row 43 — How long around.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).

## Open Source — TRIS form, Open Source section

- [x] **Row 45 — Governing License.** Completed — Apache License 2.0; design provenance declared in the repo NOTICE. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [ ] **Row 46 — License previously reviewed by legal.** Pending — input needed: whether Apache-2.0 has previously been reviewed by TDS legal (if not, this answer triggers legal review on each form). Slot: [WORKSHEET.md](WORKSHEET.md) (shared vendor fields).
- [x] **Row 47 — Distributed / external use.** Completed — yes, publicly distributed as open source; legal review triggered and declared. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 48 — Modified by TDS.** Completed — no modification planned. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 49 — Directly impacts a customer product/service.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).

## Mobile — TRIS form, Mobile section

- [x] **Row 51 — Developer.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers). (The Mobile section is largely not applicable: Fathom is a workstation tool, not a mobile app.)
- [x] **Row 52 — Store certification.** Completed — not applicable; not distributed through app stores. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 53 — Platforms.** Completed — MS Windows and Linux workstations. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 54 — TDS fee / required for a TDS service.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [ ] **Row 55 — Confidential information.** Pending — input needed: the artifact-handling conditions for artifacts under analysis (which may themselves be confidential), to be set with Security Engineering alongside the scope confirmation above. Slot: [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 56 — Third-party code.** Completed — open-source Rust crates plus the optional Ghidra provider (NSA, Apache-2.0); full SBOM generatable from Cargo.lock on request. [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 57 — User data collection language.** Completed — collects no user data of its own; the no-telemetry point is scope-confirmation item (d). [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Row 58 — Development tools/SDKs.** Completed — [WORKSHEET.md](WORKSHEET.md) (product answers).
- [x] **Rows 59–64 — Apple service rows** (in-app purchase, push notification, Game Center, iCloud, Passes, Maps). Completed — not a mobile app. [WORKSHEET.md](WORKSHEET.md) (product answers).

## Reviewer fields — TRIS form rows 66–91 (IT & DM&S use only; no requestor input)

- [ ] **Rows 68–70 — Security Engineering** (resource, review comments, recommendation). IT — completed by Security Engineering during initial approvals (process step: initial approvals, typically within 5 days).
- [ ] **Rows 72–74 — Data Management** (resource, review comments, recommendation). IT — completed by Data Management during initial approvals.
- [ ] **Rows 76–78 — Solution Architecture** (resource, review comments, recommendation). IT — completed by IT Solution Architecture during initial approvals.
- [ ] **Rows 81–89 — Leadership approvers.** IT — completed when the TRIS Administrator routes the request to the IT & DM&S Leadership Team (approval email carries Approve/Reject voting buttons, a link to the TRIS, and a 48-hour turnaround date).
- [ ] **Row 90 — Leadership review comments.** IT.
- [ ] **Row 91 — Leadership Team recommendation.** IT — on full approval the tracking entry moves to Completed, the Administrator creates the AIR entry and sends the final communication; the Requestor then submits the PER.

---
*Checklist prepared 2026-11-11 from the TRIS template and process documents and the submission package evidence. DRAFT — not submitted.*
