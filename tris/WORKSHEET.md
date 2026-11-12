# Fathom (version 1.0.0) — TRIS form-input worksheet

The requestor's working worksheet for this product's TRIS form (Technology Request Information Sheet): every requestor-facing field, pre-filled from the submission evidence wherever the evidence supports a value. Anything only the requestor can supply is marked **[INPUT NEEDED: …]** — nothing here is invented. Numbers in parentheses are the TRIS template's row numbers, so each line can be checked against the form and against [CHECKLIST.md](CHECKLIST.md).

This is one product's slice of the combined six-product submission worksheet prepared 2026-11-11 (ONTrack, LightShow, Fathom, Versemend, the Salesforce MCP integration, and Niflheim were submitted together in one email). IT reviewer fields (template rows 66–91) need no requestor input and are not listed here.

## Shared submitter fields (rows 3–6, repeated on all six forms)

- Requestor (3): Matt A. Porter — Field Service Technician (FST), matthew.porter@tdstelecom.com
- Requestor's Manager (4): Josh Barter
- PAT Manager (5): [INPUT NEEDED: PAT Manager name — note: the process document names an Internal Employee Tools PAT contact as the AIR-access contact; that is not evidence he is the PAT Manager for this request]
- CoE Director (6): [INPUT NEEDED: CoE Director for the accountable Agile team — if left blank, the TRIS Administrator determines the accountable team, AM, and AD per the process document]

## Shared vendor fields (rows 10, 11, 42, plus the shared open-source fact at row 46)

Applies to the five Qompass AI products. The Salesforce integration's vendor is Salesforce; its vendor fields are in its own block below.

- Vendor Name (10): Qompass AI (the requestor's company; he is the developer/vendor)
- Website (11): qompass.ai
- What are the company's financial resources? (42): [INPUT NEEDED: the vendor financial-resources statement you want on record for Qompass AI — no figures exist in the package evidence]
- Has the governing Open Source license previously been reviewed by legal? (46, asked on every form): [INPUT NEEDED: whether Apache-2.0 has previously been reviewed by TDS legal — if not, this answer triggers legal review on each form]

## Product answers

- Technology Name (8): Fathom
- Technology Version (9): 1.0.0 (release dated 2026-10-29)
- Website (11): qompass.ai — product page: https://qompass.ai/solutions/mcp/fathom/
- Description (14): A clean-room reverse-engineering capability delivered as an MCP server: analysts point it at a binary, application package, or capture and receive structured, evidence-labelled findings — what was observed, what was derived, what was not examined, and what the provider cannot establish. Rust workspace (policy/evidence engine, Ghidra headless provider, native/JS/.NET/process-observation providers), built on a deterministic, fail-closed policy engine.
- How used at TDS (15): Defensive reverse engineering by security engineering / technical staff: vendor-software assurance, firmware and field-tooling analysis, malware triage support, incident response.
- Who will use it (16): Developers and security engineering staff (analysts) — a small, named user group. Not field services at large, not end customers.
- Technology replaced/removed (17): Nothing approved is removed. It replaces ad-hoc, unrecorded analysis (individual tool installs, personal scripts) with one governed, evidence-producing capability.
- Direct customer impact (18): No — an internal analysis tool. Its findings may inform decisions about customer-facing systems, but it does not touch them in operation.
- Supported internally or by vendor (19): Internally — by the developer (the requestor / Qompass AI). No external support contract.
- Production or test/development (20): [INPUT NEEDED: confirm the wording — requested as internal production *use* as an analysis tool (it runs during real security work, but no TDS production system depends on it)]
- Impact if discontinued (21): Analysts return to manual/ad-hoc tooling; no TDS system depends on Fathom. Findings already produced remain as documents.
- Backout plan/cost (22): Remove the binary and its local data directory. Analyses are files the analysts keep; nothing migrates. Cost: time to uninstall; replacement is the prior ad-hoc tooling.
- Similar technologies at TDS (23): [INPUT NEEDED: whether TDS already has Ghidra or commercial RE tooling (IDA-class) approved/in use — Ghidra is the obvious related technology; Fathom itself uses a Ghidra headless provider, and its distinct value is the governed MCP interface and evidence envelopes, not raw disassembly]
- Alternatives considered (24): [INPUT NEEDED: confirm the alternatives statement — candidates from the design record: Ghidra used directly (free, NSA); adapting an existing open RE agent (REA — Fathom maps its public contracts under its repo NOTICE and uses no upstream code)]
- AI component (26): Answer as YES-adjacent: Fathom is an MCP server — a tool built to be *called by* AI assistants/agents. It bundles no model of its own, but its purpose is AI-driven analysis workflows, so AI Policy 710 is treated as applicable. [INPUT NEEDED: confirm the final Yes/No wording as the reviewers will read it]
- Requested scope — confirm before submitting: [INPUT NEEDED: confirm (a) local, stdio-transport deployment only, with the codebase's streamable-HTTP transport excluded unless Security Engineering separately approves it; (b) whether the Ghidra headless provider is in scope — it carries a JDK requirement (row 33); (c) the approved artifact classes for TDS use (e.g., vendor binaries, firmware images, malware samples in a lab); (d) no telemetry in the submitted build]
- Internet access (28): No internet access required in the requested local/stdio scope. (Model providers, if an AI client calls one, are the client's concern and outside this request.)
- Hosted internal/external (29): Internal — runs on the analyst's workstation inside the Enterprise network. No vendor-site hosting; no data processed or stored at any vendor site.
- Uploads data outside the Enterprise network (30): No, in the requested scope — the tool analyzes local files and returns results to the local client.
- Inbound access to the Enterprise network (31): No — stdio transport is a local process channel. (The HTTP transport is out of scope; see the scope confirmation above.)
- Data collected (32): Exactly what an analyst points it at: binary files, application packages, web captures (HAR), and process-behavior observations, processed locally. It does not sweep systems, applications, or network elements on its own. (Approved artifact classes: see the scope confirmation above.)
- Java required (33): No Java requirement for Fathom itself (Rust binary). If the Ghidra provider is enabled, Ghidra requires a JDK on the workstation.
- Microsoft 365 integration (34): No.
- Security risk assessment required (35): Yes — required, and requested. Fathom is a dual-use analysis capability and the checklist is written to make that assessment easy.
- Cardholder/banking data (36): No. (Use conditions should bar pointing it at artifacts containing such data.)
- How licensed (38): Open Source — Apache License 2.0 (repo LICENSE; Cargo.toml license = "Apache-2.0").
- License model (39): No per-user/concurrent/server license model; no license-control software.
- License fees and quantity (40): No fees. Quantity: one install per analyst workstation in the named user group.
- Support/maintenance fees (41): None — support is internal (row 19).
- How long around (43): Current release 1.0.0 dated 2026-10-29; in active development through 2026.
- Governing License (45): Apache License 2.0. Design provenance is declared in the repo NOTICE (capability contracts mapped from a public MIT-licensed design; no upstream code used).
- License previously reviewed by legal (46): See the shared vendor block.
- Distributed / external use (47): Yes — the software is publicly distributed as open source (public repo/release); per the template's wording this is answered Yes and legal review is triggered. Declared openly.
- Modified by TDS (48): No modification by TDS planned.
- Directly impacts a product or service provided to customers (49): No — an internal analysis tool. Its findings may inform assurance decisions about such products, which is analysis, not operation.
- Mobile — developer (51): Third party — the requestor (Matt A. Porter) as a Qompass AI product. (The Mobile section is largely not applicable: Fathom is a workstation tool, not a mobile app.)
- Mobile — store certification (52): Not applicable — not distributed through Apple/Google app stores; a workstation MCP server distributed as open source.
- Mobile — platforms (53): MS Windows and Linux workstations (Rust binary). Not a mobile platform application.
- Mobile — TDS fee / required for a TDS service (54): No fee; not required to use any TDS service.
- Mobile — confidential information (55): It processes whatever artifacts analysts submit, which can include proprietary vendor binaries and, in a lab context, malware samples. It processes no TDS confidential information by design, but artifacts under analysis may themselves be confidential — artifact-handling conditions belong in the approval (see the scope confirmation above).
- Mobile — third-party code (56): Yes — open-source Rust crates per the workspace Cargo.lock, plus the optional Ghidra provider (Ghidra is NSA open source, Apache-2.0). The open-source section above is completed. A full SBOM can be generated from Cargo.lock on request.
- Mobile — user data collection language (57): Fathom collects no user data of its own — no accounts, no telemetry (telemetry confirmed via the scope confirmation above). It processes analyst-supplied artifacts locally (row 32).
- Mobile — development tools/SDKs (58): Rust toolchain. No Apple/Google mobile SDK code (not a mobile app).
- Mobile — in-app purchase (59) / Apple push (60) / Game Center (61) / iCloud (62) / Passes (63) / Apple Maps (64): No.

---
*Worksheet slice prepared 2026-11-11 from the TRIS template and process documents and the submission package evidence. DRAFT — not yet submitted. See [README.md](README.md) for the status summary and the public-copy notes.*
