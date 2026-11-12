# Fathom — business use at TDS

**What it is.** A clean-room reverse-engineering capability built as an MCP (Model Context Protocol) server: Rust, version 1.0.0, Apache License 2.0. An analyst points it at a software artifact — a native binary, a JavaScript/Electron app, a .NET assembly, a web capture, a process-behavior trace — and gets back structured findings in an *evidence envelope*: what was observed, what was derived, what was not examined, and what the tool cannot establish. It is built on a deterministic, fail-closed policy engine, includes a Ghidra headless provider, and is designed the way the estate builds everything: Tiger Style — explicit contracts, bounded work, no hidden behavior. RE-LANDSCAPE.md in this folder makes the underlying case; this document covers the TDS uses.

**Who at TDS uses it.** Security Engineering and a small number of technical staff — analysts, not the general workforce, and not customers. It is a specialist instrument, and the request scopes it that way (see the CHECKLIST intro: local, stdio-transport deployment on analyst workstations).

**What work it changes.**

1. **Vendor software assurance.** TDS runs on other companies' software: OSS/BSS platforms, customer-premises equipment firmware, field tools, vendor agents. Today, assurance is mostly documentary — contracts, certifications, questionnaires. Fathom adds the missing empirical layer: take the actual binary the vendor shipped and check what it does — what it connects to, what it collects, whether the update changed behavior. The September 2025 joint CISA/NSA SBOM guidance (cited in RE-LANDSCAPE.md) asks the industry to know its software's ingredients; an SBOM lists components, but only binary analysis shows behavior. The two practices fit together, and Fathom is the behavior half.
2. **Incident response.** When an edge device or an appliance is compromised, the federal playbook is reverse engineering: CISA's analysis report on the RESURGE malware pulled from an Ivanti Connect Secure appliance at a critical-infrastructure organization is a worked example (cited in RE-LANDSCAPE.md). A telecom's network edge is the same class of target. Having the capability in-house, governed and rehearsed before an incident, is the difference between starting that work in hours and procuring it in weeks.
3. **Field and network tooling assurance.** The tools technicians and network staff run every day — vendor utilities, mobile apps, firmware updaters — execute with trusted access. Periodic in-house analysis of those artifacts is cheap insurance against a compromised or merely careless supplier, and it produces evidence, not vibes: every Fathom result states what was and was not established.
4. **Malware triage support.** Suspicious file on a workstation, a lab sample from a partner feed: a first-pass, evidence-labelled read before anything is escalated. Fathom does not replace a dedicated malware team or sandbox; it makes the first hour faster and the record cleaner.

**What it replaces.** No approved TDS tool is removed. It replaces the current default — ad-hoc analysis with personal tool installs and unrecorded results — with one governed capability whose outputs are documents a reviewer can check. Ghidra (free, from NSA) remains complementary; Fathom's distinct value is the controlled AI-agent interface, the policy engine, and the evidence model, not raw disassembly.

**Risk posture.** Stated without softening: reverse-engineering tooling is dual-use, and this request treats it that way.
- *Scope requested:* local deployment only — stdio transport, analyst workstations, inside the Enterprise network, no external calls, no inbound access. The codebase contains a streamable-HTTP transport; it is **excluded** from this request unless Security Engineering separately approves it.
- *Data touched:* only artifacts an analyst deliberately submits (binaries, packages, captures, traces). Those artifacts can themselves be sensitive — vendor-proprietary or, in a lab, malicious — so artifact-handling conditions belong in the approval, and the checklist (row 55) asks Security Engineering to set them.
- *AI component:* Fathom exists to be called by AI assistants; AI Policy 710 should be treated as applicable (checklist rows 26–27). It bundles no model of its own.
- *Assessment:* the checklist (row 35) requests a security risk assessment rather than arguing against one. A capability like this should enter the environment *through* that door.
- *Exit cost:* trivial — remove the binary; prior findings remain as ordinary documents (checklist rows 21–22).

**The honest limit.** Fathom will not make TDS un-hackable, and RE-LANDSCAPE.md does not claim it will. What it changes is visibility: the same techniques anyone can now apply to TDS's software estate, applied by TDS to its own estate first, under its own rules, with the evidence written down.

*Draft, 2026-11-10. Not submitted.*
