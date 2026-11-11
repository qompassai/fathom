# The reverse-engineering landscape: the new reality, and what TDS does about it

*Companion to the Fathom TRIS submission. Every source cited here was fetched and verified on 2026-11-10 (title, publisher, date, URL); verification notes follow the references.*

## The claim

Any company that ships or runs software can now be reverse engineered by anyone with modern tooling and moderate skill. That includes TDS: its customer-facing apps, its field-service tools, its customer-premises equipment, and the vendor software its network runs on. This is not a prediction and it is not a threat model with an exotic attacker in it. It is the current state of the tooling, most of it free, much of it published by the U.S. government itself. The defensive question is not whether this capability exists — it does — but whether TDS has the same visibility into its own software estate that an outsider can get in a weekend.

## The mechanism: what changed

**1. The professional toolchain became free.** In March 2019 the NSA publicly released Ghidra, the software reverse engineering framework it had built for its own hardest problems, free to anyone, announcing that the release would "level the playing field" for cybersecurity professionals [1]. Ghidra went on to pass half a million downloads and win an R&D 100 Award [1]. IDA-class disassembly and decompilation — once a five-figure, export-conscious specialty — is now a download.

**2. AI removed the expertise bottleneck.** The remaining barrier after Ghidra was skill: reading decompiled code is slow expert work. That barrier is falling. LLM4Decompile (2024) is an open model series trained specifically to turn binary code back into readable source, motivated by the authors' observation that traditional tools such as Ghidra produce output that is "often difficult to read and execute" [4]. A 2025 empirical study of LLMs for binary code understanding found large models measurably effective at the core analyst tasks — recovering function names, summarizing what code does — precisely the comprehension work that used to ration reverse engineering to specialists [5]. The cost curve is the point: an analysis that took an expert a week is becoming an afternoon for a competent generalist with an AI assistant. (Both arXiv items are unreviewed preprints; they are cited as evidence of the direction and the open availability of the technique, not as settled science.)

**3. The practice is institutional, not underground.** When CISA needed to understand the RESURGE malware found on an Ivanti Connect Secure appliance at a critical-infrastructure organization, its analysts reverse engineered the extracted binary — documenting hooking of system functions, faked integrity checks, and modifications to the boot image — and published the analysis for every defender to learn from [2]. And in September 2025, CISA, the NSA, and 19 international partners jointly published SBOM guidance pressing every organization to maintain an "ingredients list" of its software so it can identify supply-chain risk [3]. The federal posture is unambiguous: know what your software is and what it does, because the alternative is that someone else finds out first.

## What it means for a telecom specifically

- **Customer-facing applications.** TDS's customer apps and portals are distributed to devices TDS does not control. Anything in them — endpoints, protocols, embedded logic, third-party SDK behavior — should be assumed readable by competitors, researchers, and attackers. The control is not secrecy of the binary; it is designing and auditing on the assumption of visibility.
- **Field-service tooling.** Technicians' tools run with trusted access to customer-premises information and internal systems. If a vendor tool or a trojanized update misbehaves, the first organization positioned to notice is the one that can open the artifact and look. Without an in-house capability, that notice arrives from someone else.
- **Firmware and network-edge devices.** The Ivanti case [2] is the template: edge appliances are high-value targets, they run vendor binaries, and post-compromise understanding is reverse engineering. A telecom's edge is its business.
- **Vendor software assurance.** Procurement currently leans on vendor attestations. SBOM adoption [3] improves the ingredient list, but ingredients are not behavior. Binary analysis is how an operator checks behavior claims against the shipped artifact — update by update, not once at purchase.
- **Incident response.** Mean time to understanding is a real component of mean time to recovery. A rehearsed, governed RE capability turns "wait for a vendor or a contractor" into "start analysis now, with the evidence written down."

## Fathom's role

Fathom does not create this reality and does not claim to neutralize it. It gives TDS the same class of capability, under TDS's control and TDS's rules:

- **Clean-room and inspectable.** An original Rust implementation with declared design provenance (capability contracts mapped from a public MIT-licensed design; no upstream code — see the repo NOTICE), Apache-2.0, fully auditable source. There is no black box in the proposal.
- **Tiger Style discipline.** Explicit contracts, bounded work, deterministic fail-closed policy engine, confinement. An analysis tool that handles hostile artifacts must itself be built like it expects hostility.
- **Evidence, not assertions.** Every result is an envelope stating what was observed, what was derived, what was not examined, and what cannot be established. That is the property that makes RE output usable in an enterprise: a reviewer can see the limits of a finding without re-running the analysis.
- **Governed by design.** It enters through this TRIS process, with a named small user group, a local-only deployment scope, AI Policy 710 treated as applicable, and a security risk assessment requested rather than resisted (see CHECKLIST.md).

The alternative to an internal capability is not safety; it is asymmetry — everyone else can read the software estate, and TDS cannot. Fathom is the proposal to close that asymmetry with a tool built to be reviewed.

## References (all verified 2026-11-10)

1. Natalie Pittore and Liam Davitt (NSA/CSS Public Affairs), "Ghidra — the Software Reverse Engineering Tool You've Been Waiting for — is Here!", **National Security Agency**, March 5, 2019. https://www.nsa.gov/DesktopModules/ArticleCS/Print.aspx?PortalId=70&ModuleId=10970&Article=1775584 — *Fetched and read. Announces Ghidra's free public release at RSA 2019; the 500,000+ downloads and R&D 100 Award are from NSA's follow-up item in the same series.*
2. "Ivanti Connect Secure (RESURGE)," CISA Malware Analysis Report **AR25-087A** (MAR-25993211-r1.v1), **Cybersecurity and Infrastructure Security Agency**, March 2025 (release announced March 28, 2025). https://www.cisa.gov/news-events/analysis-reports/ar25-087a — *Fetched and read in full: federal reverse engineering of malware (libdsupgrade.so) extracted from a compromised network-edge appliance at a critical-infrastructure organization.*
3. "A Shared Vision of Software Bill of Materials (SBOM) for Cybersecurity," joint guidance of **CISA, the NSA, and 19 international partners**, September 3, 2025. CISA release: https://www.cisa.gov/news-events/news/cisa-nsa-and-19-international-partners-release-shared-vision-software-bill-materials-cybersecurity — *Release page fetched and read; publication date verified against NSA's Cybersecurity Advisories & Guidance listing and the guidance document itself.*
4. Hanzhuo Tan, Qi Luo, Jing Li, Yuqun Zhang, "LLM4Decompile: Decompiling Binary Code with Large Language Models," **arXiv:2403.05286** (v3), March 8, 2024. http://arxiv.org/abs/2403.05286v3 — *Fetched via the arXiv API: metadata and abstract confirmed. Unreviewed preprint.*
5. Xiuwei Shang, Zhenkan Fu, Shaoyin Cheng, Guoqiang Chen, Gangyang Li, Li Hu, Weiming Zhang, Nenghai Yu, "An Empirical Study on the Effectiveness of Large Language Models for Binary Code Understanding," **arXiv:2504.21803** (v1), April 30, 2025. http://arxiv.org/abs/2504.21803v1 — *Fetched via the arXiv API: metadata and abstract confirmed. Unreviewed preprint.*

*Draft, 2026-11-10. Not submitted.*
