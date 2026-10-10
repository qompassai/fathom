# Providers

Each provider registers its tools with an honest availability:
`available`, or `not_implemented` with the SPEC section that
defines the work. Scaffolded tools answer with the canonical
`capability_unavailable` error — never with invented results.

<details>
<summary>Native binaries (Ghidra)</summary>

Drives Ghidra 12 headless: one batch export per subject, parsed
into evidence. Functions, names, strings, inventory search, and
per-function analysis; binary layout (sections, symbols,
relocations, mitigation candidates) is read directly with goblin,
no engine required. Project state is cached per subject SHA-256.

</details>

<details>
<summary>JavaScript and Electron</summary>

oxc parses each module; parse errors are findings, not run
failures. The module graph resolves relative specifiers; Electron
boundaries (IPC channels, `contextBridge` exposures, window
preferences) are extracted from the AST. ASAR archives are read by
a hand-implemented reader for the pickle-framed format.

</details>

<details>
<summary>Managed code (.NET)</summary>

Manual ECMA-335 metadata parsing: CLI header, metadata streams,
table geometry, TypeDef/MethodDef/Field inventories, P/Invoke
maps, and per-method IL digests. CIL body decoding is staged
behind the inventory.

</details>

<details>
<summary>Observation</summary>

Process capture runs commands under the bounded runner (pipes
only; PTY is staged). Web captures read HAR 1.2 exports. EVM
bytecode analysis scans for dispatcher selectors. Browser,
firmware, Android, and Apple deep analysis follow the same
evidence contract as their stages land.

</details>
