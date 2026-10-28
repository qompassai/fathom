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
no engine required. Mach-O binaries additionally get a dylib
projection: load commands, linked libraries, rpaths, install
name, and exports/imports where present, per architecture for
fat binaries. Project state is cached per subject SHA-256.
Godot PCK archives are read by a hand-implemented reader:
header and directory parse (format versions 1–3), per-entry
SHA-256 with the directory's MD5 as an integrity cross-check;
encrypted directories and entries are reported as unknowns,
never skipped, and decryption is not implemented.

</details>

<details>
<summary>JavaScript and Electron</summary>

oxc parses each module; parse errors are findings, not run
failures. The module graph resolves relative specifiers; Electron
boundaries (IPC channels, `contextBridge` exposures, window
preferences) are extracted from the AST. ASAR archives are read by
a hand-implemented reader for the pickle-framed format. Source
maps are parsed (sources, `sourcesContent` presence, segments),
and `inspect_source_map` maps generated positions back to
original positions.

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
bytecode analysis scans for dispatcher selectors. Browser
observation runs Chromium headless and inventories the
serialized DOM (title, meta, scripts, links, forms); network
logs and screenshots are declared unknowns. Firmware inspection
detects headers and formats, scans for embedded-filesystem
signatures, and profiles entropy — no extraction. Android APK
inspection reads the ZIP directory and parses the binary
manifest (permissions, components, intent filters); DEX and
resource-table contents are inventoried by name only.

</details>
