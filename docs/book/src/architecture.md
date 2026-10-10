# Architecture

One composition root (`fathom-cli`) builds one tool registry that
every surface serves. Providers register tools into the registry;
the registry applies policy before any handler runs.

<details>
<summary>Crates</summary>

| Crate | Role |
| --- | --- |
| `fathom-a2a` | JCS canonicalization (RFC 8785) and the signed agent card |
| `fathom-cli` | The `fathom` binary: serve, card, doctor, one-shot tool calls |
| `fathom-core` | Config, evidence model, error contract, policy, registry, bounded process runner |
| `fathom-js` | JavaScript/Electron static analysis (oxc) and ASAR archives |
| `fathom-managed` | .NET metadata via manual ECMA-335 parsing over goblin PE |
| `fathom-mcp` | MCP protocol: stdio transport and streamable HTTP |
| `fathom-native` | Native binaries via Ghidra headless; binary layout via goblin |
| `fathom-observe` | Process capture, web captures, EVM, firmware, Android, Apple, browser |

</details>

<details>
<summary>Stateless per call</summary>

Upstream REA keeps a prepared-target session. The port is
stateless: every call names its target, and policy is checked on
every call. The Ghidra project cache (keyed by the subject's
SHA-256) recovers the session's performance without its implicit
state.

</details>

<details>
<summary>Engines are child processes</summary>

Ghidra runs as `analyzeHeadless` batch jobs; nothing is
reimplemented that an engine already does. Child processes run in
their own process groups with bounded output and timeouts, so a
hung engine dies as a group and never takes the server with it.

</details>
