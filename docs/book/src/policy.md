# Policy and confinement

Policy is deterministic and fail-closed. It is decided from the
tool's declared class and the operator's configuration — never
from arguments, file contents, or anything a target can
influence.

<details>
<summary>Tool classes</summary>

| Class | Default | Rule |
| --- | --- | --- |
| `read` | allow | Static inspection; still confined to target roots |
| `observe` | deny | Runs only when the tool name is in `allow_tools` |
| `execute` | deny | Runs only when the tool name is in `allow_tools` |

</details>

<details>
<summary>Confinement</summary>

- Targets must canonicalize under an operator-declared
  `target_roots` entry. Canonicalization happens before the prefix
  check, so symlink escapes fail.
- All mutable state lives under one state directory (Ghidra
  projects, caches). Nothing writes beside the target.
- A subject is re-hashed after engine runs; a changed artifact
  aborts the result with `artifact_changed`.
- Configuration validation is fail-closed: duplicate roots, empty
  allowlist names, non-loopback HTTP binds (without the explicit
  `allow_non_loopback_http` acknowledgement), and missing files all
  refuse to start.

</details>

<details>
<summary>Errors</summary>

Failures use upstream's canonical contract: 20 codes in 10
categories, one envelope shape on every surface. MCP tool failures
return `isError` with the envelope as text and no
`structuredContent`, exactly as upstream specifies.

</details>
