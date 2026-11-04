# BQ-2 Unity Mono field expansion — lessons (2026-11-03)

origin_lane: qompass
content_label: sfw
evidence: branch `pax/unity-mono-expand` (local, unpushed) commits
f2fa12a / d367c43 / 234752f / b841c87; work dir primo
`~/.local/share/pax/fathom-bq2-expand-20261103/` (prototype in
`scripts/`, Rust-vs-prototype comparison in `logs/compare4.log`,
per-title expansion records in `out/expand-*.json`, final
generalization table in `logs/summary-final.log`, gate logs in
`~/.local/share/pax/detach/bq2-*.log`).

## L1 — dormant coded-index defect in the census metadata reader

`crates/fathom-managed/src/metadata.rs`'s
`CODED_HAS_CUSTOM_ATTRIBUTE` list carries 20 tables where
ECMA-335 II.24.2.6 defines 22: it is wrong from tag 5 (lists
table 10 where the spec has 9, InterfaceImpl), drops table 40,
and shifts every later tag. Its `CODED_CUSTOM_ATTRIBUTE_TYPE`
table list `&[6, 10]` additionally makes `coded_target` decode
the valid tag 2 (MethodDef constructor) to `usize::MAX`.
Dormant because no current reader consumes table 12 through
that path and the coded-index SIZE coincides (the 5-bit tag
width is right and the listed tables dominate row counts in
practice), so the census rung's results are unaffected. BQ-2's
new `schema` module implements the corrected lists and does
not reuse the old constants; metadata.rs was deliberately
left untouched in this rung. Candidate for a curative-fix
rung: correct the two lists and add a geometry test that pins
tag -> table for all 22 entries.

## L2 — signature tokens are assembly-relative; substitution must carry the home assembly

Every node of a decoded ECMA-335 signature lives in the token
space of the assembly whose blob it was parsed from. A generic
substitution that rewrites a VAR to a type parsed from another
assembly's blob must keep the substituted node's own home
assembly, or cross-assembly generic bases (List<T> defined in
mscorlib, element types in Assembly-CSharp) resolve in the
wrong token space and classes silently misbuild.
`schema::SigType` stamps `assembly` on every node and the
layout builder's `substitute` preserves it. Found while
prototyping; encoded as a type-level invariant, not a comment.

## L3 — Unity Mono serialization rules, corpus-proven as a set

Reconstructing MonoBehaviour layouts from Managed metadata
only works under the rules the corpus arbitrated byte-exactly
(prototype + Rust port agree on all 711 pilot objects by
canonical-JSON digest; generalization over all 17 intake
titles: 698,110 MonoBehaviours = the census total exactly,
682,144 decoded, 15,966 refused by name across 11 named
constructs, zero silent drops, no wholesale title failure):

- bool is a 4-byte 0/1 value, strictly (a slot outside {0,1}
  is a named refusal), alignment 4.
- A byte (u1/i1) field of a reference type occupies a 4-byte
  slot; inside value types bytes pack. A single rule either
  way desynchronizes every following field of TMP_FontAsset.
- Struct field selection splits by assembly: in
  `UnityEngine.*` assemblies all non-static fields serialize
  regardless of access (native-backed value types,
  LayerMask.m_Mask); in package/user assemblies the ordinary
  public-or-[SerializeField] rule applies (Light2DBlendStyle).
- [SerializeReference] alone implies serialized; the field
  stream carries only i64 ids (arrays: i32 count + per-id
  4-alignment), and the objects live in a block at the end of
  the ROOT object: i32 marker 2, i32 count, per entry i64 id,
  class/namespace/assembly strings, field data against the
  named concrete class. The static field type may be an
  interface — nodes are built from signature shape alone.
- A PPtr is 12 bytes; its i64 path id is NOT 8-aligned.
- A class whose own level declares fields but serializes
  none and carries an m_Ptr is native-serialized: refuse by
  name ("native-serialized type without managed layout")
  rather than guess. Corpus-derived native layouts
  (RectOffset, AnimationCurve, GUIStyle/GUIStyleState/
  GUISettings) and a size-proven opaque (Gradient, 164 B)
  are the named exceptions; an opaque of any other size
  refuses by consumption mismatch, keeping the claim
  falsifiable.

## L4 — prototype-first verification for format rungs

For a new binary-format reader, build the independent
prototype first (here: Python over UnityPy enumeration only,
sharing no code with the port), fix a canonical value
encoding, and gate the Rust port on per-object digest
agreement (711/711 pilot objects, plus the full class table)
before trusting it at corpus scale. The prototype is also
where the format's rules are discovered; the port then has a
spec to be wrong against. This is the census rung's
cross-check pattern, extended from counts to values.

## L5 — reporting walks over recursive type graphs must be cycle-bounded by identity, not depth

`flatten_tree` rendered each reconstructed class tree to a
report by walking field paths to a depth cap of 32. The
pilot has no self-referential classes, so the cap looked
sufficient; the generalization corpus has them (in
Changing_Her_Personality_With_My_Magic_Coin, six controller
classes — Jt, JtClass, MainGame, UICtl, MainGameMode,
ModelCtl — reach back into themselves through their fields).
Depth-first enumeration under a pure depth cap is
exponential in the branching factor: the Rust run grew past
45 GB and had to be killed, while the Python prototype died
instantly by its recursion limit on the same classes — the
bug was latent in both, only its cost differed. Fix: a
class node already present among its own ancestors (by
assembly + typedef identity) is emitted but not descended,
and a total row cap (100,000) marks the tree truncated if
ever hit. The title then expands in ~1.4 s at ~185 MB. The
decoder itself was never at risk (it is bounded by payload
bytes and a nesting cap); only the report walk was. Rule:
any traversal that enumerates paths through a type graph
needs an identity-based cycle bound; a depth cap alone is
not a bound. Regression test:
`flatten_stops_at_recursive_class`.

## L6 — refusal clusters localize by Unity version; metadata/payload skew is real

15,966 named refusals across 17 titles concentrate in the
two newest-Unity titles (UltraGirl.Alters, Unity 2021.3.2f1:
8,882; ripe-for-the-picking, Unity 2022.3.62f2: 5,601) and
are dominated by "bool value out of range" (7,586) and
"byte consumption mismatch" (7,530) — the strict rules were
arbitrated on the pilot-era corpus, so newer-Unity
serialization drift is the suspect for a version-conditional
follow-on rung; every refusal is named, so the coverage loss
is measured, not silent. Separately, Changing_Her ships
modding leftovers (0Harmony, MonoMod, Boo.Lang assemblies)
and its recursive-family payloads provably predate its
shipped Managed metadata: the prototype and the Rust port
independently refuse the same 30 objects with the same
construct ("unexpected end of payload", e.g. a 12-byte Jt
payload against a layout needing more). Agreement between
independent implementations on a refusal set is verification
evidence too, not just agreement on decodes.
