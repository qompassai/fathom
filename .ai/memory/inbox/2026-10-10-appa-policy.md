# OpenAPPA policy profile added (2026-10-10)

Owner directed the estate's OpenAPPA adaptation — the pilot at
`~/openappa-pilot` (appa 0.30.0 @ 5060566a, one image profile) — be
propagated to vongola, volta, and fathom. Fathom's profile lands in
`policy/`: battery include plus root rules for this repo's workflows,
fathom's SPEC tool tiers (read runs, observe runs at this layer,
capture_process hard-denied per its SPEC default-deny), and `self`
labels on analysis artifacts under the state dir, with network sends
and uncleared writes refused while the session carries the label.

Gates at landing: `appa describe --check` exit 0; `appa replay`
9/9 files ok (34 steps: 19 allow, 13 deny, 2 authority — workflows,
hard denies, exfiltration, label confusion, sink spoofing among
them). Policy changes follow the standing rule: proposal → replay →
Owner's approval.
