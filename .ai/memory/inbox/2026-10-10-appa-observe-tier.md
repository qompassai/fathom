# observe_browser moved to ask-tier (2026-10-10)

Owner ruled the APPA layer should mirror fathom's SPEC §8: the
profile's one observe-class tool, observe_browser, no longer
runs at allow-tier — it requires attention = ["hitl"], the same
operator approval the engine's default-deny demands via its
config allowlist. The replay expectation in
policy/replay/tool-tiers.appa moves with it (34 steps: 18 allow,
13 deny, 3 authority). Gates at landing: `appa describe --check`
exit 0; `appa replay` 9/9 files ok.
