# Benchmarks

Machine: primo — 13th Gen Intel i7-13620H, 16 threads, 62 GiB RAM, cargo 1.100.0 (2026-11-05).
Method: hand-rolled `std::time` harness in `benches/hot_paths.rs` (harness = false), named-constant workloads, warmup before timed loops, results printed as ns/op and ops/s.
Note: primo was under multi-lane load tonight (load average ~40+ at times), so these numbers are baselines, not peaks; expect substantial run-to-run variance on cold start in particular.

Placement: example and bench live in `crates/fathom-mcp` (package `fathom-mcp-server`), which owns the MCP transport; the server binary is `fathom` from `crates/fathom-cli`.

Workloads:
- `cold_start_discover_and_tools_list`: spawn `fathom serve`, send `server/discover` + `tools/list` (modern era 2026-07-28), 10 reps.
- `tool_call_session_info`: one warm session, 20 warmup + 200 timed `tools/call session_info {}` (read-only; server identity, catalog digest, tool availability).

Results (2026-11-27):
- cold_start_discover_and_tools_list: 6,909,635 ns/op (~6.9 ms) over 10 reps
- tool_call_session_info: 587,873 ns/op (~0.59 ms), 1,701.0 ops/s over 200 calls

Example: `cargo run -p fathom-mcp-server --example stdio_session` — discover (fathom 1.0.0) → tools/list → one `session_info` call, transcript summary printed.
