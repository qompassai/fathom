//! fathom-mcp-server: MCP transports for fathom.
//!
//! rmcp (modern era, 2026-07-28, only) behind an era guard on
//! stdio and rmcp's streamable-HTTP service on HTTP — see
//! `guard.rs` and `http.rs`. Tool failures follow upstream's
//! rule: `isError` with the canonical error JSON as text content
//! and no `structuredContent`.
#![forbid(unsafe_code)]

pub mod guard;
pub mod http;
pub mod server;
pub mod stdio;
