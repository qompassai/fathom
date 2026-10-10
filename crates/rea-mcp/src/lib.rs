//! rea-mcp: MCP transports for the port.
//!
//! A hand-rolled JSON-RPC core (SPEC §5: the surface is small and
//! stays auditable) shared by the stdio and streamable-HTTP
//! transports. Tool failures follow upstream's rule: `isError`
//! with the canonical error JSON as text content and no
//! `structuredContent`.
#![forbid(unsafe_code)]

pub mod http;
pub mod protocol;
pub mod stdio;

/// The MCP protocol version this server negotiates.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
