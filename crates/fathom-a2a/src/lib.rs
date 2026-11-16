//! fathom-a2a: the A2A surface of the port.
//!
//! The agent card in the D-1607 fleet profile (D-1615): Fathom
//! is an MCP-over-stdio server with no A2A endpoint, and the card
//! declares that honestly — one interface under the fleet's
//! custom MCP binding URI, invocation facts in the extension
//! params, no signature block. The `jcs` module keeps the RFC
//! 8785 canonicalization the recorded future signing route
//! (A2A v1.0 §8.4) will need; fleet cards are unsigned today.
#![forbid(unsafe_code)]

pub mod card;
pub mod jcs;

pub use card::{CardParams, build_card};
