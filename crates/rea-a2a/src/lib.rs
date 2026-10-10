//! rea-a2a: the A2A surface of the port.
//!
//! A signed agent card, following the volta/vongola estate
//! pattern: the card is canonicalized with JCS (RFC 8785) and
//! signed with Ed25519. Skills are derived from the tool
//! registry, so the card can never advertise a tool the server
//! does not have.
#![forbid(unsafe_code)]

pub mod card;
pub mod jcs;

pub use card::{CardParams, build_card, load_signing_key, verify_card_signature};
