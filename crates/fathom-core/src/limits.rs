//! Named resource bounds (SPEC §8).
//!
//! Every costly operation checks its bound before it starts. A
//! bound hit is a `resource_constraint` error or a reported
//! truncation in the evidence — never an unbounded retry.

/// Entries retained from one ASAR archive listing.
pub const ASAR_ENTRIES_MAX: usize = 100_000;

/// Bytes of decompiled output retained per function dossier.
pub const DECOMPILE_BYTES_MAX: usize = 1_048_576;

/// Files inventoried under one directory target.
pub const FILE_COUNT_MAX: usize = 100_000;

/// Functions retained from one program inventory.
pub const FUNCTION_COUNT_MAX: usize = 5_000;

/// Default wall-clock bound for one Ghidra provider run, seconds.
pub const GHIDRA_TIMEOUT_SECS: u64 = 330;

/// Listing instructions retained in one function dossier.
pub const INSTRUCTION_COUNT_MAX: usize = 2_000;

/// Bytes captured from one child-process stream.
pub const OUTPUT_BYTES_MAX: usize = 8_388_608;

/// Ceiling on rows in one paged inventory read. A page is
/// additionally capped by the inventory's own count bound.
pub const PAGE_LIMIT_MAX: usize = 20_000;

/// Entries retained from one Godot PCK archive listing.
pub const PCK_ENTRIES_MAX: usize = 100_000;

/// Bytes captured from one `capture_process` stream.
pub const PROCESS_OUTPUT_BYTES_MAX: usize = 1_048_576;

/// Default wall-clock bound for one `capture_process` run, seconds.
pub const PROCESS_TIMEOUT_SECS: u64 = 60;

/// Serialized bytes of one reconstruction proof, stored or
/// inline (SPEC §4.1.9).
pub const PROOF_BYTES_MAX: usize = 1_048_576;

/// Claims in one reconstruction proof (SPEC §4.1.9).
pub const PROOF_CLAIMS_MAX: usize = 256;

/// Characters of one per-claim verification diagnostic
/// (SPEC §4.1.9).
pub const PROOF_DIAGNOSTIC_CHARS_MAX: usize = 512;

/// Evidence references bound to one claim (SPEC §4.1.9).
pub const PROOF_EVIDENCE_PER_CLAIM_MAX: usize = 32;

/// Proofs stored for one subject; a build past the cap is
/// refused, never a silent eviction (SPEC §4.1.9).
pub const PROOF_PER_SUBJECT_MAX: usize = 64;

/// Canonical bytes of one claim's statement facts (SPEC §4.1.9).
pub const PROOF_STATEMENT_BYTES_MAX: usize = 16_384;

/// Strings retained from one program inventory.
pub const STRING_COUNT_MAX: usize = 5_000;

/// Symbols retained from one program inventory.
pub const SYMBOL_COUNT_MAX: usize = 20_000;

/// Bytes in one analysis target (hashed and read by providers).
pub const TARGET_BYTES_MAX: u64 = 536_870_912;
