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

/// Bytes captured from one child-process stream.
pub const OUTPUT_BYTES_MAX: usize = 8_388_608;

/// Bytes captured from one `capture_process` stream.
pub const PROCESS_OUTPUT_BYTES_MAX: usize = 1_048_576;

/// Default wall-clock bound for one `capture_process` run, seconds.
pub const PROCESS_TIMEOUT_SECS: u64 = 60;

/// Strings retained from one program inventory.
pub const STRING_COUNT_MAX: usize = 5_000;

/// Bytes in one analysis target (hashed and read by providers).
pub const TARGET_BYTES_MAX: u64 = 536_870_912;
