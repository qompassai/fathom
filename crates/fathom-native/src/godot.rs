//! Godot PCK archive reader (SPEC §9.1), implemented directly.
//!
//! Layout (Godot engine `file_access_pack` reader semantics):
//! a `GDPC` magic, a format version (1 = Godot 3.x, 2 = Godot
//! 4.0–4.4, 3 = Godot 4.5+), the engine version, then — v2 and
//! later — pack flags and a file-data base offset; v3 adds a
//! directory offset (the directory may sit at the end of the
//! file). After 64 reserved bytes, the directory is a file
//! count followed by entries: padded path, offset, size, a
//! 16-byte MD5 of the contents, and (v2+) entry flags. Entry
//! offsets are absolute in v1 and relative to the file base in
//! v2+. Every read is bounds-checked; a malformed archive is a
//! typed error, never a panic.
//!
//! Honesty contract: this reader never decrypts. An encrypted
//! directory ends the inventory at the header (the entry claims
//! are ciphertext), and encrypted entries are listed with their
//! directory facts but no content hash. Removal entries are
//! tombstones — facts, not content. A sparse-bundle pack stores
//! its entry bytes elsewhere, so contents are unknowns. Every
//! readable entry's stored bytes are hashed (SHA-256) and
//! cross-checked against the directory MD5, so an offset that
//! lies in-bounds is caught rather than believed.

use serde_json::{Value, json};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex, subject_for_file};
use fathom_core::limits::PCK_ENTRIES_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// Entry flag: the entry's stored bytes are encrypted.
const ENTRY_FLAG_ENCRYPTED: u32 = 1 << 0;
/// Entry flag: the entry is a removal marker (delta packs);
/// it carries no data in this pack.
const ENTRY_FLAG_REMOVAL: u32 = 1 << 1;
/// Entry flag bits this reader understands.
const ENTRY_FLAGS_KNOWN: u32 = ENTRY_FLAG_ENCRYPTED | ENTRY_FLAG_REMOVAL;

/// Pack flag: the directory itself is encrypted.
const PACK_FLAG_DIRECTORY_ENCRYPTED: u32 = 1 << 0;
/// Pack flag: the file base is relative to the pack's position
/// inside a host file (embedded packs).
const PACK_FLAG_RELATIVE_BASE: u32 = 1 << 1;
/// Pack flag: sparse bundle; entry bytes are not stored here.
const PACK_FLAG_SPARSE_BUNDLE: u32 = 1 << 2;
/// Pack flag bits this reader understands.
const PACK_FLAGS_KNOWN: u32 =
    PACK_FLAG_DIRECTORY_ENCRYPTED | PACK_FLAG_RELATIVE_BASE | PACK_FLAG_SPARSE_BUNDLE;

/// Newest PCK format version this reader implements.
const FORMAT_VERSION_SUPPORTED_MAX: u32 = 3;

#[derive(Debug)]
pub struct PckArchive {
    /// True when the pack flags declare an encrypted directory;
    /// `entries` is then empty because the directory bytes are
    /// ciphertext this reader does not decrypt.
    pub directory_encrypted: bool,
    /// Directory position for format v3; absent in v1/v2, where
    /// the directory follows the header.
    pub directory_offset: Option<u64>,
    pub engine_major: u32,
    pub engine_minor: u32,
    pub engine_patch: u32,
    pub entries: Vec<PckEntry>,
    /// Base that entry offsets are relative to (v2+); 0 in v1.
    pub file_base: u64,
    pub format_version: u32,
    pub pack_flags: u32,
    /// True when the pack is a sparse bundle: entry bytes live
    /// in another pack, not at the declared offsets here.
    pub sparse_bundle: bool,
}

#[derive(Debug)]
pub struct PckEntry {
    pub flags: u32,
    /// MD5 of the contents, as declared in the directory.
    pub md5: [u8; 16],
    /// Offset as stored: absolute in v1, relative to the
    /// archive's file base in v2+.
    pub offset: u64,
    pub path: String,
    pub size: u64,
}

impl PckEntry {
    /// The entry's stored bytes are encrypted.
    pub fn encrypted(&self) -> bool {
        self.flags & ENTRY_FLAG_ENCRYPTED != 0
    }

    /// The entry is a removal tombstone with no stored data.
    pub fn removal(&self) -> bool {
        self.flags & ENTRY_FLAG_REMOVAL != 0
    }
}

/// The absolute position of an entry's stored bytes: the stored
/// offset rebased onto the file base for v2+, as stored for v1.
pub fn stored_offset(archive: &PckArchive, entry: &PckEntry) -> u64 {
    if archive.format_version >= 2 {
        archive.file_base.saturating_add(entry.offset)
    } else {
        entry.offset
    }
}

/// Parse a Godot PCK archive from its full bytes.
pub fn parse_pck(bytes: &[u8]) -> Result<PckArchive, FathomError> {
    let unsupported = |message: String| {
        FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("godot pck archive")
    };
    if bytes.len() < 20 {
        return Err(unsupported(
            "file too small to be a Godot PCK archive".to_string(),
        ));
    }
    let mut header = Cursor::new(bytes, 0);
    if header.read_bytes(4)? != b"GDPC" {
        return Err(unsupported("missing GDPC magic".to_string()));
    }
    let format_version = header.read_u32()?;
    let engine_major = header.read_u32()?;
    let engine_minor = header.read_u32()?;
    let engine_patch = header.read_u32()?;
    let mut directory_offset: Option<u64> = None;
    let (directory_start, file_base, pack_flags) = match format_version {
        0 | 1 => {
            header.skip(64)?;
            (header.position, 0, 0)
        }
        2 => {
            let pack_flags = header.read_u32()?;
            let file_base = header.read_u64()?;
            header.skip(64)?;
            (header.position, file_base, pack_flags)
        }
        3 => {
            let pack_flags = header.read_u32()?;
            let file_base = header.read_u64()?;
            let offset = header.read_u64()?;
            header.skip(64)?;
            directory_offset = Some(offset);
            let start = usize::try_from(offset).map_err(|_| {
                unsupported("PCK directory offset does not fit this platform".to_string())
            })?;
            (start, file_base, pack_flags)
        }
        other => {
            return Err(unsupported(format!(
                "PCK format version {other} is not implemented \
                 (supported: 1, 2, {FORMAT_VERSION_SUPPORTED_MAX})"
            )));
        }
    };
    let directory_encrypted = pack_flags & PACK_FLAG_DIRECTORY_ENCRYPTED != 0;
    let sparse_bundle = pack_flags & PACK_FLAG_SPARSE_BUNDLE != 0;
    let mut archive = PckArchive {
        directory_encrypted,
        directory_offset,
        engine_major,
        engine_minor,
        engine_patch,
        entries: Vec::new(),
        file_base,
        format_version,
        pack_flags,
        sparse_bundle,
    };
    if directory_encrypted {
        // The directory bytes are ciphertext. Report the header
        // facts and stop: inventing entries would fake coverage.
        return Ok(archive);
    }
    let mut directory = Cursor::new(bytes, directory_start);
    let file_count = directory.read_u32()?;
    for _ in 0..file_count {
        let path_len = usize::try_from(directory.read_u32()?).map_err(|_| {
            unsupported("PCK entry path length does not fit this platform".to_string())
        })?;
        let path_bytes = directory.read_bytes(path_len)?;
        // Paths are NUL-padded to a 4-byte boundary; the path is
        // the bytes up to the first NUL.
        let path_end = path_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path_bytes.len());
        let path = std::str::from_utf8(&path_bytes[..path_end])
            .map_err(|_| unsupported("PCK entry path is not valid UTF-8".to_string()))?
            .to_string();
        let offset = directory.read_u64()?;
        let size = directory.read_u64()?;
        let mut md5 = [0_u8; 16];
        md5.copy_from_slice(directory.read_bytes(16)?);
        let flags = if format_version >= 2 {
            directory.read_u32()?
        } else {
            0
        };
        archive.entries.push(PckEntry {
            flags,
            md5,
            offset,
            path,
            size,
        });
    }
    Ok(archive)
}

/// Extract one entry's stored bytes (bounds-checked). This is
/// the raw stored content: decryption is NOT-IMPLEMENTED, so an
/// encrypted entry is a typed refusal, as are removal tombstones
/// and sparse-bundle entries, whose bytes live elsewhere.
pub fn extract<'a>(
    bytes: &'a [u8],
    archive: &PckArchive,
    entry: &PckEntry,
) -> Result<&'a [u8], FathomError> {
    if entry.encrypted() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is encrypted; PCK decryption is not implemented",
        ));
    }
    if entry.removal() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is a removal marker; it carries no data in this pack",
        ));
    }
    if archive.sparse_bundle {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "pack is a sparse bundle; entry bytes are not stored in this pack",
        ));
    }
    let start_u64 = stored_offset(archive, entry);
    let start = usize::try_from(start_u64)
        .ok()
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| {
            FathomError::new(ErrorCode::Truncated, "entry offset overruns the archive")
        })?;
    let size = usize::try_from(entry.size)
        .map_err(|_| FathomError::new(ErrorCode::Truncated, "entry size overruns the archive"))?;
    let end = start
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| FathomError::new(ErrorCode::Truncated, "entry size overruns the archive"))?;
    Ok(&bytes[start..end])
}

pub fn inspect_godot_pck(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    let archive = parse_pck(&bytes)?;
    let mut evidence = Evidence::new("inspect_godot_pck", "godot");
    evidence.subject = Some(subject);
    if archive.directory_encrypted {
        evidence.add_finding(pack_finding(&archive, 0, 0, 0, 0, 0));
        evidence.add_unknown(
            "directory",
            "pack directory is encrypted (pack flag 0x1); the entry inventory \
             was not established — PCK decryption is NOT-IMPLEMENTED",
        );
        evidence.coverage.exhaustive = false;
        return Ok(evidence.to_value());
    }
    let total = archive.entries.len();
    let mut examined: u64 = 0;
    let mut encrypted_count: u64 = 0;
    let mut mismatch_paths: Vec<&str> = Vec::new();
    let mut overrun_paths: Vec<&str> = Vec::new();
    let mut removal_count: u64 = 0;
    let mut verified_count: u64 = 0;
    let mut rows: Vec<Value> = Vec::new();
    for entry in &archive.entries {
        let (row, outcome) = entry_row(&bytes, &archive, entry);
        match outcome {
            EntryOutcome::Encrypted => encrypted_count += 1,
            EntryOutcome::Mismatch => {
                // The bytes were read and examined; they are
                // simply not the bytes the directory describes.
                mismatch_paths.push(entry.path.as_str());
                examined += 1;
            }
            EntryOutcome::Overrun => overrun_paths.push(entry.path.as_str()),
            EntryOutcome::Removal => {
                removal_count += 1;
                examined += 1;
            }
            EntryOutcome::Sparse => {}
            EntryOutcome::Verified => {
                verified_count += 1;
                examined += 1;
            }
        }
        if rows.len() < PCK_ENTRIES_MAX {
            rows.push(row);
        }
    }
    evidence.add_finding(pack_finding(
        &archive,
        encrypted_count,
        mismatch_paths.len() as u64,
        overrun_paths.len() as u64,
        removal_count,
        verified_count,
    ));
    let mut entries_finding = Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": total.min(PCK_ENTRIES_MAX), "total": total}),
    );
    if total > PCK_ENTRIES_MAX {
        entries_finding =
            entries_finding.with_limitation("entry listing truncated at the count bound");
    }
    evidence.add_finding(entries_finding);
    if archive.sparse_bundle {
        evidence.add_unknown(
            "entry contents",
            "pack is a sparse bundle; entry bytes are stored in another pack \
             and were not hashed or verified",
        );
    }
    if encrypted_count > 0 {
        evidence.add_unknown(
            "entry contents",
            format!(
                "{encrypted_count} of {total} entries are encrypted; their stored \
                 bytes are ciphertext — not hashed, not verified"
            ),
        );
    }
    if !mismatch_paths.is_empty() {
        evidence.add_unknown(
            "entry integrity",
            format!(
                "{} entries' stored bytes do not match the MD5 declared in the \
                 directory (first: {}); their rows hash the bytes present, which \
                 are not the bytes the directory describes",
                mismatch_paths.len(),
                mismatch_paths[0],
            ),
        );
    }
    if !overrun_paths.is_empty() {
        evidence.add_unknown(
            "entry data",
            format!(
                "{} entries declare an offset/size outside the archive \
                 (first: {}); the directory's claims for them cannot be checked",
                overrun_paths.len(),
                overrun_paths[0],
            ),
        );
    }
    evidence.coverage.examined = examined;
    evidence.coverage.total = total as u64;
    evidence.coverage.exhaustive = examined == total as u64;
    Ok(evidence.to_value())
}

/// How one entry's stored bytes checked out.
enum EntryOutcome {
    Encrypted,
    Mismatch,
    Overrun,
    Removal,
    Sparse,
    Verified,
}

/// One entry's evidence row plus its verification outcome. The
/// row always carries the directory facts; content facts appear
/// only when the stored bytes were actually read.
fn entry_row(bytes: &[u8], archive: &PckArchive, entry: &PckEntry) -> (Value, EntryOutcome) {
    let mut row = json!({
        "encrypted": entry.encrypted(),
        "flags": entry.flags,
        "md5": hex_bytes(&entry.md5),
        "md5_verified": Value::Null,
        "offset": stored_offset(archive, entry),
        "path": entry.path,
        "removal": entry.removal(),
        "sha256": Value::Null,
        "size": entry.size,
        "status": "unread",
    });
    let outcome = if entry.encrypted() {
        row["status"] = json!("encrypted");
        EntryOutcome::Encrypted
    } else if entry.removal() {
        row["status"] = json!("removal");
        EntryOutcome::Removal
    } else if archive.sparse_bundle {
        row["status"] = json!("sparse_bundle");
        EntryOutcome::Sparse
    } else {
        match extract(bytes, archive, entry) {
            Ok(data) => {
                row["sha256"] = json!(sha256_hex(data));
                let verified = md5_digest(data) == entry.md5;
                row["md5_verified"] = json!(verified);
                if verified {
                    row["status"] = json!("verified");
                    EntryOutcome::Verified
                } else {
                    row["status"] = json!("md5_mismatch");
                    EntryOutcome::Mismatch
                }
            }
            Err(_) => {
                row["status"] = json!("unreadable");
                EntryOutcome::Overrun
            }
        }
    };
    (row, outcome)
}

/// The pack-level summary finding: header facts and the
/// verification census, derived from the entry records.
fn pack_finding(
    archive: &PckArchive,
    encrypted_entries: u64,
    md5_mismatch_entries: u64,
    unreadable_entries: u64,
    removal_entries: u64,
    verified_entries: u64,
) -> Finding {
    let total_file_bytes: u64 = archive
        .entries
        .iter()
        .filter(|entry| !entry.removal())
        .map(|entry| entry.size)
        .sum();
    let mut finding = Finding::new(
        "godot_pck",
        Confidence::Observed,
        json!({
            "declared_entries": archive.entries.len(),
            "directory_encrypted": archive.directory_encrypted,
            "directory_offset": archive.directory_offset,
            "encrypted_entries": encrypted_entries,
            "engine_major": archive.engine_major,
            "engine_minor": archive.engine_minor,
            "engine_patch": archive.engine_patch,
            "file_base": archive.file_base,
            "format_version": archive.format_version,
            "md5_mismatch_entries": md5_mismatch_entries,
            "pack_flags": archive.pack_flags,
            "relative_base": archive.pack_flags & PACK_FLAG_RELATIVE_BASE != 0,
            "removal_entries": removal_entries,
            "sparse_bundle": archive.sparse_bundle,
            "total_file_bytes": total_file_bytes,
            "unreadable_entries": unreadable_entries,
            "verified_entries": verified_entries,
        }),
    );
    if archive.pack_flags & PACK_FLAG_RELATIVE_BASE != 0 {
        finding = finding.with_limitation(
            "pack declares a relative file base (embedded layout); entry \
             offsets are interpreted against the stored file base — a pack \
             carved out of a host executable may declare its base relative \
             to its position in that host",
        );
    }
    let unknown_pack_flags = archive.pack_flags & !PACK_FLAGS_KNOWN;
    if unknown_pack_flags != 0 {
        finding = finding.with_limitation(format!(
            "pack declares unrecognised flag bits 0x{unknown_pack_flags:x}; \
             they are reported, not interpreted"
        ));
    }
    if archive
        .entries
        .iter()
        .any(|entry| entry.flags & !ENTRY_FLAGS_KNOWN != 0)
    {
        finding = finding.with_limitation(
            "one or more entries declare unrecognised flag bits; the raw \
             flags are reported per entry, not interpreted",
        );
    }
    finding
}

/// Bounds-checked little-endian cursor over the archive bytes.
/// Every failed read is a `Truncated` error naming the archive.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], position: usize) -> Self {
        Cursor { bytes, position }
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                FathomError::new(ErrorCode::Truncated, "godot pck archive ends mid-structure")
                    .with_target("godot pck archive")
            })?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32, FathomError> {
        let slice = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, FathomError> {
        let slice = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]))
    }

    fn skip(&mut self, count: usize) -> Result<(), FathomError> {
        self.read_bytes(count)?;
        Ok(())
    }
}

/// Lowercase hex for a byte string (MD5 digests in entry rows).
fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// MD5 (RFC 1321), implemented directly — the SPEC's pattern
/// for small format primitives with public test vectors. Used
/// only as an integrity cross-check against the digest the PCK
/// directory declares; SHA-256 remains the identity hash.
fn md5_digest(input: &[u8]) -> [u8; 16] {
    const SHIFTS: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const TABLE: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let (blocks, remainder) = input.as_chunks::<64>();
    for block in blocks {
        md5_block(&mut state, block, &SHIFTS, &TABLE);
    }
    let mut tail = [0_u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    let tail_blocks = if remainder.len() < 56 { 1 } else { 2 };
    let bit_len = (input.len() as u64).wrapping_mul(8);
    tail[tail_blocks * 64 - 8..tail_blocks * 64].copy_from_slice(&bit_len.to_le_bytes());
    md5_block(&mut state, &tail[..64], &SHIFTS, &TABLE);
    if tail_blocks == 2 {
        md5_block(&mut state, &tail[64..128], &SHIFTS, &TABLE);
    }
    let mut out = [0_u8; 16];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// One 64-byte MD5 compression block (RFC 1321 §3.4).
fn md5_block(state: &mut [u32; 4], block: &[u8], shifts: &[u32; 64], table: &[u32; 64]) {
    debug_assert_eq!(block.len(), 64);
    let mut words = [0_u32; 16];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u32::from_le_bytes([
            block[index * 4],
            block[index * 4 + 1],
            block[index * 4 + 2],
            block[index * 4 + 3],
        ]);
    }
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let sum = f
            .wrapping_add(a)
            .wrapping_add(table[i])
            .wrapping_add(words[g]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(sum.rotate_left(shifts[i]));
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Build a PCK the way Godot's packer writes one: header,
    /// directory, data at 32-byte-aligned positions (v2+),
    /// paths NUL-padded to a 4-byte boundary, real MD5s. For
    /// v3 the data section comes first and the directory sits
    /// at the end. Returns the bytes and, per entry, the
    /// position of its stored-offset field in the directory —
    /// so tests can lie about offsets. A removal entry stores
    /// no data and a zero MD5.
    fn build_pack(
        format_version: u32,
        pack_flags: u32,
        files: &[(&str, &[u8], u32)],
    ) -> (Vec<u8>, Vec<usize>) {
        let header_len: usize = match format_version {
            0 | 1 => 84,
            2 => 96,
            _ => 104,
        };
        let padded_len = |path: &str| path.len() + (4 - path.len() % 4) % 4;
        let entry_len = |path: &str| {
            4 + padded_len(path) + 8 + 8 + 16 + if format_version >= 2 { 4 } else { 0 }
        };
        let directory_len: usize = 4 + files
            .iter()
            .map(|(path, _, _)| entry_len(path))
            .sum::<usize>();
        let data_start = match format_version {
            3 => header_len.div_ceil(32) * 32,
            2 => (header_len + directory_len).div_ceil(32) * 32,
            _ => header_len + directory_len,
        };
        let mut positions: Vec<u64> = Vec::new();
        let mut cursor = data_start;
        for (_, contents, flags) in files {
            if flags & ENTRY_FLAG_REMOVAL != 0 {
                positions.push(0);
                continue;
            }
            if format_version >= 2 {
                cursor = cursor.div_ceil(32) * 32;
            }
            positions.push(cursor as u64);
            cursor += contents.len();
        }
        let file_base = if format_version >= 2 {
            data_start as u64
        } else {
            0
        };
        let directory_start = if format_version == 3 {
            cursor
        } else {
            header_len
        };
        let total_len = if format_version == 3 {
            directory_start + directory_len
        } else {
            cursor
        };
        let mut out = vec![0_u8; total_len];
        out[0..4].copy_from_slice(b"GDPC");
        write_u32(&mut out, 4, format_version);
        let (major, minor, patch) = if format_version <= 1 {
            (3, 5, 0)
        } else {
            (4, 2, 0)
        };
        write_u32(&mut out, 8, major);
        write_u32(&mut out, 12, minor);
        write_u32(&mut out, 16, patch);
        if format_version >= 2 {
            write_u32(&mut out, 20, pack_flags);
            write_u64(&mut out, 24, file_base);
        }
        if format_version >= 3 {
            write_u64(&mut out, 32, directory_start as u64);
        }
        let mut at = directory_start;
        write_u32(&mut out, at, files.len() as u32);
        at += 4;
        let mut offset_positions = Vec::new();
        for (index, (path, contents, flags)) in files.iter().enumerate() {
            let removal = flags & ENTRY_FLAG_REMOVAL != 0;
            let padded = padded_len(path);
            write_u32(&mut out, at, padded as u32);
            at += 4;
            out[at..at + path.len()].copy_from_slice(path.as_bytes());
            at += padded;
            offset_positions.push(at);
            let stored = if removal {
                0
            } else if format_version >= 2 {
                positions[index] - file_base
            } else {
                positions[index]
            };
            write_u64(&mut out, at, stored);
            at += 8;
            write_u64(
                &mut out,
                at,
                if removal { 0 } else { contents.len() as u64 },
            );
            at += 8;
            let md5 = if removal {
                [0_u8; 16]
            } else {
                md5_digest(contents)
            };
            out[at..at + 16].copy_from_slice(&md5);
            at += 16;
            if format_version >= 2 {
                write_u32(&mut out, at, *flags);
                at += 4;
            }
        }
        for (index, (_, contents, flags)) in files.iter().enumerate() {
            if flags & ENTRY_FLAG_REMOVAL != 0 {
                continue;
            }
            let start = positions[index] as usize;
            out[start..start + contents.len()].copy_from_slice(contents);
        }
        (out, offset_positions)
    }

    fn write_u32(out: &mut [u8], at: usize, value: u32) {
        out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn run_inspect(test_name: &str, bytes: &[u8]) -> (PathBuf, Value) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let pack = root.join("game.pck");
        fs::write(&pack, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": pack.display().to_string()});
        let value = inspect_godot_pck(&Registry::new(), &config, &args).unwrap();
        (root, value)
    }

    fn pack_facts(value: &Value) -> &Value {
        &value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "godot_pck")
            .expect("godot_pck finding")["facts"]
    }

    fn entry_rows(value: &Value) -> &Vec<Value> {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "entries")
            .expect("entries finding")["facts"]["entries"]
            .as_array()
            .unwrap()
    }

    #[test]
    fn adversarial_bad_magic_rejected() {
        let err = parse_pck(b"NOPE and some more bytes here").unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        assert!(parse_pck(&[0x47, 0x44]).is_err());
    }

    #[test]
    fn adversarial_encrypted_directory_is_an_unknown_not_silence() {
        let (bytes, _) = build_pack(
            2,
            PACK_FLAG_DIRECTORY_ENCRYPTED,
            &[("res://a.txt", b"x", 0)],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert!(archive.directory_encrypted);
        assert!(archive.entries.is_empty());
        let (root, value) = run_inspect("encrypted-dir", &bytes);
        assert_eq!(value["status"], "partial");
        assert_eq!(value["findings"].as_array().unwrap().len(), 1);
        assert_eq!(pack_facts(&value)["declared_entries"], 0);
        assert_eq!(value["unknowns"][0]["aspect"], "directory");
        assert_eq!(value["coverage"]["total"], 0);
        assert_eq!(value["coverage"]["exhaustive"], false);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_encrypted_entry_is_listed_not_hashed() {
        let (bytes, _) = build_pack(
            2,
            0,
            &[("res://secret.gd", b"ciphertext", ENTRY_FLAG_ENCRYPTED)],
        );
        let archive = parse_pck(&bytes).unwrap();
        let err = extract(&bytes, &archive, &archive.entries[0]).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        let (root, value) = run_inspect("encrypted-entry", &bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "encrypted");
        assert_eq!(rows[0]["sha256"], Value::Null);
        assert_eq!(rows[0]["md5_verified"], Value::Null);
        assert_eq!(value["status"], "partial");
        assert_eq!(value["coverage"]["examined"], 0);
        assert_eq!(value["coverage"]["exhaustive"], false);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_inbounds_offset_lie_caught_by_md5() {
        let (mut bytes, offset_positions) = build_pack(
            2,
            0,
            &[
                ("res://a.bin", b"AAAAAAAAAAAAAAAA", 0),
                ("res://b.bin", b"BBBBBBBBBBBBBBBB", 0),
            ],
        );
        // Point b.bin's stored offset at a.bin's data: in-bounds,
        // plausible, and wrong.
        let a_stored = u64::from_le_bytes(
            bytes[offset_positions[0]..offset_positions[0] + 8]
                .try_into()
                .unwrap(),
        );
        write_u64(&mut bytes, offset_positions[1], a_stored);
        let (root, value) = run_inspect("offset-lie-inbounds", &bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[1]["status"], "md5_mismatch");
        assert_eq!(rows[1]["md5_verified"], false);
        // The row hashes the bytes actually present (a.bin's).
        assert_eq!(rows[1]["sha256"], json!(sha256_hex(b"AAAAAAAAAAAAAAAA")));
        assert_eq!(value["unknowns"][0]["aspect"], "entry integrity");
        assert_eq!(pack_facts(&value)["md5_mismatch_entries"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_non_utf8_path_rejected() {
        let (mut bytes, _) = build_pack(1, 0, &[("res://a.txt", b"x", 0)]);
        // First path byte sits after header (84) + count (4) +
        // path length (4).
        bytes[92] = 0xff;
        bytes[93] = 0xfe;
        let err = parse_pck(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
    }

    #[test]
    fn adversarial_offset_lie_overrun_is_an_unknown_not_a_fact() {
        let (mut bytes, offset_positions) = build_pack(2, 0, &[("res://a.txt", b"hello", 0)]);
        write_u64(&mut bytes, offset_positions[0], 1 << 40);
        let archive = parse_pck(&bytes).unwrap();
        let err = extract(&bytes, &archive, &archive.entries[0]).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        let (root, value) = run_inspect("offset-lie-overrun", &bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "unreadable");
        assert_eq!(rows[0]["sha256"], Value::Null);
        assert_eq!(value["unknowns"][0]["aspect"], "entry data");
        assert_eq!(value["coverage"]["examined"], 0);
        assert_eq!(value["coverage"]["exhaustive"], false);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_path_length_overrun_rejected() {
        let (mut bytes, _) = build_pack(1, 0, &[("res://a.txt", b"x", 0)]);
        // Path-length field of the first entry (header 84 +
        // count 4).
        write_u32(&mut bytes, 88, u32::MAX);
        assert!(parse_pck(&bytes).is_err());
    }

    #[test]
    fn adversarial_poisoned_path_is_recorded_verbatim() {
        let (bytes, _) = build_pack(2, 0, &[("res://../../evil.txt", b"x", 0)]);
        let (root, value) = run_inspect("poisoned-path", &bytes);
        let rows = entry_rows(&value);
        // The path is data in the evidence, never a filesystem
        // operation: nothing was written outside the fixture.
        assert_eq!(rows[0]["path"], "res://../../evil.txt");
        assert!(!root.join("evil.txt").exists());
        assert!(!root.parent().unwrap().join("evil.txt").exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_sparse_bundle_contents_are_unknowns() {
        let (bytes, _) = build_pack(2, PACK_FLAG_SPARSE_BUNDLE, &[("res://a.txt", b"hello", 0)]);
        let archive = parse_pck(&bytes).unwrap();
        let err = extract(&bytes, &archive, &archive.entries[0]).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        let (root, value) = run_inspect("sparse", &bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "sparse_bundle");
        assert_eq!(rows[0]["sha256"], Value::Null);
        assert_eq!(value["unknowns"][0]["aspect"], "entry contents");
        assert_eq!(value["coverage"]["exhaustive"], false);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_directory_rejected() {
        let (bytes, _) = build_pack(
            2,
            0,
            &[("res://a.txt", b"hello", 0), ("res://b.txt", b"world", 0)],
        );
        // Header is 96 bytes; 10 more bytes end mid-first-entry.
        assert!(parse_pck(&bytes[..106]).is_err());
    }

    #[test]
    fn adversarial_truncated_header_rejected() {
        let (bytes, _) = build_pack(2, 0, &[("res://a.txt", b"hello", 0)]);
        assert!(parse_pck(&bytes[..40]).is_err());
    }

    #[test]
    fn adversarial_unknown_format_version_is_named_not_implemented() {
        let (mut bytes, _) = build_pack(2, 0, &[("res://a.txt", b"hello", 0)]);
        write_u32(&mut bytes, 4, 9);
        let err = parse_pck(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        assert!(err.message.contains("format version 9"), "{}", err.message);
        assert!(err.message.contains("not implemented"), "{}", err.message);
    }

    #[test]
    fn validation_empty_pack() {
        let (bytes, _) = build_pack(2, 0, &[]);
        let archive = parse_pck(&bytes).unwrap();
        assert!(archive.entries.is_empty());
        let (root, value) = run_inspect("empty", &bytes);
        assert_eq!(value["status"], "complete");
        assert_eq!(pack_facts(&value)["declared_entries"], 0);
        assert_eq!(value["coverage"]["examined"], 0);
        assert_eq!(value["coverage"]["total"], 0);
        assert_eq!(value["coverage"]["exhaustive"], true);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_inspect_envelope_complete() {
        let (bytes, _) = build_pack(
            2,
            0,
            &[
                ("res://main.gd", b"extends Node\n", 0),
                ("res://data.bin", &[1, 2, 3, 4], 0),
            ],
        );
        let (root, value) = run_inspect("envelope", &bytes);
        assert_eq!(value["tool"], "inspect_godot_pck");
        assert_eq!(value["provider"], "godot");
        assert_eq!(value["status"], "complete");
        assert_eq!(
            value["subject"]["size_bytes"].as_u64().unwrap(),
            bytes.len() as u64
        );
        assert_eq!(value["coverage"]["examined"], 2);
        assert_eq!(value["coverage"]["total"], 2);
        assert_eq!(value["coverage"]["exhaustive"], true);
        let facts = pack_facts(&value);
        assert_eq!(facts["format_version"], 2);
        assert_eq!(facts["engine_major"], 4);
        assert_eq!(facts["verified_entries"], 2);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["path"], "res://main.gd");
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[0]["md5_verified"], true);
        assert_eq!(rows[0]["sha256"], json!(sha256_hex(b"extends Node\n")));
        assert_eq!(
            rows[0]["md5"],
            json!(hex_bytes(&md5_digest(b"extends Node\n")))
        );
        assert_eq!(rows[1]["sha256"], json!(sha256_hex(&[1, 2, 3, 4])));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_md5_rfc1321_vectors() {
        // The RFC 1321 test suite.
        let vectors: [(&[u8], &str); 7] = [
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(hex_bytes(&md5_digest(input)), expected);
        }
    }

    #[test]
    fn validation_relative_base_pack_reads_with_limitation() {
        let (bytes, _) = build_pack(2, PACK_FLAG_RELATIVE_BASE, &[("res://a.txt", b"hello", 0)]);
        let archive = parse_pck(&bytes).unwrap();
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[0]).unwrap(),
            b"hello"
        );
        let (root, value) = run_inspect("relative-base", &bytes);
        assert_eq!(pack_facts(&value)["relative_base"], true);
        let finding = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "godot_pck")
            .expect("godot_pck finding");
        let limitations = finding["limitations"].as_array().unwrap();
        assert!(
            limitations
                .iter()
                .any(|text| text.as_str().unwrap().contains("relative file base")),
            "{limitations:?}"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_removal_entry_is_a_tombstone_fact() {
        let (bytes, _) = build_pack(
            2,
            0,
            &[
                ("res://kept.txt", b"here", 0),
                ("res://gone.txt", b"", ENTRY_FLAG_REMOVAL),
            ],
        );
        let (root, value) = run_inspect("removal", &bytes);
        assert_eq!(value["status"], "complete");
        assert_eq!(pack_facts(&value)["removal_entries"], 1);
        let rows = entry_rows(&value);
        assert_eq!(rows[1]["status"], "removal");
        assert_eq!(rows[1]["removal"], true);
        assert_eq!(rows[1]["sha256"], Value::Null);
        // A tombstone's whole claim lives in the directory, so
        // coverage stays exhaustive and no unknown is recorded.
        assert_eq!(value["coverage"]["examined"], 2);
        assert_eq!(value["coverage"]["exhaustive"], true);
        assert!(value["unknowns"].as_array().unwrap().is_empty());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_v1_roundtrip_entries_and_extract() {
        let (bytes, _) = build_pack(
            1,
            0,
            &[
                ("res://main.gd", b"extends Node\n", 0),
                ("res://data.bin", &[1, 2, 3, 4], 0),
            ],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert_eq!(archive.format_version, 1);
        assert_eq!(archive.engine_major, 3);
        assert_eq!(archive.engine_minor, 5);
        assert_eq!(archive.file_base, 0);
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].path, "res://main.gd");
        assert_eq!(archive.entries[0].size, 13);
        assert_eq!(archive.entries[0].flags, 0);
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[0]).unwrap(),
            b"extends Node\n"
        );
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[1]).unwrap(),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn validation_v2_roundtrip_entries_and_extract() {
        let (bytes, _) = build_pack(
            2,
            0,
            &[
                ("res://main.gd", b"extends Node\n", 0),
                ("res://data.bin", &[1, 2, 3, 4], 0),
            ],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert_eq!(archive.format_version, 2);
        assert_eq!(archive.engine_major, 4);
        assert!(archive.file_base > 0);
        assert_eq!(archive.directory_offset, None);
        assert_eq!(archive.entries.len(), 2);
        // Stored offsets are relative to the file base.
        assert!(archive.entries[0].offset < archive.file_base);
        assert_eq!(
            stored_offset(&archive, &archive.entries[0]),
            archive.file_base + archive.entries[0].offset
        );
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[0]).unwrap(),
            b"extends Node\n"
        );
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[1]).unwrap(),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn validation_v3_roundtrip_directory_at_end() {
        let (bytes, _) = build_pack(
            3,
            0,
            &[
                ("res://main.gd", b"extends Node\n", 0),
                ("res://data.bin", &[1, 2, 3, 4], 0),
            ],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert_eq!(archive.format_version, 3);
        let directory_offset = archive.directory_offset.expect("v3 directory offset");
        // The directory sits after the file data in a v3 pack.
        assert!(directory_offset > stored_offset(&archive, &archive.entries[1]));
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[0]).unwrap(),
            b"extends Node\n"
        );
        assert_eq!(
            extract(&bytes, &archive, &archive.entries[1]).unwrap(),
            &[1, 2, 3, 4]
        );
    }
}
