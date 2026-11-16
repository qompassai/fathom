//! Flutter/Dart AOT pseudo-Dart lane (D-1620): the pinned
//! jadart tool (IR0NBYTE/Jadart v1.4.0, commit
//! fe2e93fab45f30c78de6afd843792a0225c0cbe5, MIT) run as a
//! bounded child process over a Flutter target, with its JSON
//! outputs and its exported pseudo-Dart tree ingested into
//! evidence envelopes.
//!
//! Static-only discipline: jadart is a pure parser, verified
//! from its pinned sources before this lane's first run —
//! `source.py` reads the target (or one zip member of it) as
//! bytes, `elf.py` / `macho.py` walk those bytes with
//! `struct.unpack_from`, the snapshot/cluster walk is data
//! processing over the byte string, and capstone disassembly
//! (`disasm.py`, the one non-stdlib import) decodes
//! instruction bytes as data. No module in the package
//! imports `subprocess`, `ctypes`, or a socket/URL library,
//! and nothing loads, links, or executes target code; the
//! IDA/Ghidra import lines in `interop.py` are string
//! templates for scripts jadart *writes*, never imports it
//! runs. Fathom likewise never executes the target.
//!
//! The lane's reason to exist is readable code: jadart is
//! the only tool in the D-1618 head-to-head that reconstructs
//! method bodies as pseudo-Dart (its `StoredSecurityContext.
//! toString` recovers the exact string literal). The exported
//! per-library pseudo-Dart text is therefore ingested
//! faithfully — verbatim, never summarised or paraphrased —
//! because this lane feeds spec-writing.
//!
//! Error honesty: jadart's JSON error contract is the
//! strongest in the head-to-head (exit 2 with a typed JSON
//! error body whose `ContainerError` / `InputError` messages
//! carry exact offsets). [`map_jadart_error`] maps every
//! jadart error type onto a fathom typed error one-for-one in
//! kind, preserving the jadart type name and its full message
//! (offsets included) in the fathom error's message and
//! details; a jadart failure never surfaces as a success and
//! never collapses into an untyped failure.
//!
//! Input shapes: jadart reads an APK/IPA zip, a bare
//! `libapp.so`, an iOS `App` Mach-O binary, and directories
//! holding any of those. [`validate_jadart_target`] decides
//! every refusal (missing snapshot member, wrong
//! architecture or CPU type, truncated or empty file,
//! non-ELF/non-Mach-O garbage, missing counterpart file in a
//! directory) with typed errors before jadart ever runs,
//! reusing the blutter rung's ELF validation
//! ([`crate::blutter::elf_facts`]) and adding Mach-O and zip
//! container validation beside it.
//!
//! The tool is observe-class: the registry's policy engine
//! default-denies it until the operator names
//! `jadart_decompile` in `allow_tools` (SPEC §8, the
//! game-extract lane pattern).

use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject, subject_for_file};
use fathom_core::limits::TARGET_BYTES_MAX;
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run};
use fathom_core::registry::{Registry, optional_str, require_str};

use crate::blutter::{candidate_kind, elf_facts};

/// Wall-clock bound for one jadart invocation. Jadart's full
/// export took 147.6 s on the LocalSend ground truth and each
/// per-command query re-parses the snapshot from scratch; the
/// bound mirrors the blutter/aotopsy cap so a wedged child is
/// stopped on the same discipline.
const JADART_TIMEOUT_SECS: u64 = 1_800;

/// Bytes of one jadart invocation's stdout captured. Jadart
/// answers in one JSON document per command (the full
/// `functions` document is ~15 MiB on the ground truth), so
/// the capture bound is the file-scale bound the other rungs
/// read outputs under, not the chat-scale process cap.
const JADART_OUTPUT_BYTES_MAX: usize = 268_435_456;

/// Census records retained per stream in the evidence;
/// totals are always computed over the full census, never
/// over the retained page.
const JADART_RECORDS_EVIDENCE_MAX: usize = 4_096;

/// String-pool entries retained in the evidence.
const JADART_STRINGS_EVIDENCE_MAX: usize = 4_096;

/// Constant-table entries retained in the evidence. The
/// ground truth holds 744, so a real target's whole table
/// rides; the bound only bites on a pathological pool.
const JADART_CONSTANTS_EVIDENCE_MAX: usize = 4_096;

/// Findings-candidate records retained in the evidence.
const JADART_CANDIDATES_EVIDENCE_MAX: usize = 4_096;

/// Entries retained from one bounded record's array fields.
const JADART_RECORD_ARRAY_ITEMS_MAX: usize = 64;

/// Characters retained from one bounded record's string
/// fields, and from one retained string-pool entry. The
/// pseudo-Dart records are never bounded this way: their
/// text is the lane's product and is preserved verbatim.
const JADART_RECORD_VALUE_CHARS_MAX: usize = 512;

/// Source files censused in one jadart export tree.
const JADART_EXPORT_FILES_MAX: usize = 4_096;

/// Bytes of one exported pseudo-Dart file read whole.
const JADART_EXPORT_FILE_BYTES_MAX: u64 = 4_194_304;

/// Total pseudo-Dart bytes retained in one envelope.
const JADART_EXPORT_TOTAL_BYTES_MAX: u64 = 67_108_864;

/// Members listed from one zip container's central directory.
const ZIP_ENTRIES_MAX: usize = 100_000;

/// Bytes of one zip central directory read.
const ZIP_CENTRAL_DIR_BYTES_MAX: u64 = 67_108_864;

/// Tail bytes searched for a zip end-of-central-directory
/// record (the record plus the longest legal comment).
const ZIP_EOCD_SEARCH_BYTES: u64 = 65_579;

/// ELF machine value for AArch64 (`EM_AARCH64`).
const ELF_MACHINE_AARCH64: u16 = 183;

/// ELF machine value for x86-64 (`EM_X86_64`).
const ELF_MACHINE_X86_64: u16 = 62;

/// Mach-O 64 magic, as a little-endian u32 read of the
/// file's first four bytes (`CF FA ED FE` on disk).
const MACHO_MAGIC_64_LE: u32 = 0xFEED_FACF;

/// Mach-O CPU type for x86-64 (`CPU_TYPE_X86_64`).
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

/// Mach-O CPU type for arm64 (`CPU_TYPE_ARM64`).
const CPU_TYPE_ARM64: u32 = 0x0100_000C;

/// ABI preference order for a zip's `libapp.so` members,
/// mirroring jadart's own `source.ABI_ORDER`.
const ABI_ORDER: &[&str] = &["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];

/// The Mach-O 64 header facts the lane decides on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachoFacts {
    /// The `cputype` value (0x0100000C for arm64).
    pub cpu_type: u32,
    /// The `filetype` value (6 for a dylib, 2 for an executable).
    pub file_type: u32,
}

/// Parse the Mach-O 64 header facts from the first bytes of
/// a file. Fail-closed, mirroring jadart's own `macho.py` /
/// `open_container` refusals: a short buffer is `truncated`,
/// a fat (universal) or big-endian file is
/// `unsupported_target` with the specific reason, a bad magic
/// is `unsupported_target`, and a CPU type jadart has no
/// grammar for (anything but arm64 / x86-64) is
/// `unsupported_target`.
pub fn macho_facts(header: &[u8]) -> Result<MachoFacts, FathomError> {
    if header.len() < 4 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "Mach-O header truncated: {} bytes, the 4-byte magic is incomplete",
                header.len()
            ),
        ));
    }
    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    match magic {
        MACHO_MAGIC_64_LE => {}
        // The same magic byte-swapped: a big-endian file.
        0xCFFA_EDFE => {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                "big-endian Mach-O is not supported".to_string(),
            ));
        }
        // Universal (fat) magics in either byte order.
        0xBEBA_FECA | 0xCAFE_BABE => {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                "universal (fat) Mach-O is not supported; extract one architecture first"
                    .to_string(),
            ));
        }
        _ => {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                "not a Mach-O 64 file (bad magic)".to_string(),
            ));
        }
    }
    if header.len() < 32 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "Mach-O header truncated: {} bytes, the 32-byte mach_header_64 is incomplete",
                header.len()
            ),
        ));
    }
    let cpu_type = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let file_type = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    if cpu_type != CPU_TYPE_ARM64 && cpu_type != CPU_TYPE_X86_64 {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "Mach-O CPU type {cpu_type:#x} is neither arm64 ({CPU_TYPE_ARM64:#x}) \
                 nor x86-64 ({CPU_TYPE_X86_64:#x}); jadart models those two only"
            ),
        ));
    }
    Ok(MachoFacts {
        cpu_type,
        file_type,
    })
}

/// Whether the first bytes carry a Mach-O magic in any of
/// the forms [`macho_facts`] adjudicates (thin LE, thin BE,
/// fat either order). A `false` here means the bytes are not
/// Mach-O at all; a `true` still leaves [`macho_facts`] to
/// refuse the unsupported forms with their specific errors.
fn has_macho_magic(header: &[u8]) -> bool {
    header.len() >= 4
        && matches!(
            u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
            MACHO_MAGIC_64_LE | 0xCFFA_EDFE | 0xBEBA_FECA | 0xCAFE_BABE
        )
}

/// The container family of one snapshot header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotKind {
    Elf { machine: u16 },
    Macho { cpu_type: u32 },
}

/// Validate one snapshot binary's header bytes: an ELF is
/// judged by the blutter rung's [`elf_facts`] plus this
/// lane's architecture rule (64-bit AArch64 or x86-64 — the
/// two ELF targets jadart's Tier 3 models), a Mach-O by
/// [`macho_facts`], anything else is `unsupported_target`.
fn validate_snapshot_header(header: &[u8], what: &str) -> Result<SnapshotKind, FathomError> {
    if header.starts_with(&[0x7f, b'E', b'L', b'F']) {
        if header.len() < 64 {
            return Err(FathomError::new(
                ErrorCode::Truncated,
                format!(
                    "{what} is {} bytes, shorter than an ELF64 header",
                    header.len()
                ),
            ));
        }
        let facts = elf_facts(header)?;
        if !facts.is_64_bit {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!(
                    "{what} is a 32-bit ELF; the jadart decompile lane covers \
                     the 64-bit targets (arm64, x86-64)"
                ),
            ));
        }
        if facts.machine != ELF_MACHINE_AARCH64 && facts.machine != ELF_MACHINE_X86_64 {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!(
                    "{what} is ELF machine {}, neither AArch64 ({ELF_MACHINE_AARCH64}) \
                     nor x86-64 ({ELF_MACHINE_X86_64})",
                    facts.machine
                ),
            ));
        }
        return Ok(SnapshotKind::Elf {
            machine: facts.machine,
        });
    }
    if has_macho_magic(header) {
        let facts = macho_facts(header)?;
        return Ok(SnapshotKind::Macho {
            cpu_type: facts.cpu_type,
        });
    }
    Err(FathomError::new(
        ErrorCode::UnsupportedTarget,
        format!("{what} is neither an ELF nor a Mach-O 64 binary (bad magic)"),
    ))
}

/// One member of a zip container's central directory.
#[derive(Clone, Debug)]
struct ZipMember {
    name: String,
    method: u16,
    compressed_size: u64,
    local_header_offset: u64,
}

/// Read a little-endian u16 at `offset`, bounds-checked.
fn zip_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Read a little-endian u32 at `offset`, bounds-checked.
fn zip_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read a little-endian u64 at `offset`, bounds-checked.
fn zip_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

/// Read `len` bytes of `file` at `offset`.
fn read_at(file: &mut std::fs::File, offset: u64, len: usize) -> Result<Vec<u8>, FathomError> {
    file.seek(SeekFrom::Start(offset)).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot seek a zip container: {e}"),
        )
    })?;
    let mut buffer = vec![0_u8; len];
    file.read_exact(&mut buffer).map_err(|e| {
        FathomError::new(
            ErrorCode::Truncated,
            format!("zip container ends mid-structure: {e}"),
        )
    })?;
    Ok(buffer)
}

/// Locate the central directory of the zip in `file`:
/// `(entries, cd_offset, cd_size)`. Handles the ZIP64
/// end-of-central-directory record when the classic record
/// saturates its fields.
fn zip_central_directory(
    file: &mut std::fs::File,
    file_len: u64,
) -> Result<(u64, u64, u64), FathomError> {
    let tail_len = file_len.min(ZIP_EOCD_SEARCH_BYTES);
    let tail = read_at(file, file_len - tail_len, tail_len as usize)?;
    let mut eocd: Option<usize> = None;
    if tail.len() >= 22 {
        for index in (0..=tail.len() - 4).rev() {
            if tail[index..index + 4] == [0x50, 0x4b, 0x05, 0x06] {
                eocd = Some(index);
                break;
            }
        }
    }
    let eocd = eocd.ok_or_else(|| {
        FathomError::new(
            ErrorCode::Truncated,
            "zip container holds no end-of-central-directory record".to_string(),
        )
    })?;
    let record = &tail[eocd..];
    let entries = zip_u16(record, 10).unwrap_or(0) as u64;
    let cd_size = zip_u32(record, 12).unwrap_or(0) as u64;
    let cd_offset = zip_u32(record, 16).unwrap_or(0) as u64;
    if entries != 0xFFFF && cd_size != 0xFFFF_FFFF && cd_offset != 0xFFFF_FFFF {
        return Ok((entries, cd_offset, cd_size));
    }
    // ZIP64: the locator sits immediately before the EOCD.
    let eocd_abs = file_len - tail_len + eocd as u64;
    if eocd_abs < 20 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            "zip container saturates its EOCD fields but holds no ZIP64 locator".to_string(),
        ));
    }
    let locator = read_at(file, eocd_abs - 20, 20)?;
    if locator[0..4] != [0x50, 0x4b, 0x06, 0x07] {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            "zip container saturates its EOCD fields but holds no ZIP64 locator".to_string(),
        ));
    }
    let zip64_offset = zip_u64(&locator, 8).unwrap_or(0);
    let record64 = read_at(file, zip64_offset, 56)?;
    if record64[0..4] != [0x50, 0x4b, 0x06, 0x06] {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            "zip container's ZIP64 locator names no ZIP64 EOCD record".to_string(),
        ));
    }
    Ok((
        zip_u64(&record64, 32).unwrap_or(0),
        zip_u64(&record64, 48).unwrap_or(0),
        zip_u64(&record64, 40).unwrap_or(0),
    ))
}

/// List the members of the zip container at `path` from its
/// central directory. Every structural surprise is a typed
/// error; the directory is data, never trusted.
fn zip_members(path: &Path, file_len: u64) -> Result<Vec<ZipMember>, FathomError> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot open {}: {e}", path.display()),
        )
    })?;
    let (entries, cd_offset, cd_size) = zip_central_directory(&mut file, file_len)?;
    if entries > ZIP_ENTRIES_MAX as u64 {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("zip container lists {entries} members, over the {ZIP_ENTRIES_MAX} bound"),
        ));
    }
    if cd_size > ZIP_CENTRAL_DIR_BYTES_MAX || cd_offset + cd_size > file_len {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "zip central directory at {cd_offset} spanning {cd_size} bytes \
                 exceeds the {file_len}-byte container"
            ),
        ));
    }
    let directory = read_at(&mut file, cd_offset, cd_size as usize)?;
    let mut members: Vec<ZipMember> = Vec::new();
    let mut cursor = 0_usize;
    while cursor < directory.len() {
        if directory.len() - cursor < 46
            || directory[cursor..cursor + 4] != [0x50, 0x4b, 0x01, 0x02]
        {
            return Err(FathomError::new(
                ErrorCode::Truncated,
                format!("zip central directory entry at {cursor} is not a central header"),
            ));
        }
        let entry = &directory[cursor..];
        let method = zip_u16(entry, 10).unwrap_or(0);
        let mut compressed_size = zip_u32(entry, 20).unwrap_or(0) as u64;
        let mut uncompressed_size = zip_u32(entry, 24).unwrap_or(0) as u64;
        let mut local_header_offset = zip_u32(entry, 42).unwrap_or(0) as u64;
        let name_len = zip_u16(entry, 28).unwrap_or(0) as usize;
        let extra_len = zip_u16(entry, 30).unwrap_or(0) as usize;
        let comment_len = zip_u16(entry, 32).unwrap_or(0) as usize;
        let name_start = 46;
        let name_end = name_start + name_len;
        let extra_end = name_end + extra_len;
        if extra_end > entry.len() {
            return Err(FathomError::new(
                ErrorCode::Truncated,
                "zip central directory entry runs past the directory".to_string(),
            ));
        }
        // ZIP64 extra field (0x0001): values appear in the
        // order of the header fields they saturate.
        let extra = &entry[name_end..extra_end];
        let mut extra_cursor = 0_usize;
        while extra_cursor + 4 <= extra.len() {
            let field_id = zip_u16(extra, extra_cursor).unwrap_or(0);
            let field_len = zip_u16(extra, extra_cursor + 2).unwrap_or(0) as usize;
            let body_start = extra_cursor + 4;
            if field_id == 0x0001 {
                let mut value_cursor = body_start;
                if uncompressed_size == 0xFFFF_FFFF {
                    uncompressed_size = zip_u64(extra, value_cursor).unwrap_or(0);
                    value_cursor += 8;
                }
                if compressed_size == 0xFFFF_FFFF {
                    compressed_size = zip_u64(extra, value_cursor).unwrap_or(0);
                    value_cursor += 8;
                }
                if local_header_offset == 0xFFFF_FFFF {
                    local_header_offset = zip_u64(extra, value_cursor).unwrap_or(0);
                }
            }
            extra_cursor = body_start + field_len;
        }
        let name = String::from_utf8_lossy(&entry[name_start..name_end]).into_owned();
        members.push(ZipMember {
            name,
            method,
            compressed_size,
            local_header_offset,
        });
        cursor += 46 + name_len + extra_len + comment_len;
    }
    Ok(members)
}

/// Pick the snapshot member of a zip, mirroring jadart's
/// `source._pick_member`: a `libapp.so` (best ABI first)
/// wins over an iOS `App.framework/App`.
fn pick_snapshot_member(members: &[ZipMember]) -> Option<&ZipMember> {
    let mut libapps: Vec<&ZipMember> = members
        .iter()
        .filter(|member| member.name.ends_with("libapp.so"))
        .collect();
    libapps.sort_by_key(|member| {
        ABI_ORDER
            .iter()
            .position(|abi| member.name.contains(abi))
            .unwrap_or(99)
    });
    if let Some(member) = libapps.first() {
        return Some(member);
    }
    members
        .iter()
        .find(|member| member.name.ends_with("App.framework/App"))
}

/// Read the first `want` bytes of one zip member's data
/// (stored members read directly; deflated members inflate
/// under the same bound). The member's own header geometry
/// is validated before any byte is trusted.
fn zip_member_header(path: &Path, member: &ZipMember, want: usize) -> Result<Vec<u8>, FathomError> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot open {}: {e}", path.display()),
        )
    })?;
    let local = read_at(&mut file, member.local_header_offset, 30)?;
    if local[0..4] != [0x50, 0x4b, 0x03, 0x04] {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "zip member {} has no local header at {}",
                member.name, member.local_header_offset
            ),
        ));
    }
    let name_len = zip_u16(&local, 26).unwrap_or(0) as u64;
    let extra_len = zip_u16(&local, 28).unwrap_or(0) as u64;
    let data_offset = member.local_header_offset + 30 + name_len + extra_len;
    match member.method {
        0 => read_at(&mut file, data_offset, want),
        8 => {
            if member.compressed_size > ZIP_CENTRAL_DIR_BYTES_MAX {
                return Err(FathomError::new(
                    ErrorCode::ResourceConstraint,
                    format!(
                        "zip member {} claims {} compressed bytes",
                        member.name, member.compressed_size
                    ),
                ));
            }
            let compressed = read_at(&mut file, data_offset, member.compressed_size as usize)?;
            let mut decoder = flate2::read::DeflateDecoder::new(&compressed[..]);
            let mut header = vec![0_u8; want];
            let mut filled = 0_usize;
            while filled < want {
                match decoder.read(&mut header[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(e) => {
                        return Err(FathomError::new(
                            ErrorCode::UnreadableOutput,
                            format!("cannot inflate zip member {}: {e}", member.name),
                        ));
                    }
                }
            }
            header.truncate(filled);
            Ok(header)
        }
        other => Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "zip member {} uses compression method {other}, neither stored nor deflate",
                member.name
            ),
        )),
    }
}

/// A validated jadart target: what jadart will be handed,
/// what the evidence subject hashes, and the shape facts the
/// envelope records.
#[derive(Clone, Debug)]
pub struct JadartTarget {
    /// Path handed to jadart (the target as named: an APK, a
    /// bare binary, or a directory jadart resolves itself).
    pub jadart_path: PathBuf,
    /// File the evidence subject is taken over.
    pub subject_path: PathBuf,
    /// Input shape: `apk`, `ipa`, `bare_libapp`,
    /// `macho_binary`, `lib_dir`, `framework_dir`, or
    /// `directory_tree`.
    pub shape: String,
    /// Container family: `zip`, `elf`, `mach-o`, or
    /// `directory`.
    pub container: String,
    /// Snapshot member inside a zip, when the target is one.
    pub snapshot_member: Option<String>,
    /// ELF machine of the snapshot binary, when it is ELF.
    pub snapshot_machine: Option<u16>,
    /// Mach-O CPU type of the snapshot binary, when Mach-O.
    pub snapshot_cpu_type: Option<u32>,
    /// Size of the target as named (file bytes, or the
    /// snapshot binary's bytes for a directory).
    pub target_bytes: u64,
}

/// Stat one file under the lane's target bound.
fn target_file_len(path: &Path) -> Result<u64, FathomError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat {}: {e}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > TARGET_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "{} exceeds the {TARGET_BYTES_MAX}-byte target bound",
                path.display()
            ),
        ));
    }
    Ok(metadata.len())
}

/// Read the first `want` bytes of a regular file.
fn read_file_header(path: &Path, want: usize) -> Result<Vec<u8>, FathomError> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot open {}: {e}", path.display()),
        )
    })?;
    let mut buffer = vec![0_u8; want];
    let mut filled = 0_usize;
    while filled < want {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(e) => {
                return Err(FathomError::new(
                    ErrorCode::UnreadableOutput,
                    format!("cannot read {}: {e}", path.display()),
                ));
            }
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Validate a file target (zip container, bare ELF, or bare
/// Mach-O) and describe it for the envelope.
fn validate_file_target(path: &Path) -> Result<JadartTarget, FathomError> {
    let target_bytes = target_file_len(path)?;
    if target_bytes == 0 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!("{} is empty (0 bytes)", path.display()),
        ));
    }
    let header = read_file_header(path, 64)?;
    if header.starts_with(b"PK\x03\x04") {
        let members = zip_members(path, target_bytes)?;
        let member = pick_snapshot_member(&members).ok_or_else(|| {
            FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!(
                    "{} is a zip with no Flutter snapshot in it (looked for \
                     libapp.so and App.framework/App); not a Flutter app container",
                    path.display()
                ),
            )
            .with_target(path.display().to_string())
        })?;
        let member_header = zip_member_header(path, member, 64)?;
        let kind =
            validate_snapshot_header(&member_header, &format!("zip member {}", member.name))?;
        let (shape, machine, cpu_type) = match kind {
            SnapshotKind::Elf { machine } => (
                if member.name.ends_with("App.framework/App") {
                    "ipa"
                } else {
                    "apk"
                },
                Some(machine),
                None,
            ),
            SnapshotKind::Macho { cpu_type } => ("ipa", None, Some(cpu_type)),
        };
        return Ok(JadartTarget {
            jadart_path: path.to_path_buf(),
            subject_path: path.to_path_buf(),
            shape: shape.to_string(),
            container: "zip".to_string(),
            snapshot_member: Some(member.name.clone()),
            snapshot_machine: machine,
            snapshot_cpu_type: cpu_type,
            target_bytes,
        });
    }
    let kind = validate_snapshot_header(&header, &path.display().to_string())?;
    let (shape, container, machine, cpu_type) = match kind {
        SnapshotKind::Elf { machine } => ("bare_libapp", "elf", Some(machine), None),
        SnapshotKind::Macho { cpu_type } => ("macho_binary", "mach-o", None, Some(cpu_type)),
    };
    Ok(JadartTarget {
        jadart_path: path.to_path_buf(),
        subject_path: path.to_path_buf(),
        shape: shape.to_string(),
        container: container.to_string(),
        snapshot_member: None,
        snapshot_machine: machine,
        snapshot_cpu_type: cpu_type,
        target_bytes,
    })
}

/// Validate a directory target: an `App.framework` directory
/// (its `App` Mach-O), a directory holding `libapp.so`
/// directly, or an extracted tree holding
/// `lib/<abi>/libapp.so`. A directory holding none of these
/// is `target_unavailable` — the counterpart file jadart
/// needs is missing.
fn validate_dir_target(dir: &Path) -> Result<JadartTarget, FathomError> {
    let app = dir.join("App");
    if app.is_file() {
        let target_bytes = target_file_len(&app)?;
        let header = read_file_header(&app, 64)?;
        let facts = macho_facts(&header).map_err(|err| {
            FathomError::new(
                err.code,
                format!(
                    "{} (the App.framework App binary): {}",
                    err.message,
                    app.display()
                ),
            )
        })?;
        return Ok(JadartTarget {
            jadart_path: dir.to_path_buf(),
            subject_path: app,
            shape: "framework_dir".to_string(),
            container: "mach-o".to_string(),
            snapshot_member: None,
            snapshot_machine: None,
            snapshot_cpu_type: Some(facts.cpu_type),
            target_bytes,
        });
    }
    let direct = dir.join("libapp.so");
    let tree = ABI_ORDER
        .iter()
        .map(|abi| dir.join("lib").join(abi).join("libapp.so"))
        .find(|candidate| candidate.is_file());
    let (libapp, shape) = match (direct.is_file(), tree) {
        (true, _) => (direct, "lib_dir"),
        (false, Some(found)) => (found, "directory_tree"),
        (false, None) => {
            return Err(FathomError::new(
                ErrorCode::TargetUnavailable,
                format!(
                    "{} holds no App binary, no libapp.so, and no \
                     lib/<abi>/libapp.so; not a Flutter target directory",
                    dir.display()
                ),
            )
            .with_target(dir.display().to_string()));
        }
    };
    let target_bytes = target_file_len(&libapp)?;
    let header = read_file_header(&libapp, 64)?;
    let kind = validate_snapshot_header(&header, &libapp.display().to_string())?;
    let (machine, cpu_type) = match kind {
        SnapshotKind::Elf { machine } => (Some(machine), None),
        SnapshotKind::Macho { cpu_type } => (None, Some(cpu_type)),
    };
    Ok(JadartTarget {
        jadart_path: dir.to_path_buf(),
        subject_path: libapp,
        shape: shape.to_string(),
        container: "elf".to_string(),
        snapshot_member: None,
        snapshot_machine: machine,
        snapshot_cpu_type: cpu_type,
        target_bytes,
    })
}

/// Validate any jadart target shape. Every failure is a
/// typed error and nothing is claimed about a target that
/// fails validation; jadart runs only on a target that
/// passes.
pub fn validate_jadart_target(target: &Path) -> Result<JadartTarget, FathomError> {
    if target.is_dir() {
        return validate_dir_target(target);
    }
    if target.is_file() {
        return validate_file_target(target);
    }
    Err(FathomError::new(
        ErrorCode::TargetUnavailable,
        format!("{} is neither a file nor a directory", target.display()),
    )
    .with_target(target.display().to_string()))
}

/// One jadart typed JSON error, as printed on stdout with
/// `-j`: `{"ok": false, "error": ..., "type": ..., "exit": 2}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JadartTypedError {
    /// Jadart's exception class name (`ContainerError`,
    /// `InputError`, `UnknownEpoch`, ...).
    pub jadart_type: String,
    /// Jadart's full error message, offsets included.
    pub message: String,
    /// The exit code jadart reported for the failure.
    pub exit_code: i32,
    /// True when jadart flagged the failure as its own bug
    /// (exit 3), not a property of the input.
    pub internal: bool,
}

/// Parse a jadart typed error document from stdout. `None`
/// when the text is not one JSON document carrying
/// `ok: false` and a `type` — a caller then reports the run
/// as unreadable output rather than inventing a type.
pub fn parse_jadart_typed_error(stdout: &str) -> Option<JadartTypedError> {
    let value: Value = serde_json::from_str(stdout.trim()).ok()?;
    if value.get("ok") != Some(&Value::Bool(false)) {
        return None;
    }
    let jadart_type = value.get("type")?.as_str()?.to_string();
    let message = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let exit_code = value
        .get("exit")
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(-1);
    let internal = value.get("internal") == Some(&Value::Bool(true));
    Some(JadartTypedError {
        jadart_type,
        message,
        exit_code,
        internal,
    })
}

/// The fathom code one jadart error type maps onto. The
/// mapping is one-for-one in kind: each jadart type has
/// exactly one home, chosen by what the type *means* —
/// malformed-container geometry and truncated streams are
/// `truncated`, not-a-Flutter-input and unknown-epoch and
/// unsupported-target refusals are `unsupported_target`,
/// snapshot walks that cannot complete are
/// `unreadable_output`, a missing capstone in the lane
/// install is `capability_unavailable`, a name the binary
/// does not hold is `invalid_request`, and jadart's own
/// internal failures (exit 3) are `execution_failure`.
pub fn jadart_error_code(typed: &JadartTypedError) -> ErrorCode {
    if typed.internal || typed.exit_code == 3 {
        return ErrorCode::ExecutionFailure;
    }
    match typed.jadart_type.as_str() {
        "ContainerError" | "TruncatedSnapshot" => ErrorCode::Truncated,
        "InputError" | "MissingSymbol" | "UnknownEpoch" | "UnsupportedArch"
        | "UnsupportedTarget" => ErrorCode::UnsupportedTarget,
        "AllocError" | "FillError" => ErrorCode::UnreadableOutput,
        "MissingDisassembler" => ErrorCode::CapabilityUnavailable,
        "NotFound" => ErrorCode::InvalidRequest,
        _ if typed.exit_code == 2 => ErrorCode::UnsupportedTarget,
        _ => ErrorCode::ExecutionFailure,
    }
}

/// Map one jadart typed error onto its fathom typed error.
/// The jadart type name and its full message (exact offsets
/// included) survive verbatim in the fathom message and in
/// the error details; nothing about the failure is lost in
/// translation.
pub fn map_jadart_error(command: &str, typed: &JadartTypedError) -> FathomError {
    FathomError::new(
        jadart_error_code(typed),
        format!(
            "jadart {command} failed with {}: {}",
            typed.jadart_type, typed.message
        ),
    )
    .with_details(json!({
        "jadart_type": typed.jadart_type,
        "jadart_exit": typed.exit_code,
        "jadart_error": typed.message,
        "jadart_internal": typed.internal,
    }))
}

/// Locate the pinned jadart install: the operator names its
/// venv with `FATHOM_JADART_DIR` (the estate's Ghidra
/// pattern). The directory must hold `bin/jadart`, the
/// console script of the pinned install.
pub fn locate_jadart() -> Option<PathBuf> {
    let dir = std::env::var("FATHOM_JADART_DIR").ok()?;
    let dir = PathBuf::from(dir);
    let binary = dir.join("bin").join("jadart");
    if binary.is_file() { Some(binary) } else { None }
}

/// Run one jadart subcommand in JSON mode and return its
/// document. Exit 0 must carry `ok: true`; any other exit
/// goes through the typed-error mapping when stdout holds
/// the typed document, and is `unreadable_output` (never a
/// success, never an untyped execution failure) when it
/// does not.
fn run_jadart(jadart_bin: &Path, command: &str, args: &[String]) -> Result<Value, FathomError> {
    let outcome = run(&ProcessSpec {
        args: args.to_vec(),
        cwd: None,
        env: Vec::new(),
        output_cap: JADART_OUTPUT_BYTES_MAX,
        program: jadart_bin.display().to_string(),
        timeout: Duration::from_secs(JADART_TIMEOUT_SECS),
    })?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!("jadart {command} exceeded {JADART_TIMEOUT_SECS} seconds and was stopped"),
        ));
    }
    let stdout = String::from_utf8_lossy(&outcome.stdout).into_owned();
    if outcome.exit_code == Some(0) {
        let value: Value = serde_json::from_str(stdout.trim()).map_err(|e| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                format!("jadart {command} exited 0 but stdout is not one JSON document: {e}"),
            )
        })?;
        if value.get("ok") == Some(&Value::Bool(true)) {
            return Ok(value);
        }
        if let Some(typed) = parse_jadart_typed_error(&stdout) {
            return Err(map_jadart_error(command, &typed));
        }
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("jadart {command} exited 0 without an ok:true JSON document"),
        ));
    }
    if let Some(typed) = parse_jadart_typed_error(&stdout) {
        return Err(map_jadart_error(command, &typed));
    }
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    let excerpt: String = stderr.chars().take(512).collect();
    Err(FathomError::new(
        ErrorCode::UnreadableOutput,
        format!(
            "jadart {command} exited with {:?} and no JSON error document; \
             stderr excerpt: {excerpt}",
            outcome.exit_code
        ),
    ))
}

/// Run `jadart verify` in JSON mode. Verify's exit 1 is a
/// *result* (the acceptance gates failed on a parseable
/// snapshot), not a typed error: its document rides into
/// evidence either way. Exit 2 keeps the typed-error path.
fn run_jadart_verify(jadart_bin: &Path, target: &str) -> Result<Value, FathomError> {
    let args = vec!["-j".to_string(), "verify".to_string(), target.to_string()];
    let outcome = run(&ProcessSpec {
        args,
        cwd: None,
        env: Vec::new(),
        output_cap: JADART_OUTPUT_BYTES_MAX,
        program: jadart_bin.display().to_string(),
        timeout: Duration::from_secs(JADART_TIMEOUT_SECS),
    })?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!("jadart verify exceeded {JADART_TIMEOUT_SECS} seconds and was stopped"),
        ));
    }
    let stdout = String::from_utf8_lossy(&outcome.stdout).into_owned();
    if (outcome.exit_code == Some(0) || outcome.exit_code == Some(1))
        && let Ok(value) = serde_json::from_str::<Value>(stdout.trim())
        && value.get("gates").is_some_and(Value::is_array)
    {
        return Ok(value);
    }
    if let Some(typed) = parse_jadart_typed_error(&stdout) {
        return Err(map_jadart_error("verify", &typed));
    }
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    let excerpt: String = stderr.chars().take(512).collect();
    Err(FathomError::new(
        ErrorCode::UnreadableOutput,
        format!(
            "jadart verify exited with {:?} and no gates document; stderr excerpt: {excerpt}",
            outcome.exit_code
        ),
    ))
}

/// Bound one JSON record for evidence retention: string
/// fields truncated to `JADART_RECORD_VALUE_CHARS_MAX`
/// characters, array fields to
/// `JADART_RECORD_ARRAY_ITEMS_MAX` entries, recursively.
/// Census records only — pseudo-Dart text never passes
/// through here.
fn bound_record_value(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            Value::String(text.chars().take(JADART_RECORD_VALUE_CHARS_MAX).collect())
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(JADART_RECORD_ARRAY_ITEMS_MAX)
                .map(bound_record_value)
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| (key.clone(), bound_record_value(field)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The census over one jadart export `sources/` tree.
#[derive(Clone, Debug, Default)]
pub struct ExportCensus {
    /// Source files found in the tree.
    pub files_total: usize,
    /// Files retained as evidence records.
    pub files_retained: usize,
    /// Files dropped (past a bound, oversized, or unreadable).
    pub files_dropped: usize,
    /// Bytes over all files found.
    pub bytes_total: u64,
    /// Bytes over the retained records.
    pub bytes_retained: u64,
    /// Retained records: `{library, bytes, sha256, text}`,
    /// the text verbatim from jadart's export.
    pub records: Vec<Value>,
}

/// Collect `.dart` files under `dir`, bounded and
/// deterministic (the blutter rung's collector shape).
fn collect_export_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FathomError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot list {}: {e}", dir.display()),
        )
    })?;
    let mut rows: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    rows.sort();
    for path in rows {
        if path.is_dir() {
            collect_export_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "dart") {
            out.push(path);
        }
    }
    Ok(())
}

/// Census one jadart export `sources/` directory: every
/// file is counted and hashed; retained files ride into the
/// evidence with their pseudo-Dart text byte-for-byte as
/// jadart wrote it. A missing tree is a typed error — a
/// finished export that cannot show its sources is never
/// reported as partial evidence.
pub fn census_export_sources(sources_dir: &Path) -> Result<ExportCensus, FathomError> {
    if !sources_dir.is_dir() {
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            format!(
                "jadart export holds no sources/ directory at {}",
                sources_dir.display()
            ),
        ));
    }
    let mut files: Vec<PathBuf> = Vec::new();
    collect_export_files(sources_dir, &mut files)?;
    files.sort();
    let mut census = ExportCensus {
        files_total: files.len(),
        ..ExportCensus::default()
    };
    for file in files {
        let metadata = match std::fs::metadata(&file) {
            Ok(metadata) => metadata,
            Err(_) => {
                census.files_dropped += 1;
                continue;
            }
        };
        census.bytes_total += metadata.len();
        if census.records.len() >= JADART_EXPORT_FILES_MAX
            || metadata.len() > JADART_EXPORT_FILE_BYTES_MAX
            || census.bytes_retained + metadata.len() > JADART_EXPORT_TOTAL_BYTES_MAX
        {
            census.files_dropped += 1;
            continue;
        }
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(_) => {
                census.files_dropped += 1;
                continue;
            }
        };
        let (sha256, _) = fathom_core::evidence::hash_file(&file)?;
        let rel = file
            .strip_prefix(sources_dir)
            .map(|rel| rel.display().to_string())
            .unwrap_or_else(|_| file.display().to_string());
        census.bytes_retained += metadata.len();
        census.files_retained += 1;
        census.records.push(json!({
            "library": rel,
            "bytes": metadata.len(),
            "sha256": sha256,
            "text": text,
        }));
    }
    Ok(census)
}

/// The `jadart_decompile` tool: run the pinned jadart over
/// a validated Flutter target and ingest its outputs.
pub fn jadart_decompile(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target_raw = require_str(args, "target")?;
    let target = paths::validate_target(config, Path::new(target_raw))?;
    let output_dir = match optional_str(args, "output_dir") {
        Some(raw) => Some(paths::validate_output_dir(config, Path::new(raw))?),
        None => None,
    };
    analyze_with_jadart(config, &target, output_dir, locate_jadart())
}

/// The lane's work, with the jadart location explicit so
/// tests can drive it with a fixture jadart.
fn analyze_with_jadart(
    config: &Config,
    target: &Path,
    output_dir: Option<PathBuf>,
    jadart_bin: Option<PathBuf>,
) -> Result<Value, FathomError> {
    let validated = validate_jadart_target(target)?;
    let jadart_bin = jadart_bin.ok_or_else(|| {
        FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "jadart is not located; set FATHOM_JADART_DIR to the venv directory \
             holding bin/jadart from the pinned install",
        )
        .with_remediation(
            "Install IR0NBYTE/Jadart v1.4.0 (fe2e93fab45f30c78de6afd843792a0225c0cbe5) \
             with capstone 5.0.7 into an isolated venv and set FATHOM_JADART_DIR \
             to that venv.",
        )
    })?;
    let subject = subject_for_file(&validated.subject_path)?;
    let out_dir = match output_dir {
        Some(dir) => dir,
        None => {
            let base = paths::state_subdir(config, "jadart")?;
            let named = base.join(&subject.sha256[..16]);
            std::fs::create_dir_all(&named).map_err(|e| {
                FathomError::new(
                    ErrorCode::ExecutionFailure,
                    format!("cannot create output directory {}: {e}", named.display()),
                )
            })?;
            named
        }
    };
    let export_dir = out_dir.join("export");
    std::fs::create_dir_all(&export_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "cannot create export directory {}: {e}",
                export_dir.display()
            ),
        )
    })?;
    let target_arg = validated.jadart_path.display().to_string();
    let info = run_jadart(
        &jadart_bin,
        "info",
        &["-j".into(), "info".into(), target_arg.clone()],
    )?;
    let classes = run_jadart(
        &jadart_bin,
        "classes",
        &["-j".into(), "classes".into(), target_arg.clone()],
    )?;
    let functions = run_jadart(
        &jadart_bin,
        "functions",
        &[
            "-j".into(),
            "functions".into(),
            target_arg.clone(),
            "-n".into(),
            "0".into(),
        ],
    )?;
    let strings = run_jadart(
        &jadart_bin,
        "strings",
        &["-j".into(), "strings".into(), target_arg.clone()],
    )?;
    let constants = run_jadart(
        &jadart_bin,
        "constants",
        &["-j".into(), "constants".into(), target_arg.clone()],
    )?;
    let verify = run_jadart_verify(&jadart_bin, &target_arg)?;
    let export = run_jadart(
        &jadart_bin,
        "export",
        &[
            "-j".into(),
            "export".into(),
            target_arg.clone(),
            "-o".into(),
            export_dir.display().to_string(),
        ],
    )?;
    build_evidence(
        &validated,
        &info,
        &classes,
        &functions,
        &strings,
        &constants,
        &verify,
        &export,
        &export_dir,
        subject,
    )
}

/// Read a required array field of one jadart document; a
/// document missing its census array is unreadable output,
/// never a silent zero.
fn doc_array<'a>(
    doc: &'a Value,
    field: &str,
    command: &str,
) -> Result<&'a Vec<Value>, FathomError> {
    doc.get(field).and_then(Value::as_array).ok_or_else(|| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("jadart {command} document holds no {field} array"),
        )
    })
}

/// Read a required count field of one jadart document.
fn doc_count(doc: &Value, field: &str, command: &str) -> Result<usize, FathomError> {
    doc.get(field)
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                format!("jadart {command} document holds no {field} count"),
            )
        })
}

/// Ingest the finished jadart documents and export tree
/// into an evidence envelope. Missing census arrays are
/// typed errors, never partial claims.
#[allow(clippy::too_many_arguments)]
fn build_evidence(
    validated: &JadartTarget,
    info: &Value,
    classes_doc: &Value,
    functions_doc: &Value,
    strings_doc: &Value,
    constants_doc: &Value,
    verify_doc: &Value,
    export_doc: &Value,
    export_dir: &Path,
    subject: Subject,
) -> Result<Value, FathomError> {
    let mut evidence = Evidence::new("jadart_decompile", "jadart").with_subject(subject);
    evidence.add_finding(Finding::new(
        "jadart_target",
        Confidence::Observed,
        json!({
            "shape": validated.shape,
            "container": validated.container,
            "jadart_path": validated.jadart_path.display().to_string(),
            "subject_path": validated.subject_path.display().to_string(),
            "snapshot_member": validated.snapshot_member,
            "snapshot_machine": validated.snapshot_machine,
            "snapshot_cpu_type": validated.snapshot_cpu_type,
            "target_bytes": validated.target_bytes,
        }),
    ));
    let isolate = info
        .get("snapshots")
        .and_then(|snaps| snaps.get("isolate"))
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                "jadart info document holds no isolate snapshot".to_string(),
            )
        })?;
    evidence.add_finding(Finding::new(
        "dart_version",
        Confidence::Observed,
        json!({
            "version": isolate.get("dart").cloned().unwrap_or(Value::Null),
            "snapshot_hash": isolate.get("version_hash").cloned().unwrap_or(Value::Null),
            "epoch": isolate.get("epoch").cloned().unwrap_or(Value::Null),
            "target": isolate.get("target").cloned().unwrap_or(Value::Null),
            "features": isolate.get("features").cloned().unwrap_or(Value::Null),
            "container": info.pointer("/anchor/container").cloned().unwrap_or(Value::Null),
            "source": "jadart info -j (snapshot header read directly from the \
                       container; jadart reports the exact SDK version)",
        }),
    ));
    let class_rows = doc_array(classes_doc, "classes", "classes")?;
    let classes_total = doc_count(classes_doc, "count", "classes")?;
    let members_total: usize = class_rows
        .iter()
        .map(|row| {
            row.get("members")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum();
    let classes_retained: Vec<Value> = class_rows
        .iter()
        .take(JADART_RECORDS_EVIDENCE_MAX)
        .map(bound_record_value)
        .collect();
    evidence.add_finding(Finding::new(
        "jadart_classes",
        Confidence::Observed,
        json!({
            "total": classes_total,
            "members_total": members_total,
            "epoch": classes_doc.get("epoch").cloned().unwrap_or(Value::Null),
            "records_retained": classes_retained.len(),
            "records_bounded": true,
            "records": classes_retained,
        }),
    ));
    let function_rows = doc_array(functions_doc, "functions", "functions")?;
    let functions_total = doc_count(functions_doc, "total", "functions")?;
    let functions_matched = doc_count(functions_doc, "matched", "functions")?;
    let functions_retained: Vec<Value> = function_rows
        .iter()
        .take(JADART_RECORDS_EVIDENCE_MAX)
        .map(bound_record_value)
        .collect();
    evidence.add_finding(Finding::new(
        "jadart_functions",
        Confidence::Observed,
        json!({
            "total": functions_total,
            "matched": functions_matched,
            "call_graph": functions_doc.get("call_graph").cloned().unwrap_or(Value::Null),
            "call_graph_error": functions_doc.get("call_graph_error").cloned()
                .unwrap_or(Value::Null),
            "records_retained": functions_retained.len(),
            "records": functions_retained,
        }),
    ));
    let string_rows = doc_array(strings_doc, "strings", "strings")?;
    let strings_total = doc_count(strings_doc, "count", "strings")?;
    let mut candidates: Vec<Value> = Vec::new();
    for row in string_rows {
        let Some(text) = row.as_str() else { continue };
        if let Some(kind) = candidate_kind(text)
            && candidates.len() < JADART_CANDIDATES_EVIDENCE_MAX
        {
            candidates.push(json!({
                "candidate_kind": kind,
                "value": text.chars().take(JADART_RECORD_VALUE_CHARS_MAX)
                    .collect::<String>(),
                "status": "candidate_for_review_not_a_finding",
            }));
        }
    }
    let strings_retained: Vec<Value> = string_rows
        .iter()
        .take(JADART_STRINGS_EVIDENCE_MAX)
        .map(|row| {
            Value::String(
                row.as_str()
                    .unwrap_or("")
                    .chars()
                    .take(JADART_RECORD_VALUE_CHARS_MAX)
                    .collect(),
            )
        })
        .collect();
    evidence.add_finding(Finding::new(
        "jadart_strings",
        Confidence::Observed,
        json!({
            "total": strings_total,
            "epoch": strings_doc.get("epoch").cloned().unwrap_or(Value::Null),
            "records_retained": strings_retained.len(),
            "records_bounded": true,
            "records": strings_retained,
        }),
    ));
    let constant_rows = doc_array(constants_doc, "constants", "constants")?;
    let constants_total = doc_count(constants_doc, "count", "constants")?;
    let constants_retained: Vec<Value> = constant_rows
        .iter()
        .take(JADART_CONSTANTS_EVIDENCE_MAX)
        .cloned()
        .collect();
    evidence.add_finding(Finding::new(
        "jadart_constants",
        Confidence::Observed,
        json!({
            "total": constants_total,
            "records_retained": constants_retained.len(),
            "records": constants_retained,
        }),
    ));
    evidence.add_finding(Finding::new(
        "jadart_verify",
        Confidence::Observed,
        json!({
            "supported": verify_doc.get("ok").cloned().unwrap_or(Value::Null),
            "epoch": verify_doc.get("epoch").cloned().unwrap_or(Value::Null),
            "target": verify_doc.get("target").cloned().unwrap_or(Value::Null),
            "passed": verify_doc.get("passed").cloned().unwrap_or(Value::Null),
            "failed": verify_doc.get("failed").cloned().unwrap_or(Value::Null),
            "gates": verify_doc.get("gates").cloned().unwrap_or(Value::Null),
        }),
    ));
    let census = census_export_sources(&export_dir.join("sources"))?;
    evidence.add_finding(
        Finding::new(
            "jadart_pseudo_dart",
            Confidence::Observed,
            json!({
                "libraries_total": export_doc.get("libraries").cloned()
                    .unwrap_or(Value::Null),
                "files_total": census.files_total,
                "files_retained": census.files_retained,
                "files_dropped": census.files_dropped,
                "bytes_total": census.bytes_total,
                "bytes_retained": census.bytes_retained,
                "libraries": census.records,
            }),
        )
        .with_limitation(
            "Pseudo-Dart is jadart's reconstruction of the compiled program: \
             operation order, pool offsets, and string literals are recovered \
             faithfully, while pool entries and fields the binary does not name \
             stay raw (pool_0x.., field_0x..). The text is preserved verbatim \
             from jadart's export, never summarised, so spec work reads what \
             jadart actually recovered",
        ),
    );
    evidence.add_finding(Finding::new(
        "jadart_export",
        Confidence::Observed,
        json!({
            "out": export_doc.get("out").cloned().unwrap_or(Value::Null),
            "tier": export_doc.get("tier").cloned().unwrap_or(Value::Null),
            "libraries": export_doc.get("libraries").cloned().unwrap_or(Value::Null),
            "classes": export_doc.get("classes").cloned().unwrap_or(Value::Null),
            "methods": export_doc.get("methods").cloned().unwrap_or(Value::Null),
            "strings": export_doc.get("strings").cloned().unwrap_or(Value::Null),
            "selectors": export_doc.get("selectors").cloned().unwrap_or(Value::Null),
        }),
    ));
    if !candidates.is_empty() {
        evidence.add_finding(
            Finding::new(
                "jadart_findings_candidates",
                Confidence::Inferred,
                json!({"candidates": candidates}),
            )
            .with_limitation(
                "Candidates are URL-like or credential-like string-pool entries \
                 flagged for the D-1588 audit hunt; each needs human verification \
                 before it is treated as an endpoint or a credential",
            ),
        );
    }
    let examined = (functions_total + classes_total + strings_total + constants_total) as u64;
    evidence.coverage.examined = examined;
    evidence.coverage.total = examined;
    evidence.coverage.exhaustive =
        census.files_dropped == 0 && functions_total == functions_matched;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;

    /// ELF machine value for RISC-V (`EM_RISCV`); named for
    /// the wrong-architecture adversarial tests.
    const ELF_MACHINE_RISCV: u16 = 243;

    const FAKE_DEVICE_PSEUDO: &str = "// jadart tier 3, epoch objectheader-3.11, dart 3.11.5\n\
         // lib: package:localsend_isolates/model/device.dart\n\
         \n\
         class DeviceMapper extends ClassMapperBase {\n\
         \x20 _instantiate(a0) {  // 0x76c52c, 552 bytes\n\
         \x20   var t0 = dec(pool_0xb28, a0, pool_0x1ba48);\n\
         \x20   var t11 = new Device();\n\
         \x20   t11.field_0x14 = t12;\n\
         \x20   return t11;\n\
         \x20 }\n\
         }\n";

    const FAKE_STORED_PSEUDO: &str = "// jadart tier 3, epoch objectheader-3.11, dart 3.11.5\n\
         // lib: package:localsend_isolates/model/stored_security_context.dart\n\
         \n\
         class StoredSecurityContext {\n\
         \x20 toString() {  // 0xc37ea8, 12 bytes\n\
         \x20   return \"StoredSecurityContext(<privateKey>, <publicKey>, \
         <certificate>, <certificateHash>)\";\n\
         \x20 }\n\
         }\n";

    fn elf64(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn macho64(cpu_type: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        bytes[4..8].copy_from_slice(&cpu_type.to_le_bytes());
        bytes[12..16].copy_from_slice(&6_u32.to_le_bytes());
        bytes
    }

    /// Build a stored/deflate zip in memory: local headers,
    /// central directory, EOCD. CRC fields are zero — the
    /// validator reads header geometry, never checksums.
    fn zip_bytes(entries: &[(&str, u16, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        for (name, method, data) in entries {
            let local_offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
            out.extend_from_slice(&20_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-jadart-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with_root(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    /// Write a fake jadart: a python script answering each
    /// subcommand in JSON mode like the real tool. `mode` is
    /// `good` (canned census documents plus an export tree),
    /// `typed_error` (exit 2 with a ContainerError document
    /// carrying an exact offset), or `fail` (exit 3, no JSON).
    fn write_fake_jadart(dir: &Path, mode: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let template = r#"#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
cmd = next((w for w in ("info", "classes", "functions", "strings", "constants", "verify", "export") if w in argv), "")
MODE = "__MODE__"
DEVICE = '''__DEVICE__'''
STORED = '''__STORED__'''
if MODE == "typed_error":
    print(json.dumps({"ok": False, "error": "malformed container (leading bytes 7f454c4602010100): unpack_from requires a buffer of at least 14549296 bytes for unpacking 64 bytes at offset 14549232 (actual buffer size is 1048576)", "type": "ContainerError", "exit": 2}))
    sys.exit(2)
if MODE == "fail":
    print("boom", file=sys.stderr)
    sys.exit(3)
if cmd == "info":
    print(json.dumps({"ok": True, "file": "fixture", "anchor": {"symbol": "_kDartIsolateSnapshotInstructions", "va": 6908480, "file_offset": 6908480, "size": 7639520, "container": "elf"}, "snapshots": {"isolate": {"kind": "kFullAOT", "version_hash": "78da37fed6bf1489361a312568249f3f", "epoch": "objectheader-3.11", "dart": "3.11.5", "target": "arm64/compressed-pointers", "features": "product arm64 android compressed-pointers"}}}))
elif cmd == "classes":
    print(json.dumps({"ok": True, "epoch": "objectheader-3.11", "dart": "3.11.5", "count": 2, "classes": [{"name": "DeviceMapper", "superclass": "ClassMapperBase", "library": "dart.core", "members": [{"name": "_instantiate", "kind": "method"}]}, {"name": "StoredSecurityContext", "superclass": "", "library": "dart.core", "members": [{"name": "toString", "kind": "method"}]}]}))
elif cmd == "functions":
    print(json.dumps({"ok": True, "total": 3, "matched": 3, "call_graph": "built", "call_graph_error": None, "notes": [], "functions": [{"pc_offset": 128, "va": 6908608, "size": 192, "name": "main", "label": "main", "origin": "snapshot", "library": "", "callers": 0, "callees": 1, "indirect": 0, "virtual_callers": 0, "overloads": 0}]}))
elif cmd == "strings":
    print(json.dumps({"ok": True, "epoch": "objectheader-3.11", "count": 3, "strings": ["alpha", "https://api.example.com/v1", "api_key = hunter2"]}))
elif cmd == "constants":
    print(json.dumps({"ok": True, "count": 1, "constants": [{"offset": 3344, "length": 2, "elements": [30, 1073741824]}]}))
elif cmd == "verify":
    print(json.dumps({"ok": True, "epoch": "objectheader-3.11", "target": "arm64/compressed-pointers", "gates": [{"gate": "G8 instr_table_len vs rodata", "tier": "A", "status": "PASS", "passed": True, "checks": 1, "detail": "header 3 == 3", "skipped": ""}], "passed": 1, "failed": []}))
elif cmd == "export":
    out = argv[argv.index("-o") + 1]
    model = os.path.join(out, "sources", "localsend_isolates", "model")
    os.makedirs(model, exist_ok=True)
    with open(os.path.join(model, "device.dart"), "w") as fh:
        fh.write(DEVICE)
    with open(os.path.join(model, "stored_security_context.dart"), "w") as fh:
        fh.write(STORED)
    print(json.dumps({"ok": True, "out": out, "tier": 3, "libraries": 2, "classes": 2, "methods": 3, "strings": 3, "selectors": 0}))
sys.exit(0)
"#;
        let script = template
            .replace("__MODE__", mode)
            .replace("__DEVICE__", FAKE_DEVICE_PSEUDO)
            .replace("__STORED__", FAKE_STORED_PSEUDO);
        let binary = dir.join("jadart");
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        binary
    }

    fn finding<'a>(value: &'a Value, kind: &str) -> &'a Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == kind)
            .unwrap()
    }

    // ---- validation tests ----

    #[test]
    fn validation_macho_facts_parse_arm64() {
        let facts = macho_facts(&macho64(CPU_TYPE_ARM64)).unwrap();
        assert_eq!(facts.cpu_type, CPU_TYPE_ARM64);
        assert_eq!(facts.file_type, 6);
        let facts = macho_facts(&macho64(CPU_TYPE_X86_64)).unwrap();
        assert_eq!(facts.cpu_type, CPU_TYPE_X86_64);
    }

    #[test]
    fn validation_bare_elf_targets_are_accepted() {
        let root = scratch("elfshapes");
        for (tag, machine) in [("arm64", ELF_MACHINE_AARCH64), ("x64", ELF_MACHINE_X86_64)] {
            let file = root.join(format!("libapp-{tag}.so"));
            std::fs::write(&file, elf64(machine)).unwrap();
            let validated = validate_jadart_target(&file).unwrap();
            assert_eq!(validated.shape, "bare_libapp");
            assert_eq!(validated.container, "elf");
            assert_eq!(validated.snapshot_machine, Some(machine));
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_bare_macho_target_is_accepted() {
        let root = scratch("machobare");
        let file = root.join("App");
        std::fs::write(&file, macho64(CPU_TYPE_ARM64)).unwrap();
        let validated = validate_jadart_target(&file).unwrap();
        assert_eq!(validated.shape, "macho_binary");
        assert_eq!(validated.snapshot_cpu_type, Some(CPU_TYPE_ARM64));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_apk_with_libapp_member_is_accepted() {
        let root = scratch("apk");
        let file = root.join("app.apk");
        let zip = zip_bytes(&[("lib/arm64-v8a/libapp.so", 0, &elf64(ELF_MACHINE_AARCH64))]);
        std::fs::write(&file, zip).unwrap();
        let validated = validate_jadart_target(&file).unwrap();
        assert_eq!(validated.shape, "apk");
        assert_eq!(validated.container, "zip");
        assert_eq!(
            validated.snapshot_member.as_deref(),
            Some("lib/arm64-v8a/libapp.so")
        );
        assert_eq!(validated.snapshot_machine, Some(ELF_MACHINE_AARCH64));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_apk_with_deflated_member_is_accepted() {
        use std::io::Write as _;
        let root = scratch("apkdeflate");
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&elf64(ELF_MACHINE_AARCH64)).unwrap();
        let compressed = encoder.finish().unwrap();
        let file = root.join("app.apk");
        let zip = zip_bytes(&[("lib/arm64-v8a/libapp.so", 8, &compressed)]);
        std::fs::write(&file, zip).unwrap();
        let validated = validate_jadart_target(&file).unwrap();
        assert_eq!(validated.shape, "apk");
        assert_eq!(validated.snapshot_machine, Some(ELF_MACHINE_AARCH64));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_ipa_with_macho_member_is_accepted() {
        let root = scratch("ipa");
        let file = root.join("app.ipa");
        let zip = zip_bytes(&[(
            "Payload/App.app/Frameworks/App.framework/App",
            0,
            &macho64(CPU_TYPE_ARM64),
        )]);
        std::fs::write(&file, zip).unwrap();
        let validated = validate_jadart_target(&file).unwrap();
        assert_eq!(validated.shape, "ipa");
        assert_eq!(validated.snapshot_cpu_type, Some(CPU_TYPE_ARM64));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_framework_and_lib_dirs_are_accepted() {
        let root = scratch("dirs");
        let framework = root.join("App.framework");
        std::fs::create_dir_all(&framework).unwrap();
        std::fs::write(framework.join("App"), macho64(CPU_TYPE_ARM64)).unwrap();
        let validated = validate_jadart_target(&framework).unwrap();
        assert_eq!(validated.shape, "framework_dir");
        assert_eq!(validated.snapshot_cpu_type, Some(CPU_TYPE_ARM64));
        let lib_dir = root.join("arm64-v8a");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("libapp.so"), elf64(ELF_MACHINE_AARCH64)).unwrap();
        let validated = validate_jadart_target(&lib_dir).unwrap();
        assert_eq!(validated.shape, "lib_dir");
        let tree = root.join("extracted");
        let abi = tree.join("lib").join("arm64-v8a");
        std::fs::create_dir_all(&abi).unwrap();
        std::fs::write(abi.join("libapp.so"), elf64(ELF_MACHINE_AARCH64)).unwrap();
        let validated = validate_jadart_target(&tree).unwrap();
        assert_eq!(validated.shape, "directory_tree");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_fake_jadart_run_ingests_evidence() {
        let root = scratch("fakerun");
        let libapp = root.join("libapp.so");
        std::fs::write(&libapp, elf64(ELF_MACHINE_AARCH64)).unwrap();
        let fake = write_fake_jadart(&root.join("fake-jadart"), "good");
        let fake_bin = root.join("fake-jadart").join("bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        std::fs::rename(&fake, fake_bin.join("jadart")).unwrap();
        let config = config_with_root(&root);
        let value = analyze_with_jadart(
            &config,
            &libapp,
            Some(root.join("out")),
            Some(fake_bin.join("jadart")),
        )
        .unwrap();
        assert_eq!(finding(&value, "jadart_classes")["facts"]["total"], 2);
        assert_eq!(
            finding(&value, "jadart_classes")["facts"]["members_total"],
            2
        );
        assert_eq!(finding(&value, "jadart_functions")["facts"]["total"], 3);
        assert_eq!(finding(&value, "jadart_functions")["facts"]["matched"], 3);
        assert_eq!(finding(&value, "jadart_strings")["facts"]["total"], 3);
        assert_eq!(finding(&value, "jadart_constants")["facts"]["total"], 1);
        let version = finding(&value, "dart_version");
        assert_eq!(version["facts"]["version"], "3.11.5");
        assert_eq!(
            version["facts"]["snapshot_hash"],
            "78da37fed6bf1489361a312568249f3f"
        );
        let verify = finding(&value, "jadart_verify");
        assert_eq!(verify["facts"]["supported"], true);
        assert_eq!(verify["facts"]["passed"], 1);
        let pseudo = finding(&value, "jadart_pseudo_dart");
        assert_eq!(pseudo["facts"]["files_total"], 2);
        assert_eq!(pseudo["facts"]["files_retained"], 2);
        let libraries = pseudo["facts"]["libraries"].as_array().unwrap();
        let device = libraries
            .iter()
            .find(|row| row["library"].as_str().unwrap().ends_with("device.dart"))
            .unwrap();
        assert_eq!(device["text"].as_str().unwrap(), FAKE_DEVICE_PSEUDO);
        let stored = libraries
            .iter()
            .find(|row| {
                row["library"]
                    .as_str()
                    .unwrap()
                    .ends_with("stored_security_context.dart")
            })
            .unwrap();
        assert_eq!(stored["text"].as_str().unwrap(), FAKE_STORED_PSEUDO);
        assert!(stored["text"].as_str().unwrap().contains(
            "StoredSecurityContext(<privateKey>, <publicKey>, <certificate>, <certificateHash>)"
        ));
        let candidates = finding(&value, "jadart_findings_candidates");
        assert_eq!(
            candidates["facts"]["candidates"].as_array().unwrap().len(),
            2
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_pseudo_dart_text_survives_byte_for_byte() {
        let root = scratch("verbatim");
        let sources = root.join("sources");
        let sub = sources.join("pkg");
        std::fs::create_dir_all(&sub).unwrap();
        let tricky = "// lib: package:pkg/a.dart\r\n\nclass A {\n  s() {\n    \
                      return \"caf\\u{00e9} \\\"quoted\\\" \\\\ path\";\n  }\n}\n";
        std::fs::write(sub.join("a.dart"), tricky).unwrap();
        let census = census_export_sources(&sources).unwrap();
        assert_eq!(census.files_total, 1);
        assert_eq!(census.files_retained, 1);
        assert_eq!(census.records[0]["text"].as_str().unwrap(), tricky);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_typed_error_mapping_is_one_for_one() {
        let cases: &[(&str, i32, bool, ErrorCode)] = &[
            ("ContainerError", 2, false, ErrorCode::Truncated),
            ("TruncatedSnapshot", 2, false, ErrorCode::Truncated),
            ("InputError", 2, false, ErrorCode::UnsupportedTarget),
            ("UnknownEpoch", 2, false, ErrorCode::UnsupportedTarget),
            ("UnsupportedTarget", 2, false, ErrorCode::UnsupportedTarget),
            ("UnsupportedArch", 1, false, ErrorCode::UnsupportedTarget),
            ("MissingSymbol", 2, false, ErrorCode::UnsupportedTarget),
            ("AllocError", 2, false, ErrorCode::UnreadableOutput),
            ("FillError", 2, false, ErrorCode::UnreadableOutput),
            (
                "MissingDisassembler",
                2,
                false,
                ErrorCode::CapabilityUnavailable,
            ),
            ("NotFound", 1, false, ErrorCode::InvalidRequest),
            ("KeyError", 3, true, ErrorCode::ExecutionFailure),
        ];
        for (kind, exit, internal, want) in cases {
            let typed = JadartTypedError {
                jadart_type: kind.to_string(),
                message: "detail at offset 14549232".to_string(),
                exit_code: *exit,
                internal: *internal,
            };
            assert_eq!(jadart_error_code(&typed), *want, "type {kind}");
            let err = map_jadart_error("info", &typed);
            assert_eq!(err.code, *want, "type {kind}");
            assert!(err.message.contains(kind), "{}", err.message);
            assert!(err.message.contains("14549232"), "{}", err.message);
            let details = err.details.as_ref().unwrap();
            assert_eq!(details["jadart_type"], *kind);
            assert_eq!(details["jadart_exit"], *exit);
        }
        let parsed = parse_jadart_typed_error(
            "{\"ok\": false, \"error\": \"malformed container: offset 14549232\", \
             \"type\": \"ContainerError\", \"exit\": 2}",
        )
        .unwrap();
        assert_eq!(parsed.jadart_type, "ContainerError");
        assert_eq!(parsed.exit_code, 2);
        assert!(!parsed.internal);
        assert_eq!(parse_jadart_typed_error("{\"ok\": true}"), None);
        assert_eq!(parse_jadart_typed_error("not json"), None);
    }

    // ---- adversarial tests ----

    #[test]
    fn adversarial_wrong_arch_elf_is_refused() {
        let root = scratch("wrongarch");
        let file = root.join("libapp.so");
        std::fs::write(&file, elf64(ELF_MACHINE_RISCV)).unwrap();
        let err = validate_jadart_target(&file).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_wrong_cpu_and_fat_macho_are_refused() {
        let root = scratch("wrongcpu");
        let file = root.join("App");
        // CPU_TYPE_ARM (12): a 32-bit ARM Mach-O jadart has
        // no Tier 3 grammar for.
        std::fs::write(&file, macho64(12)).unwrap();
        let err = validate_jadart_target(&file).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        let mut fat = vec![0_u8; 64];
        fat[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        std::fs::write(&file, fat).unwrap();
        let err = validate_jadart_target(&file).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        assert!(err.message.contains("fat"), "{}", err.message);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_and_empty_targets_are_refused() {
        let root = scratch("truncated");
        let elf_file = root.join("libapp.so");
        std::fs::write(&elf_file, &elf64(ELF_MACHINE_AARCH64)[..32]).unwrap();
        let err = validate_jadart_target(&elf_file).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        let macho_file = root.join("App");
        std::fs::write(&macho_file, &macho64(CPU_TYPE_ARM64)[..16]).unwrap();
        let err = validate_jadart_target(&macho_file).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        let empty = root.join("empty.so");
        std::fs::write(&empty, b"").unwrap();
        let err = validate_jadart_target(&empty).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        // A zip prefix with no end-of-central-directory.
        let zip_file = root.join("broken.apk");
        std::fs::write(&zip_file, b"PK\x03\x04garbagegarbage").unwrap();
        let err = validate_jadart_target(&zip_file).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_garbage_file_is_refused() {
        let root = scratch("garbage");
        let file = root.join("libapp.so");
        std::fs::write(&file, vec![b'x'; 128]).unwrap();
        let err = validate_jadart_target(&file).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_apk_without_snapshot_member_is_refused() {
        let root = scratch("nomember");
        let file = root.join("app.apk");
        let zip = zip_bytes(&[("classes.dex", 0, b"dex\n")]);
        std::fs::write(&file, zip).unwrap();
        let err = validate_jadart_target(&file).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_apk_member_wrong_arch_is_refused() {
        let root = scratch("memberarch");
        let file = root.join("app.apk");
        let zip = zip_bytes(&[("lib/arm64-v8a/libapp.so", 0, &elf64(ELF_MACHINE_RISCV))]);
        std::fs::write(&file, zip).unwrap();
        let err = validate_jadart_target(&file).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_dirs_missing_counterparts_are_refused() {
        let root = scratch("missingparts");
        let empty_dir = root.join("App.framework");
        std::fs::create_dir_all(&empty_dir).unwrap();
        let err = validate_jadart_target(&empty_dir).unwrap_err();
        assert_eq!(err.code, ErrorCode::TargetUnavailable);
        let no_libapp = root.join("arm64-v8a");
        std::fs::create_dir_all(&no_libapp).unwrap();
        std::fs::write(no_libapp.join("libflutter.so"), elf64(ELF_MACHINE_AARCH64)).unwrap();
        let err = validate_jadart_target(&no_libapp).unwrap_err();
        assert_eq!(err.code, ErrorCode::TargetUnavailable);
        let bad_app = root.join("Bad.framework");
        std::fs::create_dir_all(&bad_app).unwrap();
        std::fs::write(bad_app.join("App"), vec![b'x'; 128]).unwrap();
        let err = validate_jadart_target(&bad_app).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_typed_error_arrives_with_detail_intact() {
        let root = scratch("typederr");
        let libapp = root.join("libapp.so");
        std::fs::write(&libapp, elf64(ELF_MACHINE_AARCH64)).unwrap();
        let fake = write_fake_jadart(&root.join("fake-jadart"), "typed_error");
        let fake_bin = root.join("fake-jadart").join("bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        std::fs::rename(&fake, fake_bin.join("jadart")).unwrap();
        let config = config_with_root(&root);
        let err = analyze_with_jadart(
            &config,
            &libapp,
            Some(root.join("out")),
            Some(fake_bin.join("jadart")),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        assert!(err.message.contains("ContainerError"), "{}", err.message);
        assert!(err.message.contains("14549232"), "{}", err.message);
        let details = err.details.as_ref().unwrap();
        assert_eq!(details["jadart_type"], "ContainerError");
        assert_eq!(details["jadart_exit"], 2);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_fake_jadart_internal_failure_is_not_a_success() {
        let root = scratch("fakefail");
        let libapp = root.join("libapp.so");
        std::fs::write(&libapp, elf64(ELF_MACHINE_AARCH64)).unwrap();
        let fake = write_fake_jadart(&root.join("fake-jadart"), "fail");
        let fake_bin = root.join("fake-jadart").join("bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        std::fs::rename(&fake, fake_bin.join("jadart")).unwrap();
        let config = config_with_root(&root);
        let err = analyze_with_jadart(
            &config,
            &libapp,
            Some(root.join("out")),
            Some(fake_bin.join("jadart")),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_unlocated_jadart_is_capability_unavailable() {
        let root = scratch("nolocate");
        let libapp = root.join("libapp.so");
        std::fs::write(&libapp, elf64(ELF_MACHINE_AARCH64)).unwrap();
        let config = config_with_root(&root);
        let err = analyze_with_jadart(&config, &libapp, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        std::fs::remove_dir_all(&root).ok();
    }
}
