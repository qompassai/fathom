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
//! Honesty contract: decryption happens only with a
//! caller-supplied script encryption key (the Godot export
//! key, 64 hex characters). With a key, encrypted
//! directories and entries are decrypted (AES-256 CFB,
//! `FileAccessEncrypted` layout: plaintext MD5, plaintext
//! length, IV, ciphertext) and the plaintext is verified
//! against both MD5s before any fact is claimed from it; a
//! wrong key is a typed integrity error, never a garbage
//! inventory. Without a key this reader never decrypts. An encrypted
//! directory ends the inventory at the header (the entry claims
//! are ciphertext), and encrypted entries are listed with their
//! directory facts but no content hash. Removal entries are
//! tombstones — facts, not content. A sparse-bundle pack stores
//! its entry bytes elsewhere, so contents are unknowns. Every
//! readable entry's stored bytes are hashed (SHA-256) and
//! cross-checked against the directory MD5, so an offset that
//! lies in-bounds is caught rather than believed.
//! The format-4 directory salt (directory-encrypted +
//! sparse bundle) stays presence-only: its role in IV
//! derivation is not established by any source this
//! reader is built on, so that combination is reported,
//! never decrypted (readers SPEC §3.2).

use serde_json::{Value, json};
use std::path::Path;

use crate::aes;
use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex, subject_for_file};
use fathom_core::limits::PCK_ENTRIES_MAX;
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, optional_str, require_str};

/// Entry flag: the entry's stored bytes are encrypted.
const ENTRY_FLAG_ENCRYPTED: u32 = 1 << 0;
/// Entry flag: the entry is a removal marker (delta packs);
/// it carries no data in this pack.
const ENTRY_FLAG_REMOVAL: u32 = 1 << 1;
/// Entry flag (format 4): the entry is a binary patch against
/// another entry for the same path (readers SPEC §3.1).
const ENTRY_FLAG_DELTA: u32 = 1 << 2;
/// Entry flag bits this reader understands in format 4.
const ENTRY_FLAGS_KNOWN: u32 = ENTRY_FLAG_ENCRYPTED | ENTRY_FLAG_REMOVAL | ENTRY_FLAG_DELTA;
/// Entry flag bits understood before format 4: the delta bit
/// did not exist, so in a format <= 3 pack it stays an
/// unknown-flag fact (readers SPEC §3.2).
const ENTRY_FLAGS_KNOWN_LEGACY: u32 = ENTRY_FLAG_ENCRYPTED | ENTRY_FLAG_REMOVAL;

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
const FORMAT_VERSION_SUPPORTED_MAX: u32 = 4;

#[derive(Debug)]
pub struct PckArchive {
    /// True when an encrypted directory was decrypted with
    /// the caller's key and its entries parsed from the
    /// verified plaintext.
    pub directory_decrypted: bool,
    /// True when the pack flags declare an encrypted
    /// directory. When no key is supplied (or the format-4
    /// salt layout applies), `entries` is empty because the
    /// directory bytes are ciphertext this reader does not
    /// decrypt.
    pub directory_encrypted: bool,
    /// Directory position for format v3; absent in v1/v2, where
    /// the directory follows the header.
    pub directory_offset: Option<u64>,
    /// True when a format-4 header carried the 32-byte
    /// encrypted-directory salt (directory-encrypted + sparse
    /// bundle). Presence only: the salt's role in IV
    /// derivation is not established, so its bytes are never
    /// used or emitted, and that layout is never decrypted
    /// (readers SPEC §3.2).
    pub directory_salt: bool,
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

    /// The entry is a format-4 delta (binary patch) entry.
    pub fn delta(&self) -> bool {
        self.flags & ENTRY_FLAG_DELTA != 0
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

/// The `FileAccessEncrypted` stream header size:
/// plaintext MD5 (16 bytes), plaintext length (8), IV
/// (16). The blob a Godot writer stores for an encrypted
/// directory or entry is this header followed by exactly
/// `length` ciphertext bytes (AES-256 CFB, 128-bit
/// segments).
const FAE_HEADER_BYTES: usize = 40;

/// Parse a Godot script encryption key: 64 hexadecimal
/// characters (an optional `0x` prefix is accepted). The
/// key text is never echoed into an error or a record.
pub fn parse_script_key(text: &str) -> Result<[u8; 32], FathomError> {
    let invalid = |message: &str| {
        FathomError::new(ErrorCode::InvalidRequest, message.to_string())
            .with_target("godot pck archive")
    };
    let hex = text.trim();
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(invalid(
            "PCK encryption key must be 64 hexadecimal characters (32 bytes)",
        ));
    }
    let mut key = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks(2).enumerate() {
        let digits = std::str::from_utf8(pair)
            .map_err(|_| invalid("PCK encryption key is not hexadecimal"))?;
        key[index] = u8::from_str_radix(digits, 16)
            .map_err(|_| invalid("PCK encryption key is not hexadecimal"))?;
    }
    Ok(key)
}

/// Decrypt one `FileAccessEncrypted` blob starting at
/// `start` in `bytes`. The plaintext is returned only
/// after its MD5 matches the header's declared MD5 — the
/// same check the engine itself performs — so a wrong key
/// fails here as an integrity error, never as content.
/// `what` names the blob ("pack directory", "entry") in
/// error text.
fn decrypt_fae(
    bytes: &[u8],
    start: usize,
    key: &[u8; 32],
    what: &str,
) -> Result<Vec<u8>, FathomError> {
    let truncated = |message: String| {
        FathomError::new(ErrorCode::Truncated, message).with_target("godot pck archive")
    };
    let header_end = start
        .checked_add(FAE_HEADER_BYTES)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| truncated(format!("encrypted {what} header overruns the archive")))?;
    let mut expected_md5 = [0_u8; 16];
    expected_md5.copy_from_slice(&bytes[start..start + 16]);
    let length = u64::from_le_bytes(bytes[start + 16..start + 24].try_into().unwrap());
    let mut iv = [0_u8; 16];
    iv.copy_from_slice(&bytes[start + 24..start + 40]);
    let length = usize::try_from(length).map_err(|_| {
        truncated(format!(
            "encrypted {what} length does not fit this platform"
        ))
    })?;
    let end = header_end
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| truncated(format!("encrypted {what} overruns the archive")))?;
    let plaintext = aes::cfb128_decrypt(key, &iv, &bytes[header_end..end]);
    if md5_digest(&plaintext) != expected_md5 {
        return Err(FathomError::new(
            ErrorCode::ArtifactIntegrityMismatch,
            format!(
                "decrypted {what} MD5 does not match its FileAccessEncrypted \
                 header; the supplied key is wrong or the {what} is corrupt"
            ),
        )
        .with_target("godot pck archive"));
    }
    Ok(plaintext)
}

/// Parse a Godot PCK archive from its full bytes.
pub fn parse_pck(bytes: &[u8]) -> Result<PckArchive, FathomError> {
    parse_pck_with_key(bytes, None)
}

/// Parse a Godot PCK archive, decrypting an encrypted
/// directory when `key` is supplied. The format-4 salt
/// layout is never decrypted (module doc): its directory
/// stays ciphertext and `entries` stays empty.
pub fn parse_pck_with_key(bytes: &[u8], key: Option<&[u8; 32]>) -> Result<PckArchive, FathomError> {
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
    let mut directory_salt = false;
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
        3 | 4 => {
            let pack_flags = header.read_u32()?;
            let file_base = header.read_u64()?;
            let offset = header.read_u64()?;
            // Format 4: when the pack flags carry both
            // directory-encrypted and sparse-bundle, a 32-byte
            // encrypted-directory salt follows the directory
            // offset (readers SPEC §3.1 item 3). A header that
            // ends inside the salt is truncated, as elsewhere.
            if format_version == 4
                && pack_flags & PACK_FLAG_DIRECTORY_ENCRYPTED != 0
                && pack_flags & PACK_FLAG_SPARSE_BUNDLE != 0
            {
                header.read_bytes(32)?;
                directory_salt = true;
            }
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
        directory_decrypted: false,
        directory_encrypted,
        directory_offset,
        directory_salt,
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
        // The directory bytes are ciphertext. Without a key,
        // report the header facts and stop: inventing entries
        // would fake coverage. The salt layout is reported,
        // never decrypted (module doc).
        let Some(key) = key.filter(|_| !directory_salt) else {
            return Ok(archive);
        };
        let plaintext = decrypt_fae(bytes, directory_start, key, "pack directory")?;
        let consumed = parse_directory(&plaintext, format_version, &mut archive)?;
        if consumed != plaintext.len() {
            return Err(FathomError::new(
                ErrorCode::ArtifactIntegrityMismatch,
                "decrypted pack directory carries trailing bytes after its last entry",
            )
            .with_target("godot pck archive"));
        }
        archive.directory_decrypted = true;
        return Ok(archive);
    }
    let Some(directory_bytes) = bytes.get(directory_start..) else {
        return Err(
            FathomError::new(ErrorCode::Truncated, "godot pck archive ends mid-structure")
                .with_target("godot pck archive"),
        );
    };
    parse_directory(directory_bytes, format_version, &mut archive)?;
    Ok(archive)
}

/// Parse the directory region (a file count, then the
/// entries) from the front of `directory_bytes` — the
/// archive slice for a plain directory, the verified
/// plaintext for a decrypted one. Returns the number of
/// bytes the directory occupied.
fn parse_directory(
    directory_bytes: &[u8],
    format_version: u32,
    archive: &mut PckArchive,
) -> Result<usize, FathomError> {
    let unsupported = |message: String| {
        FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("godot pck archive")
    };
    let mut directory = Cursor::new(directory_bytes, 0);
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
    Ok(directory.position)
}

/// Extract one entry's stored bytes (bounds-checked). This is
/// the raw stored content: an encrypted entry is a typed
/// refusal without a key (see [`extract_with_key`]), as are
/// removal tombstones and sparse-bundle entries, whose bytes
/// live elsewhere.
pub fn extract<'a>(
    bytes: &'a [u8],
    archive: &PckArchive,
    entry: &PckEntry,
) -> Result<&'a [u8], FathomError> {
    if entry.encrypted() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is encrypted; PCK decryption requires a script encryption key",
        ));
    }
    if entry.removal() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is a removal marker; it carries no data in this pack",
        ));
    }
    if archive.format_version >= 4 && entry.delta() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is a format-4 delta (patch) entry; applying it is content reconstruction, not extraction",
        ));
    }
    if archive.sparse_bundle {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "pack is a sparse bundle; entry bytes are not stored in this pack",
        ));
    }
    stored_bytes(bytes, archive, entry)
}

/// Extract one entry's content as an owned buffer,
/// decrypting when the entry is encrypted and a key is
/// supplied. The decryption is returned only after every
/// check in [`decrypt_entry`] passes; the other typed
/// refusals match [`extract`].
pub fn extract_with_key(
    bytes: &[u8],
    archive: &PckArchive,
    entry: &PckEntry,
    key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, FathomError> {
    if entry.removal() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is a removal marker; it carries no data in this pack",
        ));
    }
    if entry.encrypted() {
        let Some(key) = key else {
            return Err(FathomError::new(
                ErrorCode::CapabilityUnavailable,
                "entry is encrypted; PCK decryption requires a script encryption key",
            ));
        };
        if archive.sparse_bundle {
            return Err(FathomError::new(
                ErrorCode::CapabilityUnavailable,
                "pack is a sparse bundle; entry bytes are not stored in this pack",
            ));
        }
        return decrypt_entry(bytes, archive, entry, key);
    }
    if archive.format_version >= 4 && entry.delta() {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "entry is a format-4 delta (patch) entry; applying it is content reconstruction, not extraction",
        ));
    }
    if archive.sparse_bundle {
        return Err(FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "pack is a sparse bundle; entry bytes are not stored in this pack",
        ));
    }
    Ok(stored_bytes(bytes, archive, entry)?.to_vec())
}

/// Decrypt one encrypted entry and verify the plaintext
/// three ways before returning it: the
/// `FileAccessEncrypted` header MD5 (inside
/// [`decrypt_fae`]), the directory MD5 for this entry,
/// and the directory size, which must declare either the
/// plaintext length or the full stored blob length
/// (header + plaintext) — the two conventions writers
/// use. Any disagreement is an integrity error naming
/// the entry.
fn decrypt_entry(
    bytes: &[u8],
    archive: &PckArchive,
    entry: &PckEntry,
    key: &[u8; 32],
) -> Result<Vec<u8>, FathomError> {
    let start = usize::try_from(stored_offset(archive, entry))
        .ok()
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| {
            FathomError::new(ErrorCode::Truncated, "entry offset overruns the archive")
        })?;
    let plaintext = decrypt_fae(bytes, start, key, "entry")?;
    if md5_digest(&plaintext) != entry.md5 {
        return Err(FathomError::new(
            ErrorCode::ArtifactIntegrityMismatch,
            format!(
                "decrypted entry {} MD5 does not match the directory MD5",
                entry.path
            ),
        )
        .with_target("godot pck archive"));
    }
    let plain_len = plaintext.len() as u64;
    if entry.size != plain_len && entry.size != plain_len + FAE_HEADER_BYTES as u64 {
        return Err(FathomError::new(
            ErrorCode::ArtifactIntegrityMismatch,
            format!(
                "directory declares {} bytes for {} but its encrypted blob \
                 carries a {plain_len}-byte plaintext",
                entry.size, entry.path
            ),
        )
        .with_target("godot pck archive"));
    }
    Ok(plaintext)
}

/// The entry's stored byte range, bounds-checked, with no
/// policy refusals: the census hashes delta entries' patch
/// bytes through here even though `extract` refuses them.
fn stored_bytes<'a>(
    bytes: &'a [u8],
    archive: &PckArchive,
    entry: &PckEntry,
) -> Result<&'a [u8], FathomError> {
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

/// The PNG file signature.
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/// One unwrapped Godot texture payload: the image file a
/// texture container embeds when its data format is a
/// plain image encoding.
#[derive(Debug)]
pub struct TexturePayload<'a> {
    /// The payload's image encoding: "png" or "webp". For
    /// `.ctex` this is the header's declared data format,
    /// verified against the payload signature; for `.stex`
    /// (which declares none) it is read from the signature.
    pub data_format: &'static str,
    pub height: u32,
    /// The embedded image file bytes, exactly as stored.
    pub payload: &'a [u8],
    pub width: u32,
}

/// Unwrap a Godot texture container — `.ctex` ("GST2",
/// Godot 4) or `.stex` ("GDST", Godot 3) — to the image
/// file it embeds. Only plain PNG / WebP payloads unwrap;
/// anything else is a typed refusal.
///
/// The `.ctex` layout is measured from the estate corpus
/// (5,117 files in one Godot 4.7 title): magic, version
/// (1), width, height, texture flags, a reserved span, the
/// data-format word at byte 36 (0 = raw image data,
/// 1 = PNG, 2 = WebP, 3 = Basis Universal), basis fields,
/// a mipmap word, then one length-prefixed payload at
/// byte 52 spanning the rest of the entry. Raw-pixel and
/// Basis payloads refuse, as does a payload whose
/// signature or RIFF size contradicts the declared
/// format. The `.stex` payload follows the 20-byte GDST
/// header and runs to the end of the entry, per published
/// analyses of real Godot 3 files; it is accepted only
/// when it carries a PNG or WebP signature.
pub fn unwrap_texture(bytes: &[u8]) -> Result<TexturePayload<'_>, FathomError> {
    let refusal = |message: String| {
        FathomError::new(ErrorCode::CapabilityUnavailable, message).with_target("godot texture")
    };
    let mismatch = |message: String| {
        FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message).with_target("godot texture")
    };
    let truncated = |message: &str| {
        FathomError::new(ErrorCode::Truncated, message.to_string()).with_target("godot texture")
    };
    let word = |at: usize| -> u32 { u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) };
    if bytes.len() >= 4 && &bytes[..4] == b"GST2" {
        if bytes.len() < 56 {
            return Err(truncated("ctex header is truncated"));
        }
        let version = word(4);
        if version != 1 {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!("ctex version {version} is not implemented (supported: 1)"),
            )
            .with_target("godot texture"));
        }
        let (width, height) = (word(8), word(12));
        let data_format = match word(36) {
            0 => {
                return Err(refusal(
                    "ctex data format 0 stores raw image data; there is no \
                     embedded image file to unwrap"
                        .to_string(),
                ));
            }
            1 => "png",
            2 => "webp",
            3 => {
                return Err(refusal(
                    "ctex data format 3 stores a Basis Universal payload; \
                     transcoding is not implemented"
                        .to_string(),
                ));
            }
            other => {
                return Err(refusal(format!(
                    "ctex data format {other} is not recognised"
                )));
            }
        };
        let payload_len = word(52) as usize;
        if 56_usize.checked_add(payload_len) != Some(bytes.len()) {
            return Err(mismatch(format!(
                "ctex payload length {payload_len} does not span the entry \
                 ({} bytes follow the header)",
                bytes.len() - 56
            )));
        }
        let payload = &bytes[56..];
        check_image_payload(payload, data_format)?;
        return Ok(TexturePayload {
            data_format,
            height,
            payload,
            width,
        });
    }
    if bytes.len() >= 4 && &bytes[..4] == b"GDST" {
        if bytes.len() < 20 {
            return Err(truncated("stex header is truncated"));
        }
        let (width, height) = (word(4), word(8));
        let payload = &bytes[20..];
        let data_format = if payload.starts_with(&PNG_SIGNATURE) {
            "png"
        } else if is_webp_payload(payload) {
            "webp"
        } else {
            return Err(refusal(
                "stex payload is neither PNG nor WebP; only plain image \
                 payloads unwrap"
                    .to_string(),
            ));
        };
        check_image_payload(payload, data_format)?;
        return Ok(TexturePayload {
            data_format,
            height,
            payload,
            width,
        });
    }
    Err(FathomError::new(
        ErrorCode::UnsupportedTarget,
        "not a Godot texture container (GST2/GDST magic missing)",
    )
    .with_target("godot texture"))
}

/// True when `payload` carries the RIFF/WEBP signature
/// with a self-consistent RIFF size.
fn is_webp_payload(payload: &[u8]) -> bool {
    payload.len() >= 12
        && &payload[..4] == b"RIFF"
        && &payload[8..12] == b"WEBP"
        && u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize == payload.len() - 8
}

/// Verify a payload against the image encoding claimed
/// for it: PNG signature, or RIFF/WEBP with a consistent
/// RIFF size. A contradiction is an integrity mismatch —
/// the container's declaration is lying.
fn check_image_payload(payload: &[u8], data_format: &str) -> Result<(), FathomError> {
    let ok = match data_format {
        "png" => payload.starts_with(&PNG_SIGNATURE),
        _ => is_webp_payload(payload),
    };
    if ok {
        Ok(())
    } else {
        Err(FathomError::new(
            ErrorCode::ArtifactIntegrityMismatch,
            format!("texture declares {data_format} but the payload does not carry its signature"),
        )
        .with_target("godot texture"))
    }
}

/// The census fact for one entry's texture unwrap, when
/// the entry path names a texture container: the payload
/// facts on success, the refusal on failure.
fn texture_fact(path: &str, data: &[u8]) -> Option<Value> {
    let is_texture = [".ctex", ".stex"].iter().any(|extension| {
        path.len() >= extension.len()
            && path[path.len() - extension.len()..].eq_ignore_ascii_case(extension)
    });
    if !is_texture {
        return None;
    }
    Some(match unwrap_texture(data) {
        Ok(texture) => json!({
            "data_format": texture.data_format,
            "height": texture.height,
            "payload_bytes": texture.payload.len(),
            "payload_sha256": sha256_hex(texture.payload),
            "width": texture.width,
        }),
        Err(error) => json!({"unwrap_error": error.message}),
    })
}

pub fn inspect_godot_pck(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let key = match optional_str(args, "encryption_key") {
        Some(text) => Some(parse_script_key(text)?),
        None => None,
    };
    let subject = subject_for_file(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    let archive = parse_pck_with_key(&bytes, key.as_ref())?;
    let subject_sha256 = subject.sha256.clone();
    let mut evidence = Evidence::new("inspect_godot_pck", "godot");
    evidence.subject = Some(subject);
    if archive.directory_encrypted && !archive.directory_decrypted {
        let record = pack_record(&archive, &PackCounts::default());
        let document = json!({
            "godot_pck": record.clone(),
            "godot_pck_entries": [],
            "godot_pck_entries_total": 0,
            "godot_pck_entries_truncated": false,
        });
        let (digest, retention_note) = retain_census(config, &subject_sha256, &document);
        evidence.add_finding(pack_finding(&archive, record, digest.as_deref()));
        if let Some(note) = retention_note {
            evidence.add_unknown("retention", note);
        }
        evidence.add_unknown(
            "directory",
            if archive.directory_salt {
                "pack directory is encrypted (pack flag 0x1) in the format-4 \
                 sparse-salt layout; that layout's decryption is \
                 NOT-IMPLEMENTED — the entry inventory was not established"
            } else {
                "pack directory is encrypted (pack flag 0x1); the entry \
                 inventory was not established — no PCK encryption key was \
                 supplied"
            },
        );
        evidence.coverage.exhaustive = false;
        return Ok(evidence.to_value());
    }
    let total = archive.entries.len();
    let mut examined: u64 = 0;
    let mut decrypted_count: u64 = 0;
    let mut decryption_failed_count: u64 = 0;
    let mut delta_count: u64 = 0;
    let mut encrypted_count: u64 = 0;
    let mut mismatch_paths: Vec<&str> = Vec::new();
    let mut overrun_paths: Vec<&str> = Vec::new();
    let mut removal_count: u64 = 0;
    let mut verified_count: u64 = 0;
    let mut rows: Vec<Value> = Vec::new();
    for entry in &archive.entries {
        let (row, outcome) = entry_row(&bytes, &archive, entry, key.as_ref());
        match outcome {
            EntryOutcome::Decrypted => {
                decrypted_count += 1;
                verified_count += 1;
                examined += 1;
            }
            EntryOutcome::DecryptionFailed => {
                decryption_failed_count += 1;
                examined += 1;
            }
            EntryOutcome::Delta => {
                delta_count += 1;
                examined += 1;
            }
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
    let record = pack_record(
        &archive,
        &PackCounts {
            decrypted_entries: decrypted_count,
            decryption_failed_entries: decryption_failed_count,
            delta_entries: delta_count,
            encrypted_entries: encrypted_count,
            md5_mismatch_entries: mismatch_paths.len() as u64,
            removal_entries: removal_count,
            unreadable_entries: overrun_paths.len() as u64,
            verified_entries: verified_count,
        },
    );
    // Retention (readers SPEC §2.5): the census document is
    // the envelope's rows plus their locator keys, keyed to
    // the container record. A retention failure degrades the
    // run to partial; the census facts are unaffected.
    let doc_rows: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut doc_row = row.clone();
            doc_row["key"] = row["path"].clone();
            doc_row
        })
        .collect();
    let document = json!({
        "godot_pck": record.clone(),
        "godot_pck_entries": doc_rows,
        "godot_pck_entries_total": total,
        "godot_pck_entries_truncated": total > rows.len(),
    });
    let (digest, retention_note) = retain_census(config, &subject_sha256, &document);
    evidence.add_finding(pack_finding(&archive, record, digest.as_deref()));
    if let Some(note) = retention_note {
        evidence.add_unknown("retention", note);
    }
    if delta_count > 0 {
        evidence.add_unknown(
            "delta entries",
            format!(
                "{delta_count} of {total} entries are format-4 delta (patch) \
                 entries; their directory MD5 describes the patched result, \
                 so content verification does not apply — their rows hash \
                 the stored patch bytes"
            ),
        );
    }
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
                 bytes are ciphertext — not hashed, not verified — no PCK \
                 encryption key was supplied"
            ),
        );
    }
    if decryption_failed_count > 0 {
        evidence.add_unknown(
            "entry decryption",
            format!(
                "{decryption_failed_count} of {total} entries failed decryption \
                 or its integrity checks under the supplied key; their rows \
                 carry directory facts only"
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

/// Retain one census document under the subject's
/// `archive_census` export (readers SPEC §2.5). Returns the
/// export digest on success, or a note for the envelope's
/// unknowns on failure — retention never fails the census.
fn retain_census(
    config: &Config,
    subject_sha256: &str,
    document: &Value,
) -> (Option<String>, Option<String>) {
    match proof::retain_export(config, subject_sha256, "archive_census", document) {
        Ok(digest) => (Some(digest), None),
        Err(error) => (
            None,
            Some(format!(
                "census retention failed ({}); the census facts stand, \
                 but no proof can bind this run",
                error.message
            )),
        ),
    }
}

/// How one entry's stored bytes checked out.
enum EntryOutcome {
    Decrypted,
    DecryptionFailed,
    Delta,
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
fn entry_row(
    bytes: &[u8],
    archive: &PckArchive,
    entry: &PckEntry,
    key: Option<&[u8; 32]>,
) -> (Value, EntryOutcome) {
    let delta = archive.format_version >= 4 && entry.delta();
    let mut row = json!({
        "delta": delta,
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
        match key {
            None => {
                row["status"] = json!("encrypted");
                EntryOutcome::Encrypted
            }
            Some(key) => match decrypt_entry(bytes, archive, entry, key) {
                Ok(plaintext) => {
                    row["decrypted"] = json!(true);
                    row["sha256"] = json!(sha256_hex(&plaintext));
                    row["md5_verified"] = json!(true);
                    row["status"] = json!("verified");
                    if let Some(texture) = texture_fact(&entry.path, &plaintext) {
                        row["texture"] = texture;
                    }
                    EntryOutcome::Decrypted
                }
                Err(_) => {
                    row["status"] = json!("decryption_failed");
                    EntryOutcome::DecryptionFailed
                }
            },
        }
    } else if entry.removal() {
        row["status"] = json!("removal");
        EntryOutcome::Removal
    } else if archive.sparse_bundle {
        row["status"] = json!("sparse_bundle");
        EntryOutcome::Sparse
    } else if delta {
        // Delta entries: the stored bytes are patch data. The
        // row hashes them as an observed fact about the stored
        // bytes; the directory MD5 describes the patched
        // result and is never checked against them.
        match stored_bytes(bytes, archive, entry) {
            Ok(data) => {
                row["sha256"] = json!(sha256_hex(data));
                row["status"] = json!("delta");
                EntryOutcome::Delta
            }
            Err(_) => {
                row["status"] = json!("unreadable");
                EntryOutcome::Overrun
            }
        }
    } else {
        match extract(bytes, archive, entry) {
            Ok(data) => {
                row["sha256"] = json!(sha256_hex(data));
                if let Some(texture) = texture_fact(&entry.path, data) {
                    row["texture"] = texture;
                }
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

/// The pack-level container record: header facts and the
/// verification census, derived from the entry records. This
/// record is what the retained census document carries
/// (readers SPEC §2.5); the envelope finding adds the export
/// digest to it.
/// The per-outcome entry counts a pack record reports.
#[derive(Default)]
struct PackCounts {
    decrypted_entries: u64,
    decryption_failed_entries: u64,
    delta_entries: u64,
    encrypted_entries: u64,
    md5_mismatch_entries: u64,
    removal_entries: u64,
    unreadable_entries: u64,
    verified_entries: u64,
}

fn pack_record(archive: &PckArchive, counts: &PackCounts) -> Value {
    let total_file_bytes: u64 = archive
        .entries
        .iter()
        .filter(|entry| !entry.removal())
        .map(|entry| entry.size)
        .sum();
    json!({
        "declared_entries": archive.entries.len(),
        "decrypted_entries": counts.decrypted_entries,
        "decryption_failed_entries": counts.decryption_failed_entries,
        "delta_entries": counts.delta_entries,
        "directory_decrypted": archive.directory_decrypted,
        "directory_encrypted": archive.directory_encrypted,
        "directory_offset": archive.directory_offset,
        "directory_salt": archive.directory_salt,
        "encrypted_entries": counts.encrypted_entries,
        "engine_major": archive.engine_major,
        "engine_minor": archive.engine_minor,
        "engine_patch": archive.engine_patch,
        "file_base": archive.file_base,
        "format_version": archive.format_version,
        "md5_mismatch_entries": counts.md5_mismatch_entries,
        "pack_flags": archive.pack_flags,
        "relative_base": archive.pack_flags & PACK_FLAG_RELATIVE_BASE != 0,
        "removal_entries": counts.removal_entries,
        "sparse_bundle": archive.sparse_bundle,
        "total_file_bytes": total_file_bytes,
        "unreadable_entries": counts.unreadable_entries,
        "verified_entries": counts.verified_entries,
    })
}

fn pack_finding(archive: &PckArchive, record: Value, export_digest: Option<&str>) -> Finding {
    let mut facts = record;
    facts["export_digest"] = match export_digest {
        Some(digest) => json!(digest),
        None => Value::Null,
    };
    let mut finding = Finding::new("godot_pck", Confidence::Observed, facts);
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
    let entry_flags_known = if archive.format_version >= 4 {
        ENTRY_FLAGS_KNOWN
    } else {
        ENTRY_FLAGS_KNOWN_LEGACY
    };
    if archive
        .entries
        .iter()
        .any(|entry| entry.flags & !entry_flags_known != 0)
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
        build_pack_full(format_version, pack_flags, files, None, false, false)
    }

    /// The full writer: with a `key`, entries flagged
    /// encrypted are stored as `FileAccessEncrypted` blobs
    /// over their plaintext, and `encrypt_directory` stores
    /// the whole directory as one such blob.
    /// `declare_full_blob_sizes` picks the directory size
    /// convention for encrypted entries: the stored blob
    /// length (true) or the plaintext length (false).
    fn build_pack_full(
        format_version: u32,
        pack_flags: u32,
        files: &[(&str, &[u8], u32)],
        key: Option<&[u8; 32]>,
        encrypt_directory: bool,
        declare_full_blob_sizes: bool,
    ) -> (Vec<u8>, Vec<usize>) {
        // Format 4 with an encrypted + sparse directory
        // carries the 32-byte salt after the directory offset
        // field, before the 64 reserved bytes.
        let salt = format_version == 4
            && pack_flags & PACK_FLAG_DIRECTORY_ENCRYPTED != 0
            && pack_flags & PACK_FLAG_SPARSE_BUNDLE != 0;
        let header_len: usize = match format_version {
            0 | 1 => 84,
            2 => 96,
            _ if salt => 136,
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
        let wrapped: Vec<Vec<u8>> = files
            .iter()
            .enumerate()
            .map(|(index, (_, contents, flags))| match key {
                Some(key)
                    if flags & ENTRY_FLAG_ENCRYPTED != 0 && flags & ENTRY_FLAG_REMOVAL == 0 =>
                {
                    let mut iv = [0_u8; 16];
                    iv[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
                    fae_wrap(key, &iv, contents)
                }
                _ => contents.to_vec(),
            })
            .collect();
        let stored_directory_len = directory_len
            + if encrypt_directory {
                FAE_HEADER_BYTES
            } else {
                0
            };
        let data_start = match format_version {
            3.. => header_len.div_ceil(32) * 32,
            2 => (header_len + stored_directory_len).div_ceil(32) * 32,
            _ => header_len + stored_directory_len,
        };
        let mut positions: Vec<u64> = Vec::new();
        let mut cursor = data_start;
        for (index, (_, _, flags)) in files.iter().enumerate() {
            if flags & ENTRY_FLAG_REMOVAL != 0 {
                positions.push(0);
                continue;
            }
            if format_version >= 2 {
                cursor = cursor.div_ceil(32) * 32;
            }
            positions.push(cursor as u64);
            cursor += wrapped[index].len();
        }
        let file_base = if format_version >= 2 {
            data_start as u64
        } else {
            0
        };
        let directory_start = if format_version >= 3 {
            cursor
        } else {
            header_len
        };
        let total_len = if format_version >= 3 {
            directory_start + stored_directory_len
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
        let mut dir: Vec<u8> = Vec::with_capacity(directory_len);
        dir.extend_from_slice(&(files.len() as u32).to_le_bytes());
        let mut offset_positions = Vec::new();
        for (index, (path, contents, flags)) in files.iter().enumerate() {
            let removal = flags & ENTRY_FLAG_REMOVAL != 0;
            let padded = padded_len(path);
            dir.extend_from_slice(&(padded as u32).to_le_bytes());
            let mut path_field = path.as_bytes().to_vec();
            path_field.resize(padded, 0);
            dir.extend_from_slice(&path_field);
            offset_positions.push(directory_start + dir.len());
            let stored = if removal {
                0
            } else if format_version >= 2 {
                positions[index] - file_base
            } else {
                positions[index]
            };
            dir.extend_from_slice(&stored.to_le_bytes());
            let declared = if removal {
                0
            } else if flags & ENTRY_FLAG_ENCRYPTED != 0 && declare_full_blob_sizes {
                wrapped[index].len() as u64
            } else {
                contents.len() as u64
            };
            dir.extend_from_slice(&declared.to_le_bytes());
            let md5 = if removal {
                [0_u8; 16]
            } else {
                md5_digest(contents)
            };
            dir.extend_from_slice(&md5);
            if format_version >= 2 {
                dir.extend_from_slice(&flags.to_le_bytes());
            }
        }
        assert_eq!(dir.len(), directory_len);
        if encrypt_directory {
            let blob = fae_wrap(
                key.expect("directory encryption requires a key"),
                &[0x5a; 16],
                &dir,
            );
            out[directory_start..directory_start + blob.len()].copy_from_slice(&blob);
        } else {
            out[directory_start..directory_start + dir.len()].copy_from_slice(&dir);
        }
        for (index, (_, _, flags)) in files.iter().enumerate() {
            if flags & ENTRY_FLAG_REMOVAL != 0 {
                continue;
            }
            let start = positions[index] as usize;
            out[start..start + wrapped[index].len()].copy_from_slice(&wrapped[index]);
        }
        (out, offset_positions)
    }

    /// Wrap plaintext the way a Godot writer stores an
    /// encrypted stream: MD5, length, IV, CFB ciphertext.
    fn fae_wrap(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(FAE_HEADER_BYTES + plaintext.len());
        blob.extend_from_slice(&md5_digest(plaintext));
        blob.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
        blob.extend_from_slice(iv);
        blob.extend_from_slice(&crate::aes::cfb128_encrypt(key, iv, plaintext));
        blob
    }

    /// The fixed test key and its hex form, for fixtures
    /// and `encryption_key` arguments.
    const TEST_KEY: [u8; 32] = [7_u8; 32];

    fn test_key_hex() -> String {
        TEST_KEY.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn write_u32(out: &mut [u8], at: usize, value: u32) {
        out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn run_inspect(test_name: &str, bytes: &[u8]) -> (PathBuf, Value) {
        run_inspect_with(test_name, bytes, None)
    }

    fn run_inspect_with(test_name: &str, bytes: &[u8], key_hex: Option<&str>) -> (PathBuf, Value) {
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
        let mut args = json!({"target": pack.display().to_string()});
        if let Some(key_hex) = key_hex {
            args["encryption_key"] = json!(key_hex);
        }
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

    #[test]
    fn adversarial_v4_header_truncated_inside_salt() {
        let (bytes, _) = build_pack(
            4,
            PACK_FLAG_DIRECTORY_ENCRYPTED | PACK_FLAG_SPARSE_BUNDLE,
            &[("res://a.txt", b"x", 0)],
        );
        // The salt occupies bytes 40..72; 60 ends inside it.
        let err = parse_pck(&bytes[..60]).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
    }

    #[test]
    fn adversarial_v5_refusal_names_the_new_supported_set() {
        let (mut bytes, _) = build_pack(2, 0, &[("res://a.txt", b"hello", 0)]);
        write_u32(&mut bytes, 4, 5);
        let err = parse_pck(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        assert!(err.message.contains("format version 5"), "{}", err.message);
        assert!(err.message.contains("1, 2, 4"), "{}", err.message);
    }

    #[test]
    fn validation_delta_bit_in_v3_is_an_unknown_flag_not_a_delta() {
        let (bytes, _) = build_pack(3, 0, &[("res://a.txt", b"hello", ENTRY_FLAG_DELTA)]);
        let (root, value) = run_inspect("v3-delta-bit", &bytes);
        let rows = entry_rows(&value);
        // The bit did not exist in format 3: the entry reads
        // as an ordinary verified entry, and the flag is
        // reported as unrecognised for this version.
        assert_eq!(rows[0]["delta"], false);
        assert_eq!(rows[0]["status"], "verified");
        let finding = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "godot_pck")
            .expect("godot_pck finding");
        assert!(
            finding["limitations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|text| text.as_str().unwrap().contains("unrecognised flag bits"))
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_v4_delta_entry_hashes_patch_bytes_never_md5() {
        let (bytes, _) = build_pack(
            4,
            0,
            &[
                ("res://main.gd", b"extends Node\n", 0),
                ("res://main.gd", b"PATCH!", ENTRY_FLAG_DELTA),
            ],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert_eq!(archive.format_version, 4);
        // extract() refuses delta entries: applying a patch
        // is content reconstruction.
        let err = extract(&bytes, &archive, &archive.entries[1]).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        let (root, value) = run_inspect("v4-delta", &bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "verified");
        assert_eq!(rows[1]["status"], "delta");
        assert_eq!(rows[1]["delta"], true);
        // The gate failure this test exists to catch: a delta
        // entry reported as MD5-verified.
        assert_eq!(rows[1]["md5_verified"], Value::Null);
        assert_eq!(rows[1]["sha256"], json!(sha256_hex(b"PATCH!")));
        assert_eq!(pack_facts(&value)["delta_entries"], 1);
        assert_eq!(pack_facts(&value)["format_version"], 4);
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "delta entries")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_v4_retention_document_is_written() {
        let (bytes, _) = build_pack(4, 0, &[("res://a.txt", b"hello", 0)]);
        let (root, value) = run_inspect("v4-retention", &bytes);
        let digest = pack_facts(&value)["export_digest"]
            .as_str()
            .expect("export_digest fact")
            .to_string();
        assert_eq!(digest.len(), 64);
        // The retained document lives at the §4.1 store path
        // for (subject, "archive_census") and digests to the
        // reported value.
        let subject_sha = sha256_hex(&bytes);
        let path = root
            .join("state")
            .join("ghidra")
            .join(&subject_sha[..32])
            .join("export-archive_census.json");
        let document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(fathom_core::proof::value_digest(&document), digest);
        assert_eq!(document["godot_pck"]["format_version"], 4);
        assert_eq!(document["godot_pck_entries"][0]["key"], "res://a.txt");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_v4_sparse_encrypted_directory_carries_salt() {
        let (bytes, _) = build_pack(
            4,
            PACK_FLAG_DIRECTORY_ENCRYPTED | PACK_FLAG_SPARSE_BUNDLE,
            &[("res://a.txt", b"x", 0)],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert!(archive.directory_encrypted);
        assert!(archive.directory_salt);
        let (root, value) = run_inspect("v4-salt", &bytes);
        assert_eq!(pack_facts(&value)["directory_salt"], true);
        assert_eq!(pack_facts(&value)["declared_entries"], 0);
        // Retention succeeded; the only unknown is the
        // encrypted directory itself.
        assert_eq!(value["unknowns"].as_array().unwrap().len(), 1);
        assert_eq!(value["unknowns"][0]["aspect"], "directory");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_v4_roundtrip_entries_and_extract() {
        let (bytes, _) = build_pack(
            4,
            0,
            &[
                ("res://main.gd", b"extends Node\n", 0),
                ("res://data.bin", &[1, 2, 3, 4], 0),
            ],
        );
        let archive = parse_pck(&bytes).unwrap();
        assert_eq!(archive.format_version, 4);
        assert!(!archive.directory_salt);
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

    // D-704 item 1': key handling, PCK decryption, texture
    // unwrap. The corpus holds no encrypted pack, so these
    // synthetic writer fixtures are the gate.

    #[test]
    fn decryption_key_parsing_forms() {
        let hex = test_key_hex();
        assert_eq!(parse_script_key(&hex).unwrap(), TEST_KEY);
        assert_eq!(parse_script_key(&format!("0x{hex}")).unwrap(), TEST_KEY);
        assert_eq!(parse_script_key(&hex.to_uppercase()).unwrap(), TEST_KEY);
        for bad in ["0707", "", "zz".repeat(32).as_str()] {
            let err = parse_script_key(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidRequest, "{bad}");
        }
        let err = parse_script_key(&"07".repeat(33)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn decryption_entry_roundtrip_both_size_conventions() {
        for declare_full_blob in [false, true] {
            let (bytes, _) = build_pack_full(
                2,
                0,
                &[
                    ("res://plain.txt", b"plain", 0),
                    ("res://secret.txt", b"secret-data", ENTRY_FLAG_ENCRYPTED),
                ],
                Some(&TEST_KEY),
                false,
                declare_full_blob,
            );
            let archive = parse_pck_with_key(&bytes, Some(&TEST_KEY)).unwrap();
            assert_eq!(archive.entries.len(), 2);
            assert_eq!(
                extract_with_key(&bytes, &archive, &archive.entries[1], Some(&TEST_KEY)).unwrap(),
                b"secret-data"
            );
            // Without the key the stored bytes stay refused,
            // and the keyless extract refuses too.
            let err = extract(&bytes, &archive, &archive.entries[1]).unwrap_err();
            assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
            let err = extract_with_key(&bytes, &archive, &archive.entries[1], None).unwrap_err();
            assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
            let (root, value) = run_inspect_with("dec-entry", &bytes, Some(&test_key_hex()));
            assert_eq!(value["status"], "complete");
            let rows = entry_rows(&value);
            assert_eq!(rows[1]["status"], "verified");
            assert_eq!(rows[1]["decrypted"], true);
            assert_eq!(rows[1]["md5_verified"], true);
            let facts = pack_facts(&value);
            assert_eq!(facts["decrypted_entries"], 1);
            assert_eq!(facts["decryption_failed_entries"], 0);
            assert_eq!(facts["verified_entries"], 2);
            fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn decryption_directory_roundtrip_v2_and_v3() {
        for format in [2, 3] {
            let (bytes, _) = build_pack_full(
                format,
                PACK_FLAG_DIRECTORY_ENCRYPTED,
                &[("res://a.txt", b"alpha", 0), ("res://b.txt", b"beta", 0)],
                Some(&TEST_KEY),
                true,
                false,
            );
            let keyless = parse_pck(&bytes).unwrap();
            assert!(keyless.directory_encrypted);
            assert!(!keyless.directory_decrypted);
            assert!(keyless.entries.is_empty());
            let archive = parse_pck_with_key(&bytes, Some(&TEST_KEY)).unwrap();
            assert!(archive.directory_decrypted);
            assert_eq!(archive.entries.len(), 2);
            assert_eq!(
                extract(&bytes, &archive, &archive.entries[0]).unwrap(),
                b"alpha"
            );
            let (root, value) = run_inspect_with("dec-dir", &bytes, Some(&test_key_hex()));
            assert_eq!(value["status"], "complete");
            assert_eq!(pack_facts(&value)["directory_decrypted"], true);
            fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn decryption_wrong_key_directory_is_a_typed_error() {
        let (bytes, _) = build_pack_full(
            2,
            PACK_FLAG_DIRECTORY_ENCRYPTED,
            &[("res://a.txt", b"alpha", 0)],
            Some(&TEST_KEY),
            true,
            false,
        );
        let wrong = [9_u8; 32];
        let err = parse_pck_with_key(&bytes, Some(&wrong)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactIntegrityMismatch);
    }

    #[test]
    fn decryption_wrong_key_entry_is_a_failed_row_not_garbage() {
        let (bytes, _) = build_pack_full(
            2,
            0,
            &[("res://secret.txt", b"secret-data", ENTRY_FLAG_ENCRYPTED)],
            Some(&TEST_KEY),
            false,
            false,
        );
        let wrong_hex: String = [9_u8; 32]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let (root, value) = run_inspect_with("dec-wrong", &bytes, Some(&wrong_hex));
        assert_eq!(value["status"], "partial");
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "decryption_failed");
        assert_eq!(rows[0]["sha256"], Value::Null);
        let facts = pack_facts(&value);
        assert_eq!(facts["decryption_failed_entries"], 1);
        assert_eq!(facts["decrypted_entries"], 0);
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "entry decryption")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_encrypted_blob_is_typed() {
        let (bytes, _) = build_pack_full(
            2,
            0,
            &[("res://secret.txt", b"secret-data", ENTRY_FLAG_ENCRYPTED)],
            Some(&TEST_KEY),
            false,
            false,
        );
        let archive = parse_pck(&bytes).unwrap();
        let start = stored_offset(&archive, &archive.entries[0]) as usize;
        let truncated = &bytes[..start + 20];
        let archive = parse_pck(truncated).unwrap();
        let err = extract_with_key(truncated, &archive, &archive.entries[0], Some(&TEST_KEY))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
    }

    #[test]
    fn adversarial_encrypted_entry_size_lie_is_rejected() {
        let (mut bytes, offset_positions) = build_pack_full(
            2,
            0,
            &[("res://secret.txt", b"secret-data", ENTRY_FLAG_ENCRYPTED)],
            Some(&TEST_KEY),
            false,
            false,
        );
        // The size field follows the offset field; declare a
        // length the blob does not carry (plaintext 11 + 7).
        write_u64(&mut bytes, offset_positions[0] + 8, 18);
        let archive = parse_pck(&bytes).unwrap();
        let err =
            extract_with_key(&bytes, &archive, &archive.entries[0], Some(&TEST_KEY)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactIntegrityMismatch);
    }

    #[test]
    fn adversarial_keyed_traversal_entry_stays_inert() {
        let (bytes, _) = build_pack_full(
            2,
            0,
            &[("../../evil.txt", b"payload", ENTRY_FLAG_ENCRYPTED)],
            Some(&TEST_KEY),
            false,
            false,
        );
        let (root, value) = run_inspect_with("dec-traversal", &bytes, Some(&test_key_hex()));
        assert_eq!(value["status"], "complete");
        assert_eq!(entry_rows(&value)[0]["path"], "../../evil.txt");
        assert!(!root.join("evil.txt").exists());
        fs::remove_dir_all(&root).ok();
    }

    fn png_payload() -> Vec<u8> {
        let mut payload = PNG_SIGNATURE.to_vec();
        payload.extend_from_slice(b"rest-of-the-file");
        payload
    }

    fn webp_payload() -> Vec<u8> {
        let mut payload = b"RIFF".to_vec();
        payload.extend_from_slice(&4_u32.to_le_bytes());
        payload.extend_from_slice(b"WEBP");
        payload
    }

    /// A `.ctex` in the shape the corpus measures: 56-byte
    /// header, payload length at 52, payload to the end.
    fn make_ctex(data_format: u32, payload: &[u8], width: u32, height: u32) -> Vec<u8> {
        let mut out = vec![0_u8; 56];
        out[0..4].copy_from_slice(b"GST2");
        write_u32(&mut out, 4, 1);
        write_u32(&mut out, 8, width);
        write_u32(&mut out, 12, height);
        write_u32(&mut out, 16, 0x0d00_0000);
        write_u32(&mut out, 20, 0xffff_ffff);
        write_u32(&mut out, 36, data_format);
        out[40..42].copy_from_slice(&(width as u16).to_le_bytes());
        out[42..44].copy_from_slice(&(height as u16).to_le_bytes());
        write_u32(&mut out, 48, 5);
        write_u32(&mut out, 52, payload.len() as u32);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn texture_ctex_png_and_webp_unwrap() {
        let png = png_payload();
        let ctex = make_ctex(1, &png, 64, 32);
        let texture = unwrap_texture(&ctex).unwrap();
        assert_eq!(texture.data_format, "png");
        assert_eq!(texture.payload, png.as_slice());
        assert_eq!((texture.width, texture.height), (64, 32));
        let webp = webp_payload();
        let ctex = make_ctex(2, &webp, 2560, 1440);
        let texture = unwrap_texture(&ctex).unwrap();
        assert_eq!(texture.data_format, "webp");
        assert_eq!(texture.payload, webp.as_slice());
        // Through the census: the row carries the unwrap fact.
        let ctex = make_ctex(2, &webp, 2560, 1440);
        let (bytes, _) = build_pack(4, 0, &[("res://tex.ctex", &ctex, 0)]);
        let (root, value) = run_inspect("ctex-row", &bytes);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["texture"]["data_format"], "webp");
        assert_eq!(rows[0]["texture"]["width"], 2560);
        assert_eq!(
            rows[0]["texture"]["payload_sha256"],
            json!(sha256_hex(&webp))
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn texture_ctex_refusals_are_typed() {
        let png = png_payload();
        let err = unwrap_texture(&make_ctex(0, &png, 8, 8)).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        let err = unwrap_texture(&make_ctex(3, &png, 8, 8)).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        // Declared PNG, actual WebP: the declaration lies.
        let err = unwrap_texture(&make_ctex(1, &webp_payload(), 8, 8)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactIntegrityMismatch);
        // Length lie: payload does not span the entry.
        let mut lying = make_ctex(1, &png, 8, 8);
        lying.push(0);
        let err = unwrap_texture(&lying).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactIntegrityMismatch);
        // Unknown container version.
        let mut v2 = make_ctex(1, &png, 8, 8);
        write_u32(&mut v2, 4, 2);
        let err = unwrap_texture(&v2).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        // Not a texture at all.
        let err = unwrap_texture(b"plain bytes").unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
    }

    #[test]
    fn texture_stex_unwraps_png_and_refuses_other_payloads() {
        let png = png_payload();
        let mut stex = vec![0_u8; 20];
        stex[0..4].copy_from_slice(b"GDST");
        write_u32(&mut stex, 4, 64);
        write_u32(&mut stex, 8, 32);
        stex.extend_from_slice(&png);
        let texture = unwrap_texture(&stex).unwrap();
        assert_eq!(texture.data_format, "png");
        assert_eq!(texture.payload, png.as_slice());
        assert_eq!((texture.width, texture.height), (64, 32));
        let mut garbage = vec![0_u8; 20];
        garbage[0..4].copy_from_slice(b"GDST");
        garbage.extend_from_slice(b"not an image");
        let err = unwrap_texture(&garbage).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
    }
}
