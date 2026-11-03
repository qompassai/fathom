//! RPG Maker archive census and extraction: RGSSAD
//! containers (`.rgssad` / `.rgss2a` = version 1,
//! `.rgss3a` = version 3).
//!
//! Version 1 layout, proven against a real corpus
//! archive (an mkxp-z title's `Game.rgssad`, whose entry
//! names and Ruby-Marshal payload heads decode exactly):
//! an 8-byte signature `RGSSAD\0\x01`, then back-to-back
//! entries. A single rolling key (seed `0xDEADCAFE`,
//! advanced as `key = key * 7 + 3` after every use)
//! decrypts the header stream: each u32 field is XORed
//! with the key, and each name byte is XORed with the
//! key's low byte, advancing per byte. Entry data is
//! XORed word-wise (4-byte groups, key bytes in
//! little-endian order, remainder bytes from the key's
//! low bytes in order) with a *local copy* of the key
//! taken at the entry's data start and advanced per
//! word — the shared header key does not advance over
//! data, so the next entry's header continues from the
//! post-size state.
//!
//! Version 3 layout (`.rgss3a`, VX Ace): the signature
//! is followed by a plaintext u32 seed; the archive key
//! is `seed * 9 + 3` and does not advance. Entry headers
//! form a directory at the front: offset, size, per-entry
//! data key, and name length, each XORed with the archive
//! key; name bytes are XORed with the archive key's bytes
//! cycling. Data is XORed word-wise with the per-entry
//! key, advanced per word as in version 1. No version 3
//! archive exists in the estate corpus — that half is
//! proven by synthetic fixtures only, and says so.
//!
//! Entry names are untrusted input in extraction: they
//! are confined to the output directory exactly as in
//! the Ren'Py lane. Payload identity is the SHA-256 of
//! the *decrypted* bytes — the meaningful content.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, GAME_EXTRACT_BYTES_MAX, RGSS_ENTRIES_MAX, RGSS_NAME_BYTES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
        .with_target("rgss archive")
}

fn resource(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ResourceConstraint, message.into()).with_target("rgss archive")
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into()).with_target("rgss archive")
}

/// The RGSS key recurrence.
fn advance(key: u32) -> u32 {
    key.wrapping_mul(7).wrapping_add(3)
}

/// Decrypt `data` in place word-wise from key state
/// `key`: full 4-byte groups XOR the whole key (advanced
/// per group), remainder bytes XOR the key's bytes in
/// little-endian order.
fn decrypt_words(data: &mut [u8], mut key: u32) {
    let full = data.len() / 4;
    for group in 0..full {
        let at = group * 4;
        let word = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        data[at..at + 4].copy_from_slice(&(word ^ key).to_le_bytes());
        key = advance(key);
    }
    for (i, byte) in data[full * 4..].iter_mut().enumerate() {
        *byte ^= (key >> (8 * i)) as u8;
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// One archive entry: where its decrypted content lives
/// and the key state that decrypts it.
#[derive(Debug)]
struct Entry {
    data_key: u32,
    name: String,
    offset: u64,
    size: u64,
}

/// Read exactly `count` bytes at the cursor.
fn read_exact(file: &mut File, count: usize) -> Result<Vec<u8>, FathomError> {
    let mut buffer = vec![0_u8; count];
    file.read_exact(&mut buffer)
        .map_err(|_| mismatch("rgss archive ends mid-entry"))?;
    Ok(buffer)
}

/// Read one plain little-endian u32 at the cursor.
fn read_plain_u32(file: &mut File) -> Result<u32, FathomError> {
    let raw = read_exact(file, 4)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Read one key-XORed u32 from the header stream,
/// advancing the key after use.
fn read_header_u32(file: &mut File, key: &mut u32) -> Result<u32, FathomError> {
    let value = read_plain_u32(file)? ^ *key;
    *key = advance(*key);
    Ok(value)
}

/// Open and parse an archive: signature, version, and
/// the entries for either layout.
fn parse_archive(path: &Path) -> Result<(u8, Vec<Entry>, u64), FathomError> {
    let mut file =
        File::open(path).map_err(|error| mismatch(format!("cannot open rgss archive: {error}")))?;
    let file_len = file
        .metadata()
        .map_err(|error| mismatch(format!("cannot stat rgss archive: {error}")))?
        .len();
    if file_len > ARCHIVE_TARGET_BYTES_MAX {
        return Err(resource(format!(
            "rgss archive over {ARCHIVE_TARGET_BYTES_MAX} bytes"
        )));
    }
    if file_len < 12 {
        return Err(mismatch("rgss archive is shorter than its header"));
    }
    let header = read_exact(&mut file, 8)?;
    if header[..6] != *b"RGSSAD" || header[6] != 0 {
        return Err(unsupported("target lacks the RGSSAD signature"));
    }
    let version = header[7];
    let entries = match version {
        1 => parse_v1(&mut file, file_len)?,
        3 => parse_v3(&mut file, file_len)?,
        other => {
            return Err(unsupported(format!(
                "rgss archive version {other} is not a supported layout (1 or 3)"
            )));
        }
    };
    Ok((version, entries, file_len))
}

/// Parse the version 1 sequential layout.
fn parse_v1(file: &mut File, file_len: u64) -> Result<Vec<Entry>, FathomError> {
    let mut key: u32 = 0xDEAD_CAFE;
    let mut entries = Vec::new();
    let mut position = 8_u64;
    while position < file_len {
        if entries.len() >= RGSS_ENTRIES_MAX {
            return Err(resource(format!(
                "rgss archive over {RGSS_ENTRIES_MAX} entries"
            )));
        }
        file.seek(SeekFrom::Start(position))
            .map_err(|error| mismatch(format!("rgss archive seek failed: {error}")))?;
        let name_len = u64::from(read_header_u32(file, &mut key)?);
        if name_len == 0 || name_len > RGSS_NAME_BYTES_MAX as u64 {
            return Err(mismatch(format!(
                "rgss entry name length {name_len} is implausible"
            )));
        }
        let mut name_bytes = read_exact(file, name_len as usize)?;
        for byte in name_bytes.iter_mut() {
            *byte ^= (key & 0xFF) as u8;
            key = advance(key);
        }
        let name = String::from_utf8(name_bytes)
            .map_err(|_| mismatch("rgss entry name is not UTF-8 (census carries names as text)"))?;
        let size = u64::from(read_header_u32(file, &mut key)?);
        position += 4 + name_len + 4;
        let data_end = position
            .checked_add(size)
            .filter(|end| *end <= file_len)
            .ok_or_else(|| mismatch(format!("rgss entry '{name}' overruns the archive")))?;
        entries.push(Entry {
            data_key: key,
            name,
            offset: position,
            size,
        });
        position = data_end;
    }
    Ok(entries)
}

/// Parse the version 3 directory layout.
fn parse_v3(file: &mut File, file_len: u64) -> Result<Vec<Entry>, FathomError> {
    file.seek(SeekFrom::Start(8))
        .map_err(|error| mismatch(format!("rgss archive seek failed: {error}")))?;
    let seed = read_plain_u32(file)?;
    let key = seed.wrapping_mul(9).wrapping_add(3);
    let mut entries: Vec<Entry> = Vec::new();
    let mut position = 12_u64;
    loop {
        if entries.len() >= RGSS_ENTRIES_MAX {
            return Err(resource(format!(
                "rgss archive over {RGSS_ENTRIES_MAX} entries"
            )));
        }
        // The directory ends where the first entry's
        // data begins.
        if let Some(first) = entries.first() {
            if position >= first.offset {
                break;
            }
        }
        if position >= file_len {
            return Err(mismatch("rgss version 3 directory runs past the archive"));
        }
        file.seek(SeekFrom::Start(position))
            .map_err(|error| mismatch(format!("rgss archive seek failed: {error}")))?;
        let mut fields = [0_u32; 4];
        for field in fields.iter_mut() {
            *field = read_plain_u32(file)? ^ key;
        }
        let (offset, size, data_key, name_len) = (
            u64::from(fields[0]),
            u64::from(fields[1]),
            fields[2],
            fields[3],
        );
        if name_len == 0 || name_len > RGSS_NAME_BYTES_MAX {
            return Err(mismatch(format!(
                "rgss entry name length {name_len} is implausible"
            )));
        }
        let mut name_bytes = read_exact(file, name_len as usize)?;
        for (i, byte) in name_bytes.iter_mut().enumerate() {
            *byte ^= (key >> (8 * (i % 4))) as u8;
        }
        let name = String::from_utf8(name_bytes)
            .map_err(|_| mismatch("rgss entry name is not UTF-8 (census carries names as text)"))?;
        if offset
            .checked_add(size)
            .filter(|end| *end <= file_len)
            .is_none()
        {
            return Err(mismatch(format!(
                "rgss entry '{name}' overruns the archive"
            )));
        }
        entries.push(Entry {
            data_key,
            name,
            offset,
            size,
        });
        position += 16 + u64::from(name_len);
    }
    Ok(entries)
}

/// Confine an archive entry name to a relative path
/// under the output directory: both separators split,
/// absolute paths and `..` components refuse.
fn safe_entry_relpath(entry: &str) -> Option<PathBuf> {
    if entry.is_empty() || entry.starts_with('/') || entry.starts_with('\\') {
        return None;
    }
    let mut out = PathBuf::new();
    for part in entry.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Stream one entry's decrypted bytes through `sink` in
/// 64 KiB word-aligned chunks, returning the SHA-256 of
/// the decrypted content.
fn stream_entry(
    file: &mut File,
    entry: &Entry,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), FathomError>,
) -> Result<String, FathomError> {
    file.seek(SeekFrom::Start(entry.offset))
        .map_err(|error| mismatch(format!("rgss archive seek failed: {error}")))?;
    let mut hasher = Sha256::new();
    let mut key = entry.data_key;
    let mut remaining = entry.size;
    while remaining > 0 {
        // 65_536 is a multiple of 4, so only the final
        // chunk can end mid-word.
        let take = remaining.min(65_536) as usize;
        let mut chunk = read_exact(file, take)?;
        decrypt_words(&mut chunk, key);
        for _ in 0..take / 4 {
            key = advance(key);
        }
        hasher.update(&chunk);
        sink(&chunk)?;
        remaining -= take as u64;
    }
    Ok(hex_bytes(&hasher.finalize()))
}

/// Write `rel` under `root` atomically (temp + rename),
/// creating parent directories.
fn write_atomic(root: &Path, rel: &Path, bytes: &[u8]) -> Result<(), FathomError> {
    let destination = root.join(rel);
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
    }
    let temp = destination.with_extension("partial");
    let mut file = File::create(&temp)
        .map_err(|error| mismatch(format!("cannot create output file: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| mismatch(format!("cannot write output file: {error}")))?;
    std::fs::rename(&temp, &destination)
        .map_err(|error| mismatch(format!("cannot finalise output file: {error}")))?;
    Ok(())
}

/// Census one RGSS archive: version, entries with sizes
/// and decrypted-content hashes.
pub fn inspect_rgss_archive(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&target, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let (version, entries, file_len) = parse_archive(&target)?;
    let mut file = File::open(&target)
        .map_err(|error| mismatch(format!("cannot open rgss archive: {error}")))?;
    let mut rows = Vec::with_capacity(entries.len());
    let mut total_size = 0_u64;
    for entry in &entries {
        let sha256 = stream_entry(&mut file, entry, &mut |_| Ok(()))?;
        total_size += entry.size;
        rows.push(json!({
            "bytes": entry.size,
            "name": entry.name,
            "sha256": sha256,
        }));
    }
    let document = json!({"entries": rows, "version": version});
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "archive_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut evidence = Evidence::new("inspect_rgss_archive", "rpgmaker");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "rgss_archive",
        Confidence::Observed,
        json!({
            "archive_bytes": file_len,
            "entries": entries.len(),
            "export_digest": digest,
            "payload_bytes": total_size,
            "version": version,
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": entries.len(), "total": entries.len()}),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

/// Extract one RGSS archive's entries, decrypted, into
/// an output directory with a manifest. Entry content is
/// streamed (large archives never sit in memory).
pub fn extract_rgss_archive(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&target, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let output_dir =
        paths::validate_output_dir(config, Path::new(require_str(args, "output_dir")?))?;
    let (version, entries, _file_len) = parse_archive(&target)?;
    std::fs::create_dir_all(&output_dir)
        .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
    let mut file = File::open(&target)
        .map_err(|error| mismatch(format!("cannot open rgss archive: {error}")))?;
    let mut rows = Vec::with_capacity(entries.len());
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut spent = 0_u64;
    for entry in &entries {
        let Some(rel) = safe_entry_relpath(&entry.name) else {
            *counts.entry("refused_path").or_default() += 1;
            rows.push(json!({
                "bytes": 0, "declared_bytes": entry.size, "name": entry.name,
                "sha256": null, "status": "refused_path",
            }));
            continue;
        };
        if spent.saturating_add(entry.size) > GAME_EXTRACT_BYTES_MAX {
            *counts.entry("skipped_budget").or_default() += 1;
            rows.push(json!({
                "bytes": 0, "declared_bytes": entry.size, "name": entry.name,
                "sha256": null, "status": "skipped_budget",
            }));
            continue;
        }
        let destination = output_dir.join(&rel);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
        }
        let temp = destination.with_extension("partial");
        let mut out_file = File::create(&temp)
            .map_err(|error| mismatch(format!("cannot create output file: {error}")))?;
        let sha256 = stream_entry(&mut file, entry, &mut |chunk| {
            out_file
                .write_all(chunk)
                .map_err(|error| mismatch(format!("cannot write output file: {error}")))
        })?;
        std::fs::rename(&temp, &destination)
            .map_err(|error| mismatch(format!("cannot finalise output file: {error}")))?;
        spent += entry.size;
        *counts.entry("extracted").or_default() += 1;
        rows.push(json!({
            "bytes": entry.size, "declared_bytes": entry.size, "name": entry.name,
            "sha256": sha256, "status": "extracted",
        }));
    }
    let totals = json!({
        "extracted": counts.get("extracted").copied().unwrap_or(0),
        "refused_path": counts.get("refused_path").copied().unwrap_or(0),
        "skipped_budget": counts.get("skipped_budget").copied().unwrap_or(0),
    });
    let manifest = json!({
        "archive": target.display().to_string(),
        "entries": rows,
        "format": format!("RGSSAD version {version}"),
        "notes": [
            "entry content is the decrypted payload; sha256 is over decrypted bytes",
            "entry paths are confined to the output directory; refused paths are recorded, never written",
        ],
        "totals": totals,
        "version": version,
    });
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|error| mismatch(format!("manifest serialisation failed: {error}")))?;
    write_atomic(
        &output_dir,
        Path::new("manifest.json"),
        manifest_json.as_bytes(),
    )?;
    let extracted = counts.get("extracted").copied().unwrap_or(0);
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "rgss_extract", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut evidence = Evidence::new("extract_rgss_archive", "rpgmaker");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "rgss_extract",
        Confidence::Observed,
        json!({
            "bytes_written": spent,
            "entries": entries.len(),
            "export_digest": digest,
            "extracted": extracted,
            "output_dir": output_dir.display().to_string(),
            "version": version,
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows_len(&rows), "total": rows_len(&rows)}),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "extraction retention failed ({note}); the manifest stands on disk, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

fn rows_len(rows: &[Value]) -> usize {
    rows.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::registry::Registry;
    use serde_json::json;
    use std::fs;

    /// Build a version 1 archive from (name, payload)
    /// pairs using the proven schedule.
    fn build_v1(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"RGSSAD\0\x01".to_vec();
        let mut key: u32 = 0xDEAD_CAFE;
        for (name, payload) in files {
            out.extend_from_slice(&(name.len() as u32 ^ key).to_le_bytes());
            key = advance(key);
            for byte in name.bytes() {
                out.push(byte ^ (key & 0xFF) as u8);
                key = advance(key);
            }
            out.extend_from_slice(&(payload.len() as u32 ^ key).to_le_bytes());
            key = advance(key);
            let mut encrypted = payload.to_vec();
            decrypt_words(&mut encrypted, key);
            out.extend_from_slice(&encrypted);
        }
        out
    }

    /// Build a version 3 archive from (name, payload)
    /// pairs using the documented directory layout.
    fn build_v3(files: &[(&str, &[u8])]) -> Vec<u8> {
        let seed: u32 = 0x1122_3344;
        let key = seed.wrapping_mul(9).wrapping_add(3);
        let mut directory = Vec::new();
        let mut data = Vec::new();
        let mut offset = 12 + files.iter().map(|(name, _)| 16 + name.len()).sum::<usize>();
        for (index, (name, payload)) in files.iter().enumerate() {
            let entry_key = 0xABCD_0000_u32 + index as u32;
            for value in [
                offset as u32,
                payload.len() as u32,
                entry_key,
                name.len() as u32,
            ] {
                directory.extend_from_slice(&(value ^ key).to_le_bytes());
            }
            for (i, byte) in name.bytes().enumerate() {
                directory.push(byte ^ (key >> (8 * (i % 4))) as u8);
            }
            let mut encrypted = payload.to_vec();
            decrypt_words(&mut encrypted, entry_key);
            data.extend_from_slice(&encrypted);
            offset += payload.len();
        }
        let mut out = b"RGSSAD\0\x03".to_vec();
        out.extend_from_slice(&seed.to_le_bytes());
        out.extend_from_slice(&directory);
        out.extend_from_slice(&data);
        out
    }

    fn run_extract(
        test_name: &str,
        bytes: &[u8],
    ) -> (PathBuf, PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("Game.rgssad");
        fs::write(&target, bytes).unwrap();
        let out = root.join("out");
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({
            "output_dir": out.display().to_string(),
            "target": target.display().to_string(),
        });
        let result = extract_rgss_archive(&Registry::new(), &config, &args);
        (root, out, result)
    }

    fn run_inspect(test_name: &str, bytes: &[u8]) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("Game.rgssad");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": target.display().to_string()});
        let result = inspect_rgss_archive(&Registry::new(), &config, &args);
        (root, result)
    }

    #[test]
    fn validation_v1_round_trip() {
        let marshalish: &[u8] = b"\x04\x08I\"\x0bhello\x06:\x06ET";
        let odd_size: &[u8] = b"1234567"; // word + remainder
        let archive = build_v1(&[
            ("Data\\Scripts.rxdata", marshalish),
            ("Data\\Odd.dat", odd_size),
        ]);
        let (root, result) = run_inspect("v1-census", &archive);
        let value = result.unwrap();
        let facts = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "rgss_archive")
            .map(|finding| &finding["facts"])
            .unwrap();
        assert_eq!(facts["version"], 1);
        assert_eq!(facts["entries"], 2);
        fs::remove_dir_all(&root).ok();

        let (root, out, result) = run_extract("v1-extract", &archive);
        result.unwrap();
        assert_eq!(
            fs::read(out.join("Data/Scripts.rxdata")).unwrap(),
            marshalish
        );
        assert_eq!(fs::read(out.join("Data/Odd.dat")).unwrap(), odd_size);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_v3_round_trip() {
        let payload: &[u8] = b"\x04\x08marshal payload for vx ace";
        let archive = build_v3(&[("Data\\Actors.rvdata2", payload)]);
        let (root, result) = run_inspect("v3-census", &archive);
        let value = result.unwrap();
        let facts = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "rgss_archive")
            .map(|finding| &finding["facts"])
            .unwrap();
        assert_eq!(facts["version"], 3);
        assert_eq!(facts["entries"], 1);
        fs::remove_dir_all(&root).ok();

        let (root, out, result) = run_extract("v3-extract", &archive);
        result.unwrap();
        assert_eq!(fs::read(out.join("Data/Actors.rvdata2")).unwrap(), payload);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_headers_refused() {
        // Bad magic.
        let (root, result) = run_inspect("bad-magic", b"NOTRGSS!\x01padding");
        assert_eq!(result.unwrap_err().code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
        // Version 2 does not exist in the wild; refuse by name.
        let (root, result) = run_inspect("version-2", b"RGSSAD\0\x02\x00\x00\x00\x00");
        assert_eq!(result.unwrap_err().code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
        // Truncated mid-entry: the declared payload overruns.
        let mut archive = build_v1(&[("Data\\Big.dat", b"0123456789abcdef")]);
        archive.truncate(archive.len() - 4);
        let (root, result) = run_inspect("truncated", &archive);
        assert_eq!(
            result.unwrap_err().code,
            ErrorCode::ArtifactIntegrityMismatch
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_extract_refuses_parent_paths() {
        let archive = build_v1(&[("..\\evil.dat", b"pwned")]);
        let (root, out, result) = run_extract("evil-path", &archive);
        let value = result.unwrap();
        let entries = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "entries")
            .map(|finding| &finding["facts"]["entries"])
            .unwrap();
        assert_eq!(entries[0]["status"], "refused_path");
        assert!(!root.join("evil.dat").exists());
        assert!(!out.join("evil.dat").exists());
        fs::remove_dir_all(&root).ok();
    }
}
