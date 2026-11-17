//! RPG Maker MV/MZ encrypted image decryption
//! (D-1651): the `.rpgmvp` counterpart to the MV audio
//! lane in `audio_re`.
//!
//! The format is the one the audio lane already proves
//! against the corpus: every encrypted file carries a
//! 16-byte fake header (the literal `RPGMV` signature
//! plus the format's fixed version bytes); decryption
//! drops the header, XORs the first 16 body bytes with
//! the 16-byte key, and copies the rest verbatim. MV
//! carries the tree under a `www` directory, MZ at the
//! game root directly; both keep `data/System.json`
//! with the `encryptionKey` and the `hasEncryptedImages`
//! flag, and both generations use the identical byte
//! format (proven on real MV titles; the MZ layout is
//! covered by fixture — see the module tests).
//!
//! The never-record discipline is the lane's reason to
//! exist: the key is read from the title's own
//! System.json at runtime, held in memory only, and
//! never written to a manifest, a log, an error message,
//! or any other artifact. Error paths name the failure,
//! never the key material. The census in `game` is
//! untouched: it still records only that a key is
//! present, never the key.
//!
//! Fail-closed writes: a decrypted payload is written
//! only when it parses as a PNG — the 8-byte signature
//! and a well-formed IHDR with non-zero dimensions all
//! sit inside the 16 keyed bytes or immediately after
//! them, so the check is decisive. A payload that fails
//! (wrong key, corrupt source) is recorded in the
//! manifest as `unverified` and never written. This is
//! deliberately stricter than the audio lane, which
//! writes `decrypted_unverified` payloads: image
//! plaintext that cannot be verified is garbage, not
//! study material.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding};
use fathom_core::limits::{
    GAME_EXTRACT_BYTES_MAX, MV_FILE_BYTES_MAX, MV_FILES_MAX, MV_SYSTEM_JSON_BYTES_MAX,
};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

use crate::audio_re::{mv_decrypt, mv_key_from_hex, write_atomic};

type Result<T> = std::result::Result<T, FathomError>;

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

fn resource(message: String) -> FathomError {
    FathomError::new(ErrorCode::ResourceConstraint, message)
}

fn unsupported(message: String) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message)
}

/// The PNG signature every decrypted image must carry.
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Locate the game root: the target itself or its `www`
/// child must carry `data/System.json` (the same search
/// the audio lane performs — MV nests under `www`, MZ
/// sits at the root).
fn locate_game_root(target: &Path) -> Result<PathBuf> {
    [target.to_path_buf(), target.join("www")]
        .into_iter()
        .find(|candidate| candidate.join("data/System.json").is_file())
        .ok_or_else(|| {
            unsupported("no data/System.json under the target or its www directory".into())
        })
}

/// Read System.json (bounded) and return the in-memory
/// key plus the `hasEncryptedImages` flag. The key text
/// is consumed here and never leaves this function
/// except as decoded bytes; no error message carries
/// any part of it.
fn read_system_key(game_root: &Path) -> Result<([u8; 16], bool)> {
    let system_path = game_root.join("data/System.json");
    let metadata = std::fs::metadata(&system_path)
        .map_err(|error| mismatch(format!("cannot stat System.json: {error}")))?;
    if metadata.len() > MV_SYSTEM_JSON_BYTES_MAX {
        return Err(resource(format!(
            "System.json over {MV_SYSTEM_JSON_BYTES_MAX} bytes"
        )));
    }
    let system_bytes = std::fs::read(&system_path)
        .map_err(|error| mismatch(format!("cannot read System.json: {error}")))?;
    let system: Value = serde_json::from_slice(&system_bytes)
        .map_err(|error| mismatch(format!("System.json is not valid JSON: {error}")))?;
    let key_text = system
        .get("encryptionKey")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("System.json carries no encryptionKey".into()))?;
    let key = mv_key_from_hex(key_text)
        .ok_or_else(|| unsupported("System.json encryptionKey is not 32 hex characters".into()))?;
    let has_encrypted_images = system
        .get("hasEncryptedImages")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok((key, has_encrypted_images))
}

/// Verify decrypted bytes as a PNG and return its
/// dimensions: the 8-byte signature, then the first
/// chunk must be a 13-byte IHDR with non-zero width and
/// height. The whole checked span is inside or beside
/// the keyed region, so a wrong key cannot pass.
fn png_dimensions(plain: &[u8]) -> Option<(u32, u32)> {
    if plain.len() < 33 || !plain.starts_with(PNG_SIGNATURE) {
        return None;
    }
    let ihdr_len = u32::from_be_bytes(plain[8..12].try_into().ok()?);
    if ihdr_len != 13 || &plain[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(plain[16..20].try_into().ok()?);
    let height = u32::from_be_bytes(plain[20..24].try_into().ok()?);
    if width == 0 || height == 0 {
        return None;
    }
    Some((width, height))
}

/// Why one encrypted image was refused. The lane turns
/// each refusal into a manifest status; no plaintext is
/// produced on either arm.
#[derive(Debug, PartialEq, Eq)]
enum DecryptRefusal {
    /// The payload lacks the RPGMV fake header.
    BadHeader,
    /// Decryption ran but the payload does not parse as
    /// a PNG: wrong key or corrupt source.
    Unverified,
}

/// Decrypt one encrypted image and verify it as a PNG,
/// returning the plaintext and its dimensions. Fail-
/// closed: a bad fake header and a payload that does
/// not verify (wrong key or corrupt source) both
/// refuse, and no plaintext leaves this function on
/// failure.
fn decrypt_image(
    bytes: &[u8],
    key: &[u8; 16],
) -> std::result::Result<(Vec<u8>, (u32, u32)), DecryptRefusal> {
    let plain = mv_decrypt(bytes, key).ok_or(DecryptRefusal::BadHeader)?;
    let dimensions = png_dimensions(&plain).ok_or(DecryptRefusal::Unverified)?;
    Ok((plain, dimensions))
}

/// Bounded sorted walk of the image tree collecting
/// `.rpgmvp` files (the audio lane's walk shape).
fn collect_images(img_root: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    if !img_root.is_dir() {
        return Ok(files);
    }
    let mut stack: Vec<PathBuf> = vec![img_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|error| mismatch(format!("cannot walk image tree: {error}")))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        entries.sort();
        for entry in entries {
            if entry.is_dir() {
                stack.push(entry);
            } else if entry.is_file()
                && entry
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("rpgmvp"))
            {
                files.push(entry);
            }
        }
    }
    files.sort();
    if files.len() > MV_FILES_MAX {
        return Err(resource(format!(
            "encrypted image file count {} exceeds the bound ({MV_FILES_MAX})",
            files.len()
        )));
    }
    Ok(files)
}

/// Decrypt and extract a RPG Maker MV/MZ game's
/// encrypted images (.rpgmvp) from its game tree into
/// an output directory under a target root, using the
/// encryptionKey in data/System.json (the key itself is
/// never recorded), with a manifest whose rows verify
/// the decrypted PNG signature and IHDR; payloads that
/// fail verification are recorded, never written.
pub fn extract_rpgmaker_mv_images(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let output_arg = require_str(args, "output_dir")?;
    let output_dir = paths::validate_output_dir(config, Path::new(output_arg))?;
    let mut evidence = Evidence::new("extract_rpgmaker_mv_images", "rpgmaker");
    let game_root = locate_game_root(&path)?;
    let (key, has_encrypted_images) = read_system_key(&game_root)?;
    let files = collect_images(&game_root.join("img"))?;
    let mut rows: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut spent: u64 = 0;
    for file_path in &files {
        let status = process_image(
            file_path,
            &game_root,
            &output_dir,
            &key,
            &mut spent,
            &mut rows,
        );
        *counts.entry(status).or_insert(0) += 1;
    }
    evidence.add_unknown(
        "retention",
        "directory targets carry no single subject hash; the manifest is written to the output directory but not proof-retained",
    );
    let manifest = json!({
        "entries": rows,
        "format": "RPG Maker MV/MZ encrypted images (.rpgmvp)",
        "has_encrypted_images": has_encrypted_images,
        "notes": [
            "decryption drops the 16-byte fake header and XORs the first 16 body bytes with the System.json encryption key; the key itself is never recorded",
            "status verified means the decrypted payload parses as a PNG (signature and IHDR with non-zero dimensions); payloads that fail verification are recorded, never written",
        ],
        "source": game_root.display().to_string(),
        "totals": {
            "bad_header": counts.get("bad_header").copied().unwrap_or(0),
            "entries": files.len(),
            "failed": counts.get("failed").copied().unwrap_or(0),
            "skipped_budget": counts.get("skipped_budget").copied().unwrap_or(0),
            "unverified": counts.get("unverified").copied().unwrap_or(0),
            "verified": counts.get("verified").copied().unwrap_or(0),
        },
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("cannot serialise manifest: {error}")))?;
    std::fs::create_dir_all(&output_dir)
        .map_err(|error| mismatch(format!("cannot create output directory: {error}")))?;
    std::fs::write(output_dir.join("manifest.json"), &manifest_bytes)
        .map_err(|error| mismatch(format!("cannot write manifest: {error}")))?;
    evidence.coverage.examined = rows.len() as u64;
    evidence.coverage.total = rows.len() as u64;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    evidence.add_finding(Finding::new(
        "rpgmaker_mv_image_extract",
        Confidence::Observed,
        json!({
            "bytes_written": spent,
            "entries": files.len(),
            "format": "RPG Maker MV/MZ encrypted images",
            "game_root": game_root.display().to_string(),
            "has_encrypted_images": has_encrypted_images,
            "output_dir": output_dir.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": manifest["entries"], "returned": rows.len(), "total": rows.len()}),
    ));
    Ok(evidence.to_value())
}

/// Process one encrypted image: budget-check, read,
/// decrypt, verify, and write only on verification.
/// Pushes the manifest row and returns the row's status.
fn process_image(
    file_path: &Path,
    game_root: &Path,
    output_dir: &Path,
    key: &[u8; 16],
    spent: &mut u64,
    rows: &mut Vec<Value>,
) -> &'static str {
    let relative = file_path
        .strip_prefix(game_root)
        .unwrap_or(file_path)
        .to_path_buf();
    let size = file_path.metadata().map(|meta| meta.len()).unwrap_or(0);
    let mut row = json!({
        "bytes": size,
        "path": relative.display().to_string(),
    });
    if size > MV_FILE_BYTES_MAX || spent.saturating_add(size) > GAME_EXTRACT_BYTES_MAX {
        row["status"] = json!("skipped_budget");
        rows.push(row);
        return "skipped_budget";
    }
    let status = match std::fs::read(file_path) {
        Err(_) => "failed",
        Ok(bytes) => match decrypt_image(&bytes, key) {
            Err(DecryptRefusal::BadHeader) => "bad_header",
            Err(DecryptRefusal::Unverified) => "unverified",
            Ok((plain, (width, height))) => {
                let out_relative = relative.with_extension("png");
                let destination = output_dir.join(&out_relative);
                if let Some(parent) = destination.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match write_atomic(&destination, &plain) {
                    Ok(digest) => {
                        *spent += plain.len() as u64;
                        row["artifact"] = json!({
                            "bytes": plain.len(),
                            "height": height,
                            "kind": "png",
                            "path": out_relative.display().to_string(),
                            "sha256": digest,
                            "width": width,
                        });
                        "verified"
                    }
                    Err(_) => "failed",
                }
            }
        },
    };
    row["status"] = json!(status);
    rows.push(row);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::registry::Registry;
    use serde_json::json;
    use std::fs;

    /// A synthetic key generated inside the test suite —
    /// never a real title's key.
    fn synthetic_key() -> [u8; 16] {
        let mut key = [0u8; 16];
        for (index, slot) in key.iter_mut().enumerate() {
            *slot = (index as u8).wrapping_mul(37).wrapping_add(11);
        }
        key
    }

    fn key_hex(key: &[u8; 16]) -> String {
        key.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Encrypt exactly as the engine does: 16-byte fake
    /// header, first 16 body bytes XORed with the key.
    fn mv_encrypt(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"RPGMV\0\0\0\0\x03\x01\x01\x01\x01\x01\x01");
        assert_eq!(out.len(), 16);
        let mut body = plain.to_vec();
        for (index, byte) in body.iter_mut().take(16).enumerate() {
            *byte ^= key[index];
        }
        out.extend_from_slice(&body);
        out
    }

    /// CRC-32 (IEEE) for building well-formed PNG chunks.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (index, slot) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 == 1 {
                    0xEDB8_8320 ^ (value >> 1)
                } else {
                    value >> 1
                };
            }
            *slot = value;
        }
        let mut crc = 0xFFFF_FFFF_u32;
        for byte in bytes {
            crc = table[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }

    /// A minimal well-formed PNG: signature, IHDR, IEND.
    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let mut out = PNG_SIGNATURE.to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        out.extend_from_slice(&13_u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&ihdr);
        let mut crc_input = b"IHDR".to_vec();
        crc_input.extend_from_slice(&ihdr);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        out.extend_from_slice(b"IEND");
        out.extend_from_slice(&crc32(b"IEND").to_be_bytes());
        out
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-mvmz-test-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with_root(root: &Path) -> Config {
        Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap()
    }

    /// Build a game tree: `www/data/System.json` for MV
    /// layout, `data/System.json` at the root for MZ.
    fn build_tree(name: &str, mz_layout: bool, key: &[u8; 16]) -> PathBuf {
        let dir = scratch(name);
        let root = if mz_layout {
            dir.clone()
        } else {
            dir.join("www")
        };
        fs::create_dir_all(root.join("data")).unwrap();
        fs::create_dir_all(root.join("img/pictures")).unwrap();
        fs::write(
            root.join("data/System.json"),
            format!(
                "{{\"encryptionKey\":\"{}\",\"hasEncryptedImages\":true}}",
                key_hex(key)
            ),
        )
        .unwrap();
        dir
    }

    fn run_handler(dir: &Path) -> (PathBuf, Result<Value>) {
        let out = dir.join("out");
        let result = extract_rpgmaker_mv_images(
            &Registry::new(),
            &config_with_root(dir),
            &json!({"target": dir.display().to_string(), "output_dir": out.display().to_string()}),
        );
        (out, result)
    }

    fn first_status(value: &Value) -> String {
        value["findings"][1]["facts"]["entries"][0]["status"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn validation_decrypt_image_round_trip() {
        let key = synthetic_key();
        let plain = png_bytes(432, 384);
        let encrypted = mv_encrypt(&plain, &key);
        let (decrypted, dimensions) = decrypt_image(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plain);
        assert_eq!(dimensions, (432, 384));
    }

    #[test]
    fn validation_handler_extracts_verified_png_mv_layout() {
        let key = synthetic_key();
        let dir = build_tree("mv-ok", false, &key);
        let plain = png_bytes(64, 32);
        fs::write(
            dir.join("www/img/pictures/title.rpgmvp"),
            mv_encrypt(&plain, &key),
        )
        .unwrap();
        let (out, result) = run_handler(&dir);
        let value = result.unwrap();
        assert_eq!(first_status(&value), "verified");
        assert_eq!(fs::read(out.join("img/pictures/title.png")).unwrap(), plain);
        // The never-record law, checked against every
        // artifact the run produced.
        let manifest = fs::read_to_string(out.join("manifest.json")).unwrap();
        assert!(!manifest.contains(&key_hex(&key)));
        assert!(!format!("{value}").contains(&key_hex(&key)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validation_handler_extracts_verified_png_mz_layout() {
        let key = synthetic_key();
        let dir = build_tree("mz-ok", true, &key);
        let plain = png_bytes(960, 540);
        fs::write(
            dir.join("img/pictures/title.rpgmvp"),
            mv_encrypt(&plain, &key),
        )
        .unwrap();
        let (out, result) = run_handler(&dir);
        let value = result.unwrap();
        assert_eq!(first_status(&value), "verified");
        assert_eq!(fs::read(out.join("img/pictures/title.png")).unwrap(), plain);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_wrong_key_writes_nothing() {
        let key = synthetic_key();
        let mut wrong = synthetic_key();
        wrong[0] ^= 0xFF;
        let dir = build_tree("wrong-key", false, &wrong);
        let plain = png_bytes(64, 32);
        fs::write(
            dir.join("www/img/pictures/title.rpgmvp"),
            mv_encrypt(&plain, &key),
        )
        .unwrap();
        // The decrypt core refuses outright.
        assert_eq!(
            decrypt_image(&mv_encrypt(&plain, &key), &wrong),
            Err(DecryptRefusal::Unverified)
        );
        let (out, result) = run_handler(&dir);
        let value = result.unwrap();
        assert_eq!(first_status(&value), "unverified");
        assert!(!out.join("img/pictures/title.png").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_truncated_and_bad_header_write_nothing() {
        let key = synthetic_key();
        // Shorter than the fake header.
        assert_eq!(
            decrypt_image(b"RPGMV\0\0", &key),
            Err(DecryptRefusal::BadHeader)
        );
        // Fake header only, no body: decrypts to nothing,
        // which cannot verify as a PNG.
        assert_eq!(
            decrypt_image(&mv_encrypt(&[], &key), &key),
            Err(DecryptRefusal::Unverified)
        );
        // No fake header at all.
        assert_eq!(
            decrypt_image(&png_bytes(8, 8), &key),
            Err(DecryptRefusal::BadHeader)
        );
        let dir = build_tree("truncated", false, &key);
        fs::write(dir.join("www/img/pictures/short.rpgmvp"), b"RPGMV\0\0").unwrap();
        fs::write(dir.join("www/img/pictures/plain.rpgmvp"), png_bytes(8, 8)).unwrap();
        let (out, result) = run_handler(&dir);
        let value = result.unwrap();
        let entries = &value["findings"][1]["facts"]["entries"];
        assert_eq!(entries[0]["status"], "bad_header");
        assert_eq!(entries[1]["status"], "bad_header");
        assert!(!out.join("img/pictures/short.png").exists());
        assert!(!out.join("img/pictures/plain.png").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_missing_and_malformed_key_refuse() {
        let dir = scratch("no-key");
        fs::create_dir_all(dir.join("www/data")).unwrap();
        fs::create_dir_all(dir.join("www/img")).unwrap();
        fs::write(dir.join("www/data/System.json"), "{}").unwrap();
        let (_out, result) = run_handler(&dir);
        assert_eq!(result.unwrap_err().code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&dir).ok();

        // A malformed key refuses by shape; the error
        // must not echo the submitted key material.
        let dir = scratch("bad-key");
        fs::create_dir_all(dir.join("www/data")).unwrap();
        fs::create_dir_all(dir.join("www/img")).unwrap();
        let submitted = "not-a-real-key-value";
        fs::write(
            dir.join("www/data/System.json"),
            format!("{{\"encryptionKey\":\"{submitted}\"}}"),
        )
        .unwrap();
        let (_out, result) = run_handler(&dir);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(!error.message.contains(submitted));
        fs::remove_dir_all(&dir).ok();
    }
}
