//! Key-hunt scanner: find AES-256 key candidates in a
//! binary by sliding-window entropy, rank them by
//! proximity to AES S-box material, and — when a pak is
//! supplied — verify them against it.
//!
//! The building blocks are the estate's own: Shannon
//! entropy profiling (fathom-observe's firmware lane
//! computes the same statistic over firmware images) and
//! the AES S-box byte patterns (fathom-native's ghidra
//! detection lane matches the same tables). This module
//! composes them into a scanner and adds the one claim
//! that matters: a candidate is VERIFIED only when it
//! actually decrypts the supplied pak (an encrypted
//! index that verifies, or an encrypted entry whose
//! decrypted bytes pass the pak's own SHA-1 gate).
//! Anything else is a candidate — entropy is a hint,
//! never a verdict.
//!
//! Honesty contract: candidate rows carry a SHA-256
//! fingerprint of the window, never the window bytes —
//! a real key must not leak into evidence, retained
//! exports, or logs. Counts are exact: raw candidates,
//! filtered false positives, returned rows, verified.

use serde_json::{Value, json};
use std::path::Path;

use crate::aes;
use crate::unreal;
use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, sha256_hex, subject_for_file_with_bound,
};
use fathom_core::paths;
use fathom_core::registry::{Registry, optional_str, require_str};

/// Scan targets are read whole; past this bound the tool
/// refuses rather than guessing at a partial scan.
const SCAN_TARGET_BYTES_MAX: u64 = 1_073_741_824;
/// The candidate window: one AES-256 key.
const WINDOW_BYTES: usize = 32;
/// Entropy floor for a candidate window (bits per byte;
/// a uniform-random 32-byte window scores ≈ 4.97).
const ENTROPY_MIN: f64 = 4.65;
/// Distinct-byte floor for a candidate window.
const DISTINCT_MIN: usize = 24;
/// How many top raw candidates get a verification
/// attempt against the pak.
const VERIFY_ATTEMPTS_MAX: usize = 512;
/// Default returned-row cap.
const ROWS_DEFAULT: usize = 32;

/// One entropy-passing window before display clustering.
struct Candidate {
    distinct: usize,
    entropy: f64,
    offset: usize,
}

/// c·log2(c) for the histogram counts a 32-byte window can
/// hold; the window entropy is 5 − Σf(count)/32.
fn count_terms() -> [f64; WINDOW_BYTES + 1] {
    let mut terms = [0.0_f64; WINDOW_BYTES + 1];
    for (count, term) in terms.iter_mut().enumerate().skip(1) {
        *term = count as f64 * (count as f64).log2();
    }
    terms
}

/// False-positive shape filters. Each returns true when
/// the window is a known non-key shape:
///
/// - a counting table (monotonic byte sequences);
/// - a repeated block (the same 16 bytes twice).
///
/// Hex-string windows need no filter here: ASCII hex has
/// at most 22 distinct byte values, under the distinct
/// floor, so an encoded key's windows never become
/// candidates in the first place.
fn is_false_positive(window: &[u8]) -> bool {
    // Counting table: non-decreasing or non-increasing
    // across at least 28 of the 31 steps.
    let up = window
        .windows(2)
        .filter(|pair| pair[1] == pair[0].wrapping_add(1))
        .count();
    let down = window
        .windows(2)
        .filter(|pair| pair[1] == pair[0].wrapping_sub(1))
        .count();
    if up >= 28 || down >= 28 {
        return true;
    }
    // Repeated halves.
    window[..16] == window[16..]
}

/// All offsets where the forward or inverse AES S-box
/// prefix (first 16 table bytes) occurs in the target.
fn sbox_anchors(bytes: &[u8]) -> Vec<usize> {
    let mut anchors = Vec::new();
    for table in [&aes::SBOX, &aes::INV_SBOX] {
        let needle = &table[..16];
        if bytes.len() >= needle.len() {
            for at in 0..=bytes.len() - needle.len() {
                if &bytes[at..at + needle.len()] == needle {
                    anchors.push(at);
                }
            }
        }
    }
    anchors.sort_unstable();
    anchors
}

/// One display row for a candidate: fingerprint, never
/// bytes.
fn row_for(bytes: &[u8], anchors: &[usize], candidate: &Candidate, status: &str) -> Value {
    let window = &bytes[candidate.offset..candidate.offset + WINDOW_BYTES];
    json!({
        "distinct_bytes": candidate.distinct,
        "entropy": (candidate.entropy * 10_000.0).round() / 10_000.0,
        "offset": candidate.offset,
        "sbox_distance": anchors
            .iter()
            .map(|anchor| anchor.abs_diff(candidate.offset))
            .min(),
        "sha256": sha256_hex(window),
        "status": status,
    })
}

pub fn scan_key_candidates(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, SCAN_TARGET_BYTES_MAX)?;
    let total_bytes = subject.size_bytes;
    let bytes = std::fs::read(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {error}"),
        )
    })?;
    // Sliding window with an incremental histogram.
    let terms = count_terms();
    let mut counts = [0_u32; 256];
    let mut distinct = 0_usize;
    let mut sum: f64 = 0.0;
    let mut adjust =
        |counts: &mut [u32; 256], distinct: &mut usize, sum: &mut f64, byte: u8, delta: i32| {
            let slot = &mut counts[byte as usize];
            *sum -= terms[*slot as usize];
            if delta < 0 && *slot == 1 {
                *distinct -= 1;
            }
            if delta > 0 && *slot == 0 {
                *distinct += 1;
            }
            *slot = (*slot as i32 + delta) as u32;
            *sum += terms[*slot as usize];
        };
    let mut raw: Vec<Candidate> = Vec::new();
    let mut filtered: u64 = 0;
    if bytes.len() >= WINDOW_BYTES {
        for byte in &bytes[..WINDOW_BYTES] {
            adjust(&mut counts, &mut distinct, &mut sum, *byte, 1);
        }
        for offset in 0..=bytes.len() - WINDOW_BYTES {
            if offset > 0 {
                let out_byte = bytes[offset - 1];
                let in_byte = bytes[offset + WINDOW_BYTES - 1];
                adjust(&mut counts, &mut distinct, &mut sum, out_byte, -1);
                adjust(&mut counts, &mut distinct, &mut sum, in_byte, 1);
            }
            if distinct < DISTINCT_MIN {
                continue;
            }
            let entropy = 5.0 - sum / 32.0;
            if entropy < ENTROPY_MIN {
                continue;
            }
            let window = &bytes[offset..offset + WINDOW_BYTES];
            if is_false_positive(window) {
                filtered += 1;
                continue;
            }
            raw.push(Candidate {
                distinct,
                entropy,
                offset,
            });
        }
    }
    // Rank by entropy for verification attempts and
    // display; verification runs over the raw list so a
    // shifted window cannot crowd out the true key.
    raw.sort_by(|a, b| {
        b.entropy
            .partial_cmp(&a.entropy)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let anchors = sbox_anchors(&bytes);
    // Optional verification against a pak.
    let pak_path = match optional_str(args, "pak_target") {
        Some(pak) => Some(paths::validate_target(config, Path::new(pak))?),
        None => None,
    };
    let mut verified_offsets: Vec<usize> = Vec::new();
    if let Some(pak) = &pak_path {
        for candidate in raw.iter().take(VERIFY_ATTEMPTS_MAX) {
            let window = &bytes[candidate.offset..candidate.offset + WINDOW_BYTES];
            let key: [u8; 32] = window.try_into().unwrap();
            if unreal::key_decrypts_pak(pak, &key) {
                verified_offsets.push(candidate.offset);
            }
        }
    }
    // Display clustering: verified rows first (exact
    // offsets), then greedy non-overlapping windows by
    // entropy.
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(ROWS_DEFAULT)
        .max(1);
    let mut rows: Vec<Value> = Vec::new();
    let mut taken: Vec<usize> = Vec::new();
    for candidate in &raw {
        if verified_offsets.contains(&candidate.offset) {
            rows.push(row_for(&bytes, &anchors, candidate, "verified"));
            taken.push(candidate.offset);
        }
    }
    for candidate in &raw {
        if rows.len() >= limit {
            break;
        }
        if verified_offsets.contains(&candidate.offset) {
            continue;
        }
        if taken
            .iter()
            .any(|offset| offset.abs_diff(candidate.offset) < WINDOW_BYTES)
        {
            continue;
        }
        rows.push(row_for(&bytes, &anchors, candidate, "candidate"));
        taken.push(candidate.offset);
    }
    let mut evidence = Evidence::new("scan_key_candidates", "unreal");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "key_hunt",
        Confidence::Observed,
        json!({
            "candidates_filtered": filtered,
            "candidates_raw": raw.len(),
            "candidates_returned": rows.len(),
            "pak_target_supplied": pak_path.is_some(),
            "sbox_anchors": anchors.len(),
            "target_bytes": bytes.len(),
            "verified": verified_offsets.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows_len(&rows), "total": raw.len()}),
    ));
    if pak_path.is_none() {
        evidence.add_unknown(
            "verification",
            "no pak_target was supplied; candidates are entropy-ranked only, \
             none is verified",
        );
    } else if verified_offsets.is_empty() {
        evidence.add_unknown(
            "verification",
            format!(
                "none of the {} highest-entropy candidates decrypts the supplied \
                 pak; the key is not among them (or the pak is not AES-encrypted)",
                raw.len().min(VERIFY_ATTEMPTS_MAX)
            ),
        );
    }
    evidence.coverage.examined = bytes.len() as u64;
    evidence.coverage.total = total_bytes;
    evidence.coverage.exhaustive = pak_path.is_some();
    Ok(evidence.to_value())
}

fn rows_len(rows: &[Value]) -> usize {
    rows.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The planted key: 32 bytes of high-entropy material
    /// (an LCG stream, deterministic across runs).
    fn planted_key() -> [u8; 32] {
        let mut key = [0_u8; 32];
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for byte in &mut key {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 33) as u8;
        }
        key
    }

    /// A minimal encrypted-index pak whose index declares
    /// zero files: footer + ECB-encrypted index, footer
    /// SHA-1 over the plaintext index.
    fn encrypted_index_pak(key: &[u8; 32]) -> Vec<u8> {
        use sha1::{Digest, Sha1};
        let mut index: Vec<u8> = Vec::new();
        // Mount point FString "../../../" (9 chars + NUL).
        index.extend_from_slice(&10_i32.to_le_bytes());
        index.extend_from_slice(b"../../../\0");
        index.extend_from_slice(&0_i32.to_le_bytes()); // file count
        index.extend_from_slice(&0x8d05_6e12_u64.to_le_bytes()); // seed
        index.extend_from_slice(&0_u32.to_le_bytes()); // phi absent
        index.extend_from_slice(&0_u32.to_le_bytes()); // fdi absent
        index.extend_from_slice(&0_i32.to_le_bytes()); // blob len
        index.extend_from_slice(&0_i32.to_le_bytes()); // legacy count
        let sha1 = Sha1::digest(&index);
        let mut padded = index.clone();
        padded.resize(padded.len().div_ceil(16) * 16, 0);
        let cipher = aes::ecb_encrypt(key, &padded).unwrap();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&cipher);
        out.extend_from_slice(&[0xe1, 0x12, 0x6f, 0x5a]);
        out.extend_from_slice(&11_u32.to_le_bytes());
        out.extend_from_slice(&0_i64.to_le_bytes());
        out.extend_from_slice(&(cipher.len() as i64).to_le_bytes());
        out.extend_from_slice(&sha1);
        out.extend_from_slice(&[0_u8; 160]);
        out
    }

    fn run_scan(
        test_name: &str,
        target_bytes: &[u8],
        pak_bytes: Option<&[u8]>,
    ) -> (PathBuf, Value) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("blob.bin");
        fs::write(&target, target_bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let mut args = json!({"target": target.display().to_string()});
        if let Some(pak_bytes) = pak_bytes {
            let pak = root.join("game.pak");
            fs::write(&pak, pak_bytes).unwrap();
            args["pak_target"] = json!(pak.display().to_string());
        }
        let value = scan_key_candidates(&Registry::new(), &config, &args).unwrap();
        (root, value)
    }

    fn hunt_facts(value: &Value) -> &Value {
        &value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "key_hunt")
            .expect("key_hunt finding")["facts"]
    }

    fn hunt_rows(value: &Value) -> &Vec<Value> {
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
    fn planted_key_is_found_and_verified() {
        let key = planted_key();
        let mut blob = vec![0_u8; 512];
        blob.extend_from_slice(&b"The quick brown fox jumps over the lazy dog. ".repeat(4));
        let planted_at = blob.len();
        blob.extend_from_slice(&key);
        blob.extend_from_slice(&[0_u8; 256]);
        let pak = encrypted_index_pak(&key);
        let (root, value) = run_scan("keyhunt-planted", &blob, Some(&pak));
        let facts = hunt_facts(&value);
        assert_eq!(facts["verified"], 1);
        let rows = hunt_rows(&value);
        let verified: Vec<&Value> = rows
            .iter()
            .filter(|row| row["status"] == "verified")
            .collect();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0]["offset"], planted_at as u64);
        // The row fingerprints the key; it never carries it.
        assert_eq!(verified[0]["sha256"], json!(sha256_hex(&key)));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn text_and_random_data_yield_zero_verified() {
        let key = planted_key();
        let pak = encrypted_index_pak(&key);
        let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(64);
        let (root, value) = run_scan("keyhunt-text", &text, Some(&pak));
        assert_eq!(hunt_facts(&value)["verified"], 0);
        fs::remove_dir_all(&root).ok();
        // Deterministic pseudo-random bytes: many entropy
        // candidates, none of them the pak's key.
        let mut random = Vec::with_capacity(8192);
        let mut state: u64 = 0xdead_beef_cafe_f00d;
        for _ in 0..8192 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            random.push((state >> 33) as u8);
        }
        let (root, value) = run_scan("keyhunt-random", &random, Some(&pak));
        assert_eq!(hunt_facts(&value)["verified"], 0);
        assert!(
            hunt_rows(&value)
                .iter()
                .all(|row| row["status"] == "candidate")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn counting_table_windows_are_filtered() {
        let table: Vec<u8> = (0..8)
            .flat_map(|_| (0..=255_u8).collect::<Vec<u8>>())
            .collect();
        let (root, value) = run_scan("keyhunt-table", &table, None);
        let facts = hunt_facts(&value);
        assert_eq!(facts["candidates_raw"], 0);
        assert!(facts["candidates_filtered"].as_u64().unwrap() > 0);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn unverified_scan_says_so() {
        let key = planted_key();
        let mut blob = vec![0_u8; 128];
        blob.extend_from_slice(&key);
        blob.extend_from_slice(&[0_u8; 128]);
        let (root, value) = run_scan("keyhunt-nopak", &blob, None);
        assert_eq!(hunt_facts(&value)["verified"], 0);
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "verification")
        );
        fs::remove_dir_all(&root).ok();
    }
}
