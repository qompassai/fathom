//! `inspect_firmware` (SPEC §9.4): firmware image inspection.
//!
//! Three bounded analyses over a capped prefix of the image:
//! header/format detection, an embedded-filesystem signature scan
//! by magic bytes, and a Shannon entropy profile. Nothing is
//! extracted: a signature hit proves the bytes are present, not
//! that a valid filesystem starts there, and the findings say so.

use serde_json::{Value, json};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// Hits retained per signature kind.
const HITS_PER_SIGNATURE_MAX: usize = 64;
/// Hits retained across all signatures.
const HITS_TOTAL_MAX: usize = 512;
/// Bytes of the image read for analysis; larger images are
/// profiled over this prefix and coverage says so.
const SCAN_BYTES_MAX: u64 = 67_108_864;
/// Entropy window size.
const WINDOW_BYTES: usize = 65_536;
/// Entropy windows listed individually in the finding.
const WINDOWS_LISTED_MAX: usize = 256;

/// One signature occurrence.
#[derive(Debug)]
struct Hit {
    format: &'static str,
    offset: usize,
}

/// The result of analyzing one image buffer.
#[derive(Debug)]
struct FirmwareAnalysis {
    entropy: f64,
    format: &'static str,
    format_details: Value,
    hits: Vec<Hit>,
    scan_capped: bool,
    windows: Vec<(usize, f64)>,
}

/// Magic-byte signatures, alphabetical by name. Two-byte magics
/// (jffs2) false-positive readily; the finding's limitation covers
/// validity, and per-kind caps keep the noise bounded.
const SIGNATURES: &[(&str, &[u8])] = &[
    ("android_boot", b"ANDROID!"),
    ("bzip2", b"BZh"),
    ("cpio_newc", b"070701"),
    ("cpio_newc_crc", b"070707"),
    ("cramfs", &[0x28, 0xcd, 0x3d, 0x45]),
    ("cramfs_be", &[0x45, 0x3d, 0xcd, 0x28]),
    ("device_tree", &[0xd0, 0x0d, 0xfe, 0xed]),
    ("elf", &[0x7f, b'E', b'L', b'F']),
    ("gzip", &[0x1f, 0x8b]),
    ("jffs2", &[0x84, 0x19]),
    ("jffs2_be", &[0x19, 0x84]),
    ("lz4_frame", &[0x04, 0x22, 0x4d, 0x18]),
    ("squashfs", b"hsqs"),
    ("squashfs_be", b"sqsh"),
    ("tar", b"ustar"),
    ("trx", b"HDR0"),
    ("ubifs", &[0x31, 0x18, 0x10, 0x06]),
    ("uimage", &[0x27, 0x05, 0x19, 0x56]),
    ("xz", &[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
    ("zip", b"PK\x03\x04"),
    ("zstd", &[0x28, 0xb5, 0x2f, 0xfd]),
];

/// Inspect one firmware image file.
pub(crate) fn inspect_firmware(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    if !target.is_file() {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "firmware target must be a regular file",
        )
        .with_target(target.display().to_string()));
    }
    let size = std::fs::metadata(&target)
        .map_err(|e| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot stat firmware image: {e}"),
            )
        })?
        .len();
    let file = File::open(&target).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open firmware image: {e}"),
        )
    })?;
    let mut data = Vec::new();
    file.take(SCAN_BYTES_MAX)
        .read_to_end(&mut data)
        .map_err(|e| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read firmware image: {e}"),
            )
        })?;
    let analysis = analyze_firmware_bytes(&data);
    let scanned = data.len() as u64;

    let mut evidence = Evidence::new("inspect_firmware", "firmware");
    evidence.add_finding(Finding::new(
        "firmware_image",
        Confidence::Observed,
        json!({
            "scanned_bytes": scanned,
            "sha256": sha256_hex(&data),
            "sha256_scope": if scanned == size { "full_file" } else { "scanned_prefix" },
            "size_bytes": size,
        }),
    ));
    evidence.add_finding(Finding::new(
        "firmware_format",
        Confidence::Observed,
        json!({
            "details": analysis.format_details,
            "format": analysis.format,
        }),
    ));
    let mut signature_finding = Finding::new(
        "embedded_signatures",
        Confidence::Derived,
        json!({
            "hits": analysis
                .hits
                .iter()
                .map(|hit| json!({"format": hit.format, "offset": hit.offset}))
                .collect::<Vec<_>>(),
            "hits_capped": analysis.scan_capped,
        }),
    )
    .with_limitation(
        "Magic-byte scan: a hit proves the signature bytes occur at the offset, not that a valid filesystem or archive starts there; two-byte magics (jffs2) false-positive readily.",
    );
    if scanned < size {
        signature_finding = signature_finding.with_limitation(format!(
            "Scan covers the first {scanned} of {size} bytes; signatures beyond the prefix were not examined."
        ));
    }
    evidence.add_finding(signature_finding);
    evidence.add_finding(Finding::new(
        "entropy_profile",
        Confidence::Derived,
        json!({
            "overall_bits_per_byte": analysis.entropy,
            "window_bytes": WINDOW_BYTES,
            "windows": analysis
                .windows
                .iter()
                .map(|(offset, entropy)| json!({"entropy": entropy, "offset": offset}))
                .collect::<Vec<_>>(),
            "windows_truncated": analysis.windows.len() >= WINDOWS_LISTED_MAX,
        }),
    ));
    evidence.add_unknown(
        "filesystem_contents",
        "no extraction is performed; embedded filesystems are located by signature only",
    );
    evidence.add_unknown(
        "partition_table",
        "vendor partition tables are not parsed by this provider",
    );
    evidence.coverage.examined = scanned;
    evidence.coverage.total = size;
    evidence.coverage.exhaustive = scanned == size;
    Ok(evidence.to_value())
}

/// Analyze one image buffer. Total function: empty and truncated
/// inputs yield `unknown` format and zero entropy, never a panic.
fn analyze_firmware_bytes(data: &[u8]) -> FirmwareAnalysis {
    let (format, format_details) = detect_format(data);
    let (hits, scan_capped) = scan_signatures(data);
    let mut windows = Vec::new();
    for (index, chunk) in data.chunks(WINDOW_BYTES).enumerate() {
        if windows.len() >= WINDOWS_LISTED_MAX {
            break;
        }
        windows.push((index * WINDOW_BYTES, shannon_entropy(chunk)));
    }
    FirmwareAnalysis {
        entropy: shannon_entropy(data),
        format,
        format_details,
        hits,
        scan_capped,
        windows,
    }
}

/// Detect the container format from the header bytes at offset 0.
fn detect_format(data: &[u8]) -> (&'static str, Value) {
    if data.starts_with(b"ANDROID!") {
        return ("android_boot", json!({}));
    }
    if data.starts_with(&[0xd0, 0x0d, 0xfe, 0xed]) {
        let total_size = if data.len() >= 8 {
            Some(u32::from_be_bytes([data[4], data[5], data[6], data[7]]))
        } else {
            None
        };
        return (
            "device_tree_or_fit",
            json!({"declared_total_size": total_size}),
        );
    }
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        let class = match data.get(4) {
            Some(1) => "elf32",
            Some(2) => "elf64",
            _ => "unknown",
        };
        let little_endian = match data.get(5) {
            Some(1) => Some(true),
            Some(2) => Some(false),
            _ => None,
        };
        return (
            "elf",
            json!({"class": class, "little_endian": little_endian}),
        );
    }
    if data.starts_with(&[0x27, 0x05, 0x19, 0x56]) {
        return ("uimage", uimage_details(data));
    }
    if data.starts_with(b"hsqs") || data.starts_with(b"sqsh") {
        return ("squashfs", json!({}));
    }
    if data.starts_with(b"HDR0") {
        return ("trx", json!({}));
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return ("gzip", json!({}));
    }
    if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return ("xz", json!({}));
    }
    if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return ("zstd", json!({}));
    }
    if data.starts_with(b"BZh") {
        return ("bzip2", json!({}));
    }
    if data.starts_with(b"070701") || data.starts_with(b"070702") || data.starts_with(b"070707") {
        return ("cpio_newc", json!({}));
    }
    if data.starts_with(b"PK\x03\x04") {
        return ("zip", json!({}));
    }
    ("unknown", json!({}))
}

/// Parse the fixed uImage legacy header fields (offsets per the
/// U-Boot image header layout). All fields are reported raw.
fn uimage_details(data: &[u8]) -> Value {
    if data.len() < 64 {
        return json!({"header_truncated": true});
    }
    let name_bytes = &data[32..64];
    let name_end = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name_bytes.len());
    json!({
        "architecture": data[29],
        "compression": data[31],
        "data_size": u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        "image_type": data[30],
        "name": String::from_utf8_lossy(&name_bytes[..name_end]).into_owned(),
        "os": data[28],
    })
}

/// Scan for every signature, one pass, first-byte dispatch.
fn scan_signatures(data: &[u8]) -> (Vec<Hit>, bool) {
    let mut hits = Vec::new();
    let mut per_signature: Vec<usize> = vec![0; SIGNATURES.len()];
    let mut capped = false;
    'scan: for offset in 0..data.len() {
        for (index, (name, pattern)) in SIGNATURES.iter().enumerate() {
            if per_signature[index] >= HITS_PER_SIGNATURE_MAX {
                continue;
            }
            if data[offset] == pattern[0] && data[offset..].starts_with(pattern) {
                if hits.len() >= HITS_TOTAL_MAX {
                    capped = true;
                    break 'scan;
                }
                per_signature[index] += 1;
                hits.push(Hit {
                    format: name,
                    offset,
                });
            }
        }
    }
    if per_signature
        .iter()
        .any(|count| *count >= HITS_PER_SIGNATURE_MAX)
    {
        capped = true;
    }
    (hits, capped)
}

/// Shannon entropy in bits per byte, rounded to 4 decimal places.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0_f64;
    for count in counts {
        if count > 0 {
            let probability = count as f64 / total;
            entropy -= probability * probability.log2();
        }
    }
    (entropy * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_with(pieces: &[(usize, &[u8])], size: usize) -> Vec<u8> {
        let mut data = vec![0_u8; size];
        for (offset, bytes) in pieces {
            data[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        data
    }

    #[test]
    fn validation_detects_squashfs_and_embedded_gzip() {
        let data = image_with(&[(0, b"hsqs"), (1024, &[0x1f, 0x8b])], 4096);
        let analysis = analyze_firmware_bytes(&data);
        assert_eq!(analysis.format, "squashfs");
        assert!(
            analysis
                .hits
                .iter()
                .any(|hit| hit.format == "gzip" && hit.offset == 1024)
        );
        assert!(
            analysis
                .hits
                .iter()
                .any(|hit| hit.format == "squashfs" && hit.offset == 0)
        );
    }

    #[test]
    fn validation_entropy_bounds() {
        let all_bytes: Vec<u8> = (0..=255_u8).cycle().take(8192).collect();
        assert_eq!(shannon_entropy(&all_bytes), 8.0);
        assert_eq!(shannon_entropy(&[0_u8; 1024]), 0.0);
    }

    #[test]
    fn validation_uimage_header_fields() {
        let mut header = vec![0_u8; 64];
        header[0..4].copy_from_slice(&[0x27, 0x05, 0x19, 0x56]);
        header[12..16].copy_from_slice(&4096_u32.to_be_bytes());
        header[28] = 5;
        header[29] = 2;
        header[30] = 2;
        header[31] = 1;
        header[32..39].copy_from_slice(b"test-fw");
        let analysis = analyze_firmware_bytes(&header);
        assert_eq!(analysis.format, "uimage");
        assert_eq!(analysis.format_details["name"], "test-fw");
        assert_eq!(analysis.format_details["data_size"], 4096);
    }

    #[test]
    fn adversarial_empty_and_truncated_inputs_are_clean() {
        let empty = analyze_firmware_bytes(&[]);
        assert_eq!(empty.format, "unknown");
        assert_eq!(empty.entropy, 0.0);
        let truncated = analyze_firmware_bytes(&[0x27, 0x05]);
        assert_eq!(truncated.format, "unknown");
        assert!(truncated.hits.is_empty());
    }

    #[test]
    fn adversarial_signature_free_data_has_no_hits() {
        let data = vec![0xab_u8; 8192];
        let analysis = analyze_firmware_bytes(&data);
        assert!(analysis.hits.is_empty());
        assert_eq!(analysis.entropy, 0.0);
    }

    #[test]
    fn adversarial_ubifs_magic_inside_noise_is_located() {
        let mut data = vec![0xab_u8; 8192];
        data[5000..5004].copy_from_slice(&[0x31, 0x18, 0x10, 0x06]);
        let analysis = analyze_firmware_bytes(&data);
        assert!(
            analysis
                .hits
                .iter()
                .any(|hit| hit.format == "ubifs" && hit.offset == 5000)
        );
    }
}
