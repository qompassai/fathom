//! `inspect_evm_bytecode` (SPEC §9.4): offline EVM bytecode —
//! a dispatcher scan for `PUSH4` selector candidates with byte
//! offsets. Selector findings are `inferred`: a PUSH4 followed by
//! EQ in dispatcher position is the standard shape, not proof of
//! a function. Argument and mutability inference is scaffolded.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::evidence::{Confidence, Evidence, Finding, sha256_hex, subject_for_file};
use rea_core::paths;
use rea_core::registry::{Registry, optional_str};

/// Largest bytecode accepted, in bytes (creation code included).
const MAX_BYTECODE_BYTES: usize = 524_288;
/// Opcode for PUSH4.
const OP_PUSH4: u8 = 0x63;
/// Opcode for EQ.
const OP_EQ: u8 = 0x14;

/// Decode a hex string (optional `0x` prefix) into bytes; every
/// failure is an `unsupported_target`, never a panic.
fn decode_hex(text: &str) -> Result<Vec<u8>, ReaError> {
    let body = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))
        .unwrap_or(text.trim());
    if body.is_empty() {
        return Err(ReaError::new(
            ErrorCode::UnsupportedTarget,
            "bytecode is empty",
        ));
    }
    if body.len() % 2 != 0 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ReaError::new(
            ErrorCode::UnsupportedTarget,
            "bytecode is not well-formed hex (even length, hex digits only)",
        ));
    }
    if body.len() / 2 > MAX_BYTECODE_BYTES {
        return Err(ReaError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "bytecode is {} bytes; the cap is {MAX_BYTECODE_BYTES}",
                body.len() / 2
            ),
        ));
    }
    let mut out = Vec::with_capacity(body.len() / 2);
    for pair in body.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("hexdigit checked");
        let lo = (pair[1] as char).to_digit(16).expect("hexdigit checked");
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

/// Load bytecode from the arguments: exactly one of `bytecode`
/// (hex text) or `target` (a file under a target root; the file
/// may hold hex text or raw bytes).
fn load_bytecode(
    config: &Config,
    args: &Value,
) -> Result<(Vec<u8>, Option<rea_core::evidence::Subject>), ReaError> {
    let hex = optional_str(args, "bytecode");
    let target = optional_str(args, "target");
    match (hex, target) {
        (Some(text), None) => Ok((decode_hex(text)?, None)),
        (None, Some(target)) => {
            let path = paths::validate_target(config, Path::new(target))?;
            let subject = subject_for_file(&path)?;
            let raw = std::fs::read(&path).map_err(|e| {
                ReaError::new(
                    ErrorCode::TargetUnavailable,
                    format!("cannot read target: {e}"),
                )
            })?;
            let looks_hex = std::str::from_utf8(&raw).is_ok_and(|text| {
                let text = text.trim();
                text.starts_with("0x")
                    || text.starts_with("0X")
                    || (!text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit()))
            });
            let bytes = if looks_hex {
                let text = std::str::from_utf8(&raw).expect("utf8 checked");
                decode_hex(text)?
            } else {
                raw
            };
            if bytes.len() > MAX_BYTECODE_BYTES {
                return Err(ReaError::new(
                    ErrorCode::ResourceConstraint,
                    format!(
                        "bytecode is {} bytes; the cap is {MAX_BYTECODE_BYTES}",
                        bytes.len()
                    ),
                ));
            }
            Ok((bytes, Some(subject)))
        }
        _ => Err(ReaError::new(
            ErrorCode::InvalidRequest,
            "pass exactly one of 'bytecode' (hex) or 'target' (file)",
        )),
    }
}

/// One PUSH4 occurrence: the 4 immediate bytes and whether EQ
/// follows, the dispatcher shape.
#[derive(Debug, PartialEq)]
struct Push4Site {
    followed_by_eq: bool,
    offset: usize,
    selector: String,
}

/// Walk the instruction stream (PUSH immediates are skipped, so
/// a 0x63 inside push data is never mistaken for an opcode) and
/// collect every PUSH4 site. A truncated trailing PUSH ends the
/// walk cleanly.
fn scan_push4(bytes: &[u8]) -> Vec<Push4Site> {
    let mut sites = Vec::new();
    let mut pc = 0_usize;
    while pc < bytes.len() {
        let op = bytes[pc];
        if (0x60..=0x7f).contains(&op) {
            let immediate = usize::from(op - 0x5f);
            if op == OP_PUSH4 && pc + 4 < bytes.len() {
                let selector = bytes[pc + 1..pc + 5]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                sites.push(Push4Site {
                    followed_by_eq: bytes[pc + 5] == OP_EQ,
                    offset: pc,
                    selector,
                });
            }
            pc += 1 + immediate;
        } else {
            pc += 1;
        }
    }
    sites
}

/// Scan the bytecode and build the evidence envelope.
pub fn inspect_evm_bytecode(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, ReaError> {
    let (bytes, subject) = load_bytecode(config, args)?;
    let sites = scan_push4(&bytes);
    let mut seen = BTreeSet::new();
    let mut selectors: Vec<Value> = Vec::new();
    let mut candidates = 0_usize;
    for site in &sites {
        if site.followed_by_eq {
            candidates += 1;
        }
        if seen.insert(site.selector.clone()) {
            selectors.push(json!({
                "followed_by_eq": site.followed_by_eq,
                "offset": site.offset,
                "selector": format!("0x{}", site.selector),
            }));
        }
    }
    let mut evidence = Evidence::new("inspect_evm_bytecode", "evm");
    evidence.subject = subject;
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.add_finding(Finding::new(
        "evm_bytecode",
        Confidence::Observed,
        json!({
            "sha256": sha256_hex(&bytes),
            "size_bytes": bytes.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "function_selectors",
        Confidence::Inferred,
        json!({
            "count": selectors.len(),
            "dispatcher_candidates": candidates,
            "push4_sites": sites.len(),
            "selectors": selectors,
        }),
    ));
    evidence.add_unknown(
        "argument_inference",
        "argument and mutability inference from selectors is scaffolded (SPEC 9.4); selectors are dispatcher-shape candidates, not resolved signatures",
    );
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_dispatcher_selector_is_found() {
        // PUSH4 deadbeef; EQ; PUSH1 0; JUMP — the dispatcher shape.
        let bytes = vec![0x63, 0xde, 0xad, 0xbe, 0xef, 0x14, 0x60, 0x00, 0x56];
        let sites = scan_push4(&bytes);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].selector, "deadbeef");
        assert_eq!(sites[0].offset, 0);
        assert!(sites[0].followed_by_eq);
    }

    #[test]
    fn validation_push4_inside_push_data_is_not_an_opcode() {
        // PUSH5 whose immediate bytes contain a fake PUSH4+EQ.
        let bytes = vec![0x64, 0x63, 0xde, 0xad, 0xbe, 0xef, 0x14, 0x00];
        assert!(scan_push4(&bytes).is_empty());
    }

    #[test]
    fn adversarial_truncated_push4_is_clean() {
        let bytes = vec![0x63, 0xde, 0xad];
        assert!(scan_push4(&bytes).is_empty());
    }

    #[test]
    fn adversarial_hex_rejects_odd_and_non_hex() {
        assert!(decode_hex("0xabc").is_err());
        assert!(decode_hex("zzzz").is_err());
        assert!(decode_hex("").is_err());
        assert_eq!(decode_hex("0x00ff").unwrap(), vec![0x00, 0xff]);
    }
}
