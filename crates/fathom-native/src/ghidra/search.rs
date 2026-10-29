//! Search & utility family (fathom Ghidra G1): masked byte-pattern
//! search over initialized memory, instruction search, read-only
//! disassembly of arbitrary bytes, and number conversion (pure local
//! computation — no target, no engine).

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject};
use fathom_core::limits::{BYTE_PATTERN_BYTES_MAX, DISASSEMBLE_BYTES_MAX};
use fathom_core::registry::{Registry, require_str};

use crate::engine::Export;
use crate::ghidra::base;
use crate::ghidra::query::{self, Listing, Page};
use crate::sections::BytePatternResult;

/// Widths `convert_number` interprets a value at.
const NUMBER_WIDTHS: &[u32] = &[8, 16, 32, 64];

/// Normalize a byte pattern to lowercase hex pairs with `??`
/// wildcards: whitespace is ignored; 1..=64 bytes; at least one
/// concrete byte (an all-wildcard pattern matches everything).
pub(crate) fn normalize_pattern(text: &str) -> Result<String, FathomError> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let refuse = |why: &str| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("byte pattern {text:?} {why}"),
        )
    };
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return Err(refuse("must be whole hex byte pairs or ?? wildcards"));
    }
    let bytes = compact.len() / 2;
    if bytes > BYTE_PATTERN_BYTES_MAX {
        return Err(refuse(&format!("exceeds {BYTE_PATTERN_BYTES_MAX} bytes")));
    }
    let mut concrete = 0usize;
    let mut out = String::with_capacity(compact.len());
    for pair in compact.as_bytes().chunks(2) {
        match pair {
            [b'?', b'?'] => out.push_str("??"),
            [hi, lo] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                concrete += 1;
                out.push(hi.to_ascii_lowercase() as char);
                out.push(lo.to_ascii_lowercase() as char);
            }
            _ => return Err(refuse("must be whole hex byte pairs or ?? wildcards")),
        }
    }
    if concrete == 0 {
        return Err(refuse("needs at least one concrete byte"));
    }
    Ok(out)
}

pub fn search_byte_patterns(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let pattern = normalize_pattern(query::require_text(args, "pattern")?)?;
    let page = query::page(args)?;
    let (subject, export) =
        query::run_mode(config, args, "bytes", Some(&format!("query\t{pattern}")))?;
    byte_search_evidence(subject, &export, &pattern, page)
}

/// The result row for one pattern label.
pub(crate) fn pattern_result<'a>(
    export: &'a Export,
    label: &str,
) -> Result<&'a BytePatternResult, FathomError> {
    let search = query::section(&export.byte_search, "byte_search")?;
    let result = search
        .patterns
        .iter()
        .find(|p| p.label == label)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                format!("Ghidra export holds no result for pattern '{label}'"),
            )
        })?;
    result.matches.check("byte_search.matches")?;
    Ok(result)
}

fn byte_search_evidence(
    subject: Subject,
    export: &Export,
    pattern: &str,
    page: Page,
) -> Result<Value, FathomError> {
    let mut evidence = base("search_byte_patterns", subject);
    let result = pattern_result(export, "query")?;
    if result.pattern != pattern {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "Ghidra export answers a different pattern than the one requested",
        ));
    }
    let partial = result.matches.is_partial() || result.stopped_at_cap;
    Listing {
        confidence: Confidence::Observed,
        key: "matches",
        kind: "byte_matches",
        partial,
        retained: result.matches.rows.len(),
        rows: result
            .matches
            .rows
            .iter()
            .map(|m| json!({"address": m.address, "block": m.block, "function": m.function}))
            .collect(),
        total: result.matches.total,
    }
    .into_evidence(&mut evidence, page);
    if result.stopped_at_cap {
        evidence.add_unknown(
            "matches",
            "the scan stopped at the match bound; further matches may exist",
        );
    }
    if let Some(finding) = evidence.findings.last_mut() {
        *finding = finding.clone().with_limitation(
            "initialized memory blocks only; uninitialized (.bss-style) memory holds no bytes",
        );
    }
    Ok(evidence.to_value())
}

pub fn search_instructions(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let needle = query::require_text(args, "query")?.trim().to_lowercase();
    let prefix = match query::optional_text(args, "match")? {
        None | Some("text") => "t",
        Some("mnemonic") => "m",
        Some(other) => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("match {other:?} is not one of mnemonic, text"),
            ));
        }
    };
    let page = query::page(args)?;
    let term = format!("{prefix}:{needle}");
    let (subject, export) = query::run_mode(config, args, "insns", Some(&term))?;
    instruction_search_evidence(subject, &export, page)
}

fn instruction_search_evidence(
    subject: Subject,
    export: &Export,
    page: Page,
) -> Result<Value, FathomError> {
    let mut evidence = base("search_instructions", subject);
    let search = query::section(&export.instruction_search, "instruction_search")?;
    search.matches.check("instruction_search.matches")?;
    let rows = search
        .matches
        .rows
        .iter()
        .map(|m| {
            json!({
                "address": m.address, "function": m.function, "mnemonic": m.mnemonic,
                "text": m.text,
            })
        })
        .collect();
    Listing {
        confidence: Confidence::Observed,
        key: "matches",
        kind: "instruction_matches",
        partial: search.matches.is_partial() || search.scan_capped,
        retained: search.matches.rows.len(),
        rows,
        total: search.matches.total,
    }
    .into_evidence(&mut evidence, page);
    // Coverage is over instructions scanned, not match rows.
    query::cover(
        &mut evidence,
        search.scanned as usize,
        search.instructions_total,
        search.scan_capped || search.matches.is_partial(),
    );
    if search.scan_capped {
        evidence.add_unknown(
            "instructions",
            format!(
                "the scan stopped after {} of {} instructions",
                search.scanned, search.instructions_total
            ),
        );
    }
    Ok(evidence.to_value())
}

pub fn disassemble_bytes(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let address = query::parse_address(require_str(args, "address")?)?;
    let length =
        query::optional_count(args, "length", DISASSEMBLE_BYTES_MAX, false)?.ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                format!("argument 'length' is required: 1..={DISASSEMBLE_BYTES_MAX} bytes"),
            )
        })?;
    let (subject, export) = query::run_mode(
        config,
        args,
        "disasm",
        Some(&format!("{address}\n{length}")),
    )?;
    disassembly_evidence(subject, &export)
}

fn disassembly_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("disassemble_bytes", subject);
    let disassembly = query::section(&export.disassembly, "disassembly")?;
    if !disassembly.valid {
        evidence.add_unknown(
            "address",
            format!(
                "Ghidra could not resolve start address {} in the default address space",
                disassembly.query
            ),
        );
        return Ok(evidence.to_value());
    }
    if !disassembly.in_memory {
        evidence.add_unknown(
            "memory",
            format!(
                "start address {} lies outside every memory block",
                disassembly.start
            ),
        );
        return Ok(evidence.to_value());
    }
    let agrees = disassembly
        .instructions
        .iter()
        .filter(|i| i.listing_instruction)
        .count();
    evidence.add_finding(
        Finding::new(
            "disassembly",
            Confidence::Observed,
            json!({
                "consumed": disassembly.consumed,
                "instructions": disassembly.instructions.iter().map(|i| json!({
                    "address": i.address, "bytes": i.bytes, "length": i.length,
                    "listing_instruction": i.listing_instruction, "text": i.text,
                })).collect::<Vec<_>>(),
                "listing_agreement": agrees,
                "requested_length": disassembly.requested_length,
                "start": disassembly.start,
                "stopped": disassembly.stopped,
            }),
        )
        .with_location(disassembly.start.clone())
        .with_limitation(
            "decoded linearly from the start address with the program's default context; \
             this is not the listing's flow-based disassembly, and nothing was written to \
             the program; listing_instruction marks where the listing has an instruction \
             starting at the same address; 'consumed' exceeds the requested length when \
             the last instruction straddles its end",
        ),
    );
    if disassembly.stopped != "length_reached" {
        evidence.add_unknown(
            "disassembly",
            format!(
                "decoding stopped before the requested length: {}",
                disassembly.stopped
            ),
        );
    }
    // Coverage counts decoded instruction records, never bytes.
    let decoded = disassembly.instructions.len();
    query::cover(
        &mut evidence,
        decoded,
        decoded as u64,
        disassembly.stopped != "length_reached",
    );
    Ok(evidence.to_value())
}

pub fn convert_number(_: &Registry, _: &Config, args: &Value) -> Result<Value, FathomError> {
    let bits = match args.get("bits") {
        None => 64,
        Some(value) => value
            .as_u64()
            .and_then(|b| u32::try_from(b).ok())
            .filter(|b| NUMBER_WIDTHS.contains(b))
            .ok_or_else(|| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    "argument 'bits' must be one of 8, 16, 32, 64",
                )
            })?,
    };
    let value = match args.get("value") {
        Some(Value::String(_)) => query::require_text(args, "value")?,
        Some(Value::Number(number)) => {
            return convert_evidence(&number.to_string(), bits);
        }
        _ => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'value' is required: a string (0x/0o/0b prefixes, optional '-') \
                 or an integer",
            ));
        }
    };
    convert_evidence(value, bits)
}

/// Parse `[-](0x|0o|0b)?digits` into a sign and magnitude.
fn parse_number(text: &str) -> Result<(bool, u128), String> {
    let trimmed = text.trim().replace('_', "");
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest.to_string()),
        None => (false, trimmed),
    };
    let lower = body.to_ascii_lowercase();
    let (radix, digits) = if let Some(rest) = lower.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = lower.strip_prefix("0o") {
        (8, rest)
    } else if let Some(rest) = lower.strip_prefix("0b") {
        (2, rest)
    } else {
        (10, lower.as_str())
    };
    if digits.is_empty() || digits.starts_with(['-', '+']) {
        return Err(format!("{text:?} has no digits"));
    }
    u128::from_str_radix(digits, radix)
        .map(|magnitude| (negative, magnitude))
        .map_err(|_| format!("{text:?} is not a base-{radix} integer"))
}

fn convert_evidence(text: &str, bits: u32) -> Result<Value, FathomError> {
    let (negative, magnitude) =
        parse_number(text).map_err(|why| FathomError::new(ErrorCode::InvalidRequest, why))?;
    let mask: u128 = (1u128 << bits) - 1;
    let signed_min = 1u128 << (bits - 1);
    // Negative values must fit the signed range; positive values the
    // unsigned range. Nothing is silently wrapped.
    let raw: u128 = if negative {
        if magnitude > signed_min {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("{text} is below the {bits}-bit signed minimum"),
            ));
        }
        (mask + 1 - magnitude) & mask
    } else {
        if magnitude > mask {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("{text} exceeds the {bits}-bit unsigned maximum"),
            ));
        }
        magnitude
    };
    let unsigned = raw as u64;
    let signed: i64 = if bits == 64 {
        unsigned as i64
    } else if raw >= signed_min {
        (raw as i128 - (1i128 << bits)) as i64
    } else {
        raw as i64
    };
    let width = (bits / 8) as usize;
    let le: Vec<u8> = unsigned.to_le_bytes()[..width].to_vec();
    let be: Vec<u8> = le.iter().rev().copied().collect();
    let hex_bytes = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let ascii: String = be
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    let mut evidence = Evidence::new("convert_number", "local");
    evidence.add_finding(
        Finding::new(
            "number",
            Confidence::Derived,
            json!({
                "ascii_big_endian": ascii,
                "binary": format!("0b{unsigned:0width$b}", width = bits as usize),
                "bits": bits,
                "bytes_big_endian": hex_bytes(&be),
                "bytes_little_endian": hex_bytes(&le),
                "hex": format!("0x{unsigned:0width$x}", width = width * 2),
                "input": text,
                "octal": format!("0o{unsigned:o}"),
                "signed": signed,
                "unsigned": unsigned,
            }),
        )
        .with_limitation(
            "pure computation on the given value at the given width (two's complement \
             for signed views); no target was examined",
        ),
    );
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::query::PAGE_ROWS_DEFAULT;
    use crate::ghidra::query::tests::{export, subject};

    fn page() -> Page {
        Page {
            limit: PAGE_ROWS_DEFAULT,
            offset: 0,
        }
    }

    #[test]
    fn validation_patterns_normalize() {
        assert_eq!(normalize_pattern("48 8B ?? 05").unwrap(), "488b??05");
        assert_eq!(normalize_pattern("c3").unwrap(), "c3");
    }

    #[test]
    fn adversarial_patterns_are_refused() {
        let long = "aa".repeat(BYTE_PATTERN_BYTES_MAX + 1);
        for bad in [
            "",
            "4",
            "4?",
            "zz",
            "????",
            "48 8b ?",
            "0x48",
            long.as_str(),
        ] {
            assert!(normalize_pattern(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn validation_byte_search_lists_matches() {
        let export = export(
            "bytes",
            r#""byte_search": {"patterns": [{"label": "query", "pattern": "c3",
                "stopped_at_cap": false,
                "matches": {"rows": [{"address": "00101008", "block": ".text",
                    "function": "main"}], "total": 1, "truncated": false}}]}"#,
        );
        let value = byte_search_evidence(subject(), &export, "c3", page()).unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["matches"][0]["function"],
            "main"
        );
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn adversarial_capped_or_mismatched_search_is_flagged() {
        let export = export(
            "bytes",
            r#""byte_search": {"patterns": [{"label": "query", "pattern": "00",
                "stopped_at_cap": true,
                "matches": {"rows": [], "total": 0, "truncated": false}}]}"#,
        );
        let value = byte_search_evidence(subject(), &export, "00", page()).unwrap();
        assert_eq!(value["status"], "partial");
        assert_eq!(value["coverage"]["exhaustive"], false);
        let error = byte_search_evidence(subject(), &export, "c3", page()).unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
    }

    #[test]
    fn validation_instruction_search_coverage_counts_instructions() {
        let export = export(
            "insns",
            r#""instruction_search": {"instructions_total": 900, "scanned": 900,
                "scan_capped": false, "terms": ["m:syscall"],
                "matches": {"rows": [{"address": "00101010", "function": "f",
                    "mnemonic": "SYSCALL", "term": "m:syscall", "text": "SYSCALL"}],
                    "total": 1, "truncated": false}}"#,
        );
        let value = instruction_search_evidence(subject(), &export, page()).unwrap();
        assert_eq!(value["coverage"]["examined"], 900);
        assert_eq!(
            value["findings"][0]["facts"]["matches"][0]["mnemonic"],
            "SYSCALL"
        );
    }

    #[test]
    fn adversarial_disassembly_outside_memory_and_early_stop() {
        let export_out = export(
            "disasm",
            r#""disassembly": {"query": "dead0000", "valid": true, "in_memory": false,
                "start": "dead0000", "instructions": [], "consumed": 0,
                "requested_length": 4, "stopped": "left_memory"}"#,
        );
        let value = disassembly_evidence(subject(), &export_out).unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
        let export_stop = export(
            "disasm",
            r#""disassembly": {"query": "101000", "valid": true, "in_memory": true,
                "start": "00101000", "consumed": 1, "requested_length": 8,
                "stopped": "undecodable: UnknownInstructionException",
                "instructions": [{"address": "00101000", "bytes": "c3", "length": 1,
                    "listing_instruction": true, "text": "RET"}]}"#,
        );
        let value = disassembly_evidence(subject(), &export_stop).unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["instructions"][0]["text"],
            "RET"
        );
        assert_eq!(value["unknowns"][0]["aspect"], "disassembly");
        assert_eq!(value["coverage"]["exhaustive"], false);
    }

    #[test]
    fn validation_number_conversions() {
        let value = convert_evidence("0xff", 8).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["unsigned"], 255);
        assert_eq!(facts["signed"], -1);
        assert_eq!(facts["binary"], "0b11111111");
        let value = convert_evidence("-2", 32).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["hex"], "0xfffffffe");
        assert_eq!(facts["bytes_little_endian"], "fe ff ff ff");
        let value = convert_evidence("0x41424344", 32).unwrap();
        assert_eq!(value["findings"][0]["facts"]["ascii_big_endian"], "ABCD");
        let value = convert_evidence("18446744073709551615", 64).unwrap();
        assert_eq!(value["findings"][0]["facts"]["signed"], -1);
        let value = convert_evidence("-9223372036854775808", 64).unwrap();
        assert_eq!(value["findings"][0]["facts"]["hex"], "0x8000000000000000");
    }

    #[test]
    fn adversarial_numbers_never_wrap_silently() {
        for (text, bits) in [
            ("256", 8),
            ("-129", 8),
            ("0x", 64),
            ("--1", 64),
            ("1e3", 64),
            ("0x1g", 64),
            ("18446744073709551616", 64),
            ("-9223372036854775809", 64),
            ("", 64),
        ] {
            assert!(
                convert_evidence(text, bits).is_err(),
                "accepted {text} at {bits}"
            );
        }
        let config = Config::restrictive_default();
        let registry = Registry::new();
        assert!(convert_number(&registry, &config, &json!({"value": "1", "bits": 7})).is_err());
        assert!(convert_number(&registry, &config, &json!({"value": true})).is_err());
        let value = convert_number(&registry, &config, &json!({"value": 65, "bits": 8})).unwrap();
        assert_eq!(value["findings"][0]["facts"]["ascii_big_endian"], "A");
    }
}
