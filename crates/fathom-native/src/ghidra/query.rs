//! Shared argument contracts and export access for the read-core
//! handlers (fathom Ghidra G1). Every argument is validated before
//! the target is touched or Ghidra runs: a malformed request costs
//! nothing and reaches no engine.

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject};
use fathom_core::limits::{LIST_PAGE_ROWS_MAX, QUERY_TEXT_BYTES_MAX};

use crate::engine::{self, Export};
use crate::ghidra::subject_and_export;
use crate::sections::{AddressFacts, Detail};

/// Rows a paged listing returns when the caller names no `limit`.
pub(crate) const PAGE_ROWS_DEFAULT: usize = 100;

/// Hex digits in one caller-supplied address (64-bit ceiling).
const ADDRESS_HEX_DIGITS_MAX: usize = 16;

/// Run (or reuse) one read-core mode and prove the export answers
/// that mode. The query travels hex-encoded (see the script header).
pub(crate) fn run_mode(
    config: &Config,
    args: &Value,
    mode: &str,
    query: Option<&str>,
) -> Result<(Subject, Export), FathomError> {
    let encoded = query.map(engine::hex_query);
    let (subject, export) = subject_and_export(config, args, mode, encoded.as_deref())?;
    check_mode(&export, mode)?;
    Ok((subject, export))
}

/// An export answers a mode only if it says so and reports no
/// query error; anything else is a cache or engine fault, not data.
pub(crate) fn check_mode(export: &Export, mode: &str) -> Result<(), FathomError> {
    if let Some(error) = &export.query_error {
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("the export script rejected the query: {error}"),
        ));
    }
    if export.mode.as_deref() != Some(mode) {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!(
                "export answers mode {:?}, not the requested '{mode}'",
                export.mode
            ),
        ));
    }
    Ok(())
}

/// A required export section; its absence means the document is
/// not what the mode promises.
pub(crate) fn section<'a, T>(value: &'a Option<T>, name: &str) -> Result<&'a T, FathomError> {
    value.as_ref().ok_or_else(|| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("Ghidra export lacks the '{name}' section"),
        )
    })
}

/// Parse a caller address: hex digits with an optional `0x`
/// prefix, at most 16 digits. Returns the canonical lowercase
/// digits (no prefix, leading zeros stripped) passed to Ghidra.
pub(crate) fn parse_address(text: &str) -> Result<String, FathomError> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty()
        || digits.len() > ADDRESS_HEX_DIGITS_MAX
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "address {text:?} is not 1..={ADDRESS_HEX_DIGITS_MAX} hex digits (optional 0x prefix)"
            ),
        ));
    }
    let canonical = digits.trim_start_matches('0').to_ascii_lowercase();
    Ok(if canonical.is_empty() {
        "0".to_string()
    } else {
        canonical
    })
}

/// Numeric identity of a Ghidra address string: `(space, offset)`.
/// The default space carries no prefix; others read `SPACE:hex`.
pub(crate) fn address_key(text: &str) -> Option<(String, u64)> {
    let (space, digits) = match text.rsplit_once(':') {
        Some((space, digits)) => (space.to_string(), digits),
        None => (String::new(), text),
    };
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .unwrap_or(digits);
    if digits.is_empty() || digits.len() > ADDRESS_HEX_DIGITS_MAX {
        return None;
    }
    u64::from_str_radix(digits, 16)
        .ok()
        .map(|value| (space, value))
}

/// Whether two address strings name the same address.
pub(crate) fn same_address(a: &str, b: &str) -> bool {
    match (address_key(a), address_key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// A required free-text argument: a non-empty single line within
/// the query byte bound.
pub(crate) fn require_text<'a>(args: &'a Value, field: &str) -> Result<&'a str, FathomError> {
    let value = args.get(field).and_then(Value::as_str).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' is required and must be a string"),
        )
    })?;
    check_text(field, value)
}

/// An optional free-text argument (same contract when present).
pub(crate) fn optional_text<'a>(
    args: &'a Value,
    field: &str,
) -> Result<Option<&'a str>, FathomError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => check_text(field, value).map(Some),
        Some(_) => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' must be a string"),
        )),
    }
}

fn check_text<'a>(field: &str, value: &'a str) -> Result<&'a str, FathomError> {
    if value.trim().is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' must not be empty"),
        ));
    }
    if value.len() > QUERY_TEXT_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' exceeds {QUERY_TEXT_BYTES_MAX} bytes"),
        ));
    }
    if value.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' must be a single line without NUL"),
        ));
    }
    Ok(value)
}

/// A required array of 1..=`max` free-text items.
pub(crate) fn require_text_list<'a>(
    args: &'a Value,
    field: &str,
    max: usize,
) -> Result<Vec<&'a str>, FathomError> {
    let items = args.get(field).and_then(Value::as_array).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' is required and must be an array of strings"),
        )
    })?;
    if items.is_empty() || items.len() > max {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' must hold 1..={max} items"),
        ));
    }
    items
        .iter()
        .map(|item| {
            let text = item.as_str().ok_or_else(|| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("every item of '{field}' must be a string"),
                )
            })?;
            check_text(field, text)
        })
        .collect()
}

/// An optional non-negative integer argument within `1..=max`
/// (or `0..=max` when `allow_zero`).
pub(crate) fn optional_count(
    args: &Value,
    field: &str,
    max: usize,
    allow_zero: bool,
) -> Result<Option<usize>, FathomError> {
    let Some(value) = args.get(field) else {
        return Ok(None);
    };
    let floor = usize::from(!allow_zero);
    let parsed = value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n >= floor && *n <= max);
    parsed.map(Some).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' must be an integer in {floor}..={max}"),
        )
    })
}

/// One page of a listing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Page {
    pub limit: usize,
    pub offset: usize,
}

/// `offset` (default 0) and `limit` (default 100, 1..=5,000).
/// An oversized or zero limit is refused, never clamped silently.
pub(crate) fn page(args: &Value) -> Result<Page, FathomError> {
    let limit =
        optional_count(args, "limit", LIST_PAGE_ROWS_MAX, false)?.unwrap_or(PAGE_ROWS_DEFAULT);
    let offset = optional_count(args, "offset", usize::MAX, true)?.unwrap_or(0);
    Ok(Page { limit, offset })
}

/// The schema fragment for paged listings.
pub(crate) fn page_properties() -> Value {
    json!({
        "limit": {"type": "integer", "minimum": 1, "maximum": LIST_PAGE_ROWS_MAX},
        "offset": {"type": "integer", "minimum": 0},
    })
}

/// A paged listing finding. `rows` are every row that matched
/// within the retained section; `retained`/`total`/`partial`
/// describe that section, so a reader can tell "no more rows"
/// from "rows not retained by the export".
pub(crate) struct Listing<'a> {
    pub confidence: Confidence,
    pub key: &'a str,
    pub kind: &'a str,
    pub partial: bool,
    pub retained: usize,
    pub rows: Vec<Value>,
    pub total: u64,
}

impl Listing<'_> {
    pub(crate) fn into_evidence(self, evidence: &mut Evidence, page: Page) {
        let matched = self.rows.len();
        let rows: Vec<Value> = self
            .rows
            .into_iter()
            .skip(page.offset)
            .take(page.limit)
            .collect();
        let returned = rows.len();
        let mut facts = serde_json::Map::new();
        facts.insert(self.key.to_string(), Value::Array(rows));
        facts.insert("limit".into(), json!(page.limit));
        facts.insert("matched".into(), json!(matched));
        facts.insert("offset".into(), json!(page.offset));
        facts.insert("returned".into(), json!(returned));
        facts.insert("total".into(), json!(self.total));
        let mut finding = Finding::new(self.kind, self.confidence, Value::Object(facts));
        if self.partial {
            finding = finding.with_limitation(format!(
                "the export retained {} of {} rows at its bound; rows beyond it were not examined",
                self.retained, self.total
            ));
        }
        if page.offset.saturating_add(returned) < matched {
            finding = finding.with_limitation(format!(
                "page truncated at limit {}; {} matching rows remain past offset {}",
                page.limit,
                matched - page.offset - returned,
                page.offset + returned
            ));
        }
        evidence.add_finding(finding);
        cover(evidence, self.retained, self.total, self.partial);
    }
}

/// Coverage from examined records (SPEC §6).
pub(crate) fn cover(evidence: &mut Evidence, examined: usize, total: u64, partial: bool) {
    evidence.coverage.examined = examined as u64;
    evidence.coverage.total = total;
    evidence.coverage.exhaustive = !partial;
}

/// How a function query resolved against a row set.
pub(crate) enum Resolved<'a, T> {
    Ambiguous(Vec<&'a T>),
    Missing,
    One(&'a T, &'static str),
}

/// Resolve a function query over exported rows: exact name, then
/// entry address, then case-insensitive name. Several matches on a
/// rung are reported as ambiguous, never guessed between.
pub(crate) fn resolve_function<'a, T>(
    rows: &'a [T],
    query: &str,
    name: impl Fn(&T) -> &str,
    address: impl Fn(&T) -> &str,
) -> Resolved<'a, T> {
    let exact: Vec<&T> = rows.iter().filter(|row| name(row) == query).collect();
    if let Some(result) = decide(exact, "exact") {
        return result;
    }
    if parse_address(query).is_ok() {
        let by_address: Vec<&T> = rows
            .iter()
            .filter(|row| same_address(address(row), query))
            .collect();
        if let Some(result) = decide(by_address, "address") {
            return result;
        }
    }
    let folded = query.to_lowercase();
    let casefold: Vec<&T> = rows
        .iter()
        .filter(|row| name(row).to_lowercase() == folded)
        .collect();
    decide(casefold, "casefold").unwrap_or(Resolved::Missing)
}

fn decide<'a, T>(matches: Vec<&'a T>, via: &'static str) -> Option<Resolved<'a, T>> {
    match matches.len() {
        0 => None,
        1 => Some(Resolved::One(matches[0], via)),
        _ => Some(Resolved::Ambiguous(matches)),
    }
}

/// The per-function detail section, or `None` after recording why
/// the function query did not resolve.
pub(crate) fn found_detail<'a>(
    evidence: &mut Evidence,
    export: &'a Export,
) -> Result<Option<&'a Detail>, FathomError> {
    let detail = section(&export.detail, "detail")?;
    if !detail.found {
        function_unknown(evidence, &detail.query, &detail.candidates);
        return Ok(None);
    }
    Ok(Some(detail))
}

/// The resolved function's identity as an observed finding.
pub(crate) fn function_identity(detail: &Detail) -> Result<Finding, FathomError> {
    let function = section(&detail.function, "detail.function")?;
    Ok(Finding::new(
        "function",
        Confidence::Observed,
        json!({
            "address": function.address,
            "matched_via": detail.matched_via,
            "name": function.name,
            "query": detail.query,
            "signature": function.signature,
        }),
    ))
}

/// The one per-address row answering `canonical` (as sent).
pub(crate) fn address_row<'a>(
    export: &'a Export,
    canonical: &str,
) -> Result<&'a AddressFacts, FathomError> {
    section(&export.addresses, "addresses")?
        .iter()
        .find(|row| row.query == canonical)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                format!("Ghidra export holds no row for address query '{canonical}'"),
            )
        })
}

/// Record an address Ghidra could not place in the program; returns
/// whether the row is usable.
pub(crate) fn address_usable(evidence: &mut Evidence, row: &AddressFacts) -> bool {
    if !row.valid {
        evidence.add_unknown(
            "address",
            format!(
                "Ghidra could not resolve address {} in the program's default address space",
                row.query
            ),
        );
        return false;
    }
    if !row.in_memory {
        evidence.add_unknown(
            "memory",
            format!(
                "address {} lies outside every memory block; only references are reported",
                row.address
            ),
        );
    }
    true
}

/// Record a function query that did not resolve to one function
/// (the analyze_function precedent: an unknown, not an error).
pub(crate) fn function_unknown(evidence: &mut Evidence, query: &str, candidates: &[String]) {
    if candidates.is_empty() {
        evidence.add_unknown(
            "function",
            format!("Ghidra found no function matching '{query}'"),
        );
    } else {
        evidence.add_unknown(
            "function",
            format!(
                "no unique function matches '{query}'; ambiguous candidates: {}; \
                 re-run with an exact name or an entry-point address",
                candidates.join(", ")
            ),
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fixed subject for handler tests over synthetic exports.
    pub(crate) fn subject() -> Subject {
        Subject {
            path: "/targets/sample".to_string(),
            sha256: "0".repeat(64),
            size_bytes: 1,
        }
    }

    /// The `program` block every export carries.
    pub(crate) const PROGRAM: &str = r#""program": {"address_size": "64",
        "compiler_spec": "gcc", "executable_format": "ELF",
        "image_base": "00100000", "language_id": "x86:LE:64:default",
        "name": "sample"}"#;

    /// Parse a synthetic export for `mode` with extra top-level JSON.
    pub(crate) fn export(mode: &str, body: &str) -> Export {
        let doc = format!("{{{PROGRAM}, \"mode\": \"{mode}\", {body}}}");
        let export = crate::engine::parse_export(doc.as_bytes()).expect("synthetic export parses");
        check_mode(&export, mode).expect("mode matches");
        export
    }

    /// A `program`-mode export: every section empty except the
    /// `(name, json)` overrides given.
    pub(crate) fn program_facts(overrides: &[(&str, &str)]) -> Export {
        const EMPTY: &str = r#"{"rows": [], "total": 0, "truncated": false}"#;
        let mut sections: Vec<(String, String)> = [
            "analyzers",
            "bookmarks",
            "class_members",
            "code_gaps",
            "comments",
            "data_items",
            "entry_points",
            "external_locations",
            "function_docs",
            "function_tags",
            "namespaces",
            "option_groups",
            "options",
            "properties",
            "property_maps",
        ]
        .iter()
        .map(|name| (name.to_string(), EMPTY.to_string()))
        .collect();
        sections.push((
            "analysis".into(),
            r#"{"analyzed": true, "analyzed_option_present": true}"#.into(),
        ));
        sections.push(("calling_conventions".into(), "[]".into()));
        sections.push((
            "project".into(),
            format!(
                r#"{{"available": true, "name": "fathom", "program_path": "/sample",
                "files": {EMPTY}, "folders": {EMPTY}}}"#
            ),
        ));
        for (name, json) in overrides {
            if let Some(slot) = sections.iter_mut().find(|(n, _)| n == name) {
                slot.1 = json.to_string();
            }
        }
        let body: Vec<String> = sections
            .iter()
            .map(|(name, json)| format!("\"{name}\": {json}"))
            .collect();
        export(
            "program",
            &format!("\"program_facts\": {{{}}}", body.join(", ")),
        )
    }

    #[test]
    fn adversarial_address_overflow_and_garbage_are_refused() {
        for bad in [
            "",
            "0x",
            "12345678901234567",
            "0x1g",
            "-1",
            "1000; rm -rf /",
            "ram:1000",
        ] {
            let error = parse_address(bad).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidRequest, "accepted {bad:?}");
        }
    }

    #[test]
    fn validation_addresses_canonicalize() {
        assert_eq!(parse_address("0x00101040").unwrap(), "101040");
        assert_eq!(parse_address(" 0X0 ").unwrap(), "0");
        assert_eq!(
            parse_address("FFFFFFFFFFFFFFFF").unwrap(),
            "ffffffffffffffff"
        );
        assert!(same_address("00101040", "101040"));
        assert!(!same_address("EXTERNAL:00000010", "00000010"));
    }

    #[test]
    fn adversarial_limits_are_refused_not_clamped() {
        for args in [
            json!({"limit": 0}),
            json!({"limit": 5_001}),
            json!({"limit": -1}),
            json!({"limit": "10"}),
            json!({"offset": -5}),
            json!({"limit": 1.5}),
        ] {
            let error = page(&args).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidRequest, "accepted {args}");
        }
    }

    #[test]
    fn validation_page_defaults_and_bounds() {
        assert_eq!(
            page(&json!({})).unwrap(),
            Page {
                limit: PAGE_ROWS_DEFAULT,
                offset: 0
            }
        );
        assert_eq!(
            page(&json!({"limit": 5000, "offset": 7})).unwrap(),
            Page {
                limit: 5000,
                offset: 7
            }
        );
    }

    #[test]
    fn adversarial_text_arguments_are_bounded_single_lines() {
        let long = "a".repeat(QUERY_TEXT_BYTES_MAX + 1);
        for bad in [
            json!({"q": ""}),
            json!({"q": "  "}),
            json!({"q": long}),
            json!({"q": "a\nb"}),
            json!({"q": "a\u{0}"}),
            json!({"q": 5}),
        ] {
            assert!(require_text(&bad, "q").is_err(), "accepted {bad}");
        }
        assert!(require_text_list(&json!({"q": []}), "q", 4).is_err());
        assert!(require_text_list(&json!({"q": ["a", "b", "c"]}), "q", 2).is_err());
        assert!(require_text_list(&json!({"q": ["a", 1]}), "q", 4).is_err());
        assert_eq!(
            require_text_list(&json!({"q": ["a", "b"]}), "q", 2).unwrap(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn adversarial_export_for_another_mode_is_rejected() {
        let doc = format!("{{{PROGRAM}, \"mode\": \"types\"}}");
        let export = crate::engine::parse_export(doc.as_bytes()).unwrap();
        let error = check_mode(&export, "program").unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
        let doc = format!("{{{PROGRAM}, \"mode\": \"types\", \"query_error\": \"bad hex\"}}");
        let export = crate::engine::parse_export(doc.as_bytes()).unwrap();
        assert_eq!(
            check_mode(&export, "types").unwrap_err().code,
            ErrorCode::ExecutionFailure
        );
    }

    #[test]
    fn validation_hex_query_cannot_start_with_a_dash() {
        // The option-injection guard: "-deleteProject" must reach the
        // script as data, never as an analyzeHeadless flag.
        let encoded = engine::hex_query("-deleteProject");
        assert_eq!(encoded, "2d64656c65746550726f6a656374");
        assert!(encoded.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validation_resolve_function_ladder() {
        struct Row(&'static str, &'static str);
        let rows = vec![
            Row("main", "00101000"),
            Row("Main", "00102000"),
            Row("dup", "1"),
            Row("dup", "2"),
        ];
        let resolve = |q: &str| resolve_function(&rows, q, |r| r.0, |r| r.1);
        assert!(matches!(resolve("main"), Resolved::One(r, "exact") if r.1 == "00101000"));
        assert!(matches!(resolve("0x102000"), Resolved::One(r, "address") if r.0 == "Main"));
        assert!(matches!(resolve("dup"), Resolved::Ambiguous(v) if v.len() == 2));
        assert!(matches!(resolve("absent"), Resolved::Missing));
    }
}
