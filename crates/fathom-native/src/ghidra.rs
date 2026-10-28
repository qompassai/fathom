//! Ghidra-backed tool handlers (SPEC §9.1). Each handler
//! validates the target, runs (or reuses) the batch export, and
//! re-hashes the subject afterwards: an artifact that changed
//! under the engine aborts with `artifact_changed`.

use serde_json::{Value, json};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject, subject_for_file};
use fathom_core::limits::{FUNCTION_COUNT_MAX, PAGE_LIMIT_MAX, STRING_COUNT_MAX, SYMBOL_COUNT_MAX};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::engine::{self, Export, FunctionInfo};

fn subject_and_export(
    config: &Config,
    args: &Value,
    mode: &str,
    target: Option<&str>,
) -> Result<(Subject, Export), FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let export = engine::run_export(config, &path, &subject.sha256, mode, target)?;
    let after = subject_for_file(&path)?;
    if after.sha256 != subject.sha256 {
        return Err(FathomError::new(
            ErrorCode::ArtifactChanged,
            "the target changed while Ghidra analyzed it; results discarded",
        )
        .with_target(path.display().to_string()));
    }
    Ok((subject, export))
}

fn base(tool: &str, subject: Subject) -> Evidence {
    let mut evidence = Evidence::new(tool, "ghidra");
    evidence.subject = Some(subject);
    evidence
}

fn function_rows(rows: &[FunctionInfo]) -> Vec<Value> {
    rows.iter()
        .map(|f| {
            json!({
                "address": f.address,
                "body_size": f.body_size,
                "calling_convention": f.calling_convention,
                "classification": f.classification,
                "name": f.name,
                "signature": f.signature,
            })
        })
        .collect()
}

/// Display bound for one listed string value. The export retains
/// longer values so search can see them; listings stay bounded.
const LISTING_VALUE_CHARS_MAX: usize = 200;

/// Rows returned at most per match category in search results.
const SEARCH_MATCHES_MAX: usize = 200;

/// Truncate a value for listing display (char-boundary safe).
fn listing_value(value: &str) -> String {
    value.chars().take(LISTING_VALUE_CHARS_MAX).collect()
}

/// A bounded window of a matched value around the query, so a
/// search hit deep inside a long byte-run (the Go/Rust string
/// blob shape) is visible in the result instead of cut off by
/// the listing truncation.
fn search_snippet(value: &str, query: &str) -> String {
    if value.chars().count() <= LISTING_VALUE_CHARS_MAX {
        return value.to_string();
    }
    let lower = value.to_lowercase();
    let Some(start) = lower.find(query) else {
        return listing_value(value);
    };
    if lower.len() != value.len() {
        return listing_value(value);
    }
    let mut from = start.saturating_sub(64);
    let mut to = (start + query.len() + 64).min(value.len());
    while from > 0 && !value.is_char_boundary(from) {
        from -= 1;
    }
    while to < value.len() && !value.is_char_boundary(to) {
        to += 1;
    }
    value[from..to].to_string()
}

/// How much of the retained function export one
/// `analyze_function` call projects (SPEC §9.1 read pattern).
/// The summary is the default; the complete dossier is the
/// pre-read-pattern behaviour, available on request.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Detail {
    Complete,
    Summary,
}

/// Parse the optional `detail` argument. An absent argument is
/// the summary; any other value than the two named views is a
/// typed refusal, never a silent guess at the caller's intent.
fn parse_detail(args: &Value) -> Result<Detail, FathomError> {
    match args.get("detail") {
        None => Ok(Detail::Summary),
        Some(Value::String(value)) if value == "summary" => Ok(Detail::Summary),
        Some(Value::String(value)) if value == "complete" => Ok(Detail::Complete),
        Some(_) => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'detail' must be \"summary\" or \"complete\"",
        )),
    }
}

/// One page of a retained inventory read: the applied limit and
/// the offset into the retained rows.
struct Page {
    limit: usize,
    offset: usize,
}

/// Parse the optional `limit` / `offset` paging arguments. The
/// applied limit never exceeds the inventory's own count bound
/// or [`PAGE_LIMIT_MAX`]; an absent limit pages at the count
/// bound, so an unpaged call returns the pre-paging row set.
fn parse_page(args: &Value, inventory_bound: usize) -> Result<Page, FathomError> {
    let offset = match args.get("offset") {
        None => 0,
        Some(value) => value.as_u64().ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'offset' must be a non-negative integer",
            )
        })? as usize,
    };
    let cap = inventory_bound.min(PAGE_LIMIT_MAX);
    let limit = match args.get("limit") {
        None => cap,
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    "argument 'limit' must be a positive integer",
                )
            })?;
            if raw == 0 {
                return Err(FathomError::new(
                    ErrorCode::InvalidRequest,
                    "argument 'limit' must be at least 1",
                ));
            }
            (raw as usize).min(cap)
        }
    };
    Ok(Page { limit, offset })
}

impl Page {
    /// Whether retained rows remain beyond this page.
    fn more(&self, returned: usize, retained: usize) -> bool {
        self.offset.saturating_add(returned) < retained
    }

    /// The page's window of the retained rows. An offset past
    /// the end yields an empty window, not an error.
    fn slice<'a, T>(&self, rows: &'a [T]) -> &'a [T] {
        let start = self.offset.min(rows.len());
        let end = start.saturating_add(self.limit).min(rows.len());
        &rows[start..end]
    }
}

/// Limitation recorded when a page is a window of a larger
/// retained inventory, so the page never poses as the whole.
const PAGE_WINDOW_LIMITATION: &str = "page is a window of the retained inventory; \
     more retained rows remain beyond this page (raise offset to continue)";

/// The identity finding both `analyze_function` views lead
/// with: who the function is, from the retained export.
fn identity_finding(export: &Export, function: &FunctionInfo, query: &str) -> Finding {
    Finding::new(
        "function",
        Confidence::Observed,
        json!({
            "address": function.address,
            "body_size": function.body_size,
            "calling_convention": function.calling_convention,
            "classification": function.classification,
            "matched_via": export.function_match,
            "name": function.name,
            "query": query,
            "signature": function.signature,
        }),
    )
}

/// The summary view's findings: a projection of the retained
/// export, not a second analysis. Identity is shared with the
/// complete view; every payload-bearing finding is reduced to
/// its headline counts and says so, so the absence of a payload
/// is never mistaken for the payload being empty.
fn add_summary_findings(
    evidence: &mut Evidence,
    export: &Export,
    function: &FunctionInfo,
    query: &str,
) {
    evidence.add_finding(identity_finding(export, function, query));
    let mut listing_finding = Finding::new(
        "listing",
        Confidence::Observed,
        json!({
            "instruction_count": export.listing.len(),
            "listing_truncated": export.listing_truncated,
        }),
    );
    if export.listing_truncated {
        listing_finding =
            listing_finding.with_limitation("listing truncated at the instruction bound");
        evidence.coverage.exhaustive = false;
    }
    listing_finding = listing_finding.with_limitation(
        "summary view: instruction rows are not included; \
         re-run with detail \"complete\" for the full listing",
    );
    evidence.add_finding(listing_finding);
    evidence.add_finding(
        Finding::new(
            "call_graph",
            Confidence::Derived,
            json!({
                "callee_count": export.callees.as_ref().map_or(0, Vec::len),
                "caller_count": export.callers.as_ref().map_or(0, Vec::len),
            }),
        )
        .with_limitation(
            "summary view: callers and callees are counted, not named; \
             re-run with detail \"complete\" for the names",
        ),
    );
    evidence.add_finding(
        Finding::new(
            "references_to",
            Confidence::Observed,
            json!({"count": export.references_to.len()}),
        )
        .with_limitation(
            "summary view: references are counted, not listed; \
             re-run with detail \"complete\" for the rows",
        ),
    );
    if let Some(decompile) = &export.decompile {
        let mut finding = Finding::new(
            "decompile",
            Confidence::Derived,
            json!({"bytes": decompile.bytes, "truncated": decompile.truncated}),
        );
        if decompile.truncated {
            finding = finding.with_limitation("decompiled C truncated at the byte bound");
        }
        finding = finding.with_limitation(
            "summary view: decompiled C is not included; \
             re-run with detail \"complete\" for the full decompile",
        );
        evidence.add_finding(finding);
    } else {
        evidence.add_unknown(
            "decompile",
            "the decompiler produced no C for this function",
        );
    }
}

pub fn analyze_function(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let name = require_str(args, "function")?;
    if name.trim().is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'function' must not be empty",
        ));
    }
    let detail = parse_detail(args)?;
    let (subject, export) = subject_and_export(config, args, "function", Some(name))?;
    let mut evidence = base("analyze_function", subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    if export.function_found != Some(true) {
        if export.function_candidates.is_empty() {
            evidence.add_unknown(
                "function",
                format!("Ghidra found no function matching '{name}'"),
            );
        } else {
            evidence.add_unknown(
                "function",
                format!(
                    "Ghidra found no unique function matching '{name}'; ambiguous \
                     candidates: {}; re-run with an exact name or an entry-point address",
                    export.function_candidates.join(", ")
                ),
            );
        }
        return Ok(evidence.to_value());
    }
    let function = export.function.as_ref().ok_or_else(|| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            "export marked found without a function row",
        )
    })?;
    if detail == Detail::Summary {
        add_summary_findings(&mut evidence, &export, function, name);
        return Ok(evidence.to_value());
    }
    evidence.add_finding(identity_finding(&export, function, name));
    let listing: Vec<Value> = export
        .listing
        .iter()
        .map(|row| json!({"address": row.address, "text": row.text}))
        .collect();
    let mut listing_finding = Finding::new(
        "listing",
        Confidence::Observed,
        json!({"instructions": listing}),
    );
    if export.listing_truncated {
        listing_finding =
            listing_finding.with_limitation("listing truncated at the instruction bound");
        evidence.coverage.exhaustive = false;
    }
    evidence.add_finding(listing_finding);
    evidence.add_finding(Finding::new(
        "call_graph",
        Confidence::Derived,
        json!({
            "callees": export.callees.clone().unwrap_or_default(),
            "callers": export.callers.clone().unwrap_or_default(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "references_to",
        Confidence::Observed,
        json!({
            "count": export.references_to.len(),
            "references": export.references_to.iter()
                .map(|r| json!({"from": r.from, "type": r.kind}))
                .collect::<Vec<_>>(),
        }),
    ));
    if let Some(decompile) = &export.decompile {
        let mut finding = Finding::new(
            "decompile",
            Confidence::Derived,
            json!({"bytes": decompile.bytes, "c": decompile.c}),
        );
        if decompile.truncated {
            finding = finding.with_limitation("decompiled C truncated at the byte bound");
        }
        evidence.add_finding(finding);
    } else {
        evidence.add_unknown(
            "decompile",
            "the decompiler produced no C for this function",
        );
    }
    Ok(evidence.to_value())
}

pub fn binary_overview(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("binary_overview", subject);
    let program = &export.program;
    evidence.add_finding(Finding::new(
        "program",
        Confidence::Observed,
        json!({
            "address_size": program.address_size,
            "compiler_spec": program.compiler_spec,
            "executable_format": program.executable_format,
            "image_base": program.image_base,
            "language_id": program.language_id,
            "name": program.name,
        }),
    ));
    evidence.add_finding(Finding::new(
        "memory_blocks",
        Confidence::Observed,
        json!({
            "blocks": export.memory_blocks.iter().map(|b| json!({
                "end": b.end, "execute": b.execute, "initialized": b.initialized,
                "name": b.name, "read": b.read, "size": b.size,
                "start": b.start, "write": b.write,
            })).collect::<Vec<_>>(),
        }),
    ));
    let truncated = export.functions_truncated
        || export.strings_truncated
        || export.symbols_truncated
        || export.data_strings_truncated
        || export.data_strings_scan_capped;
    evidence.add_finding(Finding::new(
        "inventory",
        Confidence::Observed,
        json!({
            "data_strings_returned": export.data_strings.len().min(STRING_COUNT_MAX),
            "data_strings_total": export.data_strings_total,
            "functions_returned": export.functions.len().min(FUNCTION_COUNT_MAX),
            "functions_total": export.functions_total,
            "strings_returned": export.strings.len().min(STRING_COUNT_MAX),
            "strings_total": export.strings_total,
            "symbols_returned": export.symbols.len().min(SYMBOL_COUNT_MAX),
            "symbols_total": export.symbols_total,
            "truncated": truncated,
        }),
    ));
    evidence.coverage.examined = (export.functions.len()
        + export.strings.len()
        + export.symbols.len()
        + export.data_strings.len()) as u64;
    evidence.coverage.total = (export.functions_total
        + export.strings_total
        + export.symbols_total
        + export.data_strings_total) as u64;
    evidence.coverage.exhaustive = !truncated;
    Ok(evidence.to_value())
}

pub fn list_functions(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = parse_page(args, FUNCTION_COUNT_MAX)?;
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("list_functions", subject);
    let rows = page.slice(&export.functions);
    let mut finding = Finding::new(
        "functions",
        Confidence::Observed,
        json!({
            "functions": function_rows(rows),
            "limit": page.limit,
            "more": page.more(rows.len(), export.functions.len()),
            "offset": page.offset,
            "retained": export.functions.len(),
            "returned": rows.len(),
            "total": export.functions_total,
        }),
    );
    if export.functions_truncated {
        finding = finding.with_limitation("function inventory truncated at the count bound");
    }
    if page.more(rows.len(), export.functions.len()) {
        finding = finding.with_limitation(PAGE_WINDOW_LIMITATION);
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = export.functions.len() as u64;
    evidence.coverage.total = export.functions_total as u64;
    evidence.coverage.exhaustive = !export.functions_truncated;
    Ok(evidence.to_value())
}

pub fn list_names(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = parse_page(args, SYMBOL_COUNT_MAX)?;
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("list_names", subject);
    let rows = page.slice(&export.symbols);
    let mut finding = Finding::new(
        "symbols",
        Confidence::Observed,
        json!({
            "limit": page.limit,
            "more": page.more(rows.len(), export.symbols.len()),
            "offset": page.offset,
            "retained": export.symbols.len(),
            "returned": rows.len(),
            "symbols": rows.iter().map(|s| json!({
                "address": s.address, "name": s.name,
                "source": s.source, "type": s.kind,
            })).collect::<Vec<_>>(),
            "total": export.symbols_total,
        }),
    );
    if export.symbols_truncated {
        finding = finding.with_limitation("symbol inventory truncated at the count bound");
    }
    if page.more(rows.len(), export.symbols.len()) {
        finding = finding.with_limitation(PAGE_WINDOW_LIMITATION);
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = export.symbols.len() as u64;
    evidence.coverage.total = export.symbols_total as u64;
    evidence.coverage.exhaustive = !export.symbols_truncated;
    Ok(evidence.to_value())
}

pub fn list_strings(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = parse_page(args, STRING_COUNT_MAX)?;
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("list_strings", subject);
    let rows = page.slice(&export.strings);
    let mut finding = Finding::new(
        "strings",
        Confidence::Observed,
        json!({
            "limit": page.limit,
            "more": page.more(rows.len(), export.strings.len()),
            "offset": page.offset,
            "retained": export.strings.len(),
            "returned": rows.len(),
            "strings": rows.iter().map(|s| json!({
                "address": s.address, "value": listing_value(&s.value),
            })).collect::<Vec<_>>(),
            "total": export.strings_total,
        }),
    );
    if export.strings_truncated {
        finding = finding.with_limitation("string inventory truncated at the count bound");
    }
    if page.more(rows.len(), export.strings.len()) {
        finding = finding.with_limitation(PAGE_WINDOW_LIMITATION);
    }
    evidence.add_finding(finding);
    // Byte-run harvest: printable-ASCII runs in initialized memory.
    // This is what finds unterminated string literals (the dominant
    // Rust/Go form), which Ghidra never defines; it is reported as
    // derived evidence under its own kind, never merged into the
    // observed defined-string set.
    let data_rows = page.slice(&export.data_strings);
    let mut data_finding = Finding::new(
        "data_strings",
        Confidence::Derived,
        json!({
            "limit": page.limit,
            "more": page.more(data_rows.len(), export.data_strings.len()),
            "offset": page.offset,
            "retained": export.data_strings.len(),
            "returned": data_rows.len(),
            "strings": data_rows.iter().map(|s| json!({
                "address": s.address, "value": listing_value(&s.value),
            })).collect::<Vec<_>>(),
            "total": export.data_strings_total,
        }),
    )
    .with_limitation(
        "byte-run scan of initialized memory (printable ASCII, 4+ bytes): \
         includes the defined strings' bytes and any non-string data that \
         happens to be printable; runs split at 1 MiB scan-chunk boundaries \
         are reported as separate rows; each run value is capped at \
         4,096 chars and listing display at 200 chars",
    );
    if export.data_strings_truncated {
        data_finding =
            data_finding.with_limitation("data-string inventory truncated at the count bound");
    }
    if page.more(data_rows.len(), export.data_strings.len()) {
        data_finding = data_finding.with_limitation(PAGE_WINDOW_LIMITATION);
    }
    if export.data_strings_scan_capped {
        data_finding =
            data_finding.with_limitation("memory scan stopped at the aggregate byte bound");
    }
    evidence.add_finding(data_finding);
    evidence.coverage.examined = (export.strings.len() + export.data_strings.len()) as u64;
    evidence.coverage.total = (export.strings_total + export.data_strings_total) as u64;
    evidence.coverage.exhaustive = !export.strings_truncated
        && !export.data_strings_truncated
        && !export.data_strings_scan_capped;
    Ok(evidence.to_value())
}

pub fn search_inventory(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let query_raw = require_str(args, "query")?;
    let query = query_raw.trim().to_lowercase();
    if query.is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'query' must not be empty",
        ));
    }
    let (subject, export) = subject_and_export(config, args, "overview", None)?;
    let mut evidence = base("search_inventory", subject);
    let mut function_matches: Vec<Value> = export
        .functions
        .iter()
        .filter(|f| {
            f.name.to_lowercase().contains(&query) || f.signature.to_lowercase().contains(&query)
        })
        .map(|f| json!({"address": f.address, "name": f.name, "signature": f.signature}))
        .collect();
    let mut string_matches: Vec<Value> = export
        .strings
        .iter()
        .filter(|s| s.value.to_lowercase().contains(&query))
        .map(|s| json!({"address": s.address, "value": s.value}))
        .collect();
    let mut data_string_matches: Vec<Value> = export
        .data_strings
        .iter()
        .filter(|s| s.value.to_lowercase().contains(&query))
        .map(|s| json!({"address": s.address, "value": search_snippet(&s.value, &query)}))
        .collect();
    let mut symbol_matches: Vec<Value> = export
        .symbols
        .iter()
        .filter(|s| s.name.to_lowercase().contains(&query))
        .map(|s| json!({"address": s.address, "name": s.name, "type": s.kind}))
        .collect();
    let matches_capped = [
        function_matches.len(),
        string_matches.len(),
        data_string_matches.len(),
        symbol_matches.len(),
    ]
    .iter()
    .any(|count| *count > SEARCH_MATCHES_MAX);
    function_matches.truncate(SEARCH_MATCHES_MAX);
    string_matches.truncate(SEARCH_MATCHES_MAX);
    data_string_matches.truncate(SEARCH_MATCHES_MAX);
    symbol_matches.truncate(SEARCH_MATCHES_MAX);
    let truncated = export.functions_truncated
        || export.strings_truncated
        || export.symbols_truncated
        || export.data_strings_truncated
        || export.data_strings_scan_capped;
    let mut finding = Finding::new(
        "matches",
        Confidence::Observed,
        json!({
            "data_string_matches": data_string_matches,
            "function_matches": function_matches,
            "query": query_raw,
            "string_matches": string_matches,
            "symbol_matches": symbol_matches,
        }),
    );
    if truncated {
        finding = finding.with_limitation("search covered only the retained (truncated) inventory");
    }
    if matches_capped {
        finding = finding.with_limitation("matches capped at 200 rows per category");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = (export.functions.len()
        + export.strings.len()
        + export.symbols.len()
        + export.data_strings.len()) as u64;
    evidence.coverage.total = (export.functions_total
        + export.strings_total
        + export.symbols_total
        + export.data_strings_total) as u64;
    evidence.coverage.exhaustive = !truncated;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::evidence::sha256_hex;
    use std::path::PathBuf;

    const DECOMPILE_C: &str = "int target_fn(void) { return DECOMPILE_MARKER_7F3A; }";

    /// A target file plus a state dir whose Ghidra cache already
    /// holds the given export documents, so handlers read the
    /// retained export and never spawn the engine.
    struct SeededTarget {
        config: Config,
        root: PathBuf,
        subject_sha256: String,
        target: PathBuf,
    }

    impl SeededTarget {
        fn cleanup(&self) {
            std::fs::remove_dir_all(&self.root).ok();
        }

        fn target_arg(&self) -> String {
            self.target.display().to_string()
        }
    }

    fn seeded_target(tag: &str, exports: &[(&str, String)]) -> SeededTarget {
        let root =
            std::env::temp_dir().join(format!("fathom-ghidra-s1-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let state_dir = root.join("state");
        let target = root.join("target.bin");
        std::fs::create_dir_all(&state_dir).unwrap();
        let target_bytes = format!("s1-fixture-{tag}").into_bytes();
        std::fs::write(&target, &target_bytes).unwrap();
        let subject_sha256 = sha256_hex(&target_bytes);
        let cache_dir = state_dir.join("ghidra").join(&subject_sha256[..32]);
        std::fs::create_dir_all(&cache_dir).unwrap();
        for (name, document) in exports {
            std::fs::write(cache_dir.join(name), document).unwrap();
        }
        let config = Config {
            allow_programs: Vec::new(),
            allow_tools: Vec::new(),
            ghidra_headless: None,
            http_bind: "127.0.0.1:8731".parse().unwrap(),
            signing_key_file: None,
            state_dir,
            target_roots: vec![root.canonicalize().unwrap()],
            video: fathom_core::config::VideoConfig::default(),
        };
        SeededTarget {
            config,
            root,
            subject_sha256,
            target,
        }
    }

    fn function_export_file(function: &str) -> String {
        format!(
            "export-function-{}.json",
            &sha256_hex(function.as_bytes())[..12]
        )
    }

    /// A retained per-function export for `target_fn`: three
    /// listing rows (one carrying a marker), two callees, one
    /// caller, one reference, and optionally a decompile whose C
    /// carries a marker.
    fn function_export(with_decompile: bool) -> String {
        let mut doc = json!({
            "callees": ["helper_a", "helper_b"],
            "callers": ["main"],
            "function": {
                "address": "00401000",
                "body_size": 42,
                "calling_convention": "__fastcall",
                "classification": "defined",
                "name": "target_fn",
                "signature": "int target_fn(void)",
            },
            "function_found": true,
            "function_match": "exact",
            "listing": [
                {"address": "00401000", "text": "PUSH EBP ; LISTING_MARKER_7F3A"},
                {"address": "00401001", "text": "MOV EBP, ESP"},
                {"address": "00401003", "text": "RET"},
            ],
            "listing_truncated": false,
            "program": {
                "address_size": "64",
                "compiler_spec": "gcc",
                "executable_format": "ELF",
                "image_base": "00400000",
                "language_id": "x86:LE:64:default",
                "name": "sample",
            },
            "references_to": [{"from": "00402000", "type": "DATA"}],
        });
        if with_decompile {
            doc["decompile"] = json!({
                "bytes": DECOMPILE_C.len(),
                "c": DECOMPILE_C,
                "truncated": false,
            });
        }
        doc.to_string()
    }

    /// A retained overview export: 7 functions, 4 symbols,
    /// 5 defined strings, 3 data strings, nothing truncated.
    fn overview_export() -> String {
        let functions: Vec<Value> = (0..7)
            .map(|index| {
                json!({
                    "address": format!("004010{index:02}"),
                    "body_size": 16,
                    "calling_convention": "__fastcall",
                    "classification": "defined",
                    "name": format!("fn-{index}"),
                    "signature": format!("void fn-{index}(void)"),
                })
            })
            .collect();
        let symbols: Vec<Value> = (0..4)
            .map(|index| {
                json!({
                    "address": format!("004010{index:02}"),
                    "name": format!("sym-{index}"),
                    "source": "DEFAULT",
                    "type": "Function",
                })
            })
            .collect();
        let strings: Vec<Value> = (0..5)
            .map(|index| {
                json!({
                    "address": format!("004020{index:02}"),
                    "value": format!("str-{index}"),
                })
            })
            .collect();
        let data_strings: Vec<Value> = (0..3)
            .map(|index| {
                json!({
                    "address": format!("004030{index:02}"),
                    "value": format!("data-{index}"),
                })
            })
            .collect();
        json!({
            "data_strings": data_strings,
            "data_strings_scan_capped": false,
            "data_strings_total": 3,
            "data_strings_truncated": false,
            "functions": functions,
            "functions_total": 7,
            "functions_truncated": false,
            "program": {
                "address_size": "64",
                "compiler_spec": "gcc",
                "executable_format": "ELF",
                "image_base": "00400000",
                "language_id": "x86:LE:64:default",
                "name": "sample",
            },
            "strings": strings,
            "strings_total": 5,
            "strings_truncated": false,
            "symbols": symbols,
            "symbols_total": 4,
            "symbols_truncated": false,
        })
        .to_string()
    }

    fn finding<'a>(value: &'a Value, kind: &str) -> &'a Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} finding in {value}"))
    }

    fn finding_facts<'a>(value: &'a Value, kind: &str) -> &'a Value {
        &finding(value, kind)["facts"]
    }

    #[test]
    fn validation_snippet_centers_a_deep_match() {
        // The Go corpus shape: the needle sits ~900 chars into a
        // concatenated string blob; the snippet must contain it.
        let mut value = "a".repeat(900);
        value.push_str("FATHOM-CORPUS-MARKER-go-7f3a");
        value.push_str(&"b".repeat(300));
        let snippet = search_snippet(&value, "fathom-corpus-marker-go-7f3a");
        assert!(snippet.contains("FATHOM-CORPUS-MARKER-go-7f3a"));
        assert!(snippet.chars().count() <= 200);
    }

    #[test]
    fn validation_short_values_pass_through() {
        assert_eq!(listing_value("hello"), "hello");
        assert_eq!(search_snippet("hello world", "world"), "hello world");
    }

    #[test]
    fn adversarial_listing_truncation_is_char_safe() {
        let value = "é".repeat(500);
        let truncated = listing_value(&value);
        assert_eq!(truncated.chars().count(), LISTING_VALUE_CHARS_MAX);
        // A query that does not occur falls back to the bounded
        // listing form rather than panicking or inventing text.
        let fallback = search_snippet(&value, "absent");
        assert_eq!(fallback.chars().count(), LISTING_VALUE_CHARS_MAX);
    }

    #[test]
    fn validation_summary_is_the_default_view() {
        let file = function_export_file("target_fn");
        let seeded = seeded_target("summary", &[(&file, function_export(true))]);
        let registry = Registry::new();
        let args = json!({"function": "target_fn", "target": seeded.target_arg()});
        let value = analyze_function(&registry, &seeded.config, &args).unwrap();
        let identity = finding_facts(&value, "function");
        assert_eq!(identity["name"], "target_fn");
        assert_eq!(identity["address"], "00401000");
        let listing = finding_facts(&value, "listing");
        assert_eq!(listing["instruction_count"], 3);
        assert!(listing.get("instructions").is_none());
        let call_graph = finding_facts(&value, "call_graph");
        assert_eq!(call_graph["callee_count"], 2);
        assert_eq!(call_graph["caller_count"], 1);
        assert!(call_graph.get("callees").is_none());
        assert!(call_graph.get("callers").is_none());
        assert_eq!(finding_facts(&value, "references_to")["count"], 1);
        let decompile = finding_facts(&value, "decompile");
        assert_eq!(decompile["bytes"], DECOMPILE_C.len());
        assert!(decompile.get("c").is_none());
        // An explicit "summary" is the same view as the default.
        let explicit_args = json!({
            "detail": "summary",
            "function": "target_fn",
            "target": seeded.target_arg(),
        });
        let explicit = analyze_function(&registry, &seeded.config, &explicit_args).unwrap();
        assert_eq!(explicit, value);
        seeded.cleanup();
    }

    #[test]
    fn validation_complete_detail_returns_the_full_dossier() {
        let file = function_export_file("target_fn");
        let seeded = seeded_target("complete", &[(&file, function_export(true))]);
        let registry = Registry::new();
        let args = json!({
            "detail": "complete",
            "function": "target_fn",
            "target": seeded.target_arg(),
        });
        let value = analyze_function(&registry, &seeded.config, &args).unwrap();
        let listing = finding_facts(&value, "listing");
        let instructions = listing["instructions"].as_array().unwrap();
        assert_eq!(instructions.len(), 3);
        assert!(
            instructions[0]["text"]
                .as_str()
                .unwrap()
                .contains("LISTING_MARKER_7F3A")
        );
        let call_graph = finding_facts(&value, "call_graph");
        assert_eq!(call_graph["callees"], json!(["helper_a", "helper_b"]));
        assert_eq!(call_graph["callers"], json!(["main"]));
        let references = finding_facts(&value, "references_to");
        assert_eq!(references["count"], 1);
        assert_eq!(references["references"].as_array().unwrap().len(), 1);
        assert_eq!(finding_facts(&value, "decompile")["c"], DECOMPILE_C);
        seeded.cleanup();
    }

    #[test]
    fn validation_unknowns_survive_the_summary_view() {
        let file = function_export_file("target_fn");
        let seeded = seeded_target("unknowns", &[(&file, function_export(false))]);
        let registry = Registry::new();
        let args = json!({"function": "target_fn", "target": seeded.target_arg()});
        let value = analyze_function(&registry, &seeded.config, &args).unwrap();
        assert_eq!(value["status"], "partial");
        let unknowns = value["unknowns"].as_array().unwrap();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0]["aspect"], "decompile");
        assert!(
            value["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|finding| finding["kind"] != "decompile")
        );
        seeded.cleanup();
    }

    #[test]
    fn validation_paging_walks_the_retained_inventory() {
        let seeded = seeded_target("paging", &[("export-overview.json", overview_export())]);
        let registry = Registry::new();
        let cases: [(u64, Vec<&str>, bool); 3] = [
            (0, vec!["fn-0", "fn-1", "fn-2"], true),
            (3, vec!["fn-3", "fn-4", "fn-5"], true),
            (6, vec!["fn-6"], false),
        ];
        for (offset, expected_names, expected_more) in cases {
            let args = json!({"limit": 3, "offset": offset, "target": seeded.target_arg()});
            let value = list_functions(&registry, &seeded.config, &args).unwrap();
            let facts = finding_facts(&value, "functions");
            let names: Vec<&str> = facts["functions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["name"].as_str().unwrap())
                .collect();
            assert_eq!(names, expected_names, "offset {offset}");
            assert_eq!(facts["returned"], expected_names.len());
            assert_eq!(facts["limit"], 3);
            assert_eq!(facts["offset"], offset);
            assert_eq!(facts["retained"], 7);
            assert_eq!(facts["total"], 7);
            assert_eq!(facts["more"], expected_more, "offset {offset}");
        }
        seeded.cleanup();
    }

    #[test]
    fn validation_unpaged_listing_matches_the_pre_paging_shape() {
        let seeded = seeded_target("unpaged", &[("export-overview.json", overview_export())]);
        let registry = Registry::new();
        let args = json!({"target": seeded.target_arg()});
        let value = list_functions(&registry, &seeded.config, &args).unwrap();
        let facts = finding_facts(&value, "functions");
        assert_eq!(facts["returned"], 7);
        assert_eq!(facts["limit"], FUNCTION_COUNT_MAX);
        assert_eq!(facts["offset"], 0);
        assert_eq!(facts["more"], false);
        assert_eq!(facts["retained"], 7);
        assert!(finding(&value, "functions").get("limitations").is_none());
        seeded.cleanup();
    }

    #[test]
    fn validation_names_and_strings_page_each_inventory() {
        let seeded = seeded_target("multi", &[("export-overview.json", overview_export())]);
        let registry = Registry::new();
        // Symbols: 4 retained, pages of 2.
        let args = json!({"limit": 2, "target": seeded.target_arg()});
        let value = list_names(&registry, &seeded.config, &args).unwrap();
        let facts = finding_facts(&value, "symbols");
        assert_eq!(facts["returned"], 2);
        assert_eq!(facts["retained"], 4);
        assert_eq!(facts["total"], 4);
        assert_eq!(facts["more"], true);
        let args = json!({"limit": 2, "offset": 2, "target": seeded.target_arg()});
        let value = list_names(&registry, &seeded.config, &args).unwrap();
        let facts = finding_facts(&value, "symbols");
        assert_eq!(facts["returned"], 2);
        assert_eq!(facts["more"], false);
        assert_eq!(facts["symbols"][0]["name"], "sym-2");
        // Strings and data strings page independently under one
        // shared offset/limit.
        let args = json!({"limit": 2, "target": seeded.target_arg()});
        let value = list_strings(&registry, &seeded.config, &args).unwrap();
        let strings = finding_facts(&value, "strings");
        assert_eq!(strings["returned"], 2);
        assert_eq!(strings["retained"], 5);
        assert_eq!(strings["more"], true);
        let data = finding_facts(&value, "data_strings");
        assert_eq!(data["returned"], 2);
        assert_eq!(data["retained"], 3);
        assert_eq!(data["more"], true);
        let args = json!({"limit": 2, "offset": 4, "target": seeded.target_arg()});
        let value = list_strings(&registry, &seeded.config, &args).unwrap();
        let strings = finding_facts(&value, "strings");
        assert_eq!(strings["returned"], 1);
        assert_eq!(strings["more"], false);
        let data = finding_facts(&value, "data_strings");
        assert_eq!(data["returned"], 0);
        assert_eq!(data["retained"], 3);
        assert_eq!(data["more"], false);
        seeded.cleanup();
    }

    #[test]
    fn adversarial_summary_leaks_no_payload() {
        let file = function_export_file("target_fn");
        let seeded = seeded_target("leak", &[(&file, function_export(true))]);
        let registry = Registry::new();
        let args = json!({"function": "target_fn", "target": seeded.target_arg()});
        let value = analyze_function(&registry, &seeded.config, &args).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(
            !serialized.contains("DECOMPILE_MARKER_7F3A"),
            "summary leaked decompile payload: {serialized}"
        );
        assert!(
            !serialized.contains("LISTING_MARKER_7F3A"),
            "summary leaked listing payload: {serialized}"
        );
        assert!(
            finding_facts(&value, "listing")
                .get("instructions")
                .is_none()
        );
        assert!(finding_facts(&value, "decompile").get("c").is_none());
        seeded.cleanup();
    }

    #[test]
    fn adversarial_page_past_the_end_is_empty_and_honest() {
        let seeded = seeded_target("pastend", &[("export-overview.json", overview_export())]);
        let registry = Registry::new();
        let args = json!({"limit": 10, "offset": 999, "target": seeded.target_arg()});
        let value = list_functions(&registry, &seeded.config, &args).unwrap();
        let facts = finding_facts(&value, "functions");
        assert!(facts["functions"].as_array().unwrap().is_empty());
        assert_eq!(facts["returned"], 0);
        assert_eq!(facts["retained"], 7);
        assert_eq!(facts["total"], 7);
        assert_eq!(facts["more"], false);
        assert_eq!(value["coverage"]["examined"], 7);
        assert_eq!(value["coverage"]["total"], 7);
        seeded.cleanup();
    }

    #[test]
    fn adversarial_complete_detail_matches_the_pre_change_envelope() {
        // Equivalence against the pre-S1 output, field for field:
        // the expected envelope below is the dossier shape the
        // handler produced before the `detail` parameter existed.
        let file = function_export_file("target_fn");
        let seeded = seeded_target("equiv", &[(&file, function_export(true))]);
        let registry = Registry::new();
        let args = json!({
            "detail": "complete",
            "function": "target_fn",
            "target": seeded.target_arg(),
        });
        let value = analyze_function(&registry, &seeded.config, &args).unwrap();
        let expected = json!({
            // `exhaustive` stays at the Coverage default (false):
            // the pre-S1 handler never raises it on this path,
            // and the equivalence is byte-for-byte, quirk included.
            "coverage": {"examined": 1, "exhaustive": false, "total": 1},
            "findings": [
                {"confidence": "observed", "kind": "function", "facts": {
                    "address": "00401000",
                    "body_size": 42,
                    "calling_convention": "__fastcall",
                    "classification": "defined",
                    "matched_via": "exact",
                    "name": "target_fn",
                    "query": "target_fn",
                    "signature": "int target_fn(void)",
                }},
                {"confidence": "observed", "kind": "listing", "facts": {
                    "instructions": [
                        {"address": "00401000", "text": "PUSH EBP ; LISTING_MARKER_7F3A"},
                        {"address": "00401001", "text": "MOV EBP, ESP"},
                        {"address": "00401003", "text": "RET"},
                    ],
                }},
                {"confidence": "derived", "kind": "call_graph", "facts": {
                    "callees": ["helper_a", "helper_b"],
                    "callers": ["main"],
                }},
                {"confidence": "observed", "kind": "references_to", "facts": {
                    "count": 1,
                    "references": [{"from": "00402000", "type": "DATA"}],
                }},
                {"confidence": "derived", "kind": "decompile", "facts": {
                    "bytes": DECOMPILE_C.len(),
                    "c": DECOMPILE_C,
                }},
            ],
            "provider": "ghidra",
            "status": "complete",
            "subject": {
                "path": seeded.target.canonicalize().unwrap().display().to_string(),
                "sha256": seeded.subject_sha256,
                "size_bytes": std::fs::metadata(&seeded.target).unwrap().len(),
            },
            "tool": "analyze_function",
            "unknowns": [],
        });
        assert_eq!(value, expected);
        seeded.cleanup();
    }

    #[test]
    fn adversarial_malformed_detail_is_refused_before_any_work() {
        // No export is seeded: if parsing did not precede the
        // provider seam, these calls would fail at the engine,
        // not with the typed refusal.
        let seeded = seeded_target("detail", &[]);
        let registry = Registry::new();
        for detail in [
            json!("full"),
            json!("COMPLETE"),
            json!(""),
            json!(42),
            json!(true),
            json!(null),
        ] {
            let args = json!({
                "detail": detail,
                "function": "target_fn",
                "target": seeded.target_arg(),
            });
            let err = analyze_function(&registry, &seeded.config, &args).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidRequest, "detail {detail}");
        }
        seeded.cleanup();
    }

    #[test]
    fn adversarial_malformed_page_arguments_are_typed_errors() {
        let seeded = seeded_target("badpage", &[("export-overview.json", overview_export())]);
        let registry = Registry::new();
        for bad in [
            json!({"offset": -1}),
            json!({"offset": "3"}),
            json!({"offset": 1.5}),
            json!({"limit": 0}),
            json!({"limit": -2}),
            json!({"limit": "10"}),
            json!({"limit": 2.5}),
        ] {
            let mut args = json!({"target": seeded.target_arg()});
            args.as_object_mut()
                .unwrap()
                .extend(bad.as_object().unwrap().clone());
            let err = list_functions(&registry, &seeded.config, &args).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidRequest, "args {bad}");
        }
        seeded.cleanup();
    }

    #[test]
    fn adversarial_page_bounds_clamp_and_never_overflow() {
        let seeded = seeded_target("clamp", &[("export-overview.json", overview_export())]);
        let registry = Registry::new();
        let args = json!({"limit": u64::MAX, "target": seeded.target_arg()});
        let value = list_functions(&registry, &seeded.config, &args).unwrap();
        let facts = finding_facts(&value, "functions");
        assert_eq!(facts["limit"], FUNCTION_COUNT_MAX);
        assert_eq!(facts["returned"], 7);
        let args = json!({"limit": 5, "offset": u64::MAX, "target": seeded.target_arg()});
        let value = list_functions(&registry, &seeded.config, &args).unwrap();
        let facts = finding_facts(&value, "functions");
        assert_eq!(facts["returned"], 0);
        assert_eq!(facts["retained"], 7);
        assert_eq!(facts["more"], false);
        seeded.cleanup();
    }
}
