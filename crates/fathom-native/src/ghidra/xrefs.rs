//! Cross-reference family (fathom Ghidra G1): references to and
//! from addresses and functions, read from Ghidra's reference
//! manager through the per-address and per-function export modes.
//! The two mutation-flavored upstream rows of this family
//! (`add_memory_reference`, `remove_reference`) are registered
//! not-implemented in `lib.rs`; see SPEC §9.1.

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::FathomError;
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject};
use fathom_core::limits::ADDRESS_QUERY_COUNT_MAX;
use fathom_core::registry::{Registry, require_str};

use crate::engine::Export;
use crate::ghidra::base;
use crate::ghidra::query::{
    self, Listing, Page, address_row, address_usable, found_detail, function_identity,
};
use crate::sections::AddressFacts;

pub fn get_bulk_xrefs(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let raw = query::require_text_list(args, "addresses", ADDRESS_QUERY_COUNT_MAX)?;
    let mut addresses = Vec::with_capacity(raw.len());
    for text in raw {
        let canonical = query::parse_address(text)?;
        if !addresses.contains(&canonical) {
            addresses.push(canonical);
        }
    }
    let (subject, export) =
        query::run_mode(config, args, "addresses", Some(&addresses.join("\n")))?;
    bulk_evidence(subject, &export, &addresses)
}

fn bulk_evidence(
    subject: Subject,
    export: &Export,
    addresses: &[String],
) -> Result<Value, FathomError> {
    let mut evidence = base("get_bulk_xrefs", subject);
    let mut partial = false;
    for canonical in addresses {
        let row = address_row(export, canonical)?;
        if !address_usable(&mut evidence, row) {
            continue;
        }
        mid_unit_note(&mut evidence, row);
        let (to, from) = (refs_to(row)?, refs_from(row)?);
        partial |= to.1 || from.1;
        let mut finding = Finding::new(
            "xrefs",
            Confidence::Observed,
            json!({
                "address": row.address,
                "references_from": from.0,
                "references_to": to.0,
            }),
        )
        .with_location(row.address.clone());
        if to.1 || from.1 {
            finding = finding.with_limitation("reference rows truncated at the export bound");
        }
        evidence.add_finding(finding);
    }
    evidence.coverage.examined = addresses.len() as u64;
    evidence.coverage.total = addresses.len() as u64;
    evidence.coverage.exhaustive = !partial;
    Ok(evidence.to_value())
}

pub fn get_function_xrefs(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let (subject, export) = query::run_mode(config, args, "detail", Some(function))?;
    function_xrefs_evidence(subject, &export)
}

fn function_xrefs_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_xrefs", subject);
    let Some(detail) = found_detail(&mut evidence, export)? else {
        return Ok(evidence.to_value());
    };
    evidence.add_finding(function_identity(detail)?);
    let incoming = query::section(&detail.references_to, "detail.references_to")?;
    incoming.check("detail.references_to")?;
    let instructions = query::section(&detail.instructions, "detail.instructions")?;
    instructions.check("detail.instructions")?;
    let outgoing: Vec<Value> = instructions
        .rows
        .iter()
        .flat_map(|ins| {
            ins.references_from
                .iter()
                .map(|r| json!({"from": ins.address, "to": r.to, "type": r.kind}))
        })
        .collect();
    let mut to_finding = Finding::new(
        "references_to",
        Confidence::Observed,
        json!({
            "count": incoming.rows.len(),
            "references": incoming.rows.iter().map(|r| json!({
                "from": r.from, "from_function": r.from_function, "type": r.kind,
            })).collect::<Vec<_>>(),
            "total": incoming.total,
        }),
    );
    if incoming.is_partial() {
        to_finding =
            to_finding.with_limitation("incoming references truncated at the export bound");
    }
    evidence.add_finding(to_finding);
    let mut from_finding = Finding::new(
        "references_from",
        Confidence::Observed,
        json!({"count": outgoing.len(), "references": outgoing}),
    );
    if instructions.is_partial() {
        from_finding = from_finding
            .with_limitation("outgoing references cover only the instructions the export retained");
    }
    evidence.add_finding(from_finding);
    let partial = incoming.is_partial() || instructions.is_partial();
    evidence.coverage.examined = (incoming.rows.len() + instructions.rows.len()) as u64;
    evidence.coverage.total = incoming.total + instructions.total;
    evidence.coverage.exhaustive = !partial;
    Ok(evidence.to_value())
}

pub fn get_xrefs_from(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let address = query::parse_address(require_str(args, "address")?)?;
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "addresses", Some(&address))?;
    single_evidence("get_xrefs_from", subject, &export, &address, page, false)
}

pub fn get_xrefs_to(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let address = query::parse_address(require_str(args, "address")?)?;
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "addresses", Some(&address))?;
    single_evidence("get_xrefs_to", subject, &export, &address, page, true)
}

fn single_evidence(
    tool: &str,
    subject: Subject,
    export: &Export,
    canonical: &str,
    page: Page,
    incoming: bool,
) -> Result<Value, FathomError> {
    let mut evidence = base(tool, subject);
    let row = address_row(export, canonical)?;
    if !address_usable(&mut evidence, row) {
        return Ok(evidence.to_value());
    }
    let (rows, retained, total, partial) = if incoming {
        let section = query::section(&row.references_to, "addresses.references_to")?;
        section.check("addresses.references_to")?;
        let rows = section
            .rows
            .iter()
            .map(|r| json!({"from": r.from, "from_function": r.from_function, "type": r.kind}))
            .collect::<Vec<_>>();
        (
            rows,
            section.rows.len(),
            section.total,
            section.is_partial(),
        )
    } else {
        let section = query::section(&row.references_from, "addresses.references_from")?;
        section.check("addresses.references_from")?;
        let rows = section
            .rows
            .iter()
            .map(|r| json!({"to": r.to, "type": r.kind}))
            .collect::<Vec<_>>();
        (
            rows,
            section.rows.len(),
            section.total,
            section.is_partial(),
        )
    };
    if !incoming {
        mid_unit_note(&mut evidence, row);
    }
    Listing {
        confidence: Confidence::Observed,
        key: "references",
        kind: if incoming {
            "references_to"
        } else {
            "references_from"
        },
        partial,
        retained,
        rows,
        total,
    }
    .into_evidence(&mut evidence, page);
    if let Some(finding) = evidence.findings.last_mut() {
        *finding = finding.clone().with_location(row.address.clone());
    }
    Ok(evidence.to_value())
}

/// Ghidra records outgoing references at code-unit starts: an
/// address inside an instruction or data item has none of its own.
fn mid_unit_note(evidence: &mut Evidence, row: &AddressFacts) {
    if let Some(unit) = &row.code_unit
        && !query::same_address(&unit.start, &row.address)
    {
        evidence.add_unknown(
            "code_unit_start",
            format!(
                "address {} lies inside the {} starting at {}; outgoing references are \
                 recorded at code-unit starts — query {} for that unit's references",
                row.address, unit.kind, unit.start, unit.start
            ),
        );
    }
}

type RefRows = (Vec<Value>, bool);

fn refs_to(row: &AddressFacts) -> Result<RefRows, FathomError> {
    let section = query::section(&row.references_to, "addresses.references_to")?;
    section.check("addresses.references_to")?;
    Ok((
        section
            .rows
            .iter()
            .map(|r| json!({"from": r.from, "from_function": r.from_function, "type": r.kind}))
            .collect(),
        section.is_partial(),
    ))
}

fn refs_from(row: &AddressFacts) -> Result<RefRows, FathomError> {
    let section = query::section(&row.references_from, "addresses.references_from")?;
    section.check("addresses.references_from")?;
    Ok((
        section
            .rows
            .iter()
            .map(|r| json!({"to": r.to, "type": r.kind}))
            .collect(),
        section.is_partial(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::query::PAGE_ROWS_DEFAULT;
    use crate::ghidra::query::tests::{export, subject};
    use fathom_core::error::ErrorCode;

    const ADDRESSES: &str = r#""addresses": [
        {"query": "101040", "valid": true, "address": "00101040", "in_memory": true,
         "block": ".text", "bytes": "f30f1efa",
         "code_unit": {"kind": "instruction", "length": 4, "start": "00101040", "text": "ENDBR64"},
         "comments": [], "context_after": [], "context_at": null, "context_before": [],
         "data": null, "function": {"address": "00101040", "name": "main"},
         "references_from": {"rows": [{"to": "00102000", "type": "DATA"}], "total": 1, "truncated": false},
         "references_to": {"rows": [
             {"from": "00101100", "from_function": "_start", "type": "UNCONDITIONAL_CALL"},
             {"from": "00103000", "from_function": "", "type": "DATA"}],
          "total": 2, "truncated": false},
         "symbols": []},
        {"query": "101042", "valid": true, "address": "00101042", "in_memory": true,
         "block": ".text", "bytes": "",
         "code_unit": {"kind": "instruction", "length": 4, "start": "00101040", "text": "ENDBR64"},
         "references_from": {"rows": [], "total": 0, "truncated": false},
         "references_to": {"rows": [], "total": 0, "truncated": false}},
        {"query": "ffffffffffffffff", "valid": false}
    ]"#;

    fn page() -> Page {
        Page {
            limit: PAGE_ROWS_DEFAULT,
            offset: 0,
        }
    }

    #[test]
    fn validation_xrefs_to_lists_callers_with_functions() {
        let export = export("addresses", ADDRESSES);
        let value =
            single_evidence("get_xrefs_to", subject(), &export, "101040", page(), true).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["total"], 2);
        assert_eq!(facts["references"][0]["from_function"], "_start");
        assert_eq!(facts["references"][0]["type"], "UNCONDITIONAL_CALL");
        assert_eq!(value["coverage"]["exhaustive"], true);
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn validation_xrefs_from_pages_rows() {
        let export = export("addresses", ADDRESSES);
        let value = single_evidence(
            "get_xrefs_from",
            subject(),
            &export,
            "101040",
            page(),
            false,
        )
        .unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["references"][0]["to"],
            "00102000"
        );
        let one = Page {
            limit: 1,
            offset: 1,
        };
        let value =
            single_evidence("get_xrefs_to", subject(), &export, "101040", one, true).unwrap();
        assert_eq!(value["findings"][0]["facts"]["returned"], 1);
        assert_eq!(
            value["findings"][0]["facts"]["references"][0]["from"],
            "00103000"
        );
    }

    #[test]
    fn adversarial_mid_instruction_address_is_flagged_not_answered_empty() {
        let export = export("addresses", ADDRESSES);
        let value = single_evidence(
            "get_xrefs_from",
            subject(),
            &export,
            "101042",
            page(),
            false,
        )
        .unwrap();
        assert_eq!(value["status"], "partial");
        assert_eq!(value["unknowns"][0]["aspect"], "code_unit_start");
    }

    #[test]
    fn adversarial_unresolvable_address_is_an_unknown() {
        let export = export("addresses", ADDRESSES);
        let value = single_evidence(
            "get_xrefs_to",
            subject(),
            &export,
            "ffffffffffffffff",
            page(),
            true,
        )
        .unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn adversarial_missing_row_and_poisoned_counts_are_integrity_errors() {
        let export_ok = export("addresses", ADDRESSES);
        let error = single_evidence("get_xrefs_to", subject(), &export_ok, "9999", page(), true)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
        let poisoned = export(
            "addresses",
            r#""addresses": [{"query": "1", "valid": true, "address": "00000001", "in_memory": true,
                "references_to": {"rows": [{"from": "2", "from_function": "", "type": "DATA"}],
                "total": 0, "truncated": false},
                "references_from": {"rows": [], "total": 0, "truncated": false}}]"#,
        );
        let error =
            single_evidence("get_xrefs_to", subject(), &poisoned, "1", page(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
    }

    #[test]
    fn validation_bulk_reports_each_address() {
        let export = export("addresses", ADDRESSES);
        let addresses = vec!["101040".to_string(), "ffffffffffffffff".to_string()];
        let value = bulk_evidence(subject(), &export, &addresses).unwrap();
        assert_eq!(value["findings"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["findings"][0]["facts"]["references_to"][1]["from"],
            "00103000"
        );
        assert_eq!(value["unknowns"][0]["aspect"], "address");
        // A mid-instruction address carries the code-unit caveat in
        // bulk mode too (live-smoke finding, 2026-10-20).
        let value = bulk_evidence(subject(), &export, &["101042".to_string()]).unwrap();
        assert_eq!(value["unknowns"][0]["aspect"], "code_unit_start");
    }

    const DETAIL: &str = r#""detail": {"query": "main", "found": true, "match": "exact",
        "candidates": [],
        "function": {"address": "00101040", "name": "main", "signature": "int main(void)",
            "body_size": 8, "classification": "defined", "calling_convention": "__stdcall"},
        "references_to": {"rows": [{"from": "00101100", "from_function": "_start",
            "type": "UNCONDITIONAL_CALL"}], "total": 1, "truncated": false},
        "instructions": {"rows": [
            {"address": "00101040", "bytes": "e8", "fallthrough": "00101045",
             "flow_type": "UNCONDITIONAL_CALL", "flows": ["00101200"], "mnemonic": "CALL",
             "pcode": [], "references_from": [{"to": "00101200", "type": "UNCONDITIONAL_CALL"}],
             "text": "CALL 0x101200"}], "total": 3, "truncated": true}}"#;

    #[test]
    fn validation_function_xrefs_combine_both_directions() {
        let export = export("detail", DETAIL);
        let value = function_xrefs_evidence(subject(), &export).unwrap();
        assert_eq!(value["findings"][0]["facts"]["name"], "main");
        assert_eq!(
            value["findings"][1]["facts"]["references"][0]["from"],
            "00101100"
        );
        assert_eq!(
            value["findings"][2]["facts"]["references"][0]["to"],
            "00101200"
        );
        // Instruction rows were truncated: the outgoing set says so.
        assert_eq!(value["coverage"]["exhaustive"], false);
        assert!(
            !value["findings"][2]["limitations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn adversarial_unknown_function_is_an_unknown_not_empty_success() {
        let export = export(
            "detail",
            r#""detail": {"query": "nope", "found": false, "match": "none", "candidates": []}"#,
        );
        let value = function_xrefs_evidence(subject(), &export).unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
    }
}
