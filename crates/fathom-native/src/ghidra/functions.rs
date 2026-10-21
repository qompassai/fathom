//! Functions & tags family (fathom Ghidra G1): per-function facts
//! (variables, p-code, jump targets, labels), call-graph views,
//! function tags, and the next code region no function covers.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Finding, Subject};
use fathom_core::limits::CALL_GRAPH_DEPTH_MAX;
use fathom_core::registry::Registry;

use crate::engine::Export;
use crate::ghidra::base;
use crate::ghidra::query::{
    self, Listing, Page, Resolved, found_detail, function_identity, function_unknown,
};
use crate::sections::{CallNode, FunctionDoc};

/// Hops a call-graph neighborhood walks when `depth` is omitted.
const CALL_GRAPH_DEPTH_DEFAULT: usize = 2;

/// Nodes one call-graph neighborhood reports at most.
const CALL_GRAPH_NODES_MAX: usize = 2_000;

pub fn find_next_undefined_function(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let start = query::optional_text(args, "start")?
        .map(query::parse_address)
        .transpose()?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    next_undefined_evidence(subject, &export, start.as_deref())
}

fn next_undefined_evidence(
    subject: Subject,
    export: &Export,
    start: Option<&str>,
) -> Result<Value, FathomError> {
    let mut evidence = base("find_next_undefined_function", subject);
    let facts = query::section(&export.program_facts, "program_facts")?;
    let gaps = &facts.code_gaps;
    gaps.check("program_facts.code_gaps")?;
    let floor = start.and_then(query::address_key);
    let after_floor = |address: &str| match (&floor, query::address_key(address)) {
        (None, _) => true,
        (Some(floor), Some(key)) => key.0 == floor.0 && key.1 >= floor.1,
        (Some(_), None) => false,
    };
    let padding_only = gaps
        .rows
        .iter()
        .filter(|gap| {
            gap.has_instructions
                && gap.first_non_padding.is_empty()
                && after_floor(&gap.first_instruction)
        })
        .count();
    let next = gaps
        .rows
        .iter()
        .find(|gap| !gap.first_non_padding.is_empty() && after_floor(&gap.first_non_padding));
    let rule = "Ghidra's sense of 'undefined function': instructions in an executable, \
                initialized block that no function body covers; gaps holding only \
                alignment padding (NOP/INT3 mnemonics) are skipped; the first \
                substantive instruction at or after 'start' is reported";
    match next {
        Some(gap) => evidence.add_finding(
            Finding::new(
                "undefined_function",
                Confidence::Derived,
                json!({
                    "address": gap.first_non_padding,
                    "gap_end": gap.end,
                    "gap_first_instruction": gap.first_instruction,
                    "gap_size": gap.size,
                    "gap_start": gap.start,
                    "has_defined_data": gap.has_defined_data,
                    "padding_only_gaps_skipped": padding_only,
                    "start": start,
                }),
            )
            .with_location(gap.first_non_padding.clone())
            .with_limitation(rule),
        ),
        None if gaps.is_partial() => evidence.add_unknown(
            "undefined_function",
            "no candidate among the retained code gaps; the gap inventory was truncated, \
             so later gaps were not examined",
        ),
        None => evidence.add_finding(
            Finding::new(
                "undefined_function",
                Confidence::Derived,
                json!({
                    "found": false,
                    "padding_only_gaps_skipped": padding_only,
                    "start": start,
                }),
            )
            .with_limitation(rule),
        ),
    }
    query::cover(
        &mut evidence,
        gaps.rows.len(),
        gaps.total,
        gaps.is_partial(),
    );
    Ok(evidence.to_value())
}

pub fn get_full_call_graph(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "callgraph", None)?;
    full_call_graph_evidence(subject, &export, page)
}

fn full_call_graph_evidence(
    subject: Subject,
    export: &Export,
    page: Page,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_full_call_graph", subject);
    let graph = query::section(&export.callgraph, "callgraph")?;
    graph.functions.check("callgraph.functions")?;
    let names: BTreeMap<&str, &str> = graph
        .functions
        .rows
        .iter()
        .map(|node| (node.address.as_str(), node.name.as_str()))
        .collect();
    let edges: Vec<Value> = graph
        .functions
        .rows
        .iter()
        .flat_map(|node| {
            let names = &names;
            node.callees.iter().map(move |callee| {
                json!({
                    "from": node.address,
                    "from_name": node.name,
                    "to": callee,
                    "to_name": names.get(callee.as_str()).copied().unwrap_or(""),
                })
            })
        })
        .collect();
    let edges_capped = graph.functions.rows.iter().any(|n| n.callees_truncated);
    let edge_count = edges.len();
    Listing {
        confidence: Confidence::Observed,
        key: "edges",
        kind: "call_edges",
        partial: graph.functions.is_partial(),
        retained: graph.functions.rows.len(),
        rows: edges,
        total: graph.functions.total,
    }
    .into_evidence(&mut evidence, page);
    if edges_capped {
        evidence.coverage.exhaustive = false;
        evidence.add_unknown(
            "call_edges",
            "some functions call more targets than the per-function callee bound retains",
        );
    }
    evidence.add_unknown(
        "indirect_calls",
        format!(
            "{edge_count} edges are Ghidra's resolved call references; calls through \
             unresolved pointers are not in the graph"
        ),
    );
    Ok(evidence.to_value())
}

pub fn get_function_call_graph(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let depth = query::optional_count(args, "depth", CALL_GRAPH_DEPTH_MAX, false)?
        .unwrap_or(CALL_GRAPH_DEPTH_DEFAULT);
    let direction = match query::optional_text(args, "direction")? {
        None | Some("both") => Direction::Both,
        Some("callees") => Direction::Callees,
        Some("callers") => Direction::Callers,
        Some(other) => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("direction {other:?} is not one of both, callees, callers"),
            ));
        }
    };
    let (subject, export) = query::run_mode(config, args, "callgraph", None)?;
    call_graph_evidence(subject, &export, function, depth, direction)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Both,
    Callees,
    Callers,
}

/// A bounded call-graph neighborhood: nodes with their hop count,
/// the edges among them, and whether the node cap cut the walk.
pub(crate) struct Neighborhood<'a> {
    pub capped: bool,
    pub edges: Vec<(&'a str, &'a str)>,
    pub nodes: Vec<(&'a CallNode, usize)>,
}

/// Breadth-first neighborhood over the exported call edges. Edges
/// are kept only between nodes the walk reports.
pub(crate) fn neighborhood<'a>(
    nodes: &'a [CallNode],
    root: &'a CallNode,
    depth: usize,
    forward: bool,
    backward: bool,
) -> Neighborhood<'a> {
    let by_address: BTreeMap<&str, &CallNode> =
        nodes.iter().map(|n| (n.address.as_str(), n)).collect();
    let mut callers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        for callee in &node.callees {
            callers
                .entry(callee.as_str())
                .or_default()
                .push(node.address.as_str());
        }
    }
    let mut seen: BTreeSet<&str> = BTreeSet::from([root.address.as_str()]);
    let mut order = vec![(root, 0)];
    let mut edges: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut queue = VecDeque::from([(root.address.as_str(), 0usize)]);
    let mut capped = false;
    while let Some((address, hops)) = queue.pop_front() {
        if hops >= depth {
            continue;
        }
        let mut next: Vec<(&str, (&str, &str))> = Vec::new();
        if forward && let Some(node) = by_address.get(address) {
            for callee in &node.callees {
                next.push((callee.as_str(), (address, callee.as_str())));
            }
        }
        if backward && let Some(list) = callers.get(address) {
            for caller in list {
                next.push((caller, (caller, address)));
            }
        }
        for (neighbor, edge) in next {
            if seen.contains(neighbor) {
                edges.insert(edge);
                continue;
            }
            if order.len() >= CALL_GRAPH_NODES_MAX {
                capped = true;
                continue;
            }
            if let Some(node) = by_address.get(neighbor) {
                seen.insert(neighbor);
                edges.insert(edge);
                order.push((node, hops + 1));
                queue.push_back((neighbor, hops + 1));
            }
        }
    }
    Neighborhood {
        capped,
        edges: edges.into_iter().collect(),
        nodes: order,
    }
}

fn call_graph_evidence(
    subject: Subject,
    export: &Export,
    function: &str,
    depth: usize,
    direction: Direction,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_call_graph", subject);
    let graph = query::section(&export.callgraph, "callgraph")?;
    graph.functions.check("callgraph.functions")?;
    let nodes = &graph.functions.rows;
    let (root, matched_via) =
        match query::resolve_function(nodes, function, |n| &n.name, |n| &n.address) {
            Resolved::One(node, via) => (node, via),
            Resolved::Ambiguous(found) => {
                let names: Vec<String> = found
                    .iter()
                    .map(|n| format!("{}@{}", n.name, n.address))
                    .collect();
                function_unknown(&mut evidence, function, &names);
                return Ok(evidence.to_value());
            }
            Resolved::Missing => {
                function_unknown(&mut evidence, function, &[]);
                return Ok(evidence.to_value());
            }
        };
    let (forward, backward) = match direction {
        Direction::Both => (true, true),
        Direction::Callees => (true, false),
        Direction::Callers => (false, true),
    };
    let Neighborhood {
        capped,
        edges,
        nodes: order,
    } = neighborhood(nodes, root, depth, forward, backward);
    let mut finding = Finding::new(
        "call_graph",
        Confidence::Observed,
        json!({
            "depth": depth,
            "direction": format!("{direction:?}").to_lowercase(),
            "edges": edges.iter().map(|(from, to)| json!({"from": from, "to": to}))
                .collect::<Vec<_>>(),
            "nodes": order.iter().map(|(node, hops)| json!({
                "address": node.address, "classification": node.classification,
                "hops": hops, "name": node.name,
            })).collect::<Vec<_>>(),
            "root": {"address": root.address, "matched_via": matched_via, "name": root.name},
        }),
    )
    .with_location(root.address.clone())
    .with_limitation("edges are resolved call references; unresolved indirect calls are absent");
    if capped {
        finding = finding.with_limitation("neighborhood capped at 2,000 nodes");
    }
    if graph.functions.is_partial() {
        finding = finding.with_limitation(
            "the call-graph export was truncated; functions beyond its bound are absent",
        );
    }
    evidence.add_finding(finding);
    query::cover(
        &mut evidence,
        nodes.len(),
        graph.functions.total,
        graph.functions.is_partial() || capped,
    );
    Ok(evidence.to_value())
}

pub fn get_function_jump_targets(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let (subject, export) = query::run_mode(config, args, "detail", Some(function))?;
    jump_targets_evidence(subject, &export)
}

fn jump_targets_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_jump_targets", subject);
    let Some(detail) = found_detail(&mut evidence, export)? else {
        return Ok(evidence.to_value());
    };
    evidence.add_finding(function_identity(detail)?);
    let instructions = query::section(&detail.instructions, "detail.instructions")?;
    instructions.check("detail.instructions")?;
    let body: BTreeSet<_> = instructions
        .rows
        .iter()
        .filter_map(|row| query::address_key(&row.address))
        .collect();
    let mut unresolved = 0usize;
    let jumps: Vec<Value> = instructions
        .rows
        .iter()
        .filter(|row| row.flow_type.contains("JUMP"))
        .map(|row| {
            if row.flows.is_empty() {
                unresolved += 1;
            }
            json!({
                "address": row.address,
                "flow_type": row.flow_type,
                "targets": row.flows.iter().map(|target| json!({
                    "address": target,
                    "inside_function": query::address_key(target)
                        .is_some_and(|key| body.contains(&key)),
                })).collect::<Vec<_>>(),
                "text": row.text,
            })
        })
        .collect();
    let mut finding = Finding::new(
        "jump_targets",
        Confidence::Observed,
        json!({"count": jumps.len(), "jumps": jumps}),
    );
    if instructions.is_partial() {
        finding = finding.with_limitation(
            "the function's instruction listing was truncated at the export bound",
        );
    }
    evidence.add_finding(finding);
    if unresolved > 0 {
        evidence.add_unknown(
            "computed_jumps",
            format!("{unresolved} jump(s) have no target Ghidra resolved (computed jumps)"),
        );
    }
    query::cover(
        &mut evidence,
        instructions.rows.len(),
        instructions.total,
        instructions.is_partial(),
    );
    Ok(evidence.to_value())
}

pub fn get_function_labels(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let (subject, export) = query::run_mode(config, args, "detail", Some(function))?;
    labels_evidence(subject, &export)
}

fn labels_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_labels", subject);
    let Some(detail) = found_detail(&mut evidence, export)? else {
        return Ok(evidence.to_value());
    };
    evidence.add_finding(function_identity(detail)?);
    let labels = query::section(&detail.labels, "detail.labels")?;
    labels.check("detail.labels")?;
    let mut finding = Finding::new(
        "labels",
        Confidence::Observed,
        json!({
            "labels": labels.rows.iter().map(|l| json!({
                "address": l.address, "name": l.name, "primary": l.primary,
                "source": l.source,
            })).collect::<Vec<_>>(),
            "total": labels.total,
        }),
    )
    .with_limitation(
        "label symbols stored in the function body; Ghidra's dynamic LAB_ names are \
         not stored symbols and may be absent",
    );
    if labels.is_partial() {
        finding = finding.with_limitation("labels truncated at the export bound");
    }
    evidence.add_finding(finding);
    query::cover(
        &mut evidence,
        labels.rows.len(),
        labels.total,
        labels.is_partial(),
    );
    Ok(evidence.to_value())
}

pub fn get_function_pcode(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let high = match args.get("high") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'high' must be a boolean",
            ));
        }
    };
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "detail", Some(function))?;
    pcode_evidence(subject, &export, high, page)
}

fn pcode_evidence(
    subject: Subject,
    export: &Export,
    high: bool,
    page: Page,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_pcode", subject);
    let Some(detail) = found_detail(&mut evidence, export)? else {
        return Ok(evidence.to_value());
    };
    evidence.add_finding(function_identity(detail)?);
    if high {
        let function = query::section(&detail.high, "detail.high")?;
        if !function.available {
            evidence.add_unknown(
                "high_pcode",
                format!(
                    "the decompiler produced no high function: {}",
                    function.reason.as_deref().unwrap_or("no reason given")
                ),
            );
            return Ok(evidence.to_value());
        }
        let ops = query::section(&function.ops, "detail.high.ops")?;
        ops.check("detail.high.ops")?;
        let rows = ops
            .rows
            .iter()
            .map(|op| {
                json!({
                    "address": op.address, "inputs": op.inputs, "op": op.op,
                    "output": op.output, "time": op.time,
                })
            })
            .collect();
        // High p-code is decompiler output: derived, not observed.
        Listing {
            confidence: Confidence::Derived,
            key: "ops",
            kind: "high_pcode",
            partial: ops.is_partial(),
            retained: ops.rows.len(),
            rows,
            total: ops.total,
        }
        .into_evidence(&mut evidence, page);
        return Ok(evidence.to_value());
    }
    let instructions = query::section(&detail.instructions, "detail.instructions")?;
    instructions.check("detail.instructions")?;
    let rows: Vec<Value> = instructions
        .rows
        .iter()
        .flat_map(|ins| {
            ins.pcode.iter().map(move |op| {
                json!({
                    "address": ins.address, "inputs": op.inputs, "op": op.op,
                    "output": op.output,
                })
            })
        })
        .collect();
    let partial = instructions.is_partial() || detail.pcode_ops_retained < detail.pcode_ops_total;
    let retained = rows.len();
    Listing {
        confidence: Confidence::Observed,
        key: "ops",
        kind: "raw_pcode",
        partial,
        retained,
        rows,
        total: detail.pcode_ops_total.max(retained as u64),
    }
    .into_evidence(&mut evidence, page);
    Ok(evidence.to_value())
}

pub fn get_function_tags(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    function_tags_evidence(subject, &export, function)
}

/// Resolve a function over the program-mode documentation rows,
/// recording an unknown when it does not resolve to exactly one.
pub(crate) fn resolve_doc<'a>(
    evidence: &mut fathom_core::evidence::Evidence,
    docs: &'a [FunctionDoc],
    function: &str,
) -> Option<(&'a FunctionDoc, &'static str)> {
    match query::resolve_function(docs, function, |d| &d.name, |d| &d.address) {
        Resolved::One(doc, via) => Some((doc, via)),
        Resolved::Ambiguous(found) => {
            let names: Vec<String> = found
                .iter()
                .map(|d| format!("{}@{}", d.name, d.address))
                .collect();
            function_unknown(evidence, function, &names);
            None
        }
        Resolved::Missing => {
            function_unknown(evidence, function, &[]);
            None
        }
    }
}

fn function_tags_evidence(
    subject: Subject,
    export: &Export,
    function: &str,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_tags", subject);
    let facts = query::section(&export.program_facts, "program_facts")?;
    facts.function_docs.check("program_facts.function_docs")?;
    let Some((doc, matched_via)) = resolve_doc(&mut evidence, &facts.function_docs.rows, function)
    else {
        if facts.function_docs.is_partial() {
            evidence.add_unknown(
                "function_docs",
                "the function inventory was truncated; the function may lie beyond its bound",
            );
        }
        return Ok(evidence.to_value());
    };
    evidence.add_finding(
        Finding::new(
            "function_tags",
            Confidence::Observed,
            json!({
                "address": doc.address, "matched_via": matched_via, "name": doc.name,
                "tags": doc.tags,
            }),
        )
        .with_location(doc.address.clone()),
    );
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

pub fn get_function_variables(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let function = query::require_text(args, "function")?;
    let (subject, export) = query::run_mode(config, args, "detail", Some(function))?;
    variables_evidence(subject, &export)
}

fn variables_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("get_function_variables", subject);
    let Some(detail) = found_detail(&mut evidence, export)? else {
        return Ok(evidence.to_value());
    };
    evidence.add_finding(function_identity(detail)?);
    let parameters = query::section(&detail.parameters, "detail.parameters")?;
    let locals = query::section(&detail.locals, "detail.locals")?;
    parameters.check("detail.parameters")?;
    locals.check("detail.locals")?;
    let row = |v: &crate::sections::VariableRow| {
        json!({
            "first_use_offset": v.first_use_offset, "name": v.name, "ordinal": v.ordinal,
            "source": v.source, "storage": v.storage, "type": v.kind,
            "type_length": v.type_length,
        })
    };
    let mut listing = Finding::new(
        "listing_variables",
        Confidence::Observed,
        json!({
            "locals": locals.rows.iter().map(row).collect::<Vec<_>>(),
            "parameters": parameters.rows.iter().map(row).collect::<Vec<_>>(),
        }),
    );
    if parameters.is_partial() || locals.is_partial() {
        listing = listing.with_limitation("variables truncated at the export bound");
    }
    evidence.add_finding(listing);
    let high = query::section(&detail.high, "detail.high")?;
    if high.available {
        let symbols = query::section(&high.symbols, "detail.high.symbols")?;
        symbols.check("detail.high.symbols")?;
        evidence.add_finding(Finding::new(
            "decompiler_variables",
            Confidence::Derived,
            json!({
                "symbols": symbols.rows.iter().map(|s| json!({
                    "name": s.name, "parameter": s.parameter, "storage": s.storage,
                    "type": s.kind,
                })).collect::<Vec<_>>(),
            }),
        ));
    } else {
        evidence.add_unknown(
            "decompiler_variables",
            format!(
                "the decompiler produced no high function: {}",
                high.reason.as_deref().unwrap_or("no reason given")
            ),
        );
    }
    let examined = parameters.rows.len() + locals.rows.len();
    query::cover(
        &mut evidence,
        examined,
        parameters.total + locals.total,
        parameters.is_partial() || locals.is_partial(),
    );
    Ok(evidence.to_value())
}

pub fn list_function_tags(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    let mut evidence = base("list_function_tags", subject);
    let facts = query::section(&export.program_facts, "program_facts")?;
    let tags = &facts.function_tags;
    tags.check("program_facts.function_tags")?;
    Listing {
        confidence: Confidence::Observed,
        key: "tags",
        kind: "function_tags",
        partial: tags.is_partial(),
        retained: tags.rows.len(),
        rows: tags
            .rows
            .iter()
            .map(|t| json!({"comment": t.comment, "name": t.name, "use_count": t.use_count}))
            .collect(),
        total: tags.total,
    }
    .into_evidence(&mut evidence, page);
    Ok(evidence.to_value())
}

pub fn search_functions_by_tag(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let tag = query::require_text(args, "tag")?;
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    tag_search_evidence(subject, &export, tag, page)
}

fn tag_search_evidence(
    subject: Subject,
    export: &Export,
    tag: &str,
    page: Page,
) -> Result<Value, FathomError> {
    let mut evidence = base("search_functions_by_tag", subject);
    let facts = query::section(&export.program_facts, "program_facts")?;
    let docs = &facts.function_docs;
    docs.check("program_facts.function_docs")?;
    let rows = docs
        .rows
        .iter()
        .filter(|d| d.tags.iter().any(|t| t == tag))
        .map(|d| json!({"address": d.address, "name": d.name, "tags": d.tags}))
        .collect();
    Listing {
        confidence: Confidence::Observed,
        key: "functions",
        kind: "tagged_functions",
        partial: docs.is_partial(),
        retained: docs.rows.len(),
        rows,
        total: docs.total,
    }
    .into_evidence(&mut evidence, page);
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

    const CALLGRAPH: &str = r#""callgraph": {"functions": {"rows": [
        {"address": "00101000", "name": "main", "callees": ["00101100", "00101200"],
         "callees_truncated": false, "classification": "defined", "is_entry_point": false,
         "references_to": 1},
        {"address": "00101100", "name": "helper", "callees": ["00101100", "EXTERNAL:00000001"],
         "callees_truncated": false, "classification": "defined", "is_entry_point": false,
         "references_to": 2},
        {"address": "00101200", "name": "leaf", "callees": [], "callees_truncated": false,
         "classification": "defined", "is_entry_point": false, "references_to": 1},
        {"address": "00100f00", "name": "entry", "callees": ["00101000"],
         "callees_truncated": false, "classification": "defined", "is_entry_point": true,
         "references_to": 0},
        {"address": "EXTERNAL:00000001", "name": "puts", "callees": [],
         "callees_truncated": false, "classification": "external", "is_entry_point": false,
         "references_to": 1}
        ], "total": 5, "truncated": false}}"#;

    #[test]
    fn validation_call_graph_neighborhood_walks_both_ways() {
        let export = export("callgraph", CALLGRAPH);
        let value = call_graph_evidence(subject(), &export, "main", 2, Direction::Both).unwrap();
        let nodes = value["findings"][0]["facts"]["nodes"].as_array().unwrap();
        let names: Vec<&str> = nodes.iter().map(|n| n["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["main", "helper", "leaf", "entry", "puts"]);
        assert_eq!(nodes[4]["hops"], 2);
        let callers_only =
            call_graph_evidence(subject(), &export, "main", 1, Direction::Callers).unwrap();
        let nodes = callers_only["findings"][0]["facts"]["nodes"]
            .as_array()
            .unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1]["name"], "entry");
    }

    #[test]
    fn adversarial_recursion_terminates_and_unknown_root_is_unknown() {
        let export = export("callgraph", CALLGRAPH);
        // helper calls itself: the walk must terminate at the depth bound.
        let value = call_graph_evidence(
            subject(),
            &export,
            "helper",
            CALL_GRAPH_DEPTH_MAX,
            Direction::Callees,
        )
        .unwrap();
        let edges = value["findings"][0]["facts"]["edges"].as_array().unwrap();
        assert!(
            edges
                .iter()
                .any(|e| e["from"] == "00101100" && e["to"] == "00101100")
        );
        let value =
            call_graph_evidence(subject(), &export, "nonexistent", 2, Direction::Both).unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_full_call_graph_names_both_ends() {
        let export = export("callgraph", CALLGRAPH);
        let value = full_call_graph_evidence(subject(), &export, page()).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["matched"], 5);
        assert_eq!(facts["edges"][0]["to_name"], "helper");
        assert_eq!(value["unknowns"][0]["aspect"], "indirect_calls");
    }

    const DETAIL: &str = r#""detail": {"query": "main", "found": true, "match": "exact",
        "candidates": [],
        "function": {"address": "00101000", "name": "main", "signature": "int main(void)",
            "body_size": 16, "classification": "defined", "calling_convention": "__stdcall"},
        "instructions": {"rows": [
            {"address": "00101000", "bytes": "74", "fallthrough": "00101002",
             "flow_type": "CONDITIONAL_JUMP", "flows": ["00101008"], "mnemonic": "JZ",
             "pcode": [{"inputs": ["(ram, 0x101008, 8)", "(register, 0x206, 1)"],
                        "op": "CBRANCH", "output": ""}],
             "references_from": [], "text": "JZ 0x101008"},
            {"address": "00101002", "bytes": "ffe0", "fallthrough": "",
             "flow_type": "COMPUTED_JUMP", "flows": [], "mnemonic": "JMP",
             "pcode": [{"inputs": ["(register, 0x0, 8)"], "op": "BRANCHIND", "output": ""}],
             "references_from": [], "text": "JMP RAX"},
            {"address": "00101008", "bytes": "c3", "fallthrough": "",
             "flow_type": "TERMINATOR", "flows": [], "mnemonic": "RET",
             "pcode": [], "references_from": [], "text": "RET"}],
            "total": 3, "truncated": false},
        "pcode_ops_retained": 2, "pcode_ops_total": 2,
        "labels": {"rows": [{"address": "00101008", "name": "done", "primary": true,
            "source": "USER_DEFINED"}], "total": 1, "truncated": false},
        "parameters": {"rows": [{"first_use_offset": 0, "name": "argc", "ordinal": 0,
            "source": "IMPORTED", "storage": "EDI:4", "type": "int", "type_length": 4}],
            "total": 1, "truncated": false},
        "locals": {"rows": [], "total": 0, "truncated": false},
        "high": {"available": false, "reason": "timeout"}}"#;

    #[test]
    fn validation_jump_targets_separate_resolved_and_computed() {
        let export = export("detail", DETAIL);
        let value = jump_targets_evidence(subject(), &export).unwrap();
        let jumps = value["findings"][1]["facts"]["jumps"].as_array().unwrap();
        assert_eq!(jumps.len(), 2);
        assert_eq!(jumps[0]["targets"][0]["inside_function"], true);
        assert_eq!(value["unknowns"][0]["aspect"], "computed_jumps");
    }

    #[test]
    fn validation_pcode_raw_is_observed_and_paged() {
        let export = export("detail", DETAIL);
        let one = Page {
            limit: 1,
            offset: 1,
        };
        let value = pcode_evidence(subject(), &export, false, one).unwrap();
        let finding = &value["findings"][1];
        assert_eq!(finding["confidence"], "observed");
        assert_eq!(finding["facts"]["ops"][0]["op"], "BRANCHIND");
        assert_eq!(finding["facts"]["matched"], 2);
    }

    #[test]
    fn adversarial_unavailable_high_pcode_is_an_unknown() {
        let export = export("detail", DETAIL);
        let value = pcode_evidence(subject(), &export, true, page()).unwrap();
        assert_eq!(value["status"], "partial");
        assert_eq!(value["unknowns"][0]["aspect"], "high_pcode");
        assert!(
            value["unknowns"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("timeout")
        );
    }

    #[test]
    fn validation_variables_and_labels() {
        let export = export("detail", DETAIL);
        let value = variables_evidence(subject(), &export).unwrap();
        assert_eq!(
            value["findings"][1]["facts"]["parameters"][0]["storage"],
            "EDI:4"
        );
        assert_eq!(value["unknowns"][0]["aspect"], "decompiler_variables");
        let value = labels_evidence(subject(), &export).unwrap();
        assert_eq!(value["findings"][1]["facts"]["labels"][0]["name"], "done");
    }

    fn program(gaps: &str, docs: &str) -> Export {
        export(
            "program",
            &format!(
                r#""program_facts": {{
                "analysis": {{"analyzed": true, "analyzed_option_present": true}},
                "analyzers": {{"rows": [], "total": 0, "truncated": false}},
                "bookmarks": {{"rows": [], "total": 0, "truncated": false}},
                "calling_conventions": [],
                "class_members": {{"rows": [], "total": 0, "truncated": false}},
                "code_gaps": {gaps},
                "comments": {{"rows": [], "total": 0, "truncated": false}},
                "data_items": {{"rows": [], "total": 0, "truncated": false}},
                "entry_points": {{"rows": [], "total": 0, "truncated": false}},
                "external_locations": {{"rows": [], "total": 0, "truncated": false}},
                "function_docs": {docs},
                "function_tags": {{"rows": [{{"comment": "", "name": "CRYPTO", "use_count": 1}}],
                    "total": 1, "truncated": false}},
                "namespaces": {{"rows": [], "total": 0, "truncated": false}},
                "option_groups": {{"rows": [], "total": 0, "truncated": false}},
                "options": {{"rows": [], "total": 0, "truncated": false}},
                "project": {{"available": true, "name": "fathom", "program_path": "/sample",
                    "files": {{"rows": [], "total": 0, "truncated": false}},
                    "folders": {{"rows": [], "total": 0, "truncated": false}}}},
                "properties": {{"rows": [], "total": 0, "truncated": false}},
                "property_maps": {{"rows": [], "total": 0, "truncated": false}}}}"#
            ),
        )
    }

    const DOCS: &str = r#"{"rows": [
        {"address": "00101000", "body_size": 10, "classification": "defined",
         "comment_addresses": 0, "default_named_parameters": 1, "local_count": 0,
         "name": "FUN_00101000", "name_source": "DEFAULT", "parameter_count": 1,
         "plate_comment": false, "repeatable_comment": false, "return_type": "undefined",
         "signature": "undefined FUN_00101000(undefined8 param_1)",
         "signature_source": "DEFAULT", "tags": ["CRYPTO"], "undefined_typed_variables": 1}],
        "total": 1, "truncated": false}"#;

    const GAPS: &str = r#"{"rows": [
        {"start": "00101100", "end": "0010110f", "size": 16, "first_instruction": "",
         "first_non_padding": "", "has_defined_data": true, "has_instructions": false},
        {"start": "00101180", "end": "0010118f", "size": 16, "first_instruction": "00101180",
         "first_non_padding": "", "has_defined_data": false, "has_instructions": true},
        {"start": "00101200", "end": "0010121f", "size": 32, "first_instruction": "00101200",
         "first_non_padding": "00101204", "has_defined_data": false, "has_instructions": true}],
        "total": 3, "truncated": false}"#;

    #[test]
    fn validation_next_undefined_function_skips_data_and_padding_gaps() {
        let export = program(GAPS, DOCS);
        let value = next_undefined_evidence(subject(), &export, None).unwrap();
        assert_eq!(value["findings"][0]["facts"]["address"], "00101204");
        assert_eq!(
            value["findings"][0]["facts"]["padding_only_gaps_skipped"],
            1
        );
        let value = next_undefined_evidence(subject(), &export, Some("101300")).unwrap();
        assert_eq!(value["findings"][0]["facts"]["found"], false);
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn adversarial_truncated_gap_inventory_is_not_reported_as_absence() {
        let truncated = r#"{"rows": [], "total": 9, "truncated": true}"#;
        let export = program(truncated, DOCS);
        let value = next_undefined_evidence(subject(), &export, None).unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_tags_by_function_and_by_name() {
        let export = program(GAPS, DOCS);
        let value = function_tags_evidence(subject(), &export, "0x101000").unwrap();
        assert_eq!(value["findings"][0]["facts"]["tags"][0], "CRYPTO");
        let value = tag_search_evidence(subject(), &export, "CRYPTO", page()).unwrap();
        assert_eq!(value["findings"][0]["facts"]["matched"], 1);
        let value = tag_search_evidence(subject(), &export, "crypto", page()).unwrap();
        assert_eq!(value["findings"][0]["facts"]["matched"], 0);
    }
}
