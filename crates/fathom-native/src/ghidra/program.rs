//! Program, project & session family (fathom Ghidra G1): program
//! options and analyzers, comments and bookmarks, entry points,
//! externals, namespaces and classes, data items, user property
//! maps, and fathom's own per-subject Ghidra project cache.
//!
//! Upstream's session tools assume one long-lived Ghidra instance
//! with open programs. Fathom is stateless per call (SPEC §4): the
//! "project" a tool reports is the per-subject project fathom
//! caches under its state dir (SPEC §9.1). `list_open_programs` is
//! registered not-implemented for exactly that reason.

use serde_json::{Value, json};
use std::fs;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject, sha256_hex, subject_for_file};
use fathom_core::limits::FILE_COUNT_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::engine::{self, Export};
use crate::ghidra::base;
use crate::ghidra::query::{self, Listing, Page, address_row, address_usable};
use crate::sections::{AddressFacts, Bounded, ProgramFacts};

/// Comment types Ghidra stores, as the export names them.
const COMMENT_TYPES: &[&str] = &["eol", "plate", "post", "pre", "repeatable"];

/// Bytes of one script file hashed by `list_scripts`.
const SCRIPT_BYTES_MAX: u64 = 4 * 1_048_576;

fn facts(export: &Export) -> Result<&ProgramFacts, FathomError> {
    query::section(&export.program_facts, "program_facts")
}

/// One filtered, paged listing over a program-facts section.
fn listing<T>(
    evidence: &mut Evidence,
    section: &Bounded<T>,
    name: &str,
    kind: &str,
    page: Page,
    keep: impl Fn(&T) -> bool,
    row: impl Fn(&T) -> Value,
) -> Result<(), FathomError> {
    section.check(name)?;
    Listing {
        confidence: Confidence::Observed,
        key: kind,
        kind,
        partial: section.is_partial(),
        retained: section.rows.len(),
        rows: section.rows.iter().filter(|r| keep(r)).map(row).collect(),
        total: section.total,
    }
    .into_evidence(evidence, page);
    Ok(())
}

/// Run the program mode for a listing tool and hand back the
/// evidence shell plus the facts.
fn program_run(
    tool: &str,
    config: &Config,
    args: &Value,
) -> Result<(Evidence, Export), FathomError> {
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    Ok((base(tool, subject), export))
}

pub fn analysis_status(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    analysis_status_evidence(subject, &export)
}

fn analysis_status_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("analysis_status", subject);
    let facts = facts(export)?;
    facts.analyzers.check("program_facts.analyzers")?;
    let enabled = facts.analyzers.rows.iter().filter(|a| a.enabled).count();
    let mut finding = Finding::new(
        "analysis",
        Confidence::Observed,
        json!({
            "analyzed": facts.analysis.analyzed,
            "analyzed_option_present": facts.analysis.analyzed_option_present,
            "analyzers_enabled": enabled,
            "analyzers_total": facts.analyzers.total,
        }),
    )
    .with_limitation(
        "fathom runs Ghidra auto-analysis once, at first import of a subject; later \
         calls re-open the cached project with -noanalysis, so this state does not change \
         between calls",
    );
    if !facts.analysis.analyzed_option_present {
        finding = finding.with_limitation(
            "the program records no 'Analyzed' option; 'analyzed' is Ghidra's default (false)",
        );
    }
    evidence.add_finding(finding);
    query::cover(
        &mut evidence,
        facts.analyzers.rows.len(),
        facts.analyzers.total,
        facts.analyzers.is_partial(),
    );
    Ok(evidence.to_value())
}

pub fn get_comment(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let address = query::parse_address(require_str(args, "address")?)?;
    let kind = comment_type(query::optional_text(args, "type")?)?;
    let (subject, export) = query::run_mode(config, args, "addresses", Some(&address))?;
    comment_evidence("get_comment", subject, &export, &address, kind)
}

fn comment_type(kind: Option<&str>) -> Result<Option<&str>, FathomError> {
    match kind {
        Some(kind) if !COMMENT_TYPES.contains(&kind) => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "comment type {kind:?} is not one of {}",
                COMMENT_TYPES.join(", ")
            ),
        )),
        other => Ok(other),
    }
}

fn comment_evidence(
    tool: &str,
    subject: Subject,
    export: &Export,
    canonical: &str,
    kind: Option<&str>,
) -> Result<Value, FathomError> {
    let mut evidence = base(tool, subject);
    let row = address_row(export, canonical)?;
    if !address_usable(&mut evidence, row) {
        return Ok(evidence.to_value());
    }
    unit_start_note(&mut evidence, row);
    let comments: Vec<Value> = row
        .comments
        .iter()
        .filter(|c| kind.is_none_or(|k| c.kind == k))
        .map(|c| json!({"text": c.text, "text_truncated": c.text_truncated, "type": c.kind}))
        .collect();
    let truncated = row
        .comments
        .iter()
        .any(|c| c.text_truncated && kind.is_none_or(|k| c.kind == k));
    let mut finding = Finding::new(
        "comments",
        Confidence::Observed,
        json!({"address": row.address, "comments": comments, "type": kind}),
    )
    .with_location(row.address.clone());
    if truncated {
        finding = finding.with_limitation("comment text truncated at 2,000 characters");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

/// Ghidra stores comments at code-unit starts.
fn unit_start_note(evidence: &mut Evidence, row: &AddressFacts) {
    if let Some(unit) = &row.code_unit
        && !query::same_address(&unit.start, &row.address)
    {
        evidence.add_unknown(
            "code_unit_start",
            format!(
                "address {} lies inside the {} starting at {}; comments are stored at \
                 code-unit starts — query {} for that unit's comments",
                row.address, unit.kind, unit.start, unit.start
            ),
        );
    }
}

pub fn get_plate_comment(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let address = query::optional_text(args, "address")?;
    let function = query::optional_text(args, "function")?;
    match (address, function) {
        (Some(address), None) => {
            let canonical = query::parse_address(address)?;
            let (subject, export) = query::run_mode(config, args, "addresses", Some(&canonical))?;
            comment_evidence(
                "get_plate_comment",
                subject,
                &export,
                &canonical,
                Some("plate"),
            )
        }
        (None, Some(function)) => {
            let (subject, export) = query::run_mode(config, args, "detail", Some(function))?;
            function_plate_evidence(subject, &export)
        }
        _ => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "give exactly one of 'address' or 'function'",
        )),
    }
}

fn function_plate_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("get_plate_comment", subject);
    let Some(detail) = query::found_detail(&mut evidence, export)? else {
        return Ok(evidence.to_value());
    };
    let function = query::section(&detail.function, "detail.function")?;
    let comment = (!detail.plate_comment.is_empty()).then_some(detail.plate_comment.as_str());
    let mut finding = Finding::new(
        "plate_comment",
        Confidence::Observed,
        json!({
            "address": function.address,
            "function": function.name,
            "plate_comment": comment,
        }),
    )
    .with_location(function.address.clone())
    .with_limitation(
        "stored plate comment only; the banner Ghidra renders for an uncommented \
         function is generated display, not a stored comment",
    );
    if detail.plate_comment_truncated {
        finding = finding.with_limitation("comment text truncated at 2,000 characters");
    }
    evidence.add_finding(finding);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

pub fn get_entry_points(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("get_entry_points", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.entry_points,
        "program_facts.entry_points",
        "entry_points",
        page,
        |_| true,
        |e| json!({"address": e.address, "is_function": e.is_function, "name": e.name}),
    )?;
    Ok(evidence.to_value())
}

pub fn get_external_location(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let name = query::optional_text(args, "name")?;
    let address = query::optional_text(args, "address")?;
    if name.is_some() == address.is_some() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "give exactly one of 'name' or 'address'",
        ));
    }
    let address = address.map(query::parse_address).transpose()?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    external_evidence(subject, &export, name, address.as_deref())
}

fn external_evidence(
    subject: Subject,
    export: &Export,
    name: Option<&str>,
    address: Option<&str>,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_external_location", subject);
    let externals = &facts(export)?.external_locations;
    externals.check("program_facts.external_locations")?;
    let matches: Vec<Value> = externals
        .rows
        .iter()
        .filter(|e| match (name, address) {
            (Some(name), _) => e.label == name || e.original_name == name,
            (None, Some(address)) => {
                query::same_address(&e.address, address)
                    || query::same_address(&e.external_address, address)
            }
            (None, None) => false,
        })
        .map(|e| {
            json!({
                "address": e.address, "external_address": e.external_address,
                "is_function": e.is_function, "label": e.label, "library": e.library,
                "library_path": e.library_path, "original_name": e.original_name,
                "source": e.source,
            })
        })
        .collect();
    if matches.is_empty() && externals.is_partial() {
        evidence.add_unknown(
            "external_location",
            "no retained external location matches; the inventory was truncated",
        );
    } else {
        evidence.add_finding(Finding::new(
            "external_locations",
            Confidence::Observed,
            json!({"address": address, "matches": matches, "name": name}),
        ));
    }
    query::cover(
        &mut evidence,
        externals.rows.len(),
        externals.total,
        externals.is_partial(),
    );
    Ok(evidence.to_value())
}

pub fn get_program_options(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let group = query::optional_text(args, "group")?;
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("get_program_options", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.options,
        "program_facts.options",
        "options",
        page,
        |o| group.is_none_or(|g| o.group == g),
        |o| {
            json!({
                "group": o.group, "is_default": o.is_default, "name": o.name,
                "type": o.kind, "value": o.value, "value_readable": o.value_readable,
            })
        },
    )?;
    Ok(evidence.to_value())
}

pub fn get_project_info(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    project_cache_evidence(config, subject)
}

/// What fathom's state dir holds for one subject. No engine runs.
fn project_cache_evidence(config: &Config, subject: Subject) -> Result<Value, FathomError> {
    let cache_dir = engine::cache_dir_for(config, &subject.sha256);
    let mut evidence = base("get_project_info", subject);
    let present = cache_dir.is_dir();
    let mut exports = Vec::new();
    if present {
        let entries = fs::read_dir(&cache_dir).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot read the subject cache dir: {e}"),
            )
        })?;
        for entry in entries.flatten().take(FILE_COUNT_MAX) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(key) = name
                .strip_prefix("export-")
                .and_then(|n| n.strip_suffix(".json"))
            {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                exports.push(json!({"key": key, "size_bytes": size}));
            }
        }
        exports.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    }
    let project = cache_dir.join("project").join("fathom.gpr");
    evidence.add_finding(
        Finding::new(
            "project_cache",
            Confidence::Observed,
            json!({
                "cache_dir": cache_dir.display().to_string(),
                "cache_present": present,
                "cached_exports": exports,
                "project_name": "fathom",
                "project_present": project.is_file(),
            }),
        )
        .with_limitation(
            "fathom's per-subject Ghidra project cache (SPEC §9.1), read from the state \
             dir; no engine ran. project_info reports the project as Ghidra sees it",
        ),
    );
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

pub fn get_property(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let map = query::require_text(args, "map")?;
    let address = query::parse_address(require_str(args, "address")?)?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    property_evidence(subject, &export, map, &address)
}

fn property_evidence(
    subject: Subject,
    export: &Export,
    map: &str,
    address: &str,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_property", subject);
    let facts = facts(export)?;
    facts.property_maps.check("program_facts.property_maps")?;
    facts.properties.check("program_facts.properties")?;
    if !facts.property_maps.rows.iter().any(|m| m.name == map) {
        if facts.property_maps.is_partial() {
            evidence.add_unknown("property_map", "the property-map list was truncated");
        } else {
            evidence.add_unknown(
                "property_map",
                format!("the program has no user property map named '{map}'"),
            );
        }
        return Ok(evidence.to_value());
    }
    let value = facts
        .properties
        .rows
        .iter()
        .find(|p| p.map == map && query::same_address(&p.address, address));
    match value {
        Some(row) => evidence.add_finding(
            Finding::new(
                "property",
                Confidence::Observed,
                json!({"address": row.address, "map": map, "value": row.value}),
            )
            .with_location(row.address.clone()),
        ),
        None if facts.properties.is_partial() => evidence.add_unknown(
            "property",
            "no retained entry; the property inventory was truncated",
        ),
        None => evidence.add_finding(Finding::new(
            "property",
            Confidence::Observed,
            json!({"address": address, "map": map, "value": null}),
        )),
    }
    Ok(evidence.to_value())
}

pub fn list_analyzers(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_analyzers", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.analyzers,
        "program_facts.analyzers",
        "analyzers",
        page,
        |_| true,
        |a| json!({"enabled": a.enabled, "is_default": a.is_default, "name": a.name}),
    )?;
    Ok(evidence.to_value())
}

pub fn list_bookmarks(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let kind = query::optional_text(args, "type")?;
    let category = query::optional_text(args, "category")?;
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_bookmarks", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.bookmarks,
        "program_facts.bookmarks",
        "bookmarks",
        page,
        |b| kind.is_none_or(|k| b.kind == k) && category.is_none_or(|c| b.category == c),
        |b| {
            json!({
                "address": b.address, "category": b.category, "comment": b.comment,
                "type": b.kind,
            })
        },
    )?;
    Ok(evidence.to_value())
}

pub fn list_calling_conventions(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let (mut evidence, export) = program_run("list_calling_conventions", config, args)?;
    let conventions = &facts(&export)?.calling_conventions;
    evidence.add_finding(Finding::new(
        "calling_conventions",
        Confidence::Observed,
        json!({
            "conventions": conventions.iter()
                .map(|c| json!({"is_default": c.is_default, "name": c.name}))
                .collect::<Vec<_>>(),
            "default": conventions.iter().find(|c| c.is_default).map(|c| c.name.as_str()),
        }),
    ));
    query::cover(
        &mut evidence,
        conventions.len(),
        conventions.len() as u64,
        false,
    );
    Ok(evidence.to_value())
}

pub fn list_class_members(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let class = query::require_text(args, "class")?;
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    class_members_evidence(subject, &export, class, page)
}

fn class_members_evidence(
    subject: Subject,
    export: &Export,
    class: &str,
    page: Page,
) -> Result<Value, FathomError> {
    let mut evidence = base("list_class_members", subject);
    let facts = facts(export)?;
    facts.namespaces.check("program_facts.namespaces")?;
    let suffix = format!("::{class}");
    let classes: Vec<&str> = facts
        .namespaces
        .rows
        .iter()
        .filter(|n| n.kind == "Class" && (n.full_name == class || n.full_name.ends_with(&suffix)))
        .map(|n| n.full_name.as_str())
        .collect();
    let chosen = match classes.as_slice() {
        [one] => *one,
        [] => {
            evidence.add_unknown(
                "class",
                if facts.namespaces.is_partial() {
                    format!("no retained class matches '{class}'; the namespace list was truncated")
                } else {
                    format!("the program defines no class named '{class}'")
                },
            );
            return Ok(evidence.to_value());
        }
        many => {
            evidence.add_unknown(
                "class",
                format!(
                    "'{class}' names several classes: {}; re-run with a full name",
                    many.join(", ")
                ),
            );
            return Ok(evidence.to_value());
        }
    };
    listing(
        &mut evidence,
        &facts.class_members,
        "program_facts.class_members",
        "members",
        page,
        |m| m.class == chosen,
        |m| {
            json!({
                "address": m.address, "class": m.class, "name": m.name, "source": m.source,
                "type": m.kind,
            })
        },
    )?;
    Ok(evidence.to_value())
}

pub fn list_classes(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    namespace_listing("list_classes", config, args, Some("Class"))
}

pub fn list_namespaces(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    namespace_listing("list_namespaces", config, args, None)
}

fn namespace_listing(
    tool: &str,
    config: &Config,
    args: &Value,
    only: Option<&str>,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (mut evidence, export) = program_run(tool, config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.namespaces,
        "program_facts.namespaces",
        if only.is_some() {
            "classes"
        } else {
            "namespaces"
        },
        page,
        |n| only.is_none_or(|k| n.kind == k),
        |n| {
            json!({
                "full_name": n.full_name, "member_count": n.member_count, "name": n.name,
                "parent": n.parent, "type": n.kind,
            })
        },
    )?;
    Ok(evidence.to_value())
}

pub fn list_data_items(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    data_items_evidence("list_data_items", subject, &export, page, false)
}

pub fn list_data_items_by_xrefs(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    data_items_evidence("list_data_items_by_xrefs", subject, &export, page, true)
}

fn data_items_evidence(
    tool: &str,
    subject: Subject,
    export: &Export,
    page: Page,
    by_xrefs: bool,
) -> Result<Value, FathomError> {
    let mut evidence = base(tool, subject);
    let items = &facts(export)?.data_items;
    items.check("program_facts.data_items")?;
    let mut ordered: Vec<_> = items.rows.iter().collect();
    if by_xrefs {
        // Most-referenced first; address breaks ties deterministically.
        ordered.sort_by(|a, b| {
            b.references_to
                .cmp(&a.references_to)
                .then_with(|| query::address_key(&a.address).cmp(&query::address_key(&b.address)))
        });
    }
    Listing {
        confidence: Confidence::Observed,
        key: "data_items",
        kind: "data_items",
        partial: items.is_partial(),
        retained: items.rows.len(),
        rows: ordered
            .iter()
            .map(|d| {
                json!({
                    "address": d.address, "label": d.label, "length": d.length,
                    "references_to": d.references_to, "type": d.kind, "value": d.value,
                })
            })
            .collect(),
        total: items.total,
    }
    .into_evidence(&mut evidence, page);
    if by_xrefs && items.is_partial() {
        evidence.add_unknown(
            "ordering",
            "the ranking covers only the data items the export retained",
        );
    }
    Ok(evidence.to_value())
}

pub fn list_external_locations(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let library = query::optional_text(args, "library")?;
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_external_locations", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.external_locations,
        "program_facts.external_locations",
        "external_locations",
        page,
        |e| library.is_none_or(|l| e.library == l),
        |e| {
            json!({
                "address": e.address, "external_address": e.external_address,
                "is_function": e.is_function, "label": e.label, "library": e.library,
                "original_name": e.original_name,
            })
        },
    )?;
    Ok(evidence.to_value())
}

pub fn list_option_groups(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_option_groups", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.option_groups,
        "program_facts.option_groups",
        "option_groups",
        page,
        |_| true,
        |g| json!({"name": g.name, "option_count": g.option_count}),
    )?;
    Ok(evidence.to_value())
}

pub fn list_project_files(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_project_files", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.project.files,
        "program_facts.project.files",
        "files",
        page,
        |_| true,
        |f| {
            json!({
                "content_type": f.content_type, "path": f.path, "read_only": f.read_only,
                "version": f.version,
            })
        },
    )?;
    Ok(evidence.to_value())
}

pub fn list_projects(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    projects_evidence(config, page)
}

/// Enumerate fathom's per-subject project caches. Entries are named
/// by subject-digest prefix only: no target path is stored or shown.
/// Symlinked entries are skipped and counted, never followed.
fn projects_evidence(config: &Config, page: Page) -> Result<Value, FathomError> {
    let mut evidence = Evidence::new("list_projects", "ghidra");
    let root = config.state_dir.join("ghidra");
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    let mut capped = false;
    if root.is_dir() {
        let entries = fs::read_dir(&root).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot read the Ghidra state dir: {e}"),
            )
        })?;
        for (index, entry) in entries.flatten().enumerate() {
            if index >= FILE_COUNT_MAX {
                capped = true;
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir || name.len() != 32 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                skipped += 1;
                continue;
            }
            let dir = entry.path();
            let exports = fs::read_dir(&dir)
                .map(|it| {
                    it.flatten()
                        .filter(|e| {
                            let n = e.file_name();
                            let n = n.to_string_lossy();
                            n.starts_with("export-") && n.ends_with(".json")
                        })
                        .count()
                })
                .unwrap_or(0);
            rows.push(json!({
                "cache_key": name,
                "cached_exports": exports,
                "project_present": dir.join("project").join("fathom.gpr").is_file(),
            }));
        }
    }
    rows.sort_by(|a, b| a["cache_key"].as_str().cmp(&b["cache_key"].as_str()));
    let count = rows.len();
    Listing {
        confidence: Confidence::Observed,
        key: "projects",
        kind: "projects",
        partial: capped,
        retained: count,
        rows,
        total: count as u64,
    }
    .into_evidence(&mut evidence, page);
    if let Some(finding) = evidence.findings.last_mut() {
        *finding = finding.clone().with_limitation(format!(
            "fathom's per-subject Ghidra projects under {} (one per subject SHA-256 \
             prefix); {skipped} non-cache entries skipped",
            root.display()
        ));
    }
    if capped {
        evidence.add_unknown(
            "projects",
            "the state dir listing stopped at the entry bound",
        );
    }
    Ok(evidence.to_value())
}

pub fn list_properties(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let map = query::optional_text(args, "map")?;
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_properties", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.properties,
        "program_facts.properties",
        "properties",
        page,
        |p| map.is_none_or(|m| p.map == m),
        |p| json!({"address": p.address, "map": p.map, "value": p.value}),
    )?;
    Ok(evidence.to_value())
}

pub fn list_property_maps(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (mut evidence, export) = program_run("list_property_maps", config, args)?;
    listing(
        &mut evidence,
        &facts(&export)?.property_maps,
        "program_facts.property_maps",
        "property_maps",
        page,
        |_| true,
        |m| json!({"name": m.name, "size": m.size, "value_class": m.value_class}),
    )?;
    Ok(evidence.to_value())
}

pub fn list_scripts(_: &Registry, _: &Config, _: &Value) -> Result<Value, FathomError> {
    let dir = engine::locate_script_dir()?;
    scripts_evidence(&dir)
}

/// The scripts in the provider's script dir. The engine runs only
/// FathomExportAnalysis.java; others are listed, never executed.
fn scripts_evidence(dir: &Path) -> Result<Value, FathomError> {
    let mut evidence = Evidence::new("list_scripts", "ghidra");
    let entries = fs::read_dir(dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ProviderUnavailable,
            format!("cannot read the script dir: {e}"),
        )
    })?;
    let mut rows = Vec::new();
    for entry in entries.flatten().take(FILE_COUNT_MAX) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_file() || !name.ends_with(".java") {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let sha256 = if size <= SCRIPT_BYTES_MAX {
            fs::read(entry.path()).ok().map(|bytes| sha256_hex(&bytes))
        } else {
            None
        };
        rows.push(json!({
            "name": name,
            "run_by_fathom": name == "FathomExportAnalysis.java",
            "sha256": sha256,
            "size_bytes": size,
        }));
    }
    rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let count = rows.len() as u64;
    evidence.add_finding(
        Finding::new(
            "scripts",
            Confidence::Observed,
            json!({"dir": dir.display().to_string(), "scripts": rows}),
        )
        .with_limitation(
            "fathom's provider script dir; the engine runs only FathomExportAnalysis.java \
             as a post-script. Ghidra's own bundled script library is not listed",
        ),
    );
    evidence.coverage.examined = count;
    evidence.coverage.total = count;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

pub fn project_info(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let (subject, export) = query::run_mode(config, args, "program", None)?;
    project_info_evidence(subject, &export)
}

fn project_info_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("project_info", subject);
    let project = &facts(export)?.project;
    project.files.check("program_facts.project.files")?;
    project.folders.check("program_facts.project.folders")?;
    if !project.available {
        evidence.add_unknown("project", "the export script saw no active Ghidra project");
        return Ok(evidence.to_value());
    }
    evidence.add_finding(Finding::new(
        "project",
        Confidence::Observed,
        json!({
            "file_count": project.files.total,
            "folder_count": project.folders.total,
            "folders": project.folders.rows.iter().map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            "name": project.name,
            "program_path": project.program_path,
        }),
    ));
    query::cover(
        &mut evidence,
        project.files.rows.len() + project.folders.rows.len(),
        project.files.total + project.folders.total,
        project.files.is_partial() || project.folders.is_partial(),
    );
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::query::PAGE_ROWS_DEFAULT;
    use crate::ghidra::query::tests::{export, program_facts, subject};
    use fathom_core::config::ConfigFile;

    fn page() -> Page {
        Page {
            limit: PAGE_ROWS_DEFAULT,
            offset: 0,
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fathom-native-program-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validation_analysis_status_reports_flag_and_analyzers() {
        let export = program_facts(&[(
            "analyzers",
            r#"{"rows": [{"enabled": true, "is_default": true, "name": "Stack"},
                {"enabled": false, "is_default": false, "name": "Aggressive"}],
                "total": 2, "truncated": false}"#,
        )]);
        let value = analysis_status_evidence(subject(), &export).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["analyzed"], true);
        assert_eq!(facts["analyzers_enabled"], 1);
    }

    const COMMENTS: &str = r#""addresses": [
        {"query": "101000", "valid": true, "address": "00101000", "in_memory": true,
         "code_unit": {"kind": "instruction", "length": 4, "start": "00101000", "text": "NOP"},
         "comments": [{"text": "entry banner", "text_truncated": false, "type": "plate"},
                      {"text": "eol note", "text_truncated": true, "type": "eol"}]},
        {"query": "101002", "valid": true, "address": "00101002", "in_memory": true,
         "code_unit": {"kind": "instruction", "length": 4, "start": "00101000", "text": "NOP"},
         "comments": []}]"#;

    #[test]
    fn validation_comments_filter_by_type() {
        let export = export("addresses", COMMENTS);
        let value =
            comment_evidence("get_comment", subject(), &export, "101000", Some("eol")).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["comments"].as_array().unwrap().len(), 1);
        assert_eq!(facts["comments"][0]["text"], "eol note");
        assert!(
            !value["findings"][0]["limitations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let value = comment_evidence(
            "get_plate_comment",
            subject(),
            &export,
            "101000",
            Some("plate"),
        )
        .unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["comments"][0]["text"],
            "entry banner"
        );
    }

    #[test]
    fn adversarial_comment_inside_a_code_unit_is_flagged() {
        let export = export("addresses", COMMENTS);
        let value = comment_evidence("get_comment", subject(), &export, "101002", None).unwrap();
        assert_eq!(value["unknowns"][0]["aspect"], "code_unit_start");
        assert!(comment_type(Some("margin")).is_err());
    }

    #[test]
    fn validation_function_plate_comment_and_truncation_flag() {
        let export = export(
            "detail",
            r#""detail": {"query": "main", "found": true, "match": "exact", "candidates": [],
                "function": {"address": "00101000", "name": "main", "signature": "int main(void)",
                "body_size": 4, "classification": "defined", "calling_convention": "c"},
                "plate_comment": "Program entry.", "plate_comment_truncated": true}"#,
        );
        let value = function_plate_evidence(subject(), &export).unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["plate_comment"],
            "Program entry."
        );
        assert_eq!(
            value["findings"][0]["limitations"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    const EXTERNALS: &str = r#"{"rows": [
        {"address": "", "external_address": "EXTERNAL:00000010", "is_function": true,
         "label": "puts", "library": "libc.so.6", "library_path": "", "original_name": "",
         "source": "IMPORTED"}], "total": 1, "truncated": false}"#;

    #[test]
    fn validation_external_location_by_name_and_address() {
        let export = program_facts(&[("external_locations", EXTERNALS)]);
        let value = external_evidence(subject(), &export, Some("puts"), None).unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["matches"][0]["library"],
            "libc.so.6"
        );
        let value = external_evidence(subject(), &export, Some("gets"), None).unwrap();
        assert!(
            value["findings"][0]["facts"]["matches"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn adversarial_truncated_externals_never_claim_absence() {
        let truncated = EXTERNALS.replace(
            r#""total": 1, "truncated": false"#,
            r#""total": 7, "truncated": true"#,
        );
        let export = program_facts(&[("external_locations", &truncated)]);
        let value = external_evidence(subject(), &export, Some("gets"), None).unwrap();
        assert_eq!(value["status"], "partial");
    }

    #[test]
    fn validation_class_members_resolve_short_names() {
        let export = program_facts(&[
            (
                "namespaces",
                r#"{"rows": [{"full_name": "app::Widget", "member_count": 1, "name": "Widget",
                    "parent": "app", "type": "Class"},
                    {"full_name": "other::Widget", "member_count": 0, "name": "Widget",
                    "parent": "other", "type": "Class"}], "total": 2, "truncated": false}"#,
            ),
            (
                "class_members",
                r#"{"rows": [{"address": "00101000", "class": "app::Widget", "name": "draw",
                    "source": "IMPORTED", "type": "Function"}], "total": 1, "truncated": false}"#,
            ),
        ]);
        let value = class_members_evidence(subject(), &export, "app::Widget", page()).unwrap();
        assert_eq!(value["findings"][0]["facts"]["members"][0]["name"], "draw");
        // "Widget" alone names two classes: ambiguity, not a guess.
        let value = class_members_evidence(subject(), &export, "Widget", page()).unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_data_items_rank_by_references() {
        let export = program_facts(&[(
            "data_items",
            r#"{"rows": [
                {"address": "00102000", "label": "a", "length": 4, "references_to": 1,
                 "type": "dword", "value": "1h"},
                {"address": "00102010", "label": "b", "length": 4, "references_to": 9,
                 "type": "dword", "value": "2h"},
                {"address": "00102008", "label": "c", "length": 4, "references_to": 1,
                 "type": "dword", "value": "3h"}], "total": 3, "truncated": false}"#,
        )]);
        let value =
            data_items_evidence("list_data_items_by_xrefs", subject(), &export, page(), true)
                .unwrap();
        let rows = value["findings"][0]["facts"]["data_items"]
            .as_array()
            .unwrap();
        let labels: Vec<&str> = rows.iter().map(|r| r["label"].as_str().unwrap()).collect();
        assert_eq!(labels, vec!["b", "a", "c"]);
    }

    #[test]
    fn validation_property_lookup_and_missing_map() {
        let export = program_facts(&[
            (
                "property_maps",
                r#"{"rows": [{"name": "notes", "size": 1, "value_class": "String"}],
                    "total": 1, "truncated": false}"#,
            ),
            (
                "properties",
                r#"{"rows": [{"address": "00101000", "map": "notes", "value": "hot"}],
                    "total": 1, "truncated": false}"#,
            ),
        ]);
        let value = property_evidence(subject(), &export, "notes", "101000").unwrap();
        assert_eq!(value["findings"][0]["facts"]["value"], "hot");
        let value = property_evidence(subject(), &export, "notes", "101004").unwrap();
        assert!(value["findings"][0]["facts"]["value"].is_null());
        let value = property_evidence(subject(), &export, "absent", "101000").unwrap();
        assert_eq!(value["status"], "partial");
    }

    #[test]
    fn validation_project_info_reports_ghidra_project() {
        let export = program_facts(&[]);
        let value = project_info_evidence(subject(), &export).unwrap();
        assert_eq!(value["findings"][0]["facts"]["name"], "fathom");
        assert_eq!(value["findings"][0]["facts"]["program_path"], "/sample");
    }

    fn state_config(state: &Path) -> Config {
        let mut config = Config::from_file_form(ConfigFile::default()).unwrap();
        config.state_dir = state.to_path_buf();
        config
    }

    #[test]
    fn validation_project_cache_reflects_the_state_dir() {
        let state = scratch("cache");
        let config = state_config(&state);
        let subject = subject();
        let dir = engine::cache_dir_for(&config, &subject.sha256);
        fs::create_dir_all(dir.join("project")).unwrap();
        fs::write(dir.join("project").join("fathom.gpr"), b"").unwrap();
        fs::write(dir.join("export-program-sabc.json"), b"{}").unwrap();
        let value = project_cache_evidence(&config, subject).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["project_present"], true);
        assert_eq!(facts["cached_exports"][0]["key"], "program-sabc");
        let _ = fs::remove_dir_all(&state);
    }

    #[cfg(unix)]
    #[test]
    fn adversarial_projects_listing_skips_symlinks_and_junk() {
        let state = scratch("projects");
        let outside = scratch("projects-outside");
        let root = state.join("ghidra");
        fs::create_dir_all(
            root.join("0123456789abcdef0123456789abcdef")
                .join("project"),
        )
        .unwrap();
        fs::write(root.join("notes.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("fedcba9876543210fedcba9876543210"))
            .unwrap();
        let value = projects_evidence(&state_config(&state), page()).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["matched"], 1);
        assert_eq!(facts["projects"][0]["project_present"], false);
        let limitation = value["findings"][0]["limitations"][0].as_str().unwrap();
        assert!(limitation.contains("2 non-cache entries skipped"));
        let _ = fs::remove_dir_all(&state);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn validation_scripts_listing_marks_the_one_fathom_runs() {
        let dir = scratch("scripts");
        fs::write(dir.join("FathomExportAnalysis.java"), b"class A {}").unwrap();
        fs::write(dir.join("Other.java"), b"class B {}").unwrap();
        fs::write(dir.join("README"), b"x").unwrap();
        let value = scripts_evidence(&dir).unwrap();
        let scripts = value["findings"][0]["facts"]["scripts"].as_array().unwrap();
        assert_eq!(scripts.len(), 2);
        assert_eq!(scripts[0]["run_by_fathom"], true);
        assert_eq!(scripts[0]["sha256"], sha256_hex(b"class A {}"));
        let _ = fs::remove_dir_all(&dir);
    }
}
