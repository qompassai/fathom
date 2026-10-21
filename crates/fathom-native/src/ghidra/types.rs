//! Data types family (fathom Ghidra G1): the program's data type
//! manager and Ghidra's built-ins, read through the `types` export
//! mode. Type expressions (`char *`, `uint[16]`) and prototypes are
//! parsed by a small fathom grammar stated in [`parse_type`] — not
//! by Ghidra's C parser — so every size computed from one is
//! `derived`, with the rule attached.

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::FathomError;
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject};
use fathom_core::registry::Registry;

use crate::engine::Export;
use crate::ghidra::base;
use crate::ghidra::query::{self, Listing, Page};
use crate::sections::{DataTypeRow, Types};

/// Array dimensions one type expression may carry.
const ARRAY_DIMENSIONS_MAX: usize = 8;

/// Pointer levels one type expression may carry.
const POINTER_LEVELS_MAX: usize = 8;

/// Parameters one prototype may declare.
const PROTOTYPE_PARAMETERS_MAX: usize = 64;

/// Components a struct-layout result lists at most.
const LAYOUT_COMPONENTS_MAX: usize = 512;

/// The grammar every type-expression tool applies, as reported.
const TYPE_GRAMMAR: &str = "fathom type-expression grammar: optional const/volatile/\
    struct/union/enum keywords (ignored), a base type name or /category/path, then \
    '*' pointer levels, then [N] array dimensions; C multi-word integer names map to \
    Ghidra built-ins (unsigned int -> uint, long long -> longlong, ...); function-\
    pointer declarators are not parsed";

/// C multi-word spellings and their Ghidra built-in names.
const C_ALIASES: &[(&str, &str)] = &[
    ("long long", "longlong"),
    ("long long int", "longlong"),
    ("signed char", "schar"),
    ("unsigned", "uint"),
    ("unsigned char", "uchar"),
    ("unsigned int", "uint"),
    ("unsigned long", "ulong"),
    ("unsigned long long", "ulonglong"),
    ("unsigned short", "ushort"),
];

/// A parsed type expression.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TypeExpr {
    pub base: String,
    pub dimensions: Vec<u64>,
    pub pointers: usize,
}

/// Parse a type expression under [`TYPE_GRAMMAR`].
pub(crate) fn parse_type(text: &str) -> Result<TypeExpr, String> {
    if text.contains('(') || text.contains(')') {
        return Err("function-pointer declarators are not parsed".to_string());
    }
    let (head, dims_text) = match text.find('[') {
        Some(index) => text.split_at(index),
        None => (text, ""),
    };
    let mut dimensions = Vec::new();
    let mut rest = dims_text.trim();
    while !rest.is_empty() {
        let Some(inner) = rest.strip_prefix('[') else {
            return Err(format!("unexpected text after array dimensions: {rest:?}"));
        };
        let Some(close) = inner.find(']') else {
            return Err("unterminated array dimension".to_string());
        };
        let count: u64 = inner[..close]
            .trim()
            .parse()
            .map_err(|_| format!("array dimension {:?} is not a count", &inner[..close]))?;
        if count == 0 {
            return Err("array dimension must be at least 1".to_string());
        }
        dimensions.push(count);
        if dimensions.len() > ARRAY_DIMENSIONS_MAX {
            return Err(format!("more than {ARRAY_DIMENSIONS_MAX} array dimensions"));
        }
        rest = inner[close + 1..].trim();
    }
    let head = head.trim();
    let pointers = head
        .chars()
        .rev()
        .take_while(|c| *c == '*' || c.is_whitespace())
        .filter(|c| *c == '*')
        .count();
    let base_text = head.trim_end_matches(|c: char| c == '*' || c.is_whitespace());
    if head.contains('*') && base_text.contains('*') {
        return Err("'*' may only follow the base type".to_string());
    }
    if pointers > POINTER_LEVELS_MAX {
        return Err(format!("more than {POINTER_LEVELS_MAX} pointer levels"));
    }
    let words: Vec<&str> = base_text
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "volatile" | "struct" | "union" | "enum"))
        .collect();
    if words.is_empty() {
        return Err("no base type name".to_string());
    }
    let joined = words.join(" ");
    let base = C_ALIASES
        .iter()
        .find(|(c, _)| *c == joined)
        .map(|(_, ghidra)| (*ghidra).to_string())
        .unwrap_or(joined);
    if base.contains(' ') && !base.starts_with('/') {
        return Err(format!("{base:?} is not one type name"));
    }
    Ok(TypeExpr {
        base,
        dimensions,
        pointers,
    })
}

/// A resolved base type: program-defined row or Ghidra built-in.
enum Base<'a> {
    Builtin { length: i64, name: &'a str },
    Program(&'a DataTypeRow),
}

impl Base<'_> {
    fn length(&self) -> i64 {
        match self {
            Base::Builtin { length, .. } => *length,
            Base::Program(row) => row.length,
        }
    }

    fn describe(&self) -> Value {
        match self {
            Base::Builtin { length, name } => {
                json!({"length": length, "name": name, "source": "builtin"})
            }
            Base::Program(row) => json!({
                "category": row.category, "kind": row.kind, "length": row.length,
                "name": row.name, "path": row.path, "source": "program",
            }),
        }
    }
}

/// Lookup outcome for one type name.
enum Lookup<'a> {
    Ambiguous(Vec<&'a DataTypeRow>),
    Found(Base<'a>),
    Missing,
}

/// Resolve a name: exact `/category/path`, then exact program
/// name (several = ambiguous), then exact built-in name.
fn lookup<'a>(types: &'a Types, name: &str) -> Lookup<'a> {
    let rows = &types.data_types.rows;
    if name.starts_with('/') {
        return rows
            .iter()
            .find(|row| row.path == name)
            .map(|row| Lookup::Found(Base::Program(row)))
            .unwrap_or(Lookup::Missing);
    }
    let named: Vec<&DataTypeRow> = rows.iter().filter(|row| row.name == name).collect();
    match named.len() {
        1 => return Lookup::Found(Base::Program(named[0])),
        n if n > 1 => return Lookup::Ambiguous(named),
        _ => {}
    }
    types
        .builtins
        .rows
        .iter()
        .find(|row| row.name == name)
        .map(|row| {
            Lookup::Found(Base::Builtin {
                length: row.length,
                name: &row.name,
            })
        })
        .unwrap_or(Lookup::Missing)
}

fn types_section(export: &Export) -> Result<&Types, FathomError> {
    let types = query::section(&export.types, "types")?;
    types.data_types.check("types.data_types")?;
    types.builtins.check("types.builtins")?;
    types.categories.check("types.categories")?;
    Ok(types)
}

/// An unknown for a name that did not resolve, distinguishing a
/// truncated inventory from an observed absence.
fn name_unknown(evidence: &mut Evidence, types: &Types, name: &str, found: Option<Vec<String>>) {
    match found {
        Some(candidates) => evidence.add_unknown(
            "data_type",
            format!(
                "type name '{name}' is ambiguous; candidates: {}; re-run with a \
                 /category/path",
                candidates.join(", ")
            ),
        ),
        None if types.data_types.is_partial() => evidence.add_unknown(
            "data_type",
            format!(
                "no retained type is named '{name}'; the type inventory was truncated, so \
                 it may exist beyond the export bound"
            ),
        ),
        None => evidence.add_unknown(
            "data_type",
            format!("the program's data type manager and the built-ins hold no type '{name}'"),
        ),
    }
}

fn resolve_or_unknown<'a>(
    evidence: &mut Evidence,
    types: &'a Types,
    name: &str,
) -> Option<Base<'a>> {
    match lookup(types, name) {
        Lookup::Found(base) => Some(base),
        Lookup::Ambiguous(rows) => {
            let candidates = rows.iter().map(|r| r.path.clone()).collect();
            name_unknown(evidence, types, name, Some(candidates));
            None
        }
        Lookup::Missing => {
            name_unknown(evidence, types, name, None);
            None
        }
    }
}

fn cover_types(evidence: &mut Evidence, types: &Types) {
    query::cover(
        evidence,
        types.data_types.rows.len() + types.builtins.rows.len(),
        types.data_types.total + types.builtins.total,
        types.data_types.is_partial() || types.builtins.is_partial(),
    );
}

pub fn get_data_type_size(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let name = query::require_text(args, "name")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    data_type_size_evidence(subject, &export, name)
}

fn data_type_size_evidence(
    subject: Subject,
    export: &Export,
    name: &str,
) -> Result<Value, FathomError> {
    let mut evidence = base("get_data_type_size", subject);
    let types = types_section(export)?;
    if let Some(found) = resolve_or_unknown(&mut evidence, types, name) {
        let mut finding = Finding::new(
            "data_type_size",
            Confidence::Observed,
            json!({"length": found.length(), "type": found.describe()}),
        );
        if found.length() <= 0 {
            finding = finding.with_limitation(
                "Ghidra reports no fixed length for this type (dynamic or undefined size)",
            );
        }
        evidence.add_finding(finding);
    }
    cover_types(&mut evidence, types);
    Ok(evidence.to_value())
}

pub fn get_enum_values(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let name = query::require_text(args, "name")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    composite_evidence("get_enum_values", subject, &export, name, "enum")
}

pub fn get_struct_layout(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let name = query::require_text(args, "name")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    composite_evidence("get_struct_layout", subject, &export, name, "composite")
}

fn composite_evidence(
    tool: &str,
    subject: Subject,
    export: &Export,
    name: &str,
    want: &str,
) -> Result<Value, FathomError> {
    let mut evidence = base(tool, subject);
    let types = types_section(export)?;
    let Some(found) = resolve_or_unknown(&mut evidence, types, name) else {
        cover_types(&mut evidence, types);
        return Ok(evidence.to_value());
    };
    let row = match found {
        Base::Program(row) => row,
        Base::Builtin { name, .. } => {
            evidence.add_unknown(
                "data_type",
                format!("'{name}' is a Ghidra built-in, not a {want} type"),
            );
            return Ok(evidence.to_value());
        }
    };
    let finding = if want == "enum" {
        enum_finding(&mut evidence, row)?
    } else {
        layout_finding(&mut evidence, row)?
    };
    if let Some(finding) = finding {
        evidence.add_finding(finding);
    }
    cover_types(&mut evidence, types);
    Ok(evidence.to_value())
}

fn enum_finding(
    evidence: &mut Evidence,
    row: &DataTypeRow,
) -> Result<Option<Finding>, FathomError> {
    let Some(values) = &row.values else {
        evidence.add_unknown(
            "data_type",
            format!("'{}' is a {} type, not an enum", row.path, row.kind),
        );
        return Ok(None);
    };
    values.check("types.values")?;
    let mut finding = Finding::new(
        "enum_values",
        Confidence::Observed,
        json!({
            "length": row.length,
            "path": row.path,
            "values": values.rows.iter().map(|v| json!({"name": v.name, "value": v.value}))
                .collect::<Vec<_>>(),
        }),
    );
    if values.is_partial() {
        finding = finding.with_limitation("enum values truncated at the export bound");
    }
    Ok(Some(finding))
}

fn layout_finding(
    evidence: &mut Evidence,
    row: &DataTypeRow,
) -> Result<Option<Finding>, FathomError> {
    let Some(components) = &row.components else {
        evidence.add_unknown(
            "data_type",
            format!(
                "'{}' is a {} type, not a structure or union",
                row.path, row.kind
            ),
        );
        return Ok(None);
    };
    components.check("types.components")?;
    // Holes between defined components are derived from offsets and
    // lengths; unions overlap by design and report none.
    let mut holes = Vec::new();
    if row.kind == "structure" {
        let mut cursor: i64 = 0;
        for component in &components.rows {
            if component.offset > cursor {
                holes.push(json!({"length": component.offset - cursor, "offset": cursor}));
            }
            cursor = cursor.max(component.offset + component.length.max(0));
        }
        if !components.is_partial() && row.length > cursor {
            holes.push(json!({"length": row.length - cursor, "offset": cursor}));
        }
    }
    let mut finding = Finding::new(
        "struct_layout",
        Confidence::Observed,
        json!({
            "alignment": row.alignment,
            "components": components.rows.iter().take(LAYOUT_COMPONENTS_MAX).map(|c| json!({
                "comment": c.comment, "length": c.length, "name": c.name,
                "offset": c.offset, "type": c.kind,
            })).collect::<Vec<_>>(),
            "kind": row.kind,
            "length": row.length,
            "path": row.path,
            "undefined_regions": holes,
        }),
    )
    .with_limitation(
        "components are the defined ones; undefined_regions are derived from their \
         offsets and lengths",
    );
    if components.is_partial() {
        finding = finding.with_limitation("components truncated at the export bound");
    }
    Ok(Some(finding))
}

pub fn get_type_size(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let text = query::require_text(args, "type")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    expression_evidence("get_type_size", subject, &export, text)
}

pub fn validate_data_type(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let text = query::require_text(args, "type")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    expression_evidence("validate_data_type", subject, &export, text)
}

/// The size an expression denotes, or why it denotes none.
pub(crate) enum Sized {
    Bytes(u64),
    Invalid(String),
    Unsized(String),
}

fn expression_size(base: &Base, expr: &TypeExpr, pointer_size: u64) -> Sized {
    let element = if expr.pointers > 0 {
        pointer_size
    } else {
        match u64::try_from(base.length()) {
            Ok(length) if length > 0 => length,
            _ => {
                return Sized::Unsized("the base type has no fixed length in Ghidra".to_string());
            }
        }
    };
    let mut total = element;
    for dimension in &expr.dimensions {
        match total.checked_mul(*dimension) {
            Some(next) => total = next,
            None => return Sized::Invalid("array size overflows 64 bits".to_string()),
        }
    }
    Sized::Bytes(total)
}

fn expression_evidence(
    tool: &str,
    subject: Subject,
    export: &Export,
    text: &str,
) -> Result<Value, FathomError> {
    let mut evidence = base(tool, subject);
    let types = types_section(export)?;
    let verdict = |valid: bool, reason: Value, extra: Value| {
        let mut facts = json!({"expression": text, "reason": reason, "valid": valid});
        if let (Some(target), Some(more)) = (facts.as_object_mut(), extra.as_object()) {
            target.extend(more.clone());
        }
        Finding::new("type_expression", Confidence::Derived, facts).with_limitation(TYPE_GRAMMAR)
    };
    let expr = match parse_type(text) {
        Ok(expr) => expr,
        Err(reason) => {
            evidence.add_finding(verdict(false, json!(reason), json!({})));
            cover_types(&mut evidence, types);
            return Ok(evidence.to_value());
        }
    };
    let parsed = json!({
        "base": expr.base, "dimensions": expr.dimensions, "pointers": expr.pointers,
    });
    match lookup(types, &expr.base) {
        Lookup::Found(found) => {
            let (valid, reason, size) = match expression_size(&found, &expr, types.pointer_size) {
                Sized::Bytes(bytes) => (true, Value::Null, json!(bytes)),
                Sized::Unsized(why) => (true, json!(why), Value::Null),
                Sized::Invalid(why) => (false, json!(why), Value::Null),
            };
            evidence.add_finding(verdict(
                valid,
                reason,
                json!({
                    "base_type": found.describe(), "parsed": parsed,
                    "pointer_size": types.pointer_size, "size": size,
                }),
            ));
        }
        Lookup::Ambiguous(rows) => {
            let candidates: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
            evidence.add_finding(verdict(
                false,
                json!(format!("base type '{}' is ambiguous", expr.base)),
                json!({"candidates": candidates, "parsed": parsed}),
            ));
        }
        Lookup::Missing if types.data_types.is_partial() => {
            evidence.add_unknown(
                "data_type",
                format!(
                    "base type '{}' is not among the retained types; the inventory was \
                     truncated, so validity is not established",
                    expr.base
                ),
            );
        }
        Lookup::Missing => {
            evidence.add_finding(verdict(
                false,
                json!(format!(
                    "no type named '{}' exists in the program or built-ins",
                    expr.base
                )),
                json!({"parsed": parsed}),
            ));
        }
    }
    cover_types(&mut evidence, types);
    Ok(evidence.to_value())
}

pub fn validate_data_type_exists(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let name = query::require_text(args, "name")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    exists_evidence(subject, &export, name)
}

fn exists_evidence(subject: Subject, export: &Export, name: &str) -> Result<Value, FathomError> {
    let mut evidence = base("validate_data_type_exists", subject);
    let types = types_section(export)?;
    match lookup(types, name) {
        Lookup::Found(found) => evidence.add_finding(Finding::new(
            "data_type_exists",
            Confidence::Observed,
            json!({"exists": true, "name": name, "type": found.describe()}),
        )),
        Lookup::Ambiguous(rows) => evidence.add_finding(Finding::new(
            "data_type_exists",
            Confidence::Observed,
            json!({
                "exists": true, "name": name,
                "matches": rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            }),
        )),
        Lookup::Missing if types.data_types.is_partial() => {
            name_unknown(&mut evidence, types, name, None);
        }
        Lookup::Missing => evidence.add_finding(Finding::new(
            "data_type_exists",
            Confidence::Observed,
            json!({"exists": false, "name": name}),
        )),
    }
    cover_types(&mut evidence, types);
    Ok(evidence.to_value())
}

pub fn get_valid_data_types(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    let mut evidence = base("get_valid_data_types", subject);
    let types = types_section(&export)?;
    let rows: Vec<Value> = types
        .builtins
        .rows
        .iter()
        .map(|b| json!({"length": b.length, "name": b.name, "source": "builtin"}))
        .chain(types.data_types.rows.iter().map(
            |t| json!({"length": t.length, "name": t.name, "path": t.path, "source": "program"}),
        ))
        .collect();
    Listing {
        confidence: Confidence::Observed,
        key: "types",
        kind: "valid_data_types",
        partial: types.data_types.is_partial() || types.builtins.is_partial(),
        retained: rows.len(),
        rows,
        total: types.data_types.total + types.builtins.total,
    }
    .into_evidence(&mut evidence, page);
    Ok(evidence.to_value())
}

pub fn list_data_type_categories(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    let mut evidence = base("list_data_type_categories", subject);
    let types = types_section(&export)?;
    Listing {
        confidence: Confidence::Observed,
        key: "categories",
        kind: "data_type_categories",
        partial: types.categories.is_partial(),
        retained: types.categories.rows.len(),
        rows: types
            .categories
            .rows
            .iter()
            .map(|c| {
                json!({
                    "data_type_count": c.data_type_count, "path": c.path,
                    "subcategory_count": c.subcategory_count,
                })
            })
            .collect(),
        total: types.categories.total,
    }
    .into_evidence(&mut evidence, page);
    Ok(evidence.to_value())
}

pub fn list_data_types(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let category = query::optional_text(args, "category")?;
    let kind = query::optional_text(args, "kind")?;
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    filtered_types("list_data_types", subject, &export, page, |row| {
        category.is_none_or(|c| row.category == c) && kind.is_none_or(|k| row.kind == k)
    })
}

pub fn search_data_types(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let needle = query::require_text(args, "query")?.trim().to_lowercase();
    let page = query::page(args)?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    filtered_types("search_data_types", subject, &export, page, |row| {
        row.path.to_lowercase().contains(&needle)
    })
}

fn filtered_types(
    tool: &str,
    subject: Subject,
    export: &Export,
    page: Page,
    keep: impl Fn(&DataTypeRow) -> bool,
) -> Result<Value, FathomError> {
    let mut evidence = base(tool, subject);
    let types = types_section(export)?;
    let rows = types
        .data_types
        .rows
        .iter()
        .filter(|row| keep(row))
        .map(|row| {
            json!({
                "category": row.category, "kind": row.kind, "length": row.length,
                "name": row.name, "path": row.path,
            })
        })
        .collect();
    Listing {
        confidence: Confidence::Observed,
        key: "data_types",
        kind: "data_types",
        partial: types.data_types.is_partial(),
        retained: types.data_types.rows.len(),
        rows,
        total: types.data_types.total,
    }
    .into_evidence(&mut evidence, page);
    Ok(evidence.to_value())
}

pub fn validate_function_prototype(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let text = query::require_text(args, "prototype")?;
    let (subject, export) = query::run_mode(config, args, "types", None)?;
    prototype_evidence(subject, &export, text)
}

/// A prototype split into its parts (before type resolution).
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Prototype {
    pub calling_convention: Option<String>,
    pub name: String,
    pub parameters: Vec<(String, Option<String>)>,
    pub return_type: String,
    pub variadic: bool,
}

/// Split `ret [__cc] name(type a, type b, ...)`. The last word of a
/// parameter is its name when more than one word (or a trailing
/// identifier after '*') remains; `void` alone means no parameters.
pub(crate) fn parse_prototype(text: &str) -> Result<Prototype, String> {
    let open = text.find('(').ok_or("prototype has no '('")?;
    let close = text.rfind(')').ok_or("prototype has no ')'")?;
    if close < open
        || !text[close + 1..]
            .trim()
            .trim_end_matches(';')
            .trim()
            .is_empty()
    {
        return Err("text after the parameter list".to_string());
    }
    let head = text[..open].trim();
    let (head_type, name) = split_declarator(head).ok_or("no function name before '('")?;
    let mut words: Vec<&str> = head_type.split_whitespace().collect();
    let calling_convention = match words.last() {
        Some(word) if word.starts_with("__") => {
            let cc = (*word).to_string();
            words.pop();
            Some(cc)
        }
        _ => None,
    };
    let return_type = words.join(" ");
    if return_type.trim_end_matches('*').trim().is_empty() {
        return Err("no return type".to_string());
    }
    let inner = text[open + 1..close].trim();
    let mut parameters = Vec::new();
    let mut variadic = false;
    if !inner.is_empty() && inner != "void" {
        for (index, piece) in inner.split(',').map(str::trim).enumerate() {
            if piece == "..." {
                variadic = true;
                continue;
            }
            if variadic {
                return Err("'...' must be the last parameter".to_string());
            }
            if piece.is_empty() {
                return Err(format!("parameter {index} is empty"));
            }
            parameters.push(match split_declarator(piece) {
                Some((kind, name)) if !kind.trim_end_matches('*').trim().is_empty() => {
                    (kind, Some(name))
                }
                _ => (piece.to_string(), None),
            });
            if parameters.len() > PROTOTYPE_PARAMETERS_MAX {
                return Err(format!("more than {PROTOTYPE_PARAMETERS_MAX} parameters"));
            }
        }
    }
    Ok(Prototype {
        calling_convention,
        name,
        parameters,
        return_type,
        variadic,
    })
}

/// Split `type name` (the name is a trailing identifier, possibly
/// glued to '*'). Returns `None` when no identifier trails.
fn split_declarator(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    let name_start = trimmed
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
        .last()
        .map(|(index, _)| index)?;
    let name = &trimmed[name_start..];
    let kind = trimmed[..name_start].trim();
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || kind.is_empty()
        || kind.ends_with('[')
    {
        return None;
    }
    Some((kind.to_string(), name.to_string()))
}

fn prototype_evidence(subject: Subject, export: &Export, text: &str) -> Result<Value, FathomError> {
    let mut evidence = base("validate_function_prototype", subject);
    let types = types_section(export)?;
    let prototype = match parse_prototype(text) {
        Ok(prototype) => prototype,
        Err(reason) => {
            evidence.add_finding(
                Finding::new(
                    "prototype",
                    Confidence::Derived,
                    json!({"prototype": text, "reason": reason, "valid": false}),
                )
                .with_limitation(TYPE_GRAMMAR),
            );
            cover_types(&mut evidence, types);
            return Ok(evidence.to_value());
        }
    };
    let mut problems = Vec::new();
    let mut unresolved_truncated = false;
    let mut check = |role: String, type_text: &str| -> Value {
        match parse_type(type_text) {
            Err(reason) => {
                problems.push(format!("{role}: {reason}"));
                json!({"role": role, "type": type_text, "valid": false, "reason": reason})
            }
            Ok(expr) => match lookup(types, &expr.base) {
                Lookup::Found(found) => {
                    json!({"role": role, "type": type_text, "valid": true,
                        "resolved": found.describe()})
                }
                Lookup::Ambiguous(_) => {
                    problems.push(format!("{role}: base type '{}' is ambiguous", expr.base));
                    json!({"role": role, "type": type_text, "valid": false})
                }
                Lookup::Missing => {
                    if types.data_types.is_partial() {
                        unresolved_truncated = true;
                    } else {
                        problems.push(format!("{role}: no type named '{}'", expr.base));
                    }
                    json!({"role": role, "type": type_text, "valid": false})
                }
            },
        }
    };
    let mut parts = vec![check("return".to_string(), &prototype.return_type)];
    for (index, (kind, name)) in prototype.parameters.iter().enumerate() {
        let role = format!(
            "parameter {index} ({})",
            name.as_deref().unwrap_or("unnamed")
        );
        parts.push(check(role, kind));
    }
    let valid = problems.is_empty() && !unresolved_truncated;
    evidence.add_finding(
        Finding::new(
            "prototype",
            Confidence::Derived,
            json!({
                "calling_convention": prototype.calling_convention,
                "name": prototype.name,
                "parts": parts,
                "problems": problems,
                "prototype": text,
                "valid": valid,
                "variadic": prototype.variadic,
            }),
        )
        .with_limitation(TYPE_GRAMMAR),
    );
    if let Some(cc) = &prototype.calling_convention {
        evidence.add_unknown(
            "calling_convention",
            format!(
                "'{cc}' was not checked against the compiler spec (see \
                 list_calling_conventions)"
            ),
        );
    }
    if unresolved_truncated {
        evidence.add_unknown(
            "data_type",
            "some types are not among the retained types; the inventory was truncated",
        );
    }
    cover_types(&mut evidence, types);
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::query::PAGE_ROWS_DEFAULT;
    use crate::ghidra::query::tests::{export, subject};

    const TYPES: &str = r#""types": {"pointer_size": 8,
        "builtins": {"rows": [{"name": "int", "length": 4}, {"name": "uint", "length": 4},
            {"name": "char", "length": 1}, {"name": "void", "length": 0}],
            "total": 4, "truncated": false},
        "categories": {"rows": [{"path": "/", "data_type_count": 3, "subcategory_count": 1},
            {"path": "/elf", "data_type_count": 1, "subcategory_count": 0}],
            "total": 2, "truncated": false},
        "data_types": {"rows": [
            {"alignment": 8, "category": "/elf", "description": "", "kind": "structure",
             "length": 24, "name": "Elf64_Sym", "path": "/elf/Elf64_Sym",
             "components": {"rows": [
                {"comment": "", "length": 4, "name": "st_name", "offset": 0, "type": "dword"},
                {"comment": "", "length": 1, "name": "st_info", "offset": 4, "type": "byte"},
                {"comment": "", "length": 8, "name": "st_value", "offset": 8, "type": "qword"}],
              "total": 3, "truncated": false}},
            {"alignment": 4, "category": "/", "description": "", "kind": "enum",
             "length": 4, "name": "Color", "path": "/Color",
             "values": {"rows": [{"name": "RED", "value": 0}, {"name": "BLUE", "value": 2}],
               "total": 2, "truncated": false}},
            {"alignment": 1, "category": "/", "description": "", "kind": "typedef",
             "length": 8, "name": "size_t", "path": "/size_t", "base": "ulong"},
            {"alignment": 1, "category": "/a", "description": "", "kind": "structure",
             "length": 1, "name": "dup", "path": "/a/dup",
             "components": {"rows": [], "total": 0, "truncated": false}},
            {"alignment": 1, "category": "/b", "description": "", "kind": "structure",
             "length": 1, "name": "dup", "path": "/b/dup",
             "components": {"rows": [], "total": 0, "truncated": false}}],
          "total": 5, "truncated": false}}"#;

    fn page() -> Page {
        Page {
            limit: PAGE_ROWS_DEFAULT,
            offset: 0,
        }
    }

    #[test]
    fn validation_type_expressions_parse() {
        assert_eq!(
            parse_type("const char *").unwrap(),
            TypeExpr {
                base: "char".into(),
                dimensions: vec![],
                pointers: 1
            }
        );
        assert_eq!(
            parse_type("unsigned int[4][2]").unwrap(),
            TypeExpr {
                base: "uint".into(),
                dimensions: vec![4, 2],
                pointers: 0
            }
        );
        assert_eq!(parse_type("struct Elf64_Sym **").unwrap().pointers, 2);
        assert_eq!(parse_type("/elf/Elf64_Sym").unwrap().base, "/elf/Elf64_Sym");
    }

    #[test]
    fn adversarial_type_expressions_are_refused_with_reasons() {
        for bad in [
            "",
            "*",
            "int[0]",
            "int[-1]",
            "int[",
            "int[4]x",
            "int[99999999999999999999]",
            "void (*)(int)",
            "int * char",
            "unsigned banana",
            "int[1][1][1][1][1][1][1][1][1]",
            "int*********",
        ] {
            assert!(parse_type(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn validation_sizes_are_derived_from_ghidra_lengths() {
        let export = export("types", TYPES);
        let value =
            expression_evidence("get_type_size", subject(), &export, "Elf64_Sym[10]").unwrap();
        assert_eq!(value["findings"][0]["facts"]["size"], 240);
        assert_eq!(value["findings"][0]["confidence"], "derived");
        let value = expression_evidence("get_type_size", subject(), &export, "char **").unwrap();
        assert_eq!(value["findings"][0]["facts"]["size"], 8);
        let value = data_type_size_evidence(subject(), &export, "size_t").unwrap();
        assert_eq!(value["findings"][0]["facts"]["length"], 8);
    }

    #[test]
    fn adversarial_overflow_unknown_and_ambiguous_types() {
        let export = export("types", TYPES);
        let value = expression_evidence(
            "validate_data_type",
            subject(),
            &export,
            "Elf64_Sym[4294967296][4294967296]",
        )
        .unwrap();
        assert_eq!(value["findings"][0]["facts"]["valid"], false);
        let value =
            expression_evidence("validate_data_type", subject(), &export, "nosuch *").unwrap();
        assert_eq!(value["findings"][0]["facts"]["valid"], false);
        let value = expression_evidence("validate_data_type", subject(), &export, "dup").unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let value = expression_evidence("validate_data_type", subject(), &export, "void").unwrap();
        // void has no fixed length: valid name, no size claimed.
        assert_eq!(value["findings"][0]["facts"]["valid"], true);
        assert!(value["findings"][0]["facts"]["size"].is_null());
    }

    #[test]
    fn validation_struct_layout_reports_holes() {
        let export = export("types", TYPES);
        let value = composite_evidence(
            "get_struct_layout",
            subject(),
            &export,
            "Elf64_Sym",
            "composite",
        )
        .unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["components"][2]["name"], "st_value");
        // st_info ends at 5; st_value starts at 8; 16 + 8 = 24 total.
        assert_eq!(facts["undefined_regions"][0]["offset"], 5);
        assert_eq!(facts["undefined_regions"][0]["length"], 3);
        assert_eq!(facts["undefined_regions"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn adversarial_wrong_kind_and_missing_names_are_unknowns() {
        let export = export("types", TYPES);
        let value =
            composite_evidence("get_enum_values", subject(), &export, "Elf64_Sym", "enum").unwrap();
        assert_eq!(value["status"], "partial");
        let value = composite_evidence("get_struct_layout", subject(), &export, "int", "composite")
            .unwrap();
        assert_eq!(value["status"], "partial");
        let value =
            composite_evidence("get_enum_values", subject(), &export, "Color", "enum").unwrap();
        assert_eq!(value["findings"][0]["facts"]["values"][1]["name"], "BLUE");
    }

    #[test]
    fn validation_existence_is_observed_absence_when_exhaustive() {
        let export = export("types", TYPES);
        let value = exists_evidence(subject(), &export, "Color").unwrap();
        assert_eq!(value["findings"][0]["facts"]["exists"], true);
        let value = exists_evidence(subject(), &export, "Colour").unwrap();
        assert_eq!(value["findings"][0]["facts"]["exists"], false);
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn adversarial_truncated_inventory_never_claims_absence() {
        let truncated = TYPES.replace(
            r#""total": 5, "truncated": false"#,
            r#""total": 900, "truncated": true"#,
        );
        let export = export("types", &truncated);
        let value = exists_evidence(subject(), &export, "Colour").unwrap();
        assert_eq!(value["status"], "partial");
        assert!(value["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_listing_filters_and_search() {
        let export = export("types", TYPES);
        let value = filtered_types("list_data_types", subject(), &export, page(), |r| {
            r.kind == "structure"
        })
        .unwrap();
        assert_eq!(value["findings"][0]["facts"]["matched"], 3);
        let value = filtered_types("search_data_types", subject(), &export, page(), |r| {
            r.path.to_lowercase().contains("elf")
        })
        .unwrap();
        assert_eq!(
            value["findings"][0]["facts"]["data_types"][0]["name"],
            "Elf64_Sym"
        );
    }

    #[test]
    fn validation_prototypes_parse_and_validate() {
        let parsed = parse_prototype("int __stdcall main(int argc, char **argv)").unwrap();
        assert_eq!(parsed.calling_convention.as_deref(), Some("__stdcall"));
        assert_eq!(
            parsed.parameters[1],
            ("char **".to_string(), Some("argv".to_string()))
        );
        let parsed = parse_prototype("void f(void)").unwrap();
        assert!(parsed.parameters.is_empty());
        let parsed = parse_prototype("int printf(char *fmt, ...);").unwrap();
        assert!(parsed.variadic);
        let export = export("types", TYPES);
        let value =
            prototype_evidence(subject(), &export, "size_t f(Elf64_Sym *s, uint n)").unwrap();
        assert_eq!(value["findings"][0]["facts"]["valid"], true);
    }

    #[test]
    fn adversarial_malformed_prototypes_are_invalid_not_errors() {
        for bad in [
            "int",
            "int f(",
            "int f(int a,, int b)",
            "f(int a)",
            "int f(..., int a)",
            "int f(int) trailing",
        ] {
            assert!(parse_prototype(bad).is_err(), "accepted {bad:?}");
        }
        let export = export("types", TYPES);
        let value = prototype_evidence(subject(), &export, "int f(nosuch x)").unwrap();
        assert_eq!(value["findings"][0]["facts"]["valid"], false);
        let value = prototype_evidence(subject(), &export, "int __bogus f(int x)").unwrap();
        assert_eq!(value["unknowns"][0]["aspect"], "calling_convention");
    }
}
