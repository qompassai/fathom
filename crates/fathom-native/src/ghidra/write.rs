//! Documentation & write tools (SPEC §9.1, Ghidra G2): renames,
//! labels, comments, bookmarks, prototypes, variables, function
//! tags, references, and data-type creation/application — the
//! write class of the parity matrix.
//!
//! Every handler is Execute-class: the registry's `decide()` gate
//! (SPEC §8) refuses the call unless the operator's config names
//! the tool in `allow_tools` (the per-session enable), before any
//! argument is read or any project byte is touched. Handlers only
//! *build* a bounded op batch; [`super::mutate`] runs it
//! transactionally (copy-on-write, one Ghidra transaction,
//! postcondition per op, commit-or-discard with a hash proof).
//!
//! Argument contracts are validated here, before the engine: a
//! malformed request costs nothing and reaches no Ghidra run.

use serde_json::{Value, json};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Finding, subject_for_file};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::ghidra::base;
use crate::ghidra::mutate::{self, Op};
use crate::ghidra::query;

/// Characters in one caller-supplied name (symbol, type, tag).
const NAME_CHARS_MAX: usize = 128;

/// Bytes in one comment / bookmark text.
const TEXT_BYTES_MAX: usize = 8192;

/// Bytes in one prototype string.
const PROTOTYPE_BYTES_MAX: usize = 2048;

/// Entries in one batch argument (labels, comments, tags).
const BATCH_ENTRIES_MAX: usize = 128;

/// Fields in one struct/union creation, values in one enum.
const TYPE_FIELDS_MAX: usize = 256;

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message)
}

/// A caller name: non-empty, bounded, no control characters.
fn check_name(field: &str, value: &str) -> Result<String, FathomError> {
    if value.is_empty()
        || value.chars().count() > NAME_CHARS_MAX
        || value.chars().any(|c| c.is_control())
    {
        return Err(invalid(format!(
            "argument '{field}' must be 1..={NAME_CHARS_MAX} non-control characters"
        )));
    }
    Ok(value.to_string())
}

/// Free text (comments, bookmark notes): bounded, no NUL.
fn check_text(field: &str, value: &str) -> Result<String, FathomError> {
    if value.len() > TEXT_BYTES_MAX || value.contains('\0') {
        return Err(invalid(format!(
            "argument '{field}' must be at most {TEXT_BYTES_MAX} bytes with no NUL"
        )));
    }
    Ok(value.to_string())
}

/// A data-type expression: bounded, from the type grammar's
/// alphabet (names, pointers, array sizes, path separators).
fn check_type(field: &str, value: &str) -> Result<String, FathomError> {
    if value.is_empty()
        || value.len() > NAME_CHARS_MAX
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _.*[]/$-".contains(c))
    {
        return Err(invalid(format!(
            "argument '{field}' is not a bounded data-type name"
        )));
    }
    Ok(value.trim().to_string())
}

/// A caller address, canonicalized by the read-core parser.
fn check_address(field: &str, args: &Value) -> Result<String, FathomError> {
    let raw = require_str(args, field)?;
    query::parse_address(raw)
}

/// A required name argument.
fn name_arg(args: &Value, field: &str) -> Result<String, FathomError> {
    check_name(field, require_str(args, field)?)
}

/// A required type argument.
fn type_arg(args: &Value, field: &str) -> Result<String, FathomError> {
    check_type(field, require_str(args, field)?)
}

/// An optional string argument with a default.
fn opt_str(args: &Value, field: &str, default: &str) -> String {
    args.get(field)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

/// The `fields`/`values` spec of a composite creation:
/// `[{name, type}]` or `[{name, value}]` rendered `name=type;...`.
fn spec_arg(args: &Value, field: &str, value_key: &str) -> Result<String, FathomError> {
    let rows = args
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("argument '{field}' must be an array")))?;
    if rows.len() > TYPE_FIELDS_MAX {
        return Err(invalid(format!(
            "argument '{field}' exceeds the {TYPE_FIELDS_MAX}-entry bound"
        )));
    }
    let mut parts = Vec::with_capacity(rows.len());
    for row in rows {
        let name = check_name("name", require_str(row, "name")?)?;
        let value = if value_key == "type" {
            check_type("type", require_str(row, "type")?)?
        } else {
            let raw = row
                .get("value")
                .and_then(Value::as_i64)
                .ok_or_else(|| invalid("enum values must be integers"))?;
            raw.to_string()
        };
        parts.push(format!("{name}={value}"));
    }
    Ok(parts.join(";"))
}

/// One object from a batch array argument.
fn batch_rows<'a>(args: &'a Value, field: &str) -> Result<&'a Vec<Value>, FathomError> {
    let rows = args
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("argument '{field}' must be an array")))?;
    if rows.is_empty() || rows.len() > BATCH_ENTRIES_MAX {
        return Err(invalid(format!(
            "argument '{field}' must hold 1..={BATCH_ENTRIES_MAX} entries"
        )));
    }
    Ok(rows)
}

/// Build the op batch for one write tool. Pure validation and
/// translation: no engine, no filesystem. Batch tools expand to
/// repeated ops inside the SAME transaction, so a batch is atomic
/// exactly like a single call.
pub(crate) fn build_ops(tool: &str, args: &Value) -> Result<Vec<Op>, FathomError> {
    let addr = |field: &str| check_address(field, args);
    let ops = match tool {
        "add_function_tag" => vec![Op::new(
            "add_function_tag",
            vec![addr("address")?, name_arg(args, "tag")?],
        )],
        "add_memory_reference" => vec![Op::new(
            "add_memory_reference",
            vec![
                addr("from")?,
                addr("to")?,
                check_name("type", &opt_str(args, "type", "DATA"))?,
            ],
        )],
        "add_struct_field" => vec![Op::new(
            "add_struct_field",
            vec![
                type_arg(args, "struct")?,
                name_arg(args, "field")?,
                type_arg(args, "type")?,
            ],
        )],
        "apply_data_type" => vec![Op::new(
            "apply_data_type",
            vec![addr("address")?, type_arg(args, "type")?],
        )],
        "batch_add_function_tags" => {
            let mut out = Vec::new();
            for row in batch_rows(args, "entries")? {
                let tags = row
                    .get("tags")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("each entry needs a 'tags' array"))?;
                for tag in tags {
                    let tag = tag
                        .as_str()
                        .ok_or_else(|| invalid("tags must be strings"))?;
                    out.push(Op::new(
                        "add_function_tag",
                        vec![check_address("address", row)?, check_name("tag", tag)?],
                    ));
                }
            }
            out
        }
        "batch_create_labels" => batch_rows(args, "labels")?
            .iter()
            .map(|row| {
                Ok(Op::new(
                    "create_label",
                    vec![check_address("address", row)?, name_arg(row, "name")?],
                ))
            })
            .collect::<Result<Vec<_>, FathomError>>()?,
        "batch_delete_labels" => batch_rows(args, "labels")?
            .iter()
            .map(|row| {
                Ok(Op::new(
                    "delete_label",
                    vec![check_address("address", row)?, name_arg(row, "name")?],
                ))
            })
            .collect::<Result<Vec<_>, FathomError>>()?,
        "batch_remove_function_tags" => {
            let mut out = Vec::new();
            for row in batch_rows(args, "entries")? {
                let tags = row
                    .get("tags")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("each entry needs a 'tags' array"))?;
                for tag in tags {
                    let tag = tag
                        .as_str()
                        .ok_or_else(|| invalid("tags must be strings"))?;
                    out.push(Op::new(
                        "remove_function_tag",
                        vec![check_address("address", row)?, check_name("tag", tag)?],
                    ));
                }
            }
            out
        }
        "batch_set_comments" => batch_rows(args, "comments")?
            .iter()
            .map(|row| {
                Ok(Op::new(
                    "set_comment",
                    vec![
                        check_address("address", row)?,
                        comment_kind(row)?,
                        check_text("text", require_str(row, "text")?)?,
                    ],
                ))
            })
            .collect::<Result<Vec<_>, FathomError>>()?,
        "clear_function_comments" => {
            vec![Op::new("clear_function_comments", vec![addr("address")?])]
        }
        "clone_data_type" => vec![Op::new(
            "clone_data_type",
            vec![type_arg(args, "source")?, type_arg(args, "new_name")?],
        )],
        "create_array_type" => {
            let count = args
                .get("count")
                .and_then(Value::as_u64)
                .filter(|n| *n >= 1 && *n <= 1_000_000)
                .ok_or_else(|| invalid("argument 'count' must be 1..=1000000"))?;
            vec![Op::new(
                "create_array_type",
                vec![type_arg(args, "base_type")?, count.to_string()],
            )]
        }
        "create_data_type_category" => vec![Op::new(
            "create_data_type_category",
            vec![check_name("path", require_str(args, "path")?)?],
        )],
        "create_enum" => vec![Op::new(
            "create_enum",
            vec![type_arg(args, "name")?, spec_arg(args, "values", "value")?],
        )],
        "create_function" => vec![Op::new(
            "create_function",
            vec![addr("address")?, name_arg(args, "name")?],
        )],
        "create_function_signature" => vec![Op::new(
            "create_function_signature",
            vec![type_arg(args, "name")?, prototype_arg(args)?],
        )],
        "create_function_tag" => vec![Op::new(
            "create_function_tag",
            vec![
                name_arg(args, "name")?,
                check_text("comment", &opt_str(args, "comment", ""))?,
            ],
        )],
        "create_label" => vec![Op::new(
            "create_label",
            vec![addr("address")?, name_arg(args, "name")?],
        )],
        "create_pointer_type" => vec![Op::new(
            "create_pointer_type",
            vec![type_arg(args, "base_type")?],
        )],
        "create_struct" => vec![Op::new(
            "create_struct",
            vec![type_arg(args, "name")?, spec_arg(args, "fields", "type")?],
        )],
        "create_typedef" => vec![Op::new(
            "create_typedef",
            vec![type_arg(args, "name")?, type_arg(args, "base_type")?],
        )],
        "create_union" => vec![Op::new(
            "create_union",
            vec![type_arg(args, "name")?, spec_arg(args, "fields", "type")?],
        )],
        "delete_bookmark" => vec![Op::new(
            "delete_bookmark",
            vec![
                addr("address")?,
                check_name("type", &opt_str(args, "type", "Note"))?,
                check_name("category", require_str(args, "category")?)?,
            ],
        )],
        "delete_data_type" => vec![Op::new("delete_data_type", vec![type_arg(args, "name")?])],
        "delete_function" => vec![Op::new("delete_function", vec![addr("address")?])],
        "delete_label" => vec![Op::new(
            "delete_label",
            vec![addr("address")?, name_arg(args, "name")?],
        )],
        "modify_struct_field" => vec![Op::new(
            "modify_struct_field",
            vec![
                type_arg(args, "struct")?,
                name_arg(args, "field")?,
                type_arg(args, "new_type")?,
            ],
        )],
        "move_data_type_to_category" => vec![Op::new(
            "move_data_type_to_category",
            vec![
                type_arg(args, "name")?,
                check_name("category", require_str(args, "category")?)?,
            ],
        )],
        "remove_function_tag" => vec![Op::new(
            "remove_function_tag",
            vec![addr("address")?, name_arg(args, "tag")?],
        )],
        "remove_reference" => vec![Op::new(
            "remove_reference",
            vec![addr("from")?, addr("to")?],
        )],
        "remove_struct_field" => vec![Op::new(
            "remove_struct_field",
            vec![type_arg(args, "struct")?, name_arg(args, "field")?],
        )],
        "rename_data" | "rename_global_variable" | "rename_label" => vec![Op::new(
            "rename_symbol",
            vec![addr("address")?, name_arg(args, "new_name")?],
        )],
        "rename_data_type" => vec![Op::new(
            "rename_data_type",
            vec![type_arg(args, "name")?, type_arg(args, "new_name")?],
        )],
        "rename_function" => vec![Op::new(
            "rename_function",
            vec![function_address(args)?, name_arg(args, "new_name")?],
        )],
        "rename_function_by_address" => vec![Op::new(
            "rename_function",
            vec![addr("address")?, name_arg(args, "new_name")?],
        )],
        "rename_variable" => vec![Op::new(
            "rename_variable",
            vec![
                addr("function")?,
                name_arg(args, "variable")?,
                name_arg(args, "new_name")?,
            ],
        )],
        "set_bookmark" => vec![Op::new(
            "set_bookmark",
            vec![
                addr("address")?,
                check_name("type", &opt_str(args, "type", "Note"))?,
                check_name("category", require_str(args, "category")?)?,
                check_text("comment", require_str(args, "comment")?)?,
            ],
        )],
        "set_comment" => vec![Op::new(
            "set_comment",
            vec![
                addr("address")?,
                comment_kind(args)?,
                check_text("text", require_str(args, "text")?)?,
            ],
        )],
        "set_decompiler_comment" => vec![Op::new(
            "set_comment",
            vec![
                addr("address")?,
                "decompiler".to_string(),
                check_text("text", require_str(args, "text")?)?,
            ],
        )],
        "set_disassembly_comment" => vec![Op::new(
            "set_comment",
            vec![
                addr("address")?,
                "disassembly".to_string(),
                check_text("text", require_str(args, "text")?)?,
            ],
        )],
        "set_plate_comment" => vec![Op::new(
            "set_comment",
            vec![
                addr("address")?,
                "plate".to_string(),
                check_text("text", require_str(args, "text")?)?,
            ],
        )],
        "set_decompiler_variable_type" | "set_local_variable_type" => vec![Op::new(
            "set_variable_type",
            vec![
                addr("function")?,
                name_arg(args, "variable")?,
                type_arg(args, "type")?,
            ],
        )],
        "set_function_no_return" => vec![Op::new("set_function_no_return", vec![addr("address")?])],
        "set_function_prototype" => vec![Op::new(
            "set_function_prototype",
            vec![addr("address")?, prototype_arg(args)?],
        )],
        "set_function_tag_comment" => vec![Op::new(
            "set_function_tag_comment",
            vec![
                name_arg(args, "tag")?,
                check_text("comment", require_str(args, "comment")?)?,
            ],
        )],
        "set_parameter_type" => {
            let index = args
                .get("index")
                .and_then(Value::as_u64)
                .filter(|n| *n <= 255)
                .ok_or_else(|| invalid("argument 'index' must be 0..=255"))?;
            vec![Op::new(
                "set_parameter_type",
                vec![
                    addr("function")?,
                    index.to_string(),
                    type_arg(args, "type")?,
                ],
            )]
        }
        _ => {
            return Err(invalid(format!("unknown write tool: {tool}")));
        }
    };
    if ops.is_empty() || ops.len() > mutate::OPS_PER_BATCH_MAX {
        return Err(invalid(format!(
            "the batch expands past the {}-op bound",
            mutate::OPS_PER_BATCH_MAX
        )));
    }
    Ok(ops)
}

/// The comment kind argument, from fathom's named set.
fn comment_kind(args: &Value) -> Result<String, FathomError> {
    let kind = opt_str(args, "type", "eol");
    match kind.as_str() {
        "decompiler" | "disassembly" | "eol" | "plate" | "post" | "pre" | "repeatable" => Ok(kind),
        _ => Err(invalid(
            "argument 'type' must name a comment kind: eol, plate, post, pre, repeatable, decompiler, disassembly",
        )),
    }
}

/// The prototype argument: bounded C subset (see the script).
fn prototype_arg(args: &Value) -> Result<String, FathomError> {
    let proto = require_str(args, "prototype")?;
    if proto.len() > PROTOTYPE_BYTES_MAX || !proto.contains('(') || !proto.contains(')') {
        return Err(invalid(
            "argument 'prototype' must be a bounded C prototype like \"int f(int a)\"",
        ));
    }
    Ok(proto.to_string())
}

/// `rename_function` names its target by address or by current
/// name; a name is resolved through the retained export the read
/// path already trusts — here the address form is required, and a
/// bare name is refused typed rather than guessed at.
fn function_address(args: &Value) -> Result<String, FathomError> {
    if let Some(raw) = args.get("address").and_then(Value::as_str) {
        return query::parse_address(raw);
    }
    Err(invalid(
        "rename_function needs the function's 'address' (resolve a name with list_functions first)",
    ))
}

/// Run one write tool: validate the target, build the batch, run
/// it transactionally, and report the commit proof as evidence.
fn handle(tool: &str, _: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let ops = build_ops(tool, args)?;
    let outcome = mutate::run_mutation(config, &path, &subject.sha256, &ops)?;
    let after = subject_for_file(&path)?;
    if after.sha256 != subject.sha256 {
        return Err(FathomError::new(
            ErrorCode::ArtifactChanged,
            "the target changed during the mutation; the subject is never a mutation output",
        )
        .with_target(path.display().to_string()));
    }
    let mut evidence = base(tool, subject);
    evidence.add_finding(Finding::new(
        "mutation",
        Confidence::Observed,
        json!({
            "applied": outcome.applied,
            "ops": ops.iter().map(|op| op.name).collect::<Vec<_>>(),
            "project_hash_after": outcome.project_hash_after,
            "project_hash_before": outcome.project_hash_before,
            "transaction": "committed",
        }),
    ));
    evidence.add_finding(Finding::new(
        "postconditions",
        Confidence::Observed,
        json!({"verified": outcome.verified}),
    ));
    Ok(evidence.to_value())
}

macro_rules! write_tool {
    ($fn_name:ident, $name:literal) => {
        pub fn $fn_name(
            registry: &Registry,
            config: &Config,
            args: &Value,
        ) -> Result<Value, FathomError> {
            handle($name, registry, config, args)
        }
    };
}

write_tool!(add_function_tag, "add_function_tag");
write_tool!(add_memory_reference, "add_memory_reference");
write_tool!(add_struct_field, "add_struct_field");
write_tool!(apply_data_type, "apply_data_type");
write_tool!(batch_add_function_tags, "batch_add_function_tags");
write_tool!(batch_create_labels, "batch_create_labels");
write_tool!(batch_delete_labels, "batch_delete_labels");
write_tool!(batch_remove_function_tags, "batch_remove_function_tags");
write_tool!(batch_set_comments, "batch_set_comments");
write_tool!(clear_function_comments, "clear_function_comments");
write_tool!(clone_data_type, "clone_data_type");
write_tool!(create_array_type, "create_array_type");
write_tool!(create_data_type_category, "create_data_type_category");
write_tool!(create_enum, "create_enum");
write_tool!(create_function, "create_function");
write_tool!(create_function_signature, "create_function_signature");
write_tool!(create_function_tag, "create_function_tag");
write_tool!(create_label, "create_label");
write_tool!(create_pointer_type, "create_pointer_type");
write_tool!(create_struct, "create_struct");
write_tool!(create_typedef, "create_typedef");
write_tool!(create_union, "create_union");
write_tool!(delete_bookmark, "delete_bookmark");
write_tool!(delete_data_type, "delete_data_type");
write_tool!(delete_function, "delete_function");
write_tool!(delete_label, "delete_label");
write_tool!(modify_struct_field, "modify_struct_field");
write_tool!(move_data_type_to_category, "move_data_type_to_category");
write_tool!(remove_function_tag, "remove_function_tag");
write_tool!(remove_reference, "remove_reference");
write_tool!(remove_struct_field, "remove_struct_field");
write_tool!(rename_data, "rename_data");
write_tool!(rename_data_type, "rename_data_type");
write_tool!(rename_function, "rename_function");
write_tool!(rename_function_by_address, "rename_function_by_address");
write_tool!(rename_global_variable, "rename_global_variable");
write_tool!(rename_label, "rename_label");
write_tool!(rename_variable, "rename_variable");
write_tool!(set_bookmark, "set_bookmark");
write_tool!(set_comment, "set_comment");
write_tool!(set_decompiler_comment, "set_decompiler_comment");
write_tool!(set_decompiler_variable_type, "set_decompiler_variable_type");
write_tool!(set_disassembly_comment, "set_disassembly_comment");
write_tool!(set_function_no_return, "set_function_no_return");
write_tool!(set_function_prototype, "set_function_prototype");
write_tool!(set_function_tag_comment, "set_function_tag_comment");
write_tool!(set_local_variable_type, "set_local_variable_type");
write_tool!(set_parameter_type, "set_parameter_type");
write_tool!(set_plate_comment, "set_plate_comment");

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;
    use fathom_core::policy::ToolClass;
    use fathom_core::registry::Registry as CoreRegistry;

    fn args(value: Value) -> Value {
        value
    }

    #[test]
    fn validation_rename_function_builds_one_op() {
        let ops = build_ops(
            "rename_function",
            &args(json!({"address": "0x10115d", "new_name": "main_loop"})),
        )
        .unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].name, "rename_function");
        assert_eq!(ops[0].fields, vec!["10115d", "main_loop"]);
    }

    #[test]
    fn validation_batch_comments_expand_inside_one_batch() {
        let ops = build_ops(
            "batch_set_comments",
            &args(json!({"comments": [
                {"address": "101000", "type": "eol", "text": "one"},
                {"address": "101004", "type": "plate", "text": "two"},
            ]})),
        )
        .unwrap();
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|op| op.name == "set_comment"));
    }

    #[test]
    fn validation_create_struct_renders_the_field_spec() {
        let ops = build_ops(
            "create_struct",
            &args(json!({"name": "Point", "fields": [
                {"name": "x", "type": "int"}, {"name": "y", "type": "int"},
            ]})),
        )
        .unwrap();
        assert_eq!(ops[0].fields[1], "x=int;y=int");
    }

    #[test]
    fn adversarial_unknown_comment_kind_is_refused() {
        let err = build_ops(
            "set_comment",
            &args(json!({"address": "101000", "type": "bogus", "text": "x"})),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_oversized_comment_is_refused() {
        let big = "x".repeat(TEXT_BYTES_MAX + 1);
        let err = build_ops(
            "set_comment",
            &args(json!({"address": "101000", "type": "eol", "text": big})),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_bad_address_is_refused_before_the_engine() {
        let err = build_ops(
            "create_label",
            &args(json!({"address": "not-an-address", "name": "lab"})),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_rename_by_name_without_address_is_refused() {
        let err = build_ops(
            "rename_function",
            &args(json!({"function": "main", "new_name": "renamed_main"})),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_empty_batch_is_refused() {
        let err = build_ops("batch_create_labels", &args(json!({"labels": []}))).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_write_tools_are_execute_class_and_default_deny() {
        // The whole G2 class rides the registry's decide() gate:
        // without an allow_tools entry naming the tool, dispatch
        // refuses with access_denied before any handler runs.
        let mut registry = CoreRegistry::new();
        crate::register(&mut registry);
        let config = Config::from_file_form(ConfigFile {
            ..ConfigFile::default()
        })
        .unwrap();
        for name in [
            "rename_function",
            "set_comment",
            "set_bookmark",
            "create_struct",
            "apply_data_type",
            "add_memory_reference",
            "remove_reference",
        ] {
            let descriptor = registry
                .descriptors()
                .into_iter()
                .find(|d| d.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert_eq!(descriptor.tool_class, ToolClass::Execute, "{name}");
            let err = registry
                .call(
                    &config,
                    name,
                    &json!({"target": "/nonexistent", "address": "101000"}),
                )
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::AccessDenied, "{name}");
        }
    }
}
