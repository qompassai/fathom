//! Dialogue & story extraction (R9): the story layer
//! as data, per engine, in the unified-manifest shape.
//!
//! RPG Maker MV/MZ: event commands in data/*.json are
//! plain JSON, so the dialogue is honestly extractable —
//! Show Text (101) opens a message, its text lines are
//! the following 401 commands, choices are 102. The
//! dump is JSONL (map/event/page, speaker where the
//! engine carries one — the MZ name box or a face name,
//! text) plus counts. The story graph is NOT
//! reconstructed for RPG Maker (transfer/branch logic
//! is program, not data) and the manifest says so.
//!
//! Script formats (census_dialogue_tree): loose .rpy
//! sources yield labels, menus, choice options, say
//! lines, and jump/call edges — a real story graph.
//! Tyrano .ks yields labels, jump/call targets, and a
//! tag histogram. Naninovel .nani and Yarn sources
//! yield labels/commands/nodes. Compiled .rpyc exposes
//! only its RPC2 slot structure plus the printable
//! string runs that survive in the decompressed slot —
//! a strings-level census, labelled heuristic; label
//! and menu structure do not survive compilation in any
//! form this reader will claim. Ink .ink.json is
//! censused at the container level only.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::sha256_hex;
use fathom_core::evidence::{Confidence, Evidence, Finding};
use fathom_core::limits::{
    DIALOGUE_FILE_BYTES_MAX, DIALOGUE_FILES_MAX, DIALOGUE_ROWS_MAX, GAME_WALK_DEPTH_MAX,
    GAME_WALK_FILES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

/// Read one bounded JSON document.
fn read_json(path: &Path) -> Result<Value> {
    let mut file = File::open(path)
        .map_err(|error| mismatch(format!("cannot open {}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(DIALOGUE_FILE_BYTES_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| mismatch(format!("cannot read {}: {error}", path.display())))?;
    if bytes.len() as u64 > DIALOGUE_FILE_BYTES_MAX {
        return Err(mismatch(format!(
            "{} exceeds the dialogue file bound",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        mismatch(format!(
            "{} does not parse as JSON: {error}",
            path.display()
        ))
    })
}

// ------------------------------------------------------- RPG Maker

/// One dialogue message being assembled from a 101
/// header plus its 401 lines.
#[derive(Default)]
struct MessageBuilder {
    lines: Vec<String>,
    open: bool,
    speaker: Option<String>,
}

impl MessageBuilder {
    fn flush_into(&mut self, rows: &mut Vec<Value>, map: &str, event: u64, page: usize) {
        if self.open {
            rows.push(json!({
                "event": event,
                "map": map,
                "page": page,
                "speaker": self.speaker,
                "text": self.lines.join("\n"),
            }));
            self.lines.clear();
            self.open = false;
            self.speaker = None;
        }
    }
}

/// Walk one command list, appending message rows and
/// counting choice sets. Returns choice-set count.
fn walk_commands(
    commands: &Value,
    map: &str,
    event: u64,
    page: usize,
    rows: &mut Vec<Value>,
) -> usize {
    let mut choices = 0usize;
    let mut builder = MessageBuilder::default();
    let Some(list) = commands.as_array() else {
        return 0;
    };
    for command in list {
        let code = command["code"].as_u64().unwrap_or(0);
        let params = &command["parameters"];
        match code {
            101 => {
                builder.flush_into(rows, map, event, page);
                builder.open = true;
                // MZ name box is parameters[4]; the face
                // name (parameters[0]) is reported when no
                // name box exists.
                let name_box = params[4].as_str().unwrap_or("");
                let face = params[0].as_str().unwrap_or("");
                builder.speaker = if !name_box.is_empty() {
                    Some(name_box.to_string())
                } else if !face.is_empty() {
                    Some(face.to_string())
                } else {
                    None
                };
            }
            401 => {
                if builder.open {
                    builder
                        .lines
                        .push(params[0].as_str().unwrap_or("").to_string());
                }
            }
            102 => {
                builder.flush_into(rows, map, event, page);
                choices += 1;
            }
            _ => {}
        }
        if rows.len() > DIALOGUE_ROWS_MAX {
            break;
        }
    }
    builder.flush_into(rows, map, event, page);
    choices
}

/// Locate the data directory under a game root:
/// <root>/data, <root>/www/data, or the root itself.
fn locate_data_dir(root: &Path) -> Option<PathBuf> {
    [
        root.join("data"),
        root.join("www").join("data"),
        root.to_path_buf(),
    ]
    .into_iter()
    .find(|candidate| {
        candidate.join("System.json").is_file() || candidate.join("CommonEvents.json").is_file()
    })
}

pub fn extract_rpgmaker_dialogue(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let target = require_str(args, "target")?;
    let root = paths::validate_target(config, Path::new(target))?;
    let output_dir =
        paths::validate_output_dir(config, Path::new(require_str(args, "output_dir")?))?;
    let data_dir = locate_data_dir(&root).ok_or_else(|| {
        FathomError::new(
            ErrorCode::UnsupportedTarget,
            "no RPG Maker data directory (data/ or www/data with System.json) under the target",
        )
    })?;
    let mut names: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name.starts_with("Map") && name.ends_with(".json") && name != "MapInfos.json")
                || name == "CommonEvents.json"
            {
                names.push(path);
            }
        }
    }
    names.sort();
    if names.len() > DIALOGUE_FILES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "data directory holds more dialogue files than the census bound",
        ));
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut choice_sets = 0usize;
    let mut maps_with_dialogue = 0usize;
    for path in &names {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let document = read_json(path)?;
        let before = rows.len();
        if name == "CommonEvents.json" {
            if let Some(events) = document.as_array() {
                for event in events {
                    let Some(event) = event.as_object() else {
                        continue;
                    };
                    let id = event.get("id").and_then(Value::as_u64).unwrap_or(0);
                    choice_sets += walk_commands(&event["list"], "CommonEvents", id, 0, &mut rows);
                }
            }
        } else if let Some(events) = document["events"].as_array() {
            for event in events {
                let Some(event) = event.as_object() else {
                    continue;
                };
                let id = event.get("id").and_then(Value::as_u64).unwrap_or(0);
                if let Some(pages) = event["pages"].as_array() {
                    for (page_index, page) in pages.iter().enumerate() {
                        choice_sets +=
                            walk_commands(&page["list"], &name, id, page_index, &mut rows);
                    }
                }
            }
        }
        if rows.len() > before {
            maps_with_dialogue += 1;
        }
        if rows.len() > DIALOGUE_ROWS_MAX {
            break;
        }
    }
    let text_lines: usize = rows
        .iter()
        .map(|row| row["text"].as_str().unwrap_or("").matches('\n').count() + 1)
        .sum();
    std::fs::create_dir_all(&output_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot create dialogue output directory: {error}"),
        )
    })?;
    let mut jsonl = String::new();
    for row in &rows {
        jsonl.push_str(&serde_json::to_string(row).unwrap_or_default());
        jsonl.push('\n');
    }
    let dump_path = output_dir.join("dialogue.jsonl");
    let temp_path = output_dir.join("dialogue.jsonl.tmp");
    std::fs::write(&temp_path, jsonl.as_bytes()).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot write dialogue dump: {error}"),
        )
    })?;
    std::fs::rename(&temp_path, &dump_path).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot finish dialogue dump: {error}"),
        )
    })?;
    let counts = json!({
        "choice_sets": choice_sets,
        "files": names.len(),
        "maps_with_dialogue": maps_with_dialogue,
        "messages": rows.len(),
        "text_lines": text_lines,
    });
    let document = json!({
        "counts": counts,
        "dialogue_sha256": sha256_hex(jsonl.as_bytes()),
        "format": "RPG Maker MV/MZ event dialogue (JSONL dump)",
        "story_graph": Value::Null,
    });
    let (digest, retention_note) = match proof::retain_export(
        config,
        &sha256_hex(jsonl.as_bytes()),
        "rpgmaker_dialogue",
        &document,
    ) {
        Ok(digest) => (Some(digest), None),
        Err(error) => (None, Some(error.message)),
    };
    let mut evidence = Evidence::new("extract_rpgmaker_dialogue", "dialogue");
    evidence.add_finding(Finding::new(
        "dialogue",
        Confidence::Observed,
        json!({
            "choice_sets": choice_sets,
            "dump_file": "dialogue.jsonl",
            "dump_sha256": sha256_hex(jsonl.as_bytes()),
            "export_digest": digest,
            "files": names.len(),
            "format": "RPG Maker MV/MZ event dialogue (JSONL dump)",
            "maps_with_dialogue": maps_with_dialogue,
            "messages": rows.len(),
            "story_graph": Value::Null,
            "text_lines": text_lines,
        }),
    ));
    evidence.add_unknown(
        "story_graph",
        "RPG Maker transfer/branch logic is event program, not data; choices are counted, the graph is not reconstructed",
    );
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "dialogue retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

// ------------------------------------------------- script formats

/// Per-file script census tallies.
#[derive(Default)]
struct ScriptTallies {
    choices: usize,
    edges: Vec<Value>,
    labels: Vec<String>,
    menus: usize,
    text_lines: usize,
    tags: BTreeMap<String, usize>,
}

/// Census one .rpy source. The quoted-line count is a
/// line-SHAPE census (narration or speaker-prefixed
/// quoted statements): in trees that ship engine or
/// SDK sources it also counts screen text and doc
/// strings, and it is named accordingly in the rows.
fn census_rpy(text: &str, tallies: &mut ScriptTallies) {
    let mut current_label = String::from("(toplevel)");
    let mut menu_indent: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        // A menu block ends when a non-blank line returns
        // to the menu's own indent or above.
        if let Some(menu_at) = menu_indent
            && !trimmed.is_empty()
            && indent <= menu_at
            && !trimmed.starts_with('"')
        {
            menu_indent = None;
        }
        if let Some(rest) = trimmed.strip_prefix("label ") {
            if let Some(name) = rest.trim_end_matches(':').split('(').next() {
                let name = name.trim().to_string();
                tallies.labels.push(name.clone());
                current_label = name;
                menu_indent = None;
            }
            continue;
        }
        if trimmed == "menu:" || trimmed.starts_with("menu ") {
            tallies.menus += 1;
            menu_indent = Some(indent);
            continue;
        }
        if menu_indent.is_some() && trimmed.starts_with('"') && trimmed.ends_with("\":") {
            tallies.choices += 1;
            continue;
        }
        for keyword in ["jump ", "call "] {
            if let Some(rest) = trimmed.strip_prefix(keyword) {
                let to = rest
                    .split([' ', '('])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !to.is_empty() {
                    tallies.edges.push(json!({
                        "from": current_label,
                        "kind": keyword.trim(),
                        "to": to,
                    }));
                }
            }
        }
        let is_say = trimmed.starts_with('"')
            || (trimmed.split_once(' ').is_some_and(|(head, rest)| {
                head.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
                    && rest.starts_with('"')
            }));
        if is_say {
            tallies.text_lines += 1;
        }
    }
}

/// Census one Tyrano .ks scenario.
fn census_ks(text: &str, tallies: &mut ScriptTallies) {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(label) = trimmed.strip_prefix('*') {
            let name = label.split(['|', ' ']).next().unwrap_or("").to_string();
            if !name.is_empty() {
                tallies.labels.push(name);
            }
            continue;
        }
        if trimmed.starts_with('[') {
            let tag = trimmed
                .trim_start_matches('[')
                .split([' ', ']'])
                .next()
                .unwrap_or("")
                .to_string();
            if !tag.is_empty() {
                *tallies.tags.entry(tag.clone()).or_insert(0) += 1;
            }
            if (tag == "jump" || tag == "call")
                && let Some(start) = trimmed.find("target=")
            {
                let rest = &trimmed[start + 7..];
                let to = rest
                    .trim_matches(|c| c == '"' || c == '*')
                    .split(['"', ' ', ']'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !to.is_empty() {
                    tallies.edges.push(json!({
                        "from": tallies.labels.last().cloned().unwrap_or_default(),
                        "kind": tag,
                        "to": to,
                    }));
                }
            }
            continue;
        }
        if !trimmed.is_empty() && !trimmed.starts_with(';') && !trimmed.starts_with('#') {
            tallies.text_lines += 1;
        }
    }
}

/// Census one Naninovel .nani script.
fn census_nani(text: &str, tallies: &mut ScriptTallies) {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(label) = trimmed.strip_prefix("# ") {
            tallies.labels.push(label.trim().to_string());
            continue;
        }
        if let Some(command) = trimmed.strip_prefix('@') {
            let name = command.split([' ', '.']).next().unwrap_or("").to_string();
            if !name.is_empty() {
                *tallies.tags.entry(name.clone()).or_insert(0) += 1;
            }
            if name == "goto" {
                let to = command
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .split('#')
                    .next_back()
                    .unwrap_or("")
                    .to_string();
                if !to.is_empty() {
                    tallies.edges.push(json!({
                        "from": tallies.labels.last().cloned().unwrap_or_default(),
                        "kind": "goto",
                        "to": to,
                    }));
                }
            }
            continue;
        }
        if !trimmed.is_empty() && !trimmed.starts_with(';') {
            tallies.text_lines += 1;
        }
    }
}

/// Scan decompressed bytes for printable UTF-8 runs of
/// at least 4 bytes (the strings(1) heuristic, capped).
fn string_runs(bytes: &[u8], cap: usize) -> (usize, Vec<String>) {
    let mut total = 0usize;
    let mut listed = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let flush = |current: &mut Vec<u8>, total: &mut usize, listed: &mut Vec<String>| {
        if current.len() >= 4 {
            *total += 1;
            if listed.len() < cap
                && let Ok(text) = std::str::from_utf8(current)
            {
                listed.push(text.to_string());
            }
        }
        current.clear();
    };
    for byte in bytes {
        if (0x20..0x7f).contains(byte) || *byte >= 0x80 {
            current.push(*byte);
        } else {
            flush(&mut current, &mut total, &mut listed);
        }
    }
    flush(&mut current, &mut total, &mut listed);
    (total, listed)
}

pub fn census_dialogue_tree(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let target = require_str(args, "target")?;
    let root = paths::validate_target(config, Path::new(target))?;
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.clone(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > GAME_WALK_DEPTH_MAX {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        children.sort();
        for child in children {
            let Ok(metadata) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push((child, depth + 1));
            } else if metadata.is_file() {
                let name = child
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if name.ends_with(".rpy")
                    || name.ends_with(".rpyc")
                    || name.ends_with(".ks")
                    || name.ends_with(".nani")
                    || name.ends_with(".yarn")
                    || name.ends_with(".ink.json")
                {
                    files.push(child);
                }
                if files.len() > DIALOGUE_FILES_MAX {
                    return Err(FathomError::new(
                        ErrorCode::ResourceConstraint,
                        "tree holds more dialogue files than the census bound",
                    ));
                }
            }
        }
    }
    files.sort();
    if files.len() > GAME_WALK_FILES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "tree exceeds the game walk file bound",
        ));
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut graph_nodes: Vec<String> = Vec::new();
    let mut graph_edges: Vec<Value> = Vec::new();
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let mut file = File::open(path)
            .map_err(|error| mismatch(format!("cannot open dialogue file: {error}")))?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(DIALOGUE_FILE_BYTES_MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| mismatch(format!("cannot read dialogue file: {error}")))?;
        if bytes.len() as u64 > DIALOGUE_FILE_BYTES_MAX {
            rows.push(json!({"file": rel, "status": "over_bound"}));
            continue;
        }
        let mut tallies = ScriptTallies::default();
        let kind;
        if name.ends_with(".rpy") {
            kind = "renpy_source";
            census_rpy(&String::from_utf8_lossy(&bytes), &mut tallies);
        } else if name.ends_with(".ks") {
            kind = "tyrano_scenario";
            census_ks(&String::from_utf8_lossy(&bytes), &mut tallies);
        } else if name.ends_with(".nani") {
            kind = "naninovel_script";
            census_nani(&String::from_utf8_lossy(&bytes), &mut tallies);
        } else if name.ends_with(".rpyc") {
            kind = "renpy_compiled";
            let (runs, listed) = string_runs(&bytes, 64);
            rows.push(json!({
                "file": rel,
                "kind": kind,
                "string_runs_listed": listed,
                "string_runs_total": runs,
            }));
            *totals.entry("rpyc_files").or_insert(0) += 1;
            *totals.entry("rpyc_string_runs").or_insert(0) += runs;
            continue;
        } else {
            kind = if name.ends_with(".yarn") {
                "yarn_source"
            } else {
                "ink_compiled"
            };
            let text = String::from_utf8_lossy(&bytes);
            let nodes = text.matches("title:").count();
            rows.push(json!({
                "file": rel,
                "kind": kind,
                "lines": text.lines().count(),
                "yarn_nodes": nodes,
            }));
            *totals.entry("other_files").or_insert(0) += 1;
            continue;
        }
        for label in &tallies.labels {
            graph_nodes.push(format!("{rel}#{label}"));
        }
        graph_edges.extend(tallies.edges.iter().cloned());
        *totals.entry("labels").or_insert(0) += tallies.labels.len();
        *totals.entry("choices").or_insert(0) += tallies.choices;
        *totals.entry("menus").or_insert(0) += tallies.menus;
        let text_key = if kind == "renpy_source" {
            "quoted_statement_lines"
        } else {
            "text_lines"
        };
        *totals.entry(text_key).or_insert(0) += tallies.text_lines;
        let tag_rows: Vec<Value> = tallies
            .tags
            .iter()
            .map(|(tag, count)| json!({"count": count, "tag": tag}))
            .collect();
        let mut row = json!({
            "choices": tallies.choices,
            "edges": tallies.edges.len(),
            "file": rel,
            "kind": kind,
            "labels": tallies.labels,
            "menus": tallies.menus,
            "tags": tag_rows,
        });
        row[text_key] = json!(tallies.text_lines);
        rows.push(row);
    }
    let document = json!({
        "files": rows,
        "format": "dialogue/story census (scripts as data)",
        "story_graph": {"edges": graph_edges, "nodes": graph_nodes},
        "totals": totals,
    });
    // Tree censuses bind to the census document's own
    // hash (the game-census pattern).
    let document_hash = sha256_hex(&serde_json::to_vec(&document).unwrap_or_default());
    let (digest, retention_note) =
        match proof::retain_export(config, &document_hash, "dialogue_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut evidence = Evidence::new("census_dialogue_tree", "dialogue");
    evidence.add_finding(Finding::new(
        "dialogue",
        Confidence::Observed,
        json!({
            "export_digest": digest,
            "files": document["files"],
            "format": "dialogue/story census (scripts as data)",
            "story_graph": document["story_graph"],
            "totals": document["totals"],
        }),
    ));
    evidence.add_unknown(
        "rpyc_structure",
        "compiled Ren'Py label/menu structure does not survive in a form this reader claims; rpyc rows are a strings-level census (printable-run heuristic) over the raw file bytes",
    );
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "dialogue retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-dialogue-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config(root: &Path) -> Config {
        Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\nallow_tools = [\"extract_rpgmaker_dialogue\", \"census_dialogue_tree\"]\n",
            root.join("state"),
            root
        ))
        .unwrap()
    }

    #[test]
    fn validation_rpgmaker_dialogue_dump() {
        let root = scratch("mv");
        let data = root.join("www").join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("System.json"), "{}").unwrap();
        let map = json!({
            "events": [null, {
                "id": 3,
                "pages": [{
                    "list": [
                        {"code": 101, "parameters": ["", 0, 0, 2, "Ada"]},
                        {"code": 401, "parameters": ["Hello there."]},
                        {"code": 401, "parameters": ["Second line."]},
                        {"code": 102, "parameters": [["Yes", "No"], 0, 0, 0, 0]},
                        {"code": 101, "parameters": ["FaceA", 0, 0, 2]},
                        {"code": 401, "parameters": ["Faced line."]}
                    ]
                }]
            }]
        });
        std::fs::write(data.join("Map001.json"), serde_json::to_vec(&map).unwrap()).unwrap();
        let out = root.join("out");
        let config = config(&root);
        let value = extract_rpgmaker_dialogue(
            &Registry::new(),
            &config,
            &json!({"output_dir": out.display().to_string(), "target": root.display().to_string()}),
        )
        .expect("extract");
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["messages"], 2);
        assert_eq!(facts["choice_sets"], 1);
        let dump = std::fs::read_to_string(out.join("dialogue.jsonl")).unwrap();
        let first: Value = serde_json::from_str(dump.lines().next().unwrap()).unwrap();
        assert_eq!(first["speaker"], "Ada");
        assert_eq!(first["text"], "Hello there.\nSecond line.");
        let second: Value = serde_json::from_str(dump.lines().nth(1).unwrap()).unwrap();
        assert_eq!(second["speaker"], "FaceA");
    }

    #[test]
    fn validation_script_census_builds_graph() {
        let root = scratch("rpy");
        let game = root.join("game");
        std::fs::create_dir_all(&game).unwrap();
        std::fs::write(
            game.join("script.rpy"),
            "label start:\n    \"Narration line.\"\n    ada \"Hello.\"\n    menu:\n        \"Go left\":\n            jump left_path\n        \"Go right\":\n            jump right_path\nlabel left_path:\n    return\n",
        )
        .unwrap();
        let mut file = File::create(root.join("scenario.ks")).unwrap();
        file.write_all("*start\nHello text\n[jump target=\"*next\"]\n*next\n".as_bytes())
            .unwrap();
        let config = config(&root);
        let value = census_dialogue_tree(
            &Registry::new(),
            &config,
            &json!({"target": root.display().to_string()}),
        )
        .expect("census");
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["totals"]["labels"], 4);
        assert_eq!(facts["totals"]["choices"], 2);
        assert_eq!(facts["story_graph"]["edges"].as_array().unwrap().len(), 3);
    }
}
