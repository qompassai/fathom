//! `analyze_javascript_application` (SPEC §9.2): walk an
//! application root, analyze every module, resolve the relative
//! module graph, and aggregate the Electron boundary. Parse
//! errors are findings, not run failures; a module that does not
//! parse is named in the unknowns, never silently skipped.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding};
use fathom_core::limits::FILE_COUNT_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::analyzer::{ModuleFacts, analyze_source};

const EXTENSIONS: [&str; 8] = ["js", "cjs", "mjs", "ts", "tsx", "jsx", "mts", "cts"];
/// Per-module read bound; larger modules are reported, not parsed.
const MODULE_BYTES_MAX: u64 = 8_388_608;

pub fn analyze_javascript_application(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let root = if target.is_file() {
        target.parent().map(Path::to_path_buf).ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "target file has no parent directory",
            )
        })?
    } else {
        target
    };
    let mut files = Vec::new();
    collect_modules(&root, 0, &mut files)?;
    files.sort();

    let mut evidence = Evidence::new("analyze_javascript_application", "javascript");
    let mut modules_json = Vec::new();
    let mut edges = Vec::new();
    let mut unresolved = Vec::new();
    let mut external: BTreeSet<String> = BTreeSet::new();
    let mut source_maps = Vec::new();
    let mut parse_error_rows = Vec::new();
    let mut electron_rows = Vec::new();
    let file_set: BTreeSet<PathBuf> = files.iter().cloned().collect();

    for file in &files {
        let relative = relative_string(&root, file);
        if file.extension().is_some_and(|ext| ext == "map") {
            source_maps.push(relative);
            continue;
        }
        let metadata = fs::metadata(file).map_err(|e| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot stat module: {e}"),
            )
        })?;
        if metadata.len() > MODULE_BYTES_MAX {
            evidence.add_unknown(
                format!("module {relative}"),
                "module exceeds the per-module read bound; not parsed",
            );
            continue;
        }
        let source = fs::read_to_string(file).map_err(|e| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read module {relative}: {e}"),
            )
        })?;
        let facts: ModuleFacts = analyze_source(file, &source);
        let parse_errors = facts.parse_errors.clone();
        if !parse_errors.is_empty() {
            parse_error_rows.push(json!({
                "errors": parse_errors,
                "module": relative,
            }));
            evidence.add_unknown(
                format!("module {relative}"),
                "module did not parse; its imports and boundaries are unknown",
            );
        }
        for import in &facts.imports {
            if import.source.starts_with('.') {
                match resolve_relative(file, &import.source, &file_set) {
                    Some(resolved) => edges.push(json!({
                        "from": relative,
                        "specifier": import.source,
                        "to": relative_string(&root, &resolved),
                    })),
                    None => unresolved.push(json!({
                        "from": relative,
                        "specifier": import.source,
                    })),
                }
            } else {
                external.insert(import.source.clone());
            }
        }
        if facts.electron.uses_electron {
            electron_rows.push(json!({
                "boundaries": serde_json::to_value(&facts.electron).unwrap_or(Value::Null),
                "module": relative,
            }));
        }
        modules_json.push(json!({
            "electron": facts.electron.uses_electron,
            "exports": facts.exports,
            "imports": serde_json::to_value(&facts.imports).unwrap_or(Value::Null),
            "module": relative,
            "parse_errors": parse_errors,
        }));
    }

    if let Some(package) = read_package_json(&root) {
        evidence.add_finding(Finding::new("application", Confidence::Observed, package));
    }
    evidence.add_finding(Finding::new(
        "modules",
        Confidence::Observed,
        json!({"modules": modules_json}),
    ));
    let mut graph = Finding::new(
        "module_graph",
        Confidence::Derived,
        json!({
            "edges": edges,
            "external": external.iter().collect::<Vec<_>>(),
            "unresolved": unresolved,
        }),
    );
    if !parse_error_rows.is_empty() {
        graph = graph.with_limitation("graph is partial: unparseable modules contribute no edges");
    }
    evidence.add_finding(graph);
    if !electron_rows.is_empty() {
        evidence.add_finding(Finding::new(
            "electron_boundaries",
            Confidence::Observed,
            json!({"modules": electron_rows}),
        ));
    }
    if !parse_error_rows.is_empty() {
        evidence.add_finding(Finding::new(
            "parse_errors",
            Confidence::Observed,
            json!({"modules": parse_error_rows}),
        ));
    }
    if !source_maps.is_empty() {
        evidence.add_finding(Finding::new(
            "source_maps",
            Confidence::Observed,
            json!({"files": source_maps}),
        ));
    }
    evidence.coverage.examined = files.len() as u64;
    evidence.coverage.total = files.len() as u64;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

fn collect_modules(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), FathomError> {
    if depth > 32 || out.len() >= FILE_COUNT_MAX {
        return Ok(());
    }
    let mut children: Vec<PathBuf> = Vec::new();
    let read = fs::read_dir(dir).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot list {}: {e}", dir.display()),
        )
    })?;
    for entry in read {
        let entry = entry.map_err(|e| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read entry: {e}"),
            )
        })?;
        children.push(entry.path());
    }
    children.sort();
    for child in children {
        let name = child
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if child.is_dir() {
            // Vendored dependencies and VCS internals are not the
            // application under analysis.
            if name != "node_modules" && name != ".git" {
                collect_modules(&child, depth + 1, out)?;
            }
        } else if name.ends_with(".js.map")
            || name.ends_with(".mjs.map")
            || child
                .extension()
                .is_some_and(|ext| EXTENSIONS.contains(&ext.to_string_lossy().as_ref()))
        {
            out.push(child);
        }
    }
    Ok(())
}

fn read_package_json(root: &Path) -> Option<Value> {
    let text = fs::read_to_string(root.join("package.json")).ok()?;
    let parsed: Value = serde_json::from_str(&text).ok()?;
    let keys = |field: &str| -> Vec<String> {
        parsed
            .get(field)
            .and_then(Value::as_object)
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    };
    Some(json!({
        "dependencies": keys("dependencies"),
        "dev_dependencies": keys("devDependencies"),
        "main": parsed.get("main").and_then(Value::as_str),
        "name": parsed.get("name").and_then(Value::as_str),
        "version": parsed.get("version").and_then(Value::as_str),
    }))
}

fn relative_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn resolve_relative(
    from_file: &Path,
    specifier: &str,
    file_set: &BTreeSet<PathBuf>,
) -> Option<PathBuf> {
    let base = from_file.parent()?.join(specifier);
    let mut candidates = vec![base.clone()];
    for extension in EXTENSIONS {
        candidates.push(base.with_extension(extension));
    }
    for extension in EXTENSIONS {
        candidates.push(base.join(format!("index.{extension}")));
    }
    candidates
        .into_iter()
        .find(|candidate| file_set.contains(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::Config;
    use std::io::Write;

    fn fixture_config(root: &Path) -> Config {
        Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap()
    }

    #[test]
    fn validation_fixture_app_end_to_end() {
        let root = std::env::temp_dir().join(format!("fathom-js-test-{}", std::process::id()));
        let app = root.join("app");
        fs::create_dir_all(app.join("lib")).unwrap();
        let mut package = fs::File::create(app.join("package.json")).unwrap();
        package
            .write_all(br#"{"name":"fixture-app","version":"1.0.0","main":"main.js","dependencies":{"electron":"^31.0.0"}}"#)
            .unwrap();
        let mut main = fs::File::create(app.join("main.js")).unwrap();
        main.write_all(
            br#"const { app, BrowserWindow, ipcMain } = require('electron');
const { greet } = require('./lib/util.js');
ipcMain.handle('fixture:greet', async () => greet('x'));
app.whenReady().then(() => {});
"#,
        )
        .unwrap();
        let mut util = fs::File::create(app.join("lib/util.js")).unwrap();
        util.write_all(b"function greet(n) { return 'hi ' + n; }\nmodule.exports = { greet };\n")
            .unwrap();
        let config = fixture_config(&root);
        let args = json!({"target": app.display().to_string()});
        let value = analyze_javascript_application(&Registry::new(), &config, &args).unwrap();
        let graph = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == "module_graph")
            .expect("graph finding");
        let edges = graph["facts"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["to"], "lib/util.js");
        let external = graph["facts"]["external"].as_array().unwrap();
        assert!(external.iter().any(|e| e == "electron"));
        let boundaries = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == "electron_boundaries")
            .expect("boundaries finding");
        let channels = &boundaries["facts"]["modules"][0]["boundaries"]["ipc_handle"];
        assert_eq!(channels[0], "fixture:greet");
        fs::remove_dir_all(&root).ok();
    }
}
