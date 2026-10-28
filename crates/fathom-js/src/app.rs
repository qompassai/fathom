//! `analyze_javascript_application` (SPEC §9.2): walk an
//! application root, analyze every module, resolve the relative
//! module graph, and aggregate the Electron boundary. Parse
//! errors are findings, not run failures; a module that does not
//! parse is named in the unknowns, never silently skipped.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding};
use fathom_core::limits::FILE_COUNT_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::analyzer::{ModuleFacts, analyze_source};
use crate::sourcemap::{MAP_BYTES_MAX, parse_source_map};

const EXTENSIONS: [&str; 8] = ["js", "cjs", "mjs", "ts", "tsx", "jsx", "mts", "cts"];
/// Per-module read bound; larger modules are reported, not parsed.
const MODULE_BYTES_MAX: u64 = 8_388_608;

/// App-wide literal-channel usage by direction, the input to
/// the IPC pairing summary.
#[derive(Default)]
struct IpcCounts {
    handle: usize,
    invoke: usize,
    on: usize,
    send: usize,
    send_sync: usize,
}

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
    let mut source_map_rows = Vec::new();
    let mut parse_error_rows = Vec::new();
    let mut electron_rows = Vec::new();
    let mut channel_counts: BTreeMap<String, IpcCounts> = BTreeMap::new();
    let mut dynamic_site_total = 0usize;
    let file_set: BTreeSet<PathBuf> = files.iter().cloned().collect();

    for file in &files {
        let relative = relative_string(&root, file);
        if file.extension().is_some_and(|ext| ext == "map") {
            source_maps.push(relative.clone());
            source_map_rows.push(source_map_row(file, relative));
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
        if !facts.electron.ipc_dynamic.is_empty() {
            dynamic_site_total += facts.electron.ipc_dynamic.len();
            let shapes: BTreeSet<String> = facts
                .electron
                .ipc_dynamic
                .iter()
                .map(|site| format!("{} ({})", site.api, site.expression))
                .collect();
            evidence.add_unknown(
                format!("module {relative}"),
                format!(
                    "computed IPC channel name not resolvable statically at {} call site(s): {}",
                    facts.electron.ipc_dynamic.len(),
                    shapes.iter().cloned().collect::<Vec<_>>().join(", "),
                ),
            );
        }
        for channel in &facts.electron.ipc_handle {
            channel_counts.entry(channel.clone()).or_default().handle += 1;
        }
        for channel in &facts.electron.ipc_invoke {
            channel_counts.entry(channel.clone()).or_default().invoke += 1;
        }
        for channel in &facts.electron.ipc_on {
            channel_counts.entry(channel.clone()).or_default().on += 1;
        }
        for channel in &facts.electron.ipc_send {
            channel_counts.entry(channel.clone()).or_default().send += 1;
        }
        for channel in &facts.electron.ipc_send_sync {
            channel_counts.entry(channel.clone()).or_default().send_sync += 1;
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
    if !channel_counts.is_empty() || dynamic_site_total > 0 {
        let mut channel_rows = Vec::new();
        let mut ambiguous_names = Vec::new();
        let (mut paired, mut ambiguous, mut unmatched) = (0usize, 0usize, 0usize);
        for (name, counts) in &channel_counts {
            let status = ipc_pairing_status(counts);
            match status {
                "ambiguous" => {
                    ambiguous += 1;
                    ambiguous_names.push(name.clone());
                }
                "paired" => paired += 1,
                _ => unmatched += 1,
            }
            channel_rows.push(json!({
                "channel": name,
                "handle": counts.handle,
                "invoke": counts.invoke,
                "on": counts.on,
                "send": counts.send,
                "send_sync": counts.send_sync,
                "status": status,
            }));
        }
        let mut pairing = Finding::new(
            "ipc_pairing",
            Confidence::Derived,
            json!({
                "ambiguous": ambiguous_names,
                "channels": channel_rows,
                "counts": {
                    "ambiguous": ambiguous,
                    "channels": channel_counts.len(),
                    "paired": paired,
                    "unmatched": unmatched,
                },
                "dynamic_sites": dynamic_site_total,
            }),
        );
        if dynamic_site_total > 0 {
            pairing = pairing.with_limitation(format!(
                "pairing covers literal channels only: {dynamic_site_total} computed channel site(s) cannot be paired"
            ));
        }
        if !parse_error_rows.is_empty() {
            pairing = pairing
                .with_limitation("pairing is partial: unparseable modules contribute no channels");
        }
        evidence.add_finding(pairing);
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
            json!({"files": source_maps, "maps": source_map_rows}),
        ));
    }
    evidence.coverage.examined = files.len() as u64;
    evidence.coverage.total = files.len() as u64;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

/// One parsed source-map row for the `source_maps` finding. A map
/// that does not parse is named with its typed error, never
/// silently dropped (the SPEC §9.2 inventory rule).
fn source_map_row(file: &Path, relative: String) -> Value {
    let oversized = fs::metadata(file).is_ok_and(|metadata| metadata.len() > MAP_BYTES_MAX);
    if oversized {
        return json!({"error": "resource_constraint", "file": relative});
    }
    match fs::read_to_string(file) {
        Ok(text) => match parse_source_map(&text) {
            Ok(map) => json!({
                "file": relative,
                "names_count": map.names.len(),
                "segment_count": map.segment_count,
                "sources_count": map.sources.len(),
                "sources_content_present": map
                    .sources_content_present
                    .iter()
                    .filter(|present| **present)
                    .count(),
            }),
            Err(error) => json!({"error": format!("{:?}", error.code), "file": relative}),
        },
        Err(_) => json!({"error": "unreadable", "file": relative}),
    }
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

/// Pairing verdict for one literal channel, from its app-wide
/// usage counts. A channel registered in the main process with
/// both `handle` and `on` is ambiguous — transmissions on it
/// have two receiver styles — and is never reported as paired.
/// A channel is paired only when every direction present has
/// its counterpart (invoke ↔ handle, send/sendSync ↔ on) and
/// at least one complete pair exists; anything else is
/// unmatched, listed rather than silently dropped.
fn ipc_pairing_status(counts: &IpcCounts) -> &'static str {
    if counts.handle > 0 && counts.on > 0 {
        return "ambiguous";
    }
    let invoke_balanced = (counts.invoke == 0) == (counts.handle == 0);
    let send_balanced = (counts.send + counts.send_sync == 0) == (counts.on == 0);
    let any_pair = (counts.invoke > 0 && counts.handle > 0)
        || (counts.send + counts.send_sync > 0 && counts.on > 0);
    if invoke_balanced && send_balanced && any_pair {
        "paired"
    } else {
        "unmatched"
    }
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

    fn run_fixture(test_name: &str, files: &[(&str, &str)]) -> (PathBuf, Value) {
        let root =
            std::env::temp_dir().join(format!("fathom-js-test-{}-{test_name}", std::process::id()));
        let app = root.join("app");
        for (relative, contents) in files {
            let path = app.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
        }
        let config = fixture_config(&root);
        let args = json!({"target": app.display().to_string()});
        let value = analyze_javascript_application(&Registry::new(), &config, &args).unwrap();
        (root, value)
    }

    fn pairing_finding(value: &Value) -> &Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == "ipc_pairing")
            .expect("ipc_pairing finding")
    }

    #[test]
    fn adversarial_ambiguous_channel_is_not_paired() {
        let (root, value) = run_fixture(
            "ambiguous",
            &[
                (
                    "main.js",
                    "const { ipcMain } = require('electron');\nipcMain.handle('dup', () => {});\nipcMain.on('dup', () => {});\n",
                ),
                (
                    "preload.js",
                    "const { ipcRenderer } = require('electron');\nipcRenderer.invoke('dup');\n",
                ),
            ],
        );
        let pairing = pairing_finding(&value);
        assert_eq!(pairing["facts"]["counts"]["paired"], 0);
        assert_eq!(pairing["facts"]["counts"]["ambiguous"], 1);
        assert_eq!(pairing["facts"]["ambiguous"][0], "dup");
        let channels = pairing["facts"]["channels"].as_array().unwrap();
        assert_eq!(channels[0]["status"], "ambiguous");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_unmatched_endpoints_are_listed_not_paired() {
        let (root, value) = run_fixture(
            "unmatched",
            &[
                (
                    "main.js",
                    "const { ipcMain } = require('electron');\nipcMain.handle('main:only', () => {});\n",
                ),
                (
                    "preload.js",
                    "const { ipcRenderer } = require('electron');\nipcRenderer.send('renderer:only');\n",
                ),
            ],
        );
        let pairing = pairing_finding(&value);
        assert_eq!(pairing["facts"]["counts"]["paired"], 0);
        assert_eq!(pairing["facts"]["counts"]["unmatched"], 2);
        let channels = pairing["facts"]["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 2);
        assert!(
            channels
                .iter()
                .all(|channel| channel["status"] == "unmatched")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_dynamic_channel_site_is_an_unknown() {
        let (root, value) = run_fixture(
            "dynamic",
            &[(
                "main.js",
                "const { ipcMain } = require('electron');\nconst c = process.env.CH;\nipcMain.handle(c, () => {});\n",
            )],
        );
        let unknowns = value["unknowns"].as_array().unwrap();
        let unknown = unknowns
            .iter()
            .find(|u| u["aspect"] == "module main.js")
            .expect("dynamic-site unknown");
        let reason = unknown["reason"].as_str().unwrap();
        assert!(
            reason.contains("computed IPC channel name not resolvable statically"),
            "{reason}"
        );
        assert!(reason.contains("ipcMain.handle (identifier)"), "{reason}");
        let pairing = pairing_finding(&value);
        assert_eq!(pairing["facts"]["dynamic_sites"], 1);
        assert_eq!(pairing["facts"]["counts"]["channels"], 0);
        let limitations = pairing["limitations"].as_array().unwrap();
        assert!(
            limitations
                .iter()
                .any(|l| l.as_str().unwrap().contains("computed channel site")),
            "{limitations:?}"
        );
        fs::remove_dir_all(&root).ok();
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

    #[test]
    fn validation_ipc_pairing_summary() {
        let (root, value) = run_fixture(
            "pairing",
            &[
                (
                    "main.js",
                    "const { ipcMain } = require('electron');\nipcMain.handle('fixture:greet', () => {});\nipcMain.on('fixture:ping', () => {});\n",
                ),
                (
                    "preload.js",
                    "const { ipcRenderer } = require('electron');\nipcRenderer.invoke('fixture:greet');\nipcRenderer.send('fixture:ping');\n",
                ),
            ],
        );
        let pairing = pairing_finding(&value);
        assert_eq!(pairing["facts"]["counts"]["channels"], 2);
        assert_eq!(pairing["facts"]["counts"]["paired"], 2);
        assert_eq!(pairing["facts"]["counts"]["ambiguous"], 0);
        assert_eq!(pairing["facts"]["counts"]["unmatched"], 0);
        assert_eq!(pairing["facts"]["dynamic_sites"], 0);
        let channels = pairing["facts"]["channels"].as_array().unwrap();
        assert!(
            channels.iter().all(|channel| channel["status"] == "paired"),
            "{channels:?}"
        );
        fs::remove_dir_all(&root).ok();
    }
}
