//! UI structure census (R10): how each title BUILDS
//! its UI, as reconstructable structure.
//!
//! - Ren'Py: screen definitions from .rpy sources —
//!   screen names plus the widget-keyword structure of
//!   each screen block (indent-tracked).
//! - RPG Maker MV/MZ: the plugin list from
//!   js/plugins.js (names, enabled status) and the
//!   Window_*/Sprite_* class census of the js sources
//!   (the engine's UI class layer).
//! - Electron/NW.js: the HTML/CSS/JS file census plus
//!   framework fingerprints found in the markup and
//!   scripts (react/vue/angular/svelte/jquery/electron
//!   markers) — for these titles the web tree IS the UI.
//! - Unity uGUI and Unreal UMG are NOT walked here:
//!   uGUI hierarchy needs SerializedFile typetrees (the
//!   named G5 limit), and UMG structure rides the
//!   inspect_uasset_package class census
//!   (WidgetBlueprintGeneratedClass / WidgetTree / slot
//!   and widget classes). Both are reported as unknowns
//!   with the reason, per the honesty contract.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::limits::{DIALOGUE_FILE_BYTES_MAX, DIALOGUE_FILES_MAX, GAME_WALK_DEPTH_MAX};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

/// Ren'Py screen-language widget keywords counted in
/// screen blocks.
const SCREEN_WIDGETS: [&str; 16] = [
    "add",
    "bar",
    "button",
    "frame",
    "grid",
    "hbox",
    "imagebutton",
    "input",
    "key",
    "label",
    "text",
    "textbutton",
    "timer",
    "vbox",
    "viewport",
    "window",
];

/// Framework fingerprint markers searched in Electron
/// markup/scripts: (name, needle).
const FRAMEWORK_MARKERS: [(&str, &str); 7] = [
    ("angular", "ng-app"),
    ("electron-ipc", "ipcRenderer"),
    ("jquery", "jQuery"),
    ("react", "ReactDOM"),
    ("react-jsx", "jsx-runtime"),
    ("svelte", "svelte"),
    ("vue", "createApp"),
];

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .map_err(|error| mismatch(format!("cannot open {}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(DIALOGUE_FILE_BYTES_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| mismatch(format!("cannot read {}: {error}", path.display())))?;
    if bytes.len() as u64 > DIALOGUE_FILE_BYTES_MAX {
        return Err(mismatch("file exceeds the UI census bound".into()));
    }
    Ok(bytes)
}

/// Census the screens of one .rpy source: returns
/// (screen rows, widget totals).
fn census_screens(text: &str) -> (Vec<Value>, BTreeMap<String, usize>) {
    let mut screens: Vec<Value> = Vec::new();
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut current: Option<(String, usize, BTreeMap<String, usize>)> = None;
    let flush = |current: &mut Option<(String, usize, BTreeMap<String, usize>)>,
                 screens: &mut Vec<Value>,
                 totals: &mut BTreeMap<String, usize>| {
        if let Some((name, _indent, widgets)) = current.take() {
            for (widget, count) in &widgets {
                *totals.entry(widget.clone()).or_insert(0) += count;
            }
            let widget_rows: Vec<Value> = widgets
                .iter()
                .map(|(widget, count)| json!({"count": count, "widget": widget}))
                .collect();
            screens.push(json!({"name": name, "widgets": widget_rows}));
        }
    };
    for line in text.lines() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if let Some(rest) = trimmed.strip_prefix("screen ") {
            let name = rest
                .split(['(', ':', ' '])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !name.is_empty() {
                flush(&mut current, &mut screens, &mut totals);
                current = Some((name, indent, BTreeMap::new()));
                continue;
            }
        }
        if let Some((_, screen_indent, widgets)) = current.as_mut() {
            if !trimmed.is_empty() && indent <= *screen_indent && !trimmed.starts_with('#') {
                // The block ended; this line belongs to
                // whatever follows.
                let mut done = current.take();
                if let Some((name, _, widgets)) = done.take() {
                    for (widget, count) in &widgets {
                        *totals.entry(widget.clone()).or_insert(0) += count;
                    }
                    let widget_rows: Vec<Value> = widgets
                        .iter()
                        .map(|(widget, count)| json!({"count": count, "widget": widget}))
                        .collect();
                    screens.push(json!({"name": name, "widgets": widget_rows}));
                }
                continue;
            }
            let head = trimmed
                .split([' ', ':', '('])
                .next()
                .unwrap_or("")
                .to_string();
            if SCREEN_WIDGETS.contains(&head.as_str()) {
                *widgets.entry(head).or_insert(0) += 1;
            }
        }
    }
    flush(&mut current, &mut screens, &mut totals);
    (screens, totals)
}

/// Parse the plugin list of one plugins.js source:
/// the `$plugins = [ ... ];` JSON array.
fn census_plugins(text: &str) -> Vec<Value> {
    let Some(start) = text.find('[') else {
        return Vec::new();
    };
    let Some(end) = text.rfind(']') else {
        return Vec::new();
    };
    if end <= start {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_str::<Value>(&text[start..=end]) else {
        return Vec::new();
    };
    parsed
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    json!({
                        "name": row["name"],
                        "status": row["status"],
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn census_ui_tree(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let target = require_str(args, "target")?;
    let root = paths::validate_target(config, Path::new(target))?;
    let mut rpy_files: Vec<PathBuf> = Vec::new();
    let mut plugins_files: Vec<PathBuf> = Vec::new();
    let mut js_files: Vec<PathBuf> = Vec::new();
    let mut web_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut web_samples: Vec<PathBuf> = Vec::new();
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
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let name = child
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if name.ends_with(".rpy") {
                rpy_files.push(child.clone());
            }
            if name == "plugins.js" {
                plugins_files.push(child.clone());
            } else if name.ends_with(".js") {
                js_files.push(child.clone());
            }
            for ext in [".html", ".css", ".js"] {
                if name.ends_with(ext) {
                    *web_counts.entry(&ext[1..]).or_insert(0) += 1;
                    if web_samples.len() < 64 && (ext != ".js" || name == "index.html") {
                        web_samples.push(child.clone());
                    }
                }
            }
        }
    }
    if rpy_files.len() + js_files.len() > DIALOGUE_FILES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "tree holds more UI source files than the census bound",
        ));
    }
    // Ren'Py screens.
    let mut screens: Vec<Value> = Vec::new();
    let mut widget_totals: BTreeMap<String, usize> = BTreeMap::new();
    for path in &rpy_files {
        let bytes = read_bounded(path)?;
        let (rows, totals) = census_screens(&String::from_utf8_lossy(&bytes));
        for (widget, count) in totals {
            *widget_totals.entry(widget).or_insert(0) += count;
        }
        screens.extend(rows);
    }
    // RPG Maker plugins + JS class census.
    let mut plugins: Vec<Value> = Vec::new();
    for path in &plugins_files {
        let bytes = read_bounded(path)?;
        plugins.extend(census_plugins(&String::from_utf8_lossy(&bytes)));
    }
    let mut window_classes = 0usize;
    let mut sprite_classes = 0usize;
    for path in &js_files {
        let Ok(bytes) = read_bounded(path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        window_classes += text.matches("function Window_").count();
        window_classes += text.matches("Window_Base").count().min(1);
        sprite_classes += text.matches("function Sprite_").count();
    }
    // Electron fingerprints over the sampled markup.
    let mut fingerprints: Vec<&str> = Vec::new();
    for path in &web_samples {
        let Ok(bytes) = read_bounded(path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for (name, needle) in FRAMEWORK_MARKERS {
            if text.contains(needle) && !fingerprints.contains(&name) {
                fingerprints.push(name);
            }
        }
    }
    let plugin_rows_total = plugins.len();
    let document = json!({
        "electron": {
            "css_files": web_counts.get("css").copied().unwrap_or(0),
            "fingerprints": fingerprints,
            "html_files": web_counts.get("html").copied().unwrap_or(0),
            "js_files": web_counts.get("js").copied().unwrap_or(0),
        },
        "format": "UI structure census",
        "renpy_screens": screens,
        "rpgmaker": {
            "plugins": plugins,
            "sprite_classes": sprite_classes,
            "window_classes": window_classes,
        },
        "widget_totals": widget_totals,
    });
    let document_hash = sha256_hex(&serde_json::to_vec(&document).unwrap_or_default());
    let (digest, retention_note) =
        match proof::retain_export(config, &document_hash, "ui_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut evidence = Evidence::new("census_ui_tree", "ui");
    evidence.add_finding(Finding::new(
        "ui",
        Confidence::Observed,
        json!({
            "electron": document["electron"],
            "export_digest": digest,
            "format": "UI structure census",
            "plugins_total": plugin_rows_total,
            "renpy_screens": document["renpy_screens"],
            "rpgmaker": document["rpgmaker"],
            "screens_total": document["renpy_screens"].as_array().map_or(0, Vec::len),
            "widget_totals": document["widget_totals"],
        }),
    ));
    evidence.add_unknown(
        "unity_ugui",
        "uGUI Canvas/RectTransform hierarchy needs SerializedFile typetree expansion (gap G5); structure is not claimed from raw MonoBehaviour bytes",
    );
    evidence.add_unknown(
        "unreal_umg",
        "UMG structure rides the inspect_uasset_package class census (WidgetBlueprintGeneratedClass, WidgetTree, slot/widget classes), not this tree walk",
    );
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "UI census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_screens_plugins_fingerprints() {
        let rpy = "screen say(who, what):\n    window:\n        vbox:\n            text who\n            text what\nscreen main_menu():\n    frame:\n        textbutton \"Start\" action Start()\n";
        let (screens, totals) = census_screens(rpy);
        assert_eq!(screens.len(), 2);
        assert_eq!(screens[0]["name"], "say");
        assert_eq!(totals.get("text"), Some(&2));
        assert_eq!(totals.get("textbutton"), Some(&1));
        let plugins = census_plugins(
            "var $plugins = [{\"name\":\"Alpha\",\"status\":true},{\"name\":\"Beta\",\"status\":false}];",
        );
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[1]["name"], "Beta");
        assert_eq!(plugins[1]["status"], false);
    }

    #[test]
    fn adversarial_plugins_without_array_yields_empty() {
        assert!(census_plugins("var x = 1;").is_empty());
        let (screens, _) = census_screens("label start:\n    \"hi\"\n");
        assert!(screens.is_empty());
    }
}
