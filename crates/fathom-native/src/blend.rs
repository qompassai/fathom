//! Blender-backed mesh census (R8): an operator-
//! configured external backend, in the shape of the
//! estate's other program providers.
//!
//! The tool runs the configured Blender binary headless
//! with factory startup, no audio, and automatic script
//! execution DISABLED, so a studied .blend file's own
//! embedded scripts never run; the only Python executed
//! is fathom's own census script, which loads the
//! target (open for .blend, import for .fbx/.gltf/.glb/
//! .obj), walks bpy.data, and prints one JSON census
//! between markers. An optional glTF (GLB) export is
//! written to a caller-named output directory so the
//! export can be re-censused by inspect_gltf_model.
//! The backend is Execute-class: default-deny plus the
//! provider configuration are both required.

use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{ARCHIVE_TARGET_BYTES_MAX, PROCESS_OUTPUT_BYTES_MAX};
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run};
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

/// Seconds the Blender backend may run before the
/// process group is killed.
const BLEND_TIMEOUT_SECS: u64 = 600;

/// Extensions the backend census accepts.
const SUPPORTED_EXTENSIONS: [&str; 5] = ["blend", "fbx", "glb", "gltf", "obj"];

/// The census script. It loads the target named after
/// `--`, walks bpy.data defensively (Blender 5 actions
/// are layered; fcurve counts fall back to channel
/// bags), optionally exports GLB, and prints its JSON
/// between the FATHOM markers.
const CENSUS_SCRIPT: &str = r##"
import bpy
import json
import sys


def fcurve_count(action):
    total = 0
    try:
        total += len(action.fcurves)
    except Exception:
        pass
    try:
        for layer in action.layers:
            for strip in layer.strips:
                bag = getattr(strip, "channelbag", None)
                if bag is not None:
                    total += len(bag.fcurves)
    except Exception:
        pass
    return total


def main():
    argv = sys.argv[sys.argv.index("--") + 1:]
    target = argv[0]
    gltf_out = argv[1] if len(argv) > 1 else ""
    extension = target.rsplit(".", 1)[-1].lower()
    bpy.ops.wm.read_factory_settings(use_empty=True)
    if extension == "blend":
        bpy.ops.wm.open_mainfile(filepath=target)
    elif extension == "fbx":
        bpy.ops.import_scene.fbx(filepath=target)
    elif extension in ("gltf", "glb"):
        bpy.ops.import_scene.gltf(filepath=target)
    elif extension == "obj":
        bpy.ops.wm.obj_import(filepath=target)
    else:
        raise SystemExit("unsupported extension: " + extension)
    objects = []
    for obj in bpy.data.objects:
        row = {
            "name": obj.name,
            "parent": obj.parent.name if obj.parent else None,
            "type": obj.type,
        }
        if obj.type == "MESH":
            row["polygons"] = len(obj.data.polygons)
            row["vertices"] = len(obj.data.vertices)
            keys = []
            if obj.data.shape_keys:
                keys = [block.name for block in obj.data.shape_keys.key_blocks]
            row["shape_keys"] = keys
        if obj.type == "ARMATURE":
            row["bones"] = [bone.name for bone in obj.data.bones]
        objects.append(row)
    actions = [
        {"fcurves": fcurve_count(action), "name": action.name}
        for action in bpy.data.actions
    ]
    exported = None
    if gltf_out:
        bpy.ops.export_scene.gltf(filepath=gltf_out, export_format="GLB")
        exported = gltf_out
    result = {
        "actions": actions,
        "blender_version": bpy.app.version_string,
        "exported": exported,
        "materials": len(bpy.data.materials),
        "objects": objects,
    }
    print("FATHOM_BLEND_JSON_BEGIN")
    print(json.dumps(result))
    print("FATHOM_BLEND_JSON_END")


main()
"##;

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

/// Extract the marked JSON document from Blender's
/// stdout.
fn extract_census(stdout: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(stdout);
    let begin = text
        .find("FATHOM_BLEND_JSON_BEGIN")
        .ok_or_else(|| mismatch("blender census markers are absent from the output".into()))?;
    let end = text
        .find("FATHOM_BLEND_JSON_END")
        .ok_or_else(|| mismatch("blender census end marker is absent".into()))?;
    let body = text[begin..end]
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str(&body)
        .map_err(|error| mismatch(format!("blender census JSON does not parse: {error}")))
}

pub fn census_blend_file(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let target = require_str(args, "target")?;
    let path = paths::validate_target(config, Path::new(target))?;
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !SUPPORTED_EXTENSIONS.contains(&extension.as_str()) {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "blend census supports {}; got .{extension}",
                SUPPORTED_EXTENSIONS.join("/")
            ),
        ));
    }
    let program = config.blender_program.clone().ok_or_else(|| {
        FathomError::new(
            ErrorCode::ConfigurationInvalid,
            "providers.blender.program is not configured; the Blender backend is unavailable",
        )
    })?;
    let export_gltf = args
        .get("export_gltf")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut gltf_path: Option<PathBuf> = None;
    if export_gltf {
        let output_dir_raw = require_str(args, "output_dir")?;
        let output_dir = paths::validate_output_dir(config, Path::new(output_dir_raw))?;
        std::fs::create_dir_all(&output_dir).map_err(|error| {
            FathomError::new(
                ErrorCode::ArtifactOperationFailed,
                format!("cannot create gltf output directory: {error}"),
            )
        })?;
        let stem = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("model");
        gltf_path = Some(output_dir.join(format!("{stem}.glb")));
    }
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let mut evidence = Evidence::new("census_blend_file", "blender");
    evidence.subject = Some(subject);
    // Stage the census script inside the state dir.
    let script_path = config
        .state_dir
        .join(format!("blend-census-{}.py", std::process::id()));
    std::fs::create_dir_all(&config.state_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot create state directory: {error}"),
        )
    })?;
    std::fs::write(&script_path, CENSUS_SCRIPT).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot stage the blender census script: {error}"),
        )
    })?;
    let mut argv: Vec<String> = vec![
        "--background".into(),
        "--factory-startup".into(),
        "-noaudio".into(),
        "--disable-autoexec".into(),
        "--python".into(),
        script_path.display().to_string(),
        "--".into(),
        path.display().to_string(),
    ];
    if let Some(gltf) = &gltf_path {
        argv.push(gltf.display().to_string());
    }
    let spec = ProcessSpec {
        args: argv,
        cwd: None,
        env: Vec::new(),
        output_cap: PROCESS_OUTPUT_BYTES_MAX,
        program: program.display().to_string(),
        timeout: std::time::Duration::from_secs(BLEND_TIMEOUT_SECS),
    };
    let outcome = run(&spec).map_err(|error| {
        FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!("cannot run the blender backend: {}", error.message),
        )
    })?;
    let _ = std::fs::remove_file(&script_path);
    if outcome.exit_code != Some(0) {
        let tail: String = String::from_utf8_lossy(&outcome.stderr)
            .chars()
            .rev()
            .take(400)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        return Err(mismatch(format!(
            "blender backend exited with {:?}; stderr tail: {tail}",
            outcome.exit_code
        )));
    }
    let census = extract_census(&outcome.stdout)?;
    let objects = census["objects"].as_array().cloned().unwrap_or_default();
    let armatures = objects
        .iter()
        .filter(|row| row["type"] == "ARMATURE")
        .count();
    let bones: u64 = objects
        .iter()
        .map(|row| row["bones"].as_array().map_or(0, Vec::len) as u64)
        .sum();
    let shape_key_rows = objects
        .iter()
        .filter(|row| {
            row["shape_keys"]
                .as_array()
                .is_some_and(|keys| !keys.is_empty())
        })
        .count();
    let retained = json!({
        "actions": census["actions"],
        "blender_version": census["blender_version"],
        "materials": census["materials"],
        "objects": census["objects"],
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "blend_census", &retained) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "blend_census",
        Confidence::Observed,
        json!({
            "actions_count": census["actions"].as_array().map_or(0, Vec::len),
            "armatures": armatures,
            "backend_program": program.display().to_string(),
            "blender_version": census["blender_version"],
            "bones_total": bones,
            "export_digest": digest,
            "exported_gltf": gltf_path.as_ref().map(|p| p.display().to_string()),
            "format": "Blender headless census (autoexec disabled; factory startup)",
            "materials": census["materials"],
            "objects": objects.len(),
            "objects_with_shape_keys": shape_key_rows,
            "target_sha256": sha256,
        }),
    ));
    evidence.add_finding(Finding::new(
        "objects",
        Confidence::Observed,
        json!({
            "entries": census["objects"],
            "returned": objects.len(),
            "total": objects.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "actions",
        Confidence::Observed,
        json!({
            "entries": census["actions"],
            "returned": census["actions"].as_array().map_or(0, Vec::len),
            "total": census["actions"].as_array().map_or(0, Vec::len),
        }),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_extract_census_reads_marked_json() {
        let stdout = b"noise\nFATHOM_BLEND_JSON_BEGIN\n{\"objects\": []}\nFATHOM_BLEND_JSON_END\n";
        let value = extract_census(stdout).expect("extract");
        assert_eq!(value["objects"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn adversarial_extract_census_without_markers_is_refused() {
        assert!(extract_census(b"{\"objects\": []}").is_err());
    }
}
