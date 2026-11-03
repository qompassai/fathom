//! Mesh-format censuses (R8): FBX binary and glTF.
//!
//! FBX binary: the census reads the file header and
//! walks the node tree, recording node names and counts
//! only — property payloads are skipped by their
//! declared list length, never interpreted, and full
//! FBX geometry parsing is out of scope by design. Both
//! node-record widths are handled (32-bit offsets before
//! format version 7500, 64-bit from 7500). The walk is
//! depth- and count-bounded and fails closed on any
//! offset that does not advance or leaves the parent.
//!
//! glTF: `.gltf` is JSON and `.glb` carries the same
//! JSON in its first chunk; the census reports nodes,
//! meshes with per-primitive morph-target counts (the
//! facial-expression channel of the format), skins and
//! joint counts, animations, and materials — structure
//! as data, no geometry decoding.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, FBX_DEPTH_MAX, FBX_NODES_MAX, GLTF_BYTES_MAX, GLTF_ITEMS_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

const FBX_MAGIC: &[u8; 23] = b"Kaydara FBX Binary  \x00\x1a\x00";
/// Format version at which node records widen to u64.
const FBX_WIDE_FROM: u32 = 7500;

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

fn read_at(file: &mut File, offset: u64, count: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| mismatch(format!("cannot seek mesh file: {error}")))?;
    let mut buffer = vec![0u8; count];
    file.read_exact(&mut buffer)
        .map_err(|error| mismatch(format!("cannot read mesh file: {error}")))?;
    Ok(buffer)
}

// ---------------------------------------------------------------- FBX

/// Accumulates the FBX node census.
#[derive(Default)]
struct FbxWalk {
    /// Total nodes visited (excluding null sentinels).
    nodes: u64,
    /// Node-name histogram.
    names: std::collections::BTreeMap<String, u64>,
    /// Deepest nesting seen.
    max_depth: usize,
}

/// Read one node record at `pos` in `bytes` (the whole
/// file, bounded by the archive target bound); returns
/// the offset just past the node and whether it was the
/// null sentinel. `wide` selects the u64 record form.
fn fbx_node(
    bytes: &[u8],
    pos: usize,
    parent_end: usize,
    wide: bool,
    depth: usize,
    walk: &mut FbxWalk,
) -> Result<(usize, bool)> {
    let word = if wide { 8 } else { 4 };
    let header_len = word * 3 + 1;
    let header = bytes
        .get(pos..pos + header_len)
        .ok_or_else(|| mismatch("fbx node header is truncated".into()))?;
    let read_word = |at: usize| -> u64 {
        if wide {
            u64::from_le_bytes(header[at..at + 8].try_into().unwrap_or([0; 8]))
        } else {
            u32::from_le_bytes(header[at..at + 4].try_into().unwrap_or([0; 4])) as u64
        }
    };
    let end = read_word(0) as usize;
    if end == 0 {
        // Null sentinel record.
        return Ok((pos + header_len, true));
    }
    if end <= pos || end > parent_end || end > bytes.len() {
        return Err(mismatch("fbx node end offset leaves its parent".into()));
    }
    let property_len = read_word(word * 2) as usize;
    let name_len = header[word * 3] as usize;
    let name_at = pos + header_len;
    let name_bytes = bytes
        .get(name_at..name_at + name_len)
        .ok_or_else(|| mismatch("fbx node name is truncated".into()))?;
    let name = String::from_utf8(name_bytes.to_vec())
        .map_err(|_| mismatch("fbx node name is not UTF-8".into()))?;
    walk.nodes += 1;
    if walk.nodes > FBX_NODES_MAX as u64 {
        return Err(mismatch("fbx node count exceeds the census bound".into()));
    }
    *walk.names.entry(name).or_insert(0) += 1;
    walk.max_depth = walk.max_depth.max(depth);
    let children_at = name_at + name_len + property_len;
    if children_at > end {
        return Err(mismatch("fbx node properties overrun the node".into()));
    }
    // Children live between the property block and the
    // end offset; a node whose remaining room equals one
    // sentinel has no children (leaf data nodes carry no
    // trailing sentinel when the space is exact).
    if depth + 1 > FBX_DEPTH_MAX {
        return Err(mismatch("fbx nesting exceeds the census bound".into()));
    }
    let sentinel = header_len;
    let mut cursor = children_at;
    while cursor + sentinel <= end {
        let (next, was_null) = fbx_node(bytes, cursor, end, wide, depth + 1, walk)?;
        if next <= cursor {
            return Err(mismatch("fbx node walk does not advance".into()));
        }
        cursor = next;
        if was_null {
            break;
        }
    }
    if cursor != end {
        return Err(mismatch(
            "fbx node children do not tile the node exactly".into(),
        ));
    }
    Ok((end, false))
}

pub fn inspect_fbx_binary(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut evidence = Evidence::new("inspect_fbx_binary", "mesh");
    evidence.subject = Some(subject);
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open fbx file: {error}")))?;
    let bytes = read_at(&mut file, 0, file_len as usize)?;
    if bytes.len() < 27 || &bytes[0..23] != FBX_MAGIC {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target lacks the FBX binary magic (Kaydara FBX Binary)",
        ));
    }
    let version = u32::from_le_bytes(bytes[23..27].try_into().unwrap_or([0; 4]));
    let wide = version >= FBX_WIDE_FROM;
    let mut walk = FbxWalk::default();
    let mut pos = 27usize;
    while pos < bytes.len() {
        let (next, was_null) = fbx_node(&bytes, pos, bytes.len(), wide, 0, &mut walk)?;
        if next <= pos {
            return Err(mismatch("fbx top-level walk does not advance".into()));
        }
        pos = next;
        if was_null {
            break;
        }
    }
    let histogram: Vec<Value> = walk
        .names
        .iter()
        .map(|(name, count)| json!({"count": count, "name": name}))
        .collect();
    let document = json!({
        "node_names": histogram,
        "nodes": walk.nodes,
        "version": version,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "fbx_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let count_of = |name: &str| walk.names.get(name).copied().unwrap_or(0);
    evidence.add_finding(Finding::new(
        "fbx_binary",
        Confidence::Observed,
        json!({
            "counts": {
                "deformers": count_of("Deformer"),
                "geometries": count_of("Geometry"),
                "materials": count_of("Material"),
                "models": count_of("Model"),
                "textures": count_of("Texture"),
            },
            "export_digest": digest,
            "format": "FBX binary (node-tree census; properties not interpreted)",
            "max_depth": walk.max_depth,
            "nodes": walk.nodes,
            "target_sha256": sha256,
            "version": version,
        }),
    ));
    evidence.add_finding(Finding::new(
        "node_names",
        Confidence::Observed,
        json!({
            "entries": document["node_names"],
            "returned": walk.names.len(),
            "total": walk.names.len(),
        }),
    ));
    evidence.add_unknown(
        "geometry",
        "FBX property payloads (vertices, indices, skin weights) are skipped by declared length, not parsed",
    );
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

// ---------------------------------------------------------------- glTF

/// Extract the JSON document of a .gltf or .glb file.
fn gltf_document(bytes: &[u8]) -> Result<Value> {
    if bytes.starts_with(b"glTF") {
        // GLB: 12-byte header, then the JSON chunk
        // (length + "JSON" + payload).
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0; 4]));
        if version != 2 {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!("GLB version {version} is not supported (2 only)"),
            ));
        }
        let json_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap_or([0; 4])) as usize;
        if bytes.get(16..20) != Some(b"JSON") {
            return Err(mismatch("glb first chunk is not JSON".into()));
        }
        let json_bytes = bytes
            .get(20..20 + json_len)
            .ok_or_else(|| mismatch("glb JSON chunk is truncated".into()))?;
        serde_json::from_slice(json_bytes)
            .map_err(|error| mismatch(format!("glb JSON does not parse: {error}")))
    } else {
        serde_json::from_slice(bytes)
            .map_err(|error| mismatch(format!("gltf JSON does not parse: {error}")))
    }
}

fn array_len(document: &Value, key: &str) -> usize {
    document[key].as_array().map_or(0, Vec::len)
}

pub fn inspect_gltf_model(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    if file_len > GLTF_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "gltf file exceeds the census read bound",
        ));
    }
    let mut evidence = Evidence::new("inspect_gltf_model", "mesh");
    evidence.subject = Some(subject);
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open gltf file: {error}")))?;
    let bytes = read_at(&mut file, 0, file_len as usize)?;
    let document = gltf_document(&bytes)?;
    if array_len(&document, "nodes") > GLTF_ITEMS_MAX
        || array_len(&document, "meshes") > GLTF_ITEMS_MAX
    {
        return Err(mismatch("gltf item counts exceed the census bound".into()));
    }
    let node_names: Vec<Value> = document["nodes"]
        .as_array()
        .map(|nodes| {
            nodes
                .iter()
                .map(|node| json!({"mesh": node["mesh"], "name": node["name"], "skin": node["skin"]}))
                .collect()
        })
        .unwrap_or_default();
    let meshes: Vec<Value> = document["meshes"]
        .as_array()
        .map(|meshes| {
            meshes
                .iter()
                .map(|mesh| {
                    let primitives = mesh["primitives"].as_array();
                    let morph_targets: Vec<usize> = primitives
                        .map(|rows| {
                            rows.iter()
                                .map(|prim| prim["targets"].as_array().map_or(0, Vec::len))
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({
                        "morph_targets": morph_targets,
                        "name": mesh["name"],
                        "primitives": primitives.map_or(0, Vec::len),
                        "target_names": mesh["extras"]["targetNames"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let skins: Vec<Value> = document["skins"]
        .as_array()
        .map(|skins| {
            skins
                .iter()
                .map(|skin| {
                    json!({
                        "joints": skin["joints"].as_array().map_or(0, Vec::len),
                        "name": skin["name"],
                        "skeleton": skin["skeleton"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let animations: Vec<Value> = document["animations"]
        .as_array()
        .map(|animations| {
            animations
                .iter()
                .map(|anim| {
                    json!({
                        "channels": anim["channels"].as_array().map_or(0, Vec::len),
                        "name": anim["name"],
                        "samplers": anim["samplers"].as_array().map_or(0, Vec::len),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let facts = json!({
        "animations": animations,
        "asset_version": document["asset"]["version"],
        "counts": {
            "accessors": array_len(&document, "accessors"),
            "animations": array_len(&document, "animations"),
            "images": array_len(&document, "images"),
            "materials": array_len(&document, "materials"),
            "meshes": array_len(&document, "meshes"),
            "nodes": array_len(&document, "nodes"),
            "scenes": array_len(&document, "scenes"),
            "skins": array_len(&document, "skins"),
            "textures": array_len(&document, "textures"),
        },
        "format": "glTF (JSON structure census; buffers not decoded)",
        "meshes": meshes,
        "nodes": node_names,
        "skins": skins,
        "target_sha256": sha256,
    });
    let retained = json!({
        "animations": facts["animations"],
        "counts": facts["counts"],
        "meshes": facts["meshes"],
        "nodes": facts["nodes"],
        "skins": facts["skins"],
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "gltf_census", &retained) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut facts = facts;
    facts["export_digest"] = json!(digest);
    evidence.add_finding(Finding::new("gltf_model", Confidence::Observed, facts));
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

    /// Build a minimal wide-format (v7500) FBX with one
    /// top-level "Objects" node holding one "Geometry"
    /// leaf with a 4-byte property block and a sentinel.
    /// Node end offsets are absolute file offsets, as in
    /// the format.
    fn build_fbx() -> Vec<u8> {
        fn node(start: usize, name: &str, props: &[u8], children: &[u8]) -> Vec<u8> {
            let header = 8 * 3 + 1;
            let total = header + name.len() + props.len() + children.len();
            let mut out = Vec::new();
            out.extend_from_slice(&((start + total) as u64).to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&(props.len() as u64).to_le_bytes());
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(props);
            out.extend_from_slice(children);
            out
        }
        let sentinel_len = 8 * 3 + 1;
        // Objects starts at 27; its header+name is 32
        // bytes, so Geometry starts at 59.
        let geometry = node(59, "Geometry", &[1, 2, 3, 4], &vec![0u8; sentinel_len]);
        let objects = node(27, "Objects", &[], &geometry);
        let mut out = Vec::new();
        out.extend_from_slice(FBX_MAGIC);
        out.extend_from_slice(&7500u32.to_le_bytes());
        out.extend_from_slice(&objects);
        out.extend_from_slice(&vec![0u8; sentinel_len]);
        out
    }

    #[test]
    fn validation_fbx_walk_counts_nodes() {
        let bytes = build_fbx();
        let mut walk = FbxWalk::default();
        let mut pos = 27usize;
        while pos < bytes.len() {
            let (next, was_null) =
                fbx_node(&bytes, pos, bytes.len(), true, 0, &mut walk).expect("walk");
            pos = next;
            if was_null {
                break;
            }
        }
        assert_eq!(pos, bytes.len());
        assert_eq!(walk.nodes, 2);
        assert_eq!(walk.names.get("Geometry"), Some(&1));
        assert_eq!(walk.names.get("Objects"), Some(&1));
    }

    #[test]
    fn adversarial_fbx_node_end_out_of_parent_is_refused() {
        let mut bytes = build_fbx();
        // Corrupt the Objects node end offset (at 27).
        bytes[27..35].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut walk = FbxWalk::default();
        let result = fbx_node(&bytes, 27, bytes.len(), true, 0, &mut walk);
        assert!(result.is_err());
    }

    #[test]
    fn validation_gltf_json_census() {
        let document = json!({
            "asset": {"version": "2.0"},
            "meshes": [{
                "name": "face",
                "primitives": [{"targets": [{"POSITION": 1}, {"POSITION": 2}]}],
                "extras": {"targetNames": ["smile", "blink"]}
            }],
            "nodes": [{"name": "root", "mesh": 0, "skin": 0}],
            "skins": [{"name": "armature", "joints": [0, 1, 2]}],
            "animations": [{"name": "idle", "channels": [{}], "samplers": [{}]}],
            "scenes": [{}],
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let parsed = gltf_document(&bytes).expect("parse");
        assert_eq!(array_len(&parsed, "meshes"), 1);
        assert_eq!(
            parsed["meshes"][0]["primitives"][0]["targets"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn adversarial_glb_bad_version_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"glTF");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&20u32.to_le_bytes());
        let result = gltf_document(&bytes);
        assert!(result.is_err());
    }
}
