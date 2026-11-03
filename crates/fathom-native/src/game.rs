//! Game-tree census: engine fingerprinting and the
//! unified extraction manifest (programme rung R2).
//!
//! A game directory (or a bare archive file) is walked
//! once, bounded by the GAME_WALK limits; the walk feeds
//! three products in one manifest: the engine verdict
//! (a fingerprint over directory and file names, with
//! the evidence for the verdict kept), the container
//! inventory (archives and packs with size and SHA-256,
//! each naming the fathom reader that censuses it), and
//! per-class asset counts. The manifest is the shape
//! every later programme rung extends (audio, meshes,
//! dialogue, UI sections join it per-title).
//!
//! Honesty contract: a fingerprint is a name-pattern
//! verdict, not a proof of engine — the evidence lines
//! are the claim, and competing engines are reported as
//! also-detected instead of being hidden by the winner.
//! Chromium `.pak` files (NW.js/Electron locales and
//! resource packs) are explicitly not Unreal evidence.
//! A bare `.zip`/`.apk` target is fingerprinted from its
//! central-directory names without extraction; `.rar`
//! and `.7z` listings are not read (no reader), so those
//! targets record the container and an unknown engine.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, FILE_COUNT_MAX, GAME_WALK_DEPTH_MAX, GAME_WALK_FILES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// One walked file (relative path in `/` form).
struct WalkedFile {
    bytes: u64,
    ext: String,
    name: String,
    rel: String,
}

/// The bounded walk result.
struct Walk {
    capped: bool,
    dirs: Vec<String>,
    files: Vec<WalkedFile>,
    unreadable: usize,
}

/// Walk a directory tree without following directory
/// symlinks (a symlink loop cannot hang the census);
/// entries are visited in name order so the manifest is
/// deterministic.
fn walk_tree(root: &Path) -> Walk {
    let mut walk = Walk {
        capped: false,
        dirs: Vec::new(),
        files: Vec::new(),
        unreadable: 0,
    };
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        if walk.files.len() >= GAME_WALK_FILES_MAX || depth > GAME_WALK_DEPTH_MAX {
            walk.capped = true;
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                walk.unreadable += 1;
                continue;
            }
        };
        let mut rows: Vec<(String, PathBuf, std::fs::FileType)> = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let kind = match entry.file_type() {
                        Ok(kind) => kind,
                        Err(_) => {
                            walk.unreadable += 1;
                            continue;
                        }
                    };
                    rows.push((
                        entry.file_name().to_string_lossy().into_owned(),
                        entry.path(),
                        kind,
                    ));
                }
                Err(_) => walk.unreadable += 1,
            }
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, path, kind) in rows {
            if walk.files.len() >= GAME_WALK_FILES_MAX {
                walk.capped = true;
                break;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if kind.is_dir() {
                walk.dirs.push(rel.clone());
                stack.push((path, rel, depth + 1));
            } else if kind.is_file() {
                let bytes = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
                walk.files.push(WalkedFile {
                    bytes,
                    ext: extension_of(&name),
                    name: name.to_lowercase(),
                    rel,
                });
            }
        }
    }
    walk
}

/// Lowercased final extension (no dot), or "".
fn extension_of(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_lowercase())
        .unwrap_or_default()
}

/// The asset class an extension belongs to (the
/// manifest's per-class counts).
fn asset_class(ext: &str) -> &'static str {
    match ext {
        "7z" | "apk" | "asar" | "pak" | "rar" | "rgss3a" | "rpa" | "ucas" | "utoc" | "xp3"
        | "zip" => "archive",
        "aac" | "acb" | "aif" | "aiff" | "awb" | "bnk" | "flac" | "fsb" | "m4a" | "mp3" | "ogg"
        | "opus" | "wav" | "wem" => "audio",
        "csv" | "ini" | "json" | "ks" | "nani" | "rvdata" | "rvdata2" | "rxdata" | "txt"
        | "xml" | "yaml" | "yml" => "data",
        "appimage" | "dll" | "dylib" | "exe" | "so" => "executable",
        "avif" | "bmp" | "gif" | "jpeg" | "jpg" | "png" | "psd" | "tga" | "webp" => "image",
        "blend" | "fbx" | "glb" | "gltf" | "moc3" => "model",
        "c" | "cpp" | "cs" | "gd" | "h" | "java" | "js" | "lua" | "py" | "rpy" | "rpyc" | "sh"
        | "ts" => "script",
        "assets" | "bundle" | "res" | "resource" => "unity_data",
        "avi" | "mkv" | "mov" | "mp4" | "webm" | "wmv" => "video",
        _ => "other",
    }
}

/// One engine candidate from the fingerprint rules.
struct Candidate {
    engine: &'static str,
    evidence: String,
    strength: u32,
    variant: &'static str,
}

/// Fingerprint an engine from walked names. `files` are
/// lowercased relative paths, `dirs` likewise. Returns
/// the winning candidate (if any), every candidate's
/// evidence lines, and the losing engines' names.
fn fingerprint(files: &[String], dirs: &[String]) -> (Option<Candidate>, Vec<String>, Vec<String>) {
    let mut candidates: Vec<Candidate> = Vec::new();
    let has_file = |pred: &dyn Fn(&str) -> bool| files.iter().any(|f| pred(f));
    let has_dir = |name: &str| {
        dirs.iter()
            .any(|d| d == name || d.ends_with(&format!("/{name}")))
    };

    // Unity: a *_Data directory holding the standard
    // payloads, or the player/IL2CPP binaries. The check
    // is on the final path segment (an APK's bin/Data is
    // a segment of its own, not a *_Data suffix).
    let data_dir = dirs.iter().find(|d| {
        let segment = d.rsplit('/').next().unwrap_or(d);
        segment == "data" || segment.ends_with("_data")
    });
    if let Some(dir) = data_dir {
        let marker = files.iter().find(|f| {
            f.starts_with(&format!("{dir}/"))
                && (f.ends_with("globalgamemanagers")
                    || f.ends_with("globalgamemanagers.assets")
                    || f.contains("sharedassets")
                    || f.ends_with("/level0"))
        });
        if let Some(marker) = marker {
            candidates.push(Candidate {
                engine: "unity",
                evidence: format!("Unity data directory '{dir}' with '{marker}'"),
                strength: 100,
                variant: "unity",
            });
        }
    }
    if has_file(&|f| f.ends_with("unityplayer.dll")) {
        candidates.push(Candidate {
            engine: "unity",
            evidence: "UnityPlayer.dll present".to_string(),
            strength: 100,
            variant: "unity",
        });
    }
    if has_file(&|f| f.ends_with("gameassembly.dll")) {
        candidates.push(Candidate {
            engine: "unity",
            evidence: "GameAssembly.dll present (IL2CPP build)".to_string(),
            strength: 90,
            variant: "unity-il2cpp",
        });
    }
    // Unreal: a .pak in the Content/Paks layout, or any
    // .pak beside an Engine/Binaries layout. Chromium
    // .pak files (locales, nw.pak, resources.pak at an
    // NW.js root) are excluded by name and path.
    let unreal_pak = files.iter().find(|f| {
        f.ends_with(".pak")
            && !f.contains("locales/")
            && !f.ends_with("nw.pak")
            && !f.ends_with("resources.pak")
            && (f.contains("content/paks/") || has_dir("engine") || has_dir("binaries"))
    });
    if let Some(pak) = unreal_pak {
        candidates.push(Candidate {
            engine: "unreal",
            evidence: format!("Unreal pak '{pak}' in a Content/Paks or Engine layout"),
            strength: 90,
            variant: "unreal",
        });
    }
    // Ren'Py: the renpy/ runtime directory is decisive;
    // archives and loose scripts corroborate.
    if has_dir("renpy") {
        candidates.push(Candidate {
            engine: "renpy",
            evidence: "renpy/ runtime directory present".to_string(),
            strength: 85,
            variant: "renpy",
        });
    } else if has_file(&|f| f.ends_with(".rpa")) {
        candidates.push(Candidate {
            engine: "renpy",
            evidence: "Ren'Py .rpa archive present".to_string(),
            strength: 80,
            variant: "renpy",
        });
    } else if has_file(&|f| {
        (f.starts_with("game/") || f.contains("/game/"))
            && (f.ends_with(".rpy") || f.ends_with(".rpyc"))
    }) {
        candidates.push(Candidate {
            engine: "renpy",
            evidence: "game/ holds Ren'Py scripts".to_string(),
            strength: 75,
            variant: "renpy",
        });
    }
    // RPG Maker: archive/data generations.
    if has_file(&|f| f.ends_with(".rgss3a")) {
        candidates.push(Candidate {
            engine: "rpgmaker",
            evidence: "Game.rgss3a archive present (VX Ace generation)".to_string(),
            strength: 85,
            variant: "vx-ace",
        });
    } else if has_file(&|f| f.ends_with(".rvdata2")) {
        candidates.push(Candidate {
            engine: "rpgmaker",
            evidence: "Data/*.rvdata2 present (VX Ace generation)".to_string(),
            strength: 80,
            variant: "vx-ace",
        });
    } else if has_file(&|f| f.ends_with(".rxdata")) {
        candidates.push(Candidate {
            engine: "rpgmaker",
            evidence: "Data/*.rxdata present (XP generation)".to_string(),
            strength: 80,
            variant: "xp",
        });
    }
    if has_file(&|f| f.contains("www/data/") && f.ends_with(".json")) && has_dir("js") {
        candidates.push(Candidate {
            engine: "rpgmaker",
            evidence: "www/data/*.json with js/ runtime (MV/MZ generation)".to_string(),
            strength: 85,
            variant: "mv-mz",
        });
    }
    // KiriKiri / Tyrano.
    if has_dir("tyrano") || has_file(&|f| f.contains("tyrano/")) {
        candidates.push(Candidate {
            engine: "tyrano",
            evidence: "tyrano/ framework directory present".to_string(),
            strength: 85,
            variant: "tyrano",
        });
    }
    if has_file(&|f| f.ends_with(".xp3")) {
        candidates.push(Candidate {
            engine: "kirikiri",
            evidence: "KiriKiri .xp3 archive present".to_string(),
            strength: 80,
            variant: "kirikiri",
        });
    }
    // GameMaker.
    if has_file(&|f| f.ends_with("data.win")) {
        candidates.push(Candidate {
            engine: "gamemaker",
            evidence: "GameMaker data.win present".to_string(),
            strength: 85,
            variant: "gamemaker",
        });
    }
    // Electron / NW.js runtimes (weakest: wrappers, not
    // game engines — they lose to any engine above).
    if has_file(&|f| f.ends_with("app.asar")) {
        candidates.push(Candidate {
            engine: "electron",
            evidence: "Electron app.asar present".to_string(),
            strength: 60,
            variant: "electron",
        });
    }
    if has_file(&|f| f.ends_with("nw.dll")) || has_file(&|f| f.ends_with("nw.pak")) {
        candidates.push(Candidate {
            engine: "nwjs",
            evidence: "NW.js runtime files present".to_string(),
            strength: 35,
            variant: "nwjs",
        });
    }

    candidates.sort_by(|a, b| b.strength.cmp(&a.strength).then(a.engine.cmp(b.engine)));
    let evidence: Vec<String> = candidates.iter().map(|c| c.evidence.clone()).collect();
    let mut also_detected: Vec<String> = candidates
        .iter()
        .skip(1)
        .map(|c| c.engine.to_string())
        .collect();
    also_detected.dedup();
    let winner = candidates.into_iter().next();
    (winner, evidence, also_detected)
}

/// Read a zip's central directory entry names (no
/// extraction), bounded by FILE_COUNT_MAX. Returns the
/// entry names in `/` form plus implied directories, or
/// None when the file is not a readable zip.
fn zip_listing(path: &Path) -> Option<(Vec<String>, Vec<String>)> {
    let bytes = read_bounded_file(path)?;
    if bytes.len() < 22 {
        return None;
    }
    // End of central directory: scan the tail backwards
    // for the signature.
    let tail_start = bytes.len().saturating_sub(65_557);
    let mut eocd = None;
    for index in (tail_start..=bytes.len() - 22).rev() {
        if bytes[index..index + 4] == [0x50, 0x4B, 0x05, 0x06] {
            eocd = Some(index);
            break;
        }
    }
    let eocd = eocd?;
    let count = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into().ok()?) as usize;
    let mut position = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().ok()?) as usize;
    let mut files = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    for _ in 0..count.min(FILE_COUNT_MAX) {
        if position + 46 > bytes.len() || bytes[position..position + 4] != [0x50, 0x4B, 0x01, 0x02]
        {
            return None;
        }
        let name_len =
            u16::from_le_bytes(bytes[position + 28..position + 30].try_into().ok()?) as usize;
        let extra_len =
            u16::from_le_bytes(bytes[position + 30..position + 32].try_into().ok()?) as usize;
        let comment_len =
            u16::from_le_bytes(bytes[position + 32..position + 34].try_into().ok()?) as usize;
        let name_start = position + 46;
        let name_end = name_start.checked_add(name_len)?;
        let name = String::from_utf8_lossy(bytes.get(name_start..name_end)?).into_owned();
        if name.ends_with('/') {
            dirs.push(name.trim_end_matches('/').to_string());
        } else {
            files.push(name.clone());
            let mut prefix = name.as_str();
            while let Some((head, _)) = prefix.rsplit_once('/') {
                if dirs.iter().any(|dir| dir == head) {
                    break;
                }
                dirs.push(head.to_string());
                prefix = head;
            }
        }
        position = name_end.checked_add(extra_len)?.checked_add(comment_len)?;
    }
    Some((files, dirs))
}

/// Read a whole file bounded by ARCHIVE_TARGET_BYTES_MAX.
fn read_bounded_file(path: &Path) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 + read as u64 > ARCHIVE_TARGET_BYTES_MAX {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Some(bytes)
}

/// Streaming SHA-256 of one file (containers only).
fn sha256_file(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hex_bytes(&hasher.finalize()))
}

/// Lowercase hex of a byte slice.
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The fathom reader that censuses a container kind, if
/// one exists.
fn container_tool(kind: &str) -> Option<&'static str> {
    match kind {
        "pak" => Some("inspect_unreal_pak"),
        "pck" => Some("inspect_godot_pck"),
        "rpa" => Some("inspect_renpy_archive"),
        _ => None,
    }
}

/// The container kind a walked file represents, if any.
fn container_kind(file: &WalkedFile) -> Option<&'static str> {
    match file.ext.as_str() {
        "7z" => Some("7z"),
        "apk" => Some("apk"),
        "asar" => Some("asar"),
        "pak" => Some("pak"),
        "rar" => Some("rar"),
        "rgss3a" => Some("rgss3a"),
        "rpa" => Some("rpa"),
        "ucas" => Some("ucas"),
        "utoc" => Some("utoc"),
        "xp3" => Some("xp3"),
        "zip" => Some("zip"),
        _ => {
            if file.name == "data.win" {
                Some("data_win")
            } else {
                None
            }
        }
    }
}

/// Census one game tree or bare archive file and emit
/// the unified manifest.
pub fn census_game_tree(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target_raw = require_str(args, "target")?;
    let target = paths::validate_target(config, Path::new(target_raw))?;
    let metadata = std::fs::metadata(&target).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat game target {}: {error}", target.display()),
        )
    })?;
    let target_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut unknowns: Vec<(String, String)> = Vec::new();
    let mut classes: BTreeMap<&'static str, (usize, u64)> = BTreeMap::new();
    let mut containers: Vec<Value> = Vec::new();
    let (fp_files, fp_dirs, total_files, total_bytes, walk_facts) = if metadata.is_dir() {
        let walk = walk_tree(&target);
        if walk.capped {
            unknowns.push((
                "walk coverage".to_string(),
                format!(
                    "the tree walk stopped at a bound (GAME_WALK_FILES_MAX {GAME_WALK_FILES_MAX} files / depth {GAME_WALK_DEPTH_MAX}); counts are a floor, not a total"
                ),
            ));
        }
        if walk.unreadable > 0 {
            unknowns.push((
                "unreadable entries".to_string(),
                format!(
                    "{} directory entries could not be read and are uncounted",
                    walk.unreadable
                ),
            ));
        }
        for file in &walk.files {
            let entry = classes.entry(asset_class(&file.ext)).or_default();
            entry.0 += 1;
            entry.1 += file.bytes;
            if let Some(kind) = container_kind(file) {
                containers.push(json!({
                    "bytes": file.bytes,
                    "census_tool": container_tool(kind),
                    "kind": kind,
                    "path": file.rel,
                    "sha256": sha256_file(&target.join(&file.rel)),
                }));
            }
        }
        (
            walk.files
                .iter()
                .map(|f| f.rel.to_lowercase())
                .collect::<Vec<_>>(),
            walk.dirs
                .iter()
                .map(|d| d.to_lowercase())
                .collect::<Vec<_>>(),
            walk.files.len(),
            walk.files.iter().map(|f| f.bytes).sum::<u64>(),
            Some(json!({
                "capped": walk.capped,
                "files": walk.files.len(),
                "unreadable": walk.unreadable,
            })),
        )
    } else {
        // Bare file target: a container in its own
        // right; zip-family files also fingerprint from
        // their central-directory names.
        let ext = extension_of(&target_name);
        let kind = match ext.as_str() {
            "7z" => "7z",
            "apk" => "apk",
            "rar" => "rar",
            "zip" => "zip",
            _ => "file",
        };
        containers.push(json!({
            "bytes": metadata.len(),
            "census_tool": container_tool(kind),
            "kind": kind,
            "path": target_name,
            "sha256": sha256_file(&target),
        }));
        let mut listing: Option<(Vec<String>, Vec<String>)> = None;
        if kind == "zip" || kind == "apk" {
            match zip_listing(&target) {
                Some((files, dirs)) => {
                    if let Some(row) = containers.last_mut() {
                        row["entries"] = json!(files.len());
                    }
                    for rel in &files {
                        classes.entry(asset_class(&extension_of(rel))).or_default().0 += 1;
                    }
                    listing = Some((
                        files.iter().map(|f| f.to_lowercase()).collect(),
                        dirs.iter().map(|d| d.to_lowercase()).collect(),
                    ));
                }
                None => unknowns.push((
                    "archive listing".to_string(),
                    "the zip central directory could not be read; the engine verdict rests on the file alone".to_string(),
                )),
            }
        } else if kind == "rar" || kind == "7z" {
            unknowns.push((
                "archive listing".to_string(),
                format!(
                    "fathom has no {kind} listing reader; the engine is unrecorded until the archive is extracted"
                ),
            ));
        }
        match listing {
            Some((files, dirs)) => {
                let total = files.len();
                (files, dirs, total, metadata.len(), None)
            }
            None => (Vec::new(), Vec::new(), 1, metadata.len(), None),
        }
    };

    let (winner, evidence, also_detected) = fingerprint(&fp_files, &fp_dirs);
    let (engine, variant) = match &winner {
        Some(candidate) => (candidate.engine, candidate.variant),
        None => {
            unknowns.push((
                "engine".to_string(),
                "no fingerprint rule matched; the engine is unrecorded, not guessed".to_string(),
            ));
            ("unknown", "unknown")
        }
    };
    let class_rows: Vec<Value> = classes
        .iter()
        .map(|(class, (count, bytes))| json!({"bytes": bytes, "class": class, "count": count}))
        .collect();
    let container_total = containers.len();
    let manifest = json!({
        "asset_classes": class_rows,
        "containers": containers,
        "dialogue": Value::Null,
        "engine": {
            "also_detected": also_detected,
            "evidence": evidence,
            "name": engine,
            "variant": variant,
        },
        "files": {"bytes": total_bytes, "total": total_files},
        "root": target_name,
        "ui": Value::Null,
        "walk": walk_facts,
    });

    // Retention: file targets bind to their subject;
    // directory targets bind to the manifest's own hash.
    let (digest, retention_note) = if metadata.is_file() {
        match subject_for_file_with_bound(&target, ARCHIVE_TARGET_BYTES_MAX) {
            Ok(subject) => {
                let sha = subject.sha256.clone();
                match proof::retain_export(config, &sha, "game_census", &manifest) {
                    Ok(digest) => (Some(digest), None),
                    Err(error) => (None, Some(error.message)),
                }
            }
            Err(error) => (None, Some(error.message)),
        }
    } else {
        let canonical = serde_json::to_string(&manifest).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let key = hex_bytes(&hasher.finalize());
        match proof::retain_export(config, &key, "game_census", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        }
    };
    if let Some(note) = retention_note {
        unknowns.push((
            "retention".to_string(),
            format!("manifest retention failed ({note}); the census facts stand, but no proof can bind this run"),
        ));
    }

    let mut evidence_record = Evidence::new("census_game_tree", "game");
    if metadata.is_file() {
        if let Ok(subject) = subject_for_file_with_bound(&target, ARCHIVE_TARGET_BYTES_MAX) {
            evidence_record.subject = Some(subject);
        }
    }
    evidence_record.add_finding(Finding::new("game_census", Confidence::Observed, manifest));
    evidence_record.add_finding(Finding::new(
        "game",
        Confidence::Observed,
        json!({
            "containers": container_total,
            "engine": engine,
            "export_digest": digest,
            "files": total_files,
            "root": target_name,
            "variant": variant,
        }),
    ));
    for (aspect, reason) in unknowns {
        evidence_record.add_unknown(aspect, reason);
    }
    Ok(evidence_record.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::Config;
    use fathom_core::error::FathomError;
    use fathom_core::registry::Registry;
    use std::fs;
    use std::path::PathBuf;

    fn run_game(
        test_name: &str,
        files: &[(&str, Vec<u8>)],
    ) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-game-test-{}-{test_name}",
            std::process::id()
        ));
        let game = root.join("game");
        fs::create_dir_all(&game).unwrap();
        for (name, bytes) in files {
            let path = game.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, bytes).unwrap();
        }
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": game.display().to_string()});
        let result = census_game_tree(&Registry::new(), &config, &args);
        (root, result)
    }

    fn run_game_file(
        test_name: &str,
        file_name: &str,
        bytes: &[u8],
    ) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-game-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join(file_name);
        fs::write(&file, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": file.display().to_string()});
        let result = census_game_tree(&Registry::new(), &config, &args);
        (root, result)
    }

    fn manifest_of(value: &Value) -> &Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "game_census")
            .map(|finding| &finding["facts"])
            .unwrap()
    }

    /// Minimal stored-entry zip (local headers + central
    /// directory + end record), contents empty.
    fn build_zip(names: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for name in names {
            let offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
            out.extend_from_slice(&20_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_at = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&(names.len() as u16).to_le_bytes());
        out.extend_from_slice(&(names.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_at.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out
    }

    #[test]
    fn validation_unity_tree() {
        let (root, result) = run_game(
            "unity",
            &[
                ("Game_Data/globalgamemanagers", b"x".to_vec()),
                ("Game_Data/sharedassets0.assets", b"y".to_vec()),
                ("UnityPlayer.dll", b"z".to_vec()),
                ("Game.exe", b"e".to_vec()),
            ],
        );
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "unity");
        assert_eq!(manifest["files"]["total"], 4);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_renpy_tree_with_rpa_container() {
        let (root, result) = run_game(
            "renpy",
            &[
                ("renpy/common/00start.rpy", b"#".to_vec()),
                ("game/archive.rpa", b"RPA-3.0 fake".to_vec()),
                ("Game.exe", b"e".to_vec()),
            ],
        );
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "renpy");
        let containers = manifest["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["kind"], "rpa");
        assert_eq!(containers[0]["census_tool"], "inspect_renpy_archive");
        assert_eq!(containers[0]["sha256"].as_str().unwrap().len(), 64);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_rpgmaker_mv_and_vxace() {
        let (root, result) = run_game(
            "mv",
            &[
                ("www/data/Actors.json", b"[]".to_vec()),
                ("js/rpg_core.js", b"//".to_vec()),
                ("Game.exe", b"e".to_vec()),
            ],
        );
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "rpgmaker");
        assert_eq!(manifest["engine"]["variant"], "mv-mz");
        fs::remove_dir_all(&root).ok();

        let (root, result) = run_game(
            "vxace",
            &[
                ("Game.rgss3a", b"RGSSAD".to_vec()),
                ("Game.exe", b"e".to_vec()),
            ],
        );
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "rpgmaker");
        assert_eq!(manifest["engine"]["variant"], "vx-ace");
        assert_eq!(manifest["containers"][0]["kind"], "rgss3a");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_unreal_kirikiri_gamemaker_electron() {
        let cases: &[(&str, Vec<(&str, Vec<u8>)>, &str)] = &[
            (
                "unreal",
                vec![
                    ("Game/Content/Paks/game.pak", b"pak".to_vec()),
                    ("Engine/Binaries/x.dll", b"d".to_vec()),
                ],
                "unreal",
            ),
            ("kirikiri", vec![("data.xp3", b"xp3".to_vec())], "kirikiri"),
            (
                "gamemaker",
                vec![("data.win", b"FORM".to_vec()), ("game.exe", b"e".to_vec())],
                "gamemaker",
            ),
            (
                "electron",
                vec![
                    ("resources/app.asar", b"asar".to_vec()),
                    ("app.exe", b"e".to_vec()),
                ],
                "electron",
            ),
        ];
        for (name, files, engine) in cases {
            let refs: Vec<(&str, Vec<u8>)> = files.clone();
            let (root, result) = run_game(name, &refs);
            let value = result.unwrap();
            assert_eq!(
                manifest_of(&value)["engine"]["name"],
                *engine,
                "case {name}"
            );
            fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn validation_bare_zip_and_apk_listings() {
        let zip = build_zip(&["renpy/common/00start.rpy", "game/script.rpy"]);
        let (root, result) = run_game_file("barezip", "game.zip", &zip);
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "renpy");
        assert_eq!(manifest["containers"][0]["entries"], 2);
        fs::remove_dir_all(&root).ok();

        let apk = build_zip(&["assets/bin/Data/globalgamemanagers", "classes.dex"]);
        let (root, result) = run_game_file("bareapk", "game.apk", &apk);
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "unity");
        assert_eq!(manifest["containers"][0]["kind"], "apk");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_unity_nested_apk_layout() {
        // Regression: an APK-style layout nests the Data
        // directory (assets/bin/Data); the *_Data check
        // must see the final segment, not a path suffix.
        let (root, result) = run_game(
            "nested-unity",
            &[
                ("assets/bin/Data/globalgamemanagers", b"x".to_vec()),
                ("classes.dex", b"y".to_vec()),
            ],
        );
        let value = result.unwrap();
        assert_eq!(manifest_of(&value)["engine"]["name"], "unity");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_chromium_paks_are_not_unreal() {
        let (root, result) = run_game(
            "chromium",
            &[
                ("locales/en-US.pak", b"pak".to_vec()),
                ("resources.pak", b"pak".to_vec()),
                ("nw.pak", b"pak".to_vec()),
                ("nw.dll", b"d".to_vec()),
            ],
        );
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_ne!(manifest["engine"]["name"], "unreal");
        assert_eq!(manifest["engine"]["name"], "nwjs");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_empty_tree_and_bare_rar_are_unknown() {
        let (root, result) = run_game("empty", &[]);
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "unknown");
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "engine")
        );
        fs::remove_dir_all(&root).ok();

        let (root, result) = run_game_file("barerare", "game.rar", b"Rar! fake bytes");
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "unknown");
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "archive listing")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_symlink_loop_terminates() {
        let (root, result) = run_game("loop", &[("readme.txt", b"hi".to_vec())]);
        let game = root.join("game");
        std::os::unix::fs::symlink(&game, game.join("selflink")).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": game.display().to_string()});
        let value = census_game_tree(&Registry::new(), &config, &args).unwrap();
        let _ = result;
        assert_eq!(manifest_of(&value)["files"]["total"], 1);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_deep_nesting_reports_the_cap() {
        let root =
            std::env::temp_dir().join(format!("fathom-game-test-{}-deep", std::process::id()));
        let mut dir = root.join("game");
        for level in 0..30 {
            dir = dir.join(format!("d{level}"));
        }
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bottom.txt"), b"x").unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": root.join("game").display().to_string()});
        let value = census_game_tree(&Registry::new(), &config, &args).unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["walk"]["capped"], true);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_second_engine_is_also_detected() {
        let (root, result) = run_game(
            "multi",
            &[
                ("Game_Data/globalgamemanagers", b"x".to_vec()),
                ("game/archive.rpa", b"RPA-3.0 fake".to_vec()),
            ],
        );
        let value = result.unwrap();
        let manifest = manifest_of(&value);
        assert_eq!(manifest["engine"]["name"], "unity");
        assert!(
            manifest["engine"]["also_detected"]
                .as_array()
                .unwrap()
                .iter()
                .any(|engine| engine == "renpy")
        );
        fs::remove_dir_all(&root).ok();
    }
}
