//! Artifact inspection (SPEC §9.4): one file (identity, SHA-256,
//! format classification) or one directory (bounded inventory;
//! `.app`-style bundles get their `Info.plist` facts). Reads the
//! artifact, never executes it, writes nothing.

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use fathom_core::limits::FILE_COUNT_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// Files at or below this size are hashed during a directory walk.
const WALK_HASH_BYTES_MAX: u64 = 67_108_864;
/// Directory depth bound for the inventory walk.
const WALK_DEPTH_MAX: usize = 32;

pub fn inspect_artifact(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let metadata = fs::metadata(&path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat target: {e}"),
        )
    })?;
    if metadata.is_dir() {
        inspect_directory(&path)
    } else {
        inspect_file(&path)
    }
}

fn inspect_file(path: &Path) -> Result<Value, FathomError> {
    let subject = subject_for_file(path)?;
    let head = read_head(path, 4096)?;
    let mut evidence = Evidence::new("inspect_artifact", "artifact");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    evidence.add_finding(Finding::new(
        "artifact",
        Confidence::Observed,
        json!({
            "classification": classify(&head),
            "kind": "file",
            "magic_prefix": head.iter().take(16)
                .map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
        }),
    ));
    Ok(evidence.to_value())
}

fn inspect_directory(path: &Path) -> Result<Value, FathomError> {
    let mut entries: Vec<Value> = Vec::new();
    let mut seen: u64 = 0;
    walk(path, path, 0, &mut entries, &mut seen)?;
    let truncated = seen > entries.len() as u64;
    let mut evidence = Evidence::new("inspect_artifact", "artifact");
    evidence.coverage.examined = entries.len() as u64;
    evidence.coverage.total = seen;
    evidence.coverage.exhaustive = !truncated;
    let mut inventory = Finding::new(
        "inventory",
        Confidence::Observed,
        json!({
            "entries": entries,
            "kind": "directory",
            "root": path.display().to_string(),
        }),
    );
    if truncated {
        inventory = inventory.with_limitation("inventory truncated at the file-count bound");
    }
    evidence.add_finding(inventory);
    let plist = path.join("Info.plist");
    if plist.is_file()
        && let Ok(text) = fs::read_to_string(&plist)
    {
        let facts = json!({
            "CFBundleExecutable": plist_string(&text, "CFBundleExecutable"),
            "CFBundleIdentifier": plist_string(&text, "CFBundleIdentifier"),
            "CFBundleName": plist_string(&text, "CFBundleName"),
            "CFBundleShortVersionString":
                plist_string(&text, "CFBundleShortVersionString"),
        });
        evidence.add_finding(Finding::new("info_plist", Confidence::Observed, facts));
    }
    Ok(evidence.to_value())
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    entries: &mut Vec<Value>,
    seen: &mut u64,
) -> Result<(), FathomError> {
    if depth > WALK_DEPTH_MAX {
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
        *seen += 1;
        if entries.len() >= FILE_COUNT_MAX {
            continue;
        }
        let metadata = fs::symlink_metadata(&child).map_err(|e| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot stat {}: {e}", child.display()),
            )
        })?;
        let relative = child
            .strip_prefix(root)
            .unwrap_or(&child)
            .display()
            .to_string();
        if metadata.is_dir() {
            entries.push(json!({"kind": "directory", "path": relative}));
            walk(root, &child, depth + 1, entries, seen)?;
        } else if metadata.file_type().is_symlink() {
            entries.push(json!({"kind": "symlink", "path": relative}));
        } else {
            let size = metadata.len();
            let sha256 = if size <= WALK_HASH_BYTES_MAX {
                fathom_core::evidence::hash_file(&child)
                    .ok()
                    .map(|(hash, _)| hash)
            } else {
                None
            };
            entries.push(json!({
                "kind": "file",
                "path": relative,
                "sha256": sha256,
                "size_bytes": size,
            }));
        }
    }
    Ok(())
}

/// Format classification from magic bytes (SPEC §9.4).
pub fn classify(head: &[u8]) -> &'static str {
    if head.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return "ELF";
    }
    if head.starts_with(b"MZ") {
        return "PE";
    }
    if head.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || head.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || head.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        return "Mach-O";
    }
    if head.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
        return "ZIP";
    }
    if head.starts_with(b"GDPC") {
        return "Godot PCK";
    }
    if head.len() >= 17
        && head[0..4] == [4, 0, 0, 0]
        && head[16] == b'{'
        && u32::from_le_bytes([head[12], head[13], head[14], head[15]]) > 0
    {
        return "ASAR";
    }
    if head.starts_with(b"#!") {
        return "script";
    }
    if !head.is_empty() && head.iter().all(|b| *b != 0) && std::str::from_utf8(head).is_ok() {
        return "text";
    }
    "unknown"
}

/// Extract one `<key>KEY</key><string>VALUE</string>` pair from
/// plist XML text. Deliberately small: bundle identity facts
/// only, not a plist parser.
pub fn plist_string(plist: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let start = plist.find(&needle)? + needle.len();
    let rest = &plist[start..];
    let open = rest.find("<string>")? + "<string>".len();
    let close = rest[open..].find("</string>")?;
    Some(rest[open..open + close].to_string())
}

fn read_head(path: &Path, max: usize) -> Result<Vec<u8>, FathomError> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target: {e}"),
        )
    })?;
    let mut buffer = vec![0_u8; max];
    let read = file.read(&mut buffer).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    buffer.truncate(read);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_plist_key_absent_is_none() {
        assert_eq!(plist_string("<plist></plist>", "CFBundleName"), None);
        assert_eq!(
            plist_string("<key>CFBundleName</key><string></string>", "CFBundleName"),
            Some(String::new())
        );
    }

    #[test]
    fn validation_classifications() {
        assert_eq!(classify(&[0x7f, b'E', b'L', b'F', 2]), "ELF");
        assert_eq!(classify(b"MZ"), "PE");
        assert_eq!(classify(b"PK\x03\x04rest"), "ZIP");
        assert_eq!(classify(b"GDPC\x02\0\0\0"), "Godot PCK");
        assert_eq!(classify(b"#!/bin/sh\n"), "script");
        assert_eq!(classify(b"plain text"), "text");
        assert_eq!(classify(&[0x00, 0x01]), "unknown");
    }

    #[test]
    fn validation_plist_string_extracts() {
        let plist = "<dict><key>CFBundleName</key>\n<string>Widget</string></dict>";
        assert_eq!(
            plist_string(plist, "CFBundleName"),
            Some("Widget".to_string())
        );
    }
}
