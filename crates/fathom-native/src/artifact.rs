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

/// The pak footer magic (`E1 12 6F 5A`) sits at the start of
/// the file's last 204 bytes; a pak is invisible to head
/// classification (readers SPEC §0.4).
const PAK_FOOTER_BYTES: usize = 204;
const PAK_MAGIC: [u8; 4] = [0xe1, 0x12, 0x6f, 0x5a];

/// Tail window for the PyInstaller cookie probe: the cookie
/// is 88 bytes and builds with appended data put it within
/// the cookie scan window the python reader itself uses.
const PYINSTALLER_TAIL_BYTES: usize = 65_624;

fn inspect_file(path: &Path) -> Result<Value, FathomError> {
    let subject = subject_for_file(path)?;
    let head = read_head(path, 4096)?;
    let mut classification = classify(&head);
    if classification == "unknown" && subject.size_bytes >= PAK_FOOTER_BYTES as u64 {
        // Bounded tail probe: exactly the footer size, read
        // once, only when the head said nothing.
        if let Ok(tail) = read_tail(path, PAK_FOOTER_BYTES)
            && tail.starts_with(&PAK_MAGIC)
        {
            classification = "Unreal pak";
        }
    }
    if classification == "ELF" || classification == "PE" {
        // A PyInstaller archive hides inside an executable:
        // its cookie sits at (or near) the end of the file.
        // One bounded tail read decides (the whole file when
        // it is smaller than the window).
        let tail_len = (subject.size_bytes as usize).min(PYINSTALLER_TAIL_BYTES);
        if tail_len >= 88
            && let Ok(tail) = read_tail(path, tail_len)
            && crate::python::contains_cookie(&tail)
        {
            classification = "PyInstaller archive";
        }
    }
    let mut evidence = Evidence::new("inspect_artifact", "artifact");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.coverage.exhaustive = true;
    evidence.add_finding(Finding::new(
        "artifact",
        Confidence::Observed,
        json!({
            "classification": classification,
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
        if head.len() >= 20 && u16::from_le_bytes([head[18], head[19]]) == crate::gpu::EM_AMDGPU {
            return "AMDGPU code object";
        }
        return "ELF";
    }
    if head.len() >= 12 && &head[0..4] == b"FOR1" && &head[8..12] == b"BEAM" {
        return "BEAM module";
    }
    if head.starts_with(crate::gpu::OFFLOAD_BUNDLE_MAGIC) {
        return "Clang offload bundle";
    }
    if head.len() >= 4
        && head[2] == 0x0d
        && head[3] == 0x0a
        && crate::python::pyc_version(u16::from_le_bytes([head[0], head[1]])).is_some()
    {
        return "Python bytecode (pyc)";
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
    if head.starts_with(b"UnityFS\0") {
        return "Unity bundle (UnityFS)";
    }
    if head.starts_with(b"RPA-2.0 ")
        || head.starts_with(b"RPA-3.0 ")
        || head.starts_with(b"RPA-3.2 ")
    {
        return "Ren'Py RPA";
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

fn read_tail(path: &Path, count: usize) -> Result<Vec<u8>, FathomError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target: {e}"),
        )
    })?;
    file.seek(SeekFrom::End(-(count as i64))).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot seek target: {e}"),
        )
    })?;
    let mut buffer = vec![0_u8; count];
    file.read_exact(&mut buffer).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    Ok(buffer)
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
    fn validation_classifications_s5_s7() {
        let mut elf = vec![0_u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[18] = 62; // x86-64 stays a plain ELF
        assert_eq!(classify(&elf), "ELF");
        elf[18] = 224; // EM_AMDGPU
        elf[19] = 0;
        assert_eq!(classify(&elf), "AMDGPU code object");
        assert_eq!(classify(b"FOR1\0\0\0\x10BEAM"), "BEAM module");
        assert_eq!(
            classify(b"__CLANG_OFFLOAD_BUNDLE__\x02\0\0\0"),
            "Clang offload bundle"
        );
        // Python 3.12 magic 3531 = 0x0dcb little-endian.
        assert_eq!(
            classify(&[0xcb, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]),
            "Python bytecode (pyc)"
        );
        // The 0x0d 0x0a terminator alone does not classify an
        // unknown magic.
        assert_eq!(classify(&[0xff, 0x7f, 0x0d, 0x0a]), "unknown");
    }

    #[test]
    fn validation_classifications() {
        assert_eq!(classify(&[0x7f, b'E', b'L', b'F', 2]), "ELF");
        assert_eq!(classify(b"MZ"), "PE");
        assert_eq!(classify(b"PK\x03\x04rest"), "ZIP");
        assert_eq!(classify(b"GDPC\x02\0\0\0"), "Godot PCK");
        assert_eq!(classify(b"UnityFS\0\0\0\0\x07"), "Unity bundle (UnityFS)");
        assert_eq!(
            classify(b"RPA-3.0 0123456789abcdef 00000000\n"),
            "Ren'Py RPA"
        );
        assert_eq!(classify(b"RPA-2.0 0123456789abcdef\n"), "Ren'Py RPA");
        assert_eq!(
            classify(b"RPA-3.2 0123456789abcdef 00000000\n"),
            "Ren'Py RPA"
        );
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
