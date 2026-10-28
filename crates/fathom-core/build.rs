// Build-time source revision embedding (SPEC §4.1.5, D-092 Q3).
//
// The producer binding of a reconstruction proof names the
// implementation that produced the evidence. Version and
// catalog digest alone collide across local builds from one
// checkout, so the git HEAD at build time joins the binding —
// suffixed `-dirty` when the tree carried uncommitted changes,
// because a dirty tree is not the revision it names. Outside a
// checkout (a tarball build) the honest value is "unknown".

use std::path::PathBuf;
use std::process::Command;

fn git(root: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().and_then(|crates| crates.parent());
    let revision = root
        .and_then(|root| {
            let head = git(root, &["rev-parse", "HEAD"])?;
            let dirty = git(root, &["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
            Some(if dirty { format!("{head}-dirty") } else { head })
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FATHOM_SOURCE_REVISION={revision}");
    if let Some(root) = root {
        let head_file = root.join(".git").join("HEAD");
        if head_file.exists() {
            println!("cargo:rerun-if-changed={}", head_file.display());
        }
    }
}
