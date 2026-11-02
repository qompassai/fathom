//! Target confinement (SPEC §8).
//!
//! Every target path must canonicalize to a location under one of
//! the operator's declared target roots. Symlink escapes are
//! rejected because canonicalization resolves them before the
//! prefix check runs.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::{ErrorCode, FathomError};

/// Resolve `target` and prove it lives under a configured root.
/// Returns the canonical path handlers may use.
pub fn validate_target(config: &Config, target: &Path) -> Result<PathBuf, FathomError> {
    let canonical = target.canonicalize().map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("target {} cannot be resolved: {e}", target.display()),
        )
        .with_target(target.display().to_string())
    })?;
    if config.target_roots.is_empty() {
        return Err(FathomError::new(
            ErrorCode::AccessDenied,
            "no target roots are configured; the operator must declare target_roots before any target is analyzable",
        )
        .with_target(target.display().to_string()));
    }
    for root in &config.target_roots {
        if canonical.starts_with(root) {
            return Ok(canonical);
        }
    }
    Err(FathomError::new(
        ErrorCode::AccessDenied,
        "target is outside every configured target root",
    )
    .with_target(target.display().to_string())
    .with_remediation("Add the containing directory to target_roots in the config."))
}

/// Resolve a caller-named output directory and prove it lives
/// under a configured target root, creating it if needed.
///
/// Unlike `validate_target`, the directory may not exist yet.
/// The longest existing ancestor is canonicalized (resolving
/// symlinks) and must sit under a root; `..` components are
/// refused outright, so the not-yet-existing tail can only add
/// plain names under that ancestor. After creation the full
/// path is canonicalized and checked again, closing any
/// symlink planted in the tail between the two checks.
pub fn validate_output_dir(config: &Config, dir: &Path) -> Result<PathBuf, FathomError> {
    let denied = |message: String| {
        FathomError::new(ErrorCode::AccessDenied, message)
            .with_target(dir.display().to_string())
            .with_remediation("Name an output directory under one of the configured target_roots.")
    };
    if config.target_roots.is_empty() {
        return Err(denied(
            "no target roots are configured; the operator must declare target_roots before any output directory is writable"
                .to_string(),
        ));
    }
    if dir
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(denied(format!(
            "output directory {} contains a '..' component",
            dir.display()
        )));
    }
    let absolute = std::path::absolute(dir).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("output directory {} cannot be resolved: {e}", dir.display()),
        )
        .with_target(dir.display().to_string())
    })?;
    // The longest existing ancestor plus the plain file names
    // below it. A tail component that already exists (even as
    // a symlink) stops the walk, so it is canonicalized as
    // part of the ancestor and judged by the prefix check.
    let mut ancestor = absolute.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !ancestor.exists() {
        match ancestor.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                let popped = ancestor.pop();
                assert!(popped, "a path with a file name pops");
            }
            None => {
                return Err(denied(format!(
                    "output directory {} has no existing ancestor",
                    dir.display()
                )));
            }
        }
    }
    let canonical_ancestor = ancestor.canonicalize().map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!(
                "output directory ancestor {} cannot be resolved: {e}",
                ancestor.display()
            ),
        )
        .with_target(dir.display().to_string())
    })?;
    if !config
        .target_roots
        .iter()
        .any(|root| canonical_ancestor.starts_with(root))
    {
        return Err(denied(format!(
            "output directory {} is outside every configured target root",
            dir.display()
        )));
    }
    let mut resolved = canonical_ancestor;
    for name in tail.iter().rev() {
        resolved.push(name);
    }
    std::fs::create_dir_all(&resolved).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create output directory {}: {e}", resolved.display()),
        )
    })?;
    let canonical = resolved.canonicalize().map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!(
                "output directory {} cannot be resolved after creation: {e}",
                resolved.display()
            ),
        )
        .with_target(dir.display().to_string())
    })?;
    if !config
        .target_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        return Err(denied(format!(
            "output directory {} resolves outside every configured target root",
            dir.display()
        )));
    }
    Ok(canonical)
}

/// Create (if needed) and return a named subdirectory of the
/// state dir. Providers write only under the state dir.
pub fn state_subdir(config: &Config, name: &str) -> Result<PathBuf, FathomError> {
    assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "state subdir names are generated, never target-supplied"
    );
    let dir = config.state_dir.join(name);
    std::fs::create_dir_all(&dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create state dir {}: {e}", dir.display()),
        )
    })?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigFile;

    fn config_with_root(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-core-paths-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn adversarial_dotdot_escape_is_rejected() {
        let root = scratch("root");
        let outside = scratch("outside");
        let escape = root.join("..").join(outside.file_name().unwrap()).join("f");
        std::fs::write(outside.join("f"), b"x").unwrap();
        let config = config_with_root(&root);
        let err = validate_target(&config, &escape).unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn adversarial_no_roots_denies_everything() {
        let config = Config::restrictive_default();
        let err = validate_target(&config, Path::new("/usr/bin/true")).unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
    }

    #[test]
    fn validation_target_inside_root_is_accepted() {
        let root = scratch("ok");
        let file = root.join("target.bin");
        std::fs::write(&file, b"x").unwrap();
        let config = config_with_root(&root);
        let resolved = validate_target(&config, &file).unwrap();
        assert_eq!(resolved, file.canonicalize().unwrap());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_output_dir_inside_root_is_created() {
        let root = scratch("outok");
        let config = config_with_root(&root);
        let wanted = root.join("extract").join("run-1");
        let resolved = validate_output_dir(&config, &wanted).unwrap();
        assert_eq!(resolved, wanted.canonicalize().unwrap());
        assert!(resolved.is_dir());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_output_dir_dotdot_is_rejected() {
        let root = scratch("outdotdot");
        let config = config_with_root(&root);
        let escape = root.join("sub").join("..").join("..").join("elsewhere");
        let err = validate_output_dir(&config, &escape).unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_output_dir_outside_root_is_rejected() {
        let root = scratch("outroot");
        let outside = scratch("outoutside");
        let config = config_with_root(&root);
        let err = validate_output_dir(&config, &outside.join("extract")).unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
        assert!(!outside.join("extract").exists(), "nothing was created");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn adversarial_output_dir_symlink_ancestor_escape_is_rejected() {
        let root = scratch("outlinkroot");
        let outside = scratch("outlinkoutside");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let config = config_with_root(&root);
        let err = validate_output_dir(&config, &root.join("link").join("extract")).unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
        assert!(!outside.join("extract").exists(), "nothing was created");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn adversarial_symlink_escape_is_rejected() {
        let root = scratch("linkroot");
        let outside = scratch("linkoutside");
        std::fs::write(outside.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("link")).unwrap();
        let config = config_with_root(&root);
        let err = validate_target(&config, &root.join("link")).unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }
}
