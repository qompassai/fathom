//! Target confinement (SPEC §8).
//!
//! Every target path must canonicalize to a location under one of
//! the operator's declared target roots. Symlink escapes are
//! rejected because canonicalization resolves them before the
//! prefix check runs.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::{ErrorCode, ReaError};

/// Resolve `target` and prove it lives under a configured root.
/// Returns the canonical path handlers may use.
pub fn validate_target(config: &Config, target: &Path) -> Result<PathBuf, ReaError> {
    let canonical = target.canonicalize().map_err(|e| {
        ReaError::new(
            ErrorCode::TargetUnavailable,
            format!("target {} cannot be resolved: {e}", target.display()),
        )
        .with_target(target.display().to_string())
    })?;
    if config.target_roots.is_empty() {
        return Err(ReaError::new(
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
    Err(ReaError::new(
        ErrorCode::AccessDenied,
        "target is outside every configured target root",
    )
    .with_target(target.display().to_string())
    .with_remediation("Add the containing directory to target_roots in the config."))
}

/// Create (if needed) and return a named subdirectory of the
/// state dir. Providers write only under the state dir.
pub fn state_subdir(config: &Config, name: &str) -> Result<PathBuf, ReaError> {
    assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "state subdir names are generated, never target-supplied"
    );
    let dir = config.state_dir.join(name);
    std::fs::create_dir_all(&dir).map_err(|e| {
        ReaError::new(
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
        let dir = std::env::temp_dir().join(format!("rea-core-paths-{tag}-{}", std::process::id()));
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
