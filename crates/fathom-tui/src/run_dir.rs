//! Run directories and artifact writes.
//!
//! One timestamped directory per run, created under the
//! configured output root — never inside the target tree,
//! which is evidence. Writes are atomic (temp file + rename)
//! so a killed run never leaves a torn artifact behind.

use crate::error::WorkflowError;
use std::path::{Path, PathBuf};

/// Suffix attempts when two runs start in the same second.
const RUN_DIR_SUFFIX_MAX: u32 = 100;

/// Create `output_root` if needed and a fresh run directory
/// under it, named from `unix_secs` (UTC) as
/// `run-YYYYMMDD-HHMMSS`, with a numeric suffix on collision.
///
/// # Errors
/// `WorkflowError::Io` on filesystem failure, or after
/// `RUN_DIR_SUFFIX_MAX` collisions in one second.
pub fn create_run_dir(output_root: &Path, unix_secs: u64) -> Result<PathBuf, WorkflowError> {
    std::fs::create_dir_all(output_root)
        .map_err(|error| WorkflowError::io("create output root", &error))?;
    let stamp = format_run_stamp(unix_secs);
    for suffix in 0..RUN_DIR_SUFFIX_MAX {
        let name = if suffix == 0 {
            format!("run-{stamp}")
        } else {
            format!("run-{stamp}-{suffix}")
        };
        let candidate = output_root.join(name);
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(WorkflowError::io("create run directory", &error)),
        }
    }
    Err(WorkflowError::Internal(format!(
        "more than {RUN_DIR_SUFFIX_MAX} runs in one second under {}",
        output_root.display()
    )))
}

/// Write `contents` to `path` atomically: a sibling temp file,
/// then rename over the destination.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), WorkflowError> {
    let temp = path.with_extension("tmp-write");
    std::fs::write(&temp, contents)
        .map_err(|error| WorkflowError::io(format!("write {}", temp.display()), &error))?;
    std::fs::rename(&temp, path)
        .map_err(|error| WorkflowError::io(format!("rename into {}", path.display()), &error))?;
    Ok(())
}

/// Append a text block to a file, creating it if absent. Used
/// for the operator note on the plan document.
pub fn append_text(path: &Path, text: &str) -> Result<(), WorkflowError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|error| WorkflowError::io(format!("open {}", path.display()), &error))?;
    file.write_all(text.as_bytes())
        .map_err(|error| WorkflowError::io(format!("append to {}", path.display()), &error))?;
    Ok(())
}

/// Format unix seconds as `YYYYMMDD-HHMMSS` in UTC. The civil
/// conversion is the standard days-from-epoch algorithm; no
/// date crate is needed for a fixed-format stamp.
pub fn format_run_stamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// (year, month, day) for a day count since 1970-01-01
/// (Howard Hinnant's civil-from-days algorithm).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The current time as unix seconds; the engine's only clock
/// read, isolated so tests can inject a fixed stamp.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_formats_known_instants() {
        assert_eq!(format_run_stamp(0), "19700101-000000");
        // 2026-11-16 01:52:31 UTC is 1794793951.
        assert_eq!(format_run_stamp(1_794_793_951), "20261116-015231");
        // Leap day: 2024-02-29 12:00:00 UTC is 1709208000.
        assert_eq!(format_run_stamp(1_709_208_000), "20240229-120000");
    }

    #[test]
    fn run_dirs_are_unique_within_one_second() {
        let root =
            std::env::temp_dir().join(format!("fathom-tui-rundir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let first = create_run_dir(&root, 1_794_793_951).expect("first");
        let second = create_run_dir(&root, 1_794_793_951).expect("second");
        assert_ne!(first, second);
        assert!(first.ends_with("run-20261116-015231"));
        assert!(second.ends_with("run-20261116-015231-1"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_write_replaces_contents() {
        let root =
            std::env::temp_dir().join(format!("fathom-tui-atomic-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let file = root.join("plan.md");
        write_atomic(&file, b"one").expect("write one");
        write_atomic(&file, b"two").expect("write two");
        assert_eq!(std::fs::read(&file).expect("read"), b"two");
        let _ = std::fs::remove_dir_all(&root);
    }
}
