//! The transactional headless mutation path (SPEC §9.1, Ghidra
//! G2): the write class's engine.
//!
//! Mechanism: **copy-on-write project swap**, chosen over
//! snapshot/restore of the live cache because the existing engine
//! already treats the per-subject project as a cache keyed by
//! subject SHA-256 (see `engine::run_export`): a mutation can work
//! on a disposable copy and the cache only changes at one atomic
//! rename boundary. Steps per batch:
//!
//! 1. A per-subject lock directory is taken (`mutation.lock`); a
//!    second live holder is a typed `revision_conflict`, never a
//!    queue and never a shared project.
//! 2. The cached project's tree hash is recorded, then the project
//!    is copied to a transaction directory beside it.
//! 3. `analyzeHeadless` runs `FathomMutate.java` against the copy.
//!    The script applies the whole batch inside ONE Ghidra
//!    transaction and verifies a postcondition per op; any failure
//!    ends the transaction uncommitted, so Ghidra discards it.
//! 4. Commit only on the script's `committed` result: the copy is
//!    swapped into the cache by rename and every cached export is
//!    invalidated. On any other outcome the transaction directory
//!    is discarded and the cached project is re-hashed: it must be
//!    byte-identical to step 2, or the failure escalates to
//!    `artifact_integrity_mismatch`.
//!
//! The subject binary itself is never written; only the Ghidra
//! project cache (fathom's own state) changes.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::sha256_hex;
use fathom_core::limits::{GHIDRA_TIMEOUT_SECS, OUTPUT_BYTES_MAX};
use fathom_core::process::{ProcessSpec, run};

use crate::engine;

/// Ops in one mutation batch (mirrors the script's bound).
pub(crate) const OPS_PER_BATCH_MAX: usize = 256;

/// Project files in one tree hash / copy (a fixture project is
/// tens of files; this bound is generous, never silent).
const PROJECT_FILES_MAX: usize = 10_000;

/// Bytes hashed/copied for one project tree.
const PROJECT_BYTES_MAX: u64 = 1_073_741_824;

static TXN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One mutation op: a name plus its ordered fields. Fields travel
/// Base64-encoded, one op per line (see `FathomMutate.java`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Op {
    pub name: &'static str,
    pub fields: Vec<String>,
}

impl Op {
    pub(crate) fn new(name: &'static str, fields: Vec<String>) -> Self {
        Op { name, fields }
    }
}

/// What a committed batch proved.
#[derive(Clone, Debug)]
pub(crate) struct MutationOutcome {
    pub applied: usize,
    pub project_hash_after: String,
    pub project_hash_before: String,
    pub verified: Vec<String>,
}

#[derive(Deserialize)]
struct MutationResult {
    status: String,
    #[serde(default)]
    applied: usize,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    verified: Vec<String>,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64 (the script decodes with `java.util.Base64`).
fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let word = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(word >> 18) as usize & 63] as char);
        out.push(B64[(word >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(word >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[word as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Encode a batch as the script's ops file: one op per line,
/// tab-joined Base64 fields.
pub(crate) fn encode_ops(ops: &[Op]) -> String {
    let mut out = String::new();
    for op in ops {
        let mut fields = vec![b64_encode(op.name.as_bytes())];
        fields.extend(op.fields.iter().map(|f| b64_encode(f.as_bytes())));
        out.push_str(&fields.join("\t"));
        out.push('\n');
    }
    out
}

/// SHA-256 over a project tree: relative paths in sorted order,
/// each contributing its path, length, and bytes. Deterministic
/// for identical trees; any byte change anywhere changes it.
pub(crate) fn tree_hash(dir: &Path) -> Result<String, FathomError> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort();
    if files.len() > PROJECT_FILES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "Ghidra project exceeds the file bound for tree hashing",
        ));
    }
    let mut material = Vec::new();
    let mut total: u64 = 0;
    for rel in &files {
        let bytes = fs::read(dir.join(rel)).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot read project file for hashing: {e}"),
            )
        })?;
        total = total.saturating_add(bytes.len() as u64);
        if total > PROJECT_BYTES_MAX {
            return Err(FathomError::new(
                ErrorCode::ResourceConstraint,
                "Ghidra project exceeds the byte bound for tree hashing",
            ));
        }
        material.extend_from_slice(rel.as_bytes());
        material.push(0);
        material.extend_from_slice(bytes.len().to_le_bytes().as_slice());
        material.extend_from_slice(&bytes);
    }
    Ok(sha256_hex(&material))
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), FathomError> {
    let entries = fs::read_dir(dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read project dir: {e}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            FathomError::new(ErrorCode::ExecutionFailure, format!("project entry: {e}"))
        })?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| {
            FathomError::new(ErrorCode::ExecutionFailure, format!("project entry: {e}"))
        })?;
        if kind.is_dir() {
            collect_files(root, &path, out)?;
        } else if kind.is_file() {
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            out.push(rel);
        }
    }
    Ok(())
}

/// Copy a project tree (bounded like the hash).
pub(crate) fn copy_tree(src: &Path, dst: &Path) -> Result<(), FathomError> {
    let mut files = Vec::new();
    collect_files(src, src, &mut files)?;
    if files.len() > PROJECT_FILES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "Ghidra project exceeds the file bound for copying",
        ));
    }
    let mut total: u64 = 0;
    for rel in &files {
        let bytes = fs::read(src.join(rel)).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot read project file for copy: {e}"),
            )
        })?;
        total = total.saturating_add(bytes.len() as u64);
        if total > PROJECT_BYTES_MAX {
            return Err(FathomError::new(
                ErrorCode::ResourceConstraint,
                "Ghidra project exceeds the byte bound for copying",
            ));
        }
        let target = dst.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                FathomError::new(
                    ErrorCode::ExecutionFailure,
                    format!("cannot create transaction dir: {e}"),
                )
            })?;
        }
        fs::write(&target, &bytes).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot write transaction copy: {e}"),
            )
        })?;
    }
    Ok(())
}

/// The per-subject mutation lock. Held for one batch; a second
/// holder is refused typed, never queued.
#[derive(Debug)]
pub(crate) struct ProjectLock {
    dir: PathBuf,
}

impl ProjectLock {
    pub(crate) fn acquire(cache_dir: &Path) -> Result<ProjectLock, FathomError> {
        let dir = cache_dir.join("mutation.lock");
        match fs::create_dir(&dir) {
            Ok(()) => Ok(ProjectLock { dir }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(FathomError::new(
                ErrorCode::RevisionConflict,
                "another mutation session holds this subject's project lock; \
                     concurrent mutation is refused, not queued",
            )
            .with_remediation("Retry after the other session's batch commits or rolls back.")),
            Err(e) => Err(FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot take the mutation lock: {e}"),
            )),
        }
    }
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        // Best-effort: a stale lock is visible state the operator
        // can remove; hiding the failure would be worse.
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Swap a committed transaction project into the cache. The old
/// project is renamed aside first and restored if the swap fails.
pub(crate) fn commit_txn(cache_dir: &Path, txn_dir: &Path) -> Result<(), FathomError> {
    let project_dir = cache_dir.join("project");
    let backup_dir = cache_dir.join("project.pre-txn");
    if backup_dir.exists() {
        fs::remove_dir_all(&backup_dir).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot clear stale pre-transaction project: {e}"),
            )
        })?;
    }
    fs::rename(&project_dir, &backup_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot set the cached project aside for commit: {e}"),
        )
    })?;
    if let Err(e) = fs::rename(txn_dir.join("project"), &project_dir) {
        let _ = fs::rename(&backup_dir, &project_dir);
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot swap the committed project into the cache: {e}"),
        ));
    }
    fs::remove_dir_all(&backup_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::CleanupIncomplete,
            format!("committed, but the pre-transaction project remains: {e}"),
        )
    })?;
    Ok(())
}

/// Drop every cached export: they describe the pre-mutation
/// program and must never answer a post-mutation read.
fn invalidate_exports(cache_dir: &Path) -> Result<(), FathomError> {
    let entries = fs::read_dir(cache_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot list the cache for export invalidation: {e}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            FathomError::new(ErrorCode::ExecutionFailure, format!("cache entry: {e}"))
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("export-") && name.ends_with(".json") {
            fs::remove_file(entry.path()).map_err(|e| {
                FathomError::new(
                    ErrorCode::CleanupIncomplete,
                    format!("cannot invalidate a cached export: {e}"),
                )
            })?;
        } else if name.starts_with("out-") {
            fs::remove_dir_all(entry.path()).map_err(|e| {
                FathomError::new(
                    ErrorCode::CleanupIncomplete,
                    format!("cannot invalidate a cached export dir: {e}"),
                )
            })?;
        }
    }
    Ok(())
}

/// Run one batch transactionally against the subject's cached
/// Ghidra project. The caller has already validated every op.
pub(crate) fn run_mutation(
    config: &Config,
    subject_path: &Path,
    subject_sha256: &str,
    ops: &[Op],
) -> Result<MutationOutcome, FathomError> {
    if ops.is_empty() || ops.len() > OPS_PER_BATCH_MAX {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("a mutation batch holds 1..={OPS_PER_BATCH_MAX} ops"),
        ));
    }
    let cache_dir = engine::cache_dir_for(config, subject_sha256);
    fs::create_dir_all(&cache_dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create Ghidra cache dir: {e}"),
        )
    })?;
    let project_dir = cache_dir.join("project");
    if !project_dir.join("fathom.gpr").exists() {
        // First touch: build the cached project with a read export
        // (the engine's own import path), then mutate its copy.
        engine::run_export(config, subject_path, subject_sha256, "program", None)?;
    }
    let _lock = ProjectLock::acquire(&cache_dir)?;
    let hash_before = tree_hash(&project_dir)?;

    let txn_id = format!(
        "txn-{}-{}",
        std::process::id(),
        TXN_COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let txn_dir = cache_dir.join(&txn_id);
    let txn_project = txn_dir.join("project");
    let outcome = run_txn(
        config,
        subject_path,
        &cache_dir,
        &txn_dir,
        &txn_project,
        &project_dir,
        ops,
    );
    match outcome {
        Ok(verified) => {
            commit_txn(&cache_dir, &txn_dir)?;
            invalidate_exports(&cache_dir)?;
            let hash_after = tree_hash(&project_dir)?;
            let _ = fs::remove_dir_all(&txn_dir);
            Ok(MutationOutcome {
                applied: ops.len(),
                project_hash_after: hash_after,
                project_hash_before: hash_before,
                verified,
            })
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&txn_dir);
            // The rollback proof: the cached project the batch
            // never touched must hash exactly as before. If it
            // does not, that is the headline failure.
            match tree_hash(&project_dir) {
                Ok(now) if now == hash_before => Err(error),
                Ok(_) => Err(FathomError::new(
                    ErrorCode::ArtifactIntegrityMismatch,
                    "a refused/failed mutation batch left the cached project changed",
                )),
                Err(hash_error) => Err(hash_error),
            }
        }
    }
}

/// The transaction body: copy, run the script on the copy, and
/// hand back the verified postconditions on a committed result.
#[allow(clippy::too_many_arguments)]
fn run_txn(
    config: &Config,
    subject_path: &Path,
    cache_dir: &Path,
    txn_dir: &Path,
    txn_project: &Path,
    project_dir: &Path,
    ops: &[Op],
) -> Result<Vec<String>, FathomError> {
    let _ = cache_dir;
    copy_tree(project_dir, txn_project)?;
    let ops_file = txn_dir.join("ops.txt");
    fs::write(&ops_file, encode_ops(ops)).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot write the mutation ops file: {e}"),
        )
    })?;
    let result_file = txn_dir.join("result.json");
    let headless = engine::locate_headless(config).ok_or_else(|| {
        FathomError::new(
            ErrorCode::ProviderUnavailable,
            "Ghidra analyzeHeadless not found",
        )
        .with_remediation("Install Ghidra 12 or set ghidra_headless / FATHOM_GHIDRA_HEADLESS.")
    })?;
    let script_dir = engine::locate_script_dir()?;
    if !script_dir.join("FathomMutate.java").exists() {
        return Err(FathomError::new(
            ErrorCode::ProviderUnavailable,
            "FathomMutate.java not found beside FathomExportAnalysis.java",
        ));
    }
    let program_name = subject_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "program".to_string());
    let args: Vec<String> = vec![
        txn_project.display().to_string(),
        "fathom".to_string(),
        "-process".to_string(),
        program_name,
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        script_dir.display().to_string(),
        "-postScript".to_string(),
        "FathomMutate.java".to_string(),
        ops_file.display().to_string(),
        result_file.display().to_string(),
    ];
    let outcome = run(&ProcessSpec {
        args,
        cwd: Some(txn_dir.to_path_buf()),
        env: Vec::new(),
        output_cap: OUTPUT_BYTES_MAX,
        program: headless.display().to_string(),
        timeout: std::time::Duration::from_secs(GHIDRA_TIMEOUT_SECS),
    })?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            "the mutation run exceeded the provider bound; the batch was discarded",
        ));
    }
    let bytes = fs::read(&result_file).map_err(|_| {
        let tail: String = String::from_utf8_lossy(&outcome.stderr)
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "the mutation script produced no result (exit {:?}); stderr tail: {tail}",
                outcome.exit_code
            ),
        )
    })?;
    let result: MutationResult = serde_json::from_slice(&bytes).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("the mutation result does not parse: {e}"),
        )
    })?;
    if result.status != "committed" {
        return Err(FathomError::new(
            ErrorCode::ArtifactOperationFailed,
            format!(
                "mutation batch rolled back: {}",
                result
                    .error
                    .as_deref()
                    .unwrap_or("script reported no reason")
            ),
        ));
    }
    if result.applied != ops.len() || result.verified.len() != ops.len() {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the mutation result does not verify every op in the batch",
        ));
    }
    Ok(result.verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "fathom-mutate-{tag}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validation_b64_matches_the_java_decoder_alphabet() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(
            b64_encode("rename_function".as_bytes()),
            "cmVuYW1lX2Z1bmN0aW9u"
        );
    }

    #[test]
    fn validation_encode_ops_is_one_b64_line_per_op() {
        let ops = vec![
            Op::new(
                "rename_function",
                vec!["0010115d".into(), "main_loop".into()],
            ),
            Op::new(
                "set_comment",
                vec!["0010115d".into(), "eol".into(), "hi\tthere".into()],
            ),
        ];
        let text = encode_ops(&ops);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        // The tab inside the comment text is inside the Base64, so
        // each line's field count stays exact.
        assert_eq!(lines[1].split('\t').count(), 4);
    }

    #[test]
    fn validation_tree_hash_is_deterministic() {
        let dir = temp_dir("hash");
        fs::write(dir.join("a.bin"), b"one").unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/b.bin"), b"two").unwrap();
        let first = tree_hash(&dir).unwrap();
        assert_eq!(first, tree_hash(&dir).unwrap());
        fs::remove_dir_all(&dir).ok();
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn adversarial_tree_hash_changes_with_any_byte() {
        let dir = temp_dir("hashflip");
        fs::write(dir.join("a.bin"), b"one").unwrap();
        let before = tree_hash(&dir).unwrap();
        fs::write(dir.join("a.bin"), b"onf").unwrap();
        assert_ne!(before, tree_hash(&dir).unwrap());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_second_lock_holder_is_refused_typed() {
        let dir = temp_dir("lock");
        let first = ProjectLock::acquire(&dir).unwrap();
        let err = ProjectLock::acquire(&dir).unwrap_err();
        assert_eq!(err.code, ErrorCode::RevisionConflict);
        drop(first);
        assert!(ProjectLock::acquire(&dir).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validation_commit_swaps_the_transaction_project_in() {
        let dir = temp_dir("commit");
        let cache = dir.join("cache");
        let project = cache.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("fathom.gpr"), b"old").unwrap();
        let txn = dir.join("txn");
        let txn_project = txn.join("project");
        fs::create_dir_all(&txn_project).unwrap();
        fs::write(txn_project.join("fathom.gpr"), b"new").unwrap();
        let before = tree_hash(&project).unwrap();
        commit_txn(&cache, &txn).unwrap();
        let after = tree_hash(&project).unwrap();
        assert_ne!(before, after);
        assert_eq!(fs::read(project.join("fathom.gpr")).unwrap(), b"new");
        assert!(!cache.join("project.pre-txn").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_discard_leaves_the_project_byte_identical() {
        // The rollback shape the engine relies on: work happens in
        // the transaction copy; discarding it cannot touch the
        // cached project, proven by hash.
        let dir = temp_dir("discard");
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("fathom.gpr"), b"original").unwrap();
        let before = tree_hash(&project).unwrap();
        let txn_project = dir.join("txn/project");
        copy_tree(&project, &txn_project).unwrap();
        fs::write(txn_project.join("fathom.gpr"), b"mutated").unwrap();
        fs::remove_dir_all(dir.join("txn")).unwrap();
        assert_eq!(before, tree_hash(&project).unwrap());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_empty_batch_is_refused_before_any_engine_work() {
        let config = Config::from_file_form(fathom_core::config::ConfigFile::default()).unwrap();
        let err =
            run_mutation(&config, Path::new("/nonexistent"), &"0".repeat(64), &[]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }
}
