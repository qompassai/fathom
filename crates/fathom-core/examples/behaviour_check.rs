//! Pipeline runner for the behaviour-check stage (D-1097):
//! the standing, re-runnable form of `fathom_core::behaviour`.
//!
//! Usage: `behaviour_check <ledger.json> <artifacts_dir>`.
//! Reads one obligation ledger and the retained fixture
//! artifacts it cites (every regular file directly inside
//! `artifacts_dir`, keyed by file name), prints the evaluation
//! as JSON, and exits 0 when the ledger's gate verdict is
//! `checked`, 1 when `blocked`, 2 when the ledger is refused
//! (malformed or tampered) or the inputs cannot be read.
//!
//! This is a pipeline stage, not a tool: it is not in the MCP
//! catalog and carries no tool shape. The library does the
//! checking; this runner only feeds it files and reports.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use fathom_core::behaviour::{evaluate, parse_ledger};
use fathom_core::evidence::sha256_hex;
use fathom_core::limits::BEHAVIOUR_BYTES_MAX;

/// Files retained in one artifacts directory.
const ARTIFACTS_MAX: usize = 1024;
/// Bytes read from one artifact file (run logs and smoke
/// outputs are small; the cap exists so a stray large file
/// cannot make the runner unbounded).
const ARTIFACT_BYTES_MAX: u64 = 67_108_864;

fn fail(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("behaviour_check: {message}");
    ExitCode::from(2)
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds the {max_bytes}-byte read bound", path.display()),
        ));
    }
    Ok(bytes)
}

fn artifact_digests(dir: &Path) -> Result<BTreeMap<String, String>, std::io::Error> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.len() > ARTIFACTS_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} holds {} entries, over the {ARTIFACTS_MAX} bound",
                dir.display(),
                entries.len()
            ),
        ));
    }
    let mut digests = BTreeMap::new();
    for entry in entries {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let bytes = read_bounded(&entry.path(), ARTIFACT_BYTES_MAX)?;
        digests.insert(
            entry.file_name().to_string_lossy().into_owned(),
            sha256_hex(&bytes),
        );
    }
    Ok(digests)
}

fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return fail("usage: behaviour_check <ledger.json> <artifacts_dir>");
    }
    let ledger_bytes = match read_bounded(Path::new(&args[0]), BEHAVIOUR_BYTES_MAX as u64) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let ledger_json: serde_json::Value = match serde_json::from_slice(&ledger_bytes) {
        Ok(value) => value,
        Err(error) => return fail(format!("ledger is not valid JSON: {error}")),
    };
    let ledger = match parse_ledger(&ledger_json) {
        Ok(ledger) => ledger,
        Err(error) => return fail(error),
    };
    let artifacts = match artifact_digests(Path::new(&args[1])) {
        Ok(digests) => digests,
        Err(error) => return fail(error),
    };
    let evaluation = match evaluate(&ledger, &artifacts) {
        Ok(evaluation) => evaluation,
        Err(error) => return fail(error),
    };
    let value = evaluation.to_value(&ledger.title);
    match serde_json::to_string_pretty(&value) {
        Ok(text) => println!("{text}"),
        Err(error) => return fail(error),
    }
    match evaluation.verdict {
        fathom_core::behaviour::GateVerdict::Checked => ExitCode::from(0),
        fathom_core::behaviour::GateVerdict::Blocked => ExitCode::from(1),
    }
}

fn main() -> ExitCode {
    run()
}
