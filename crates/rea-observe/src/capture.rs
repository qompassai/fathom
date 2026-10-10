//! `capture_process` (SPEC §9.4): run one allowlisted command
//! confined, pipes only, and record what happened — exit, signal,
//! timing, and SHA-256 of both streams — so a report can be
//! hashed independently of terminal output. PTY capture and
//! filesystem-diff observation are scaffolded (unknowns below).

use serde_json::{Value, json};
use std::time::Duration;

use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use rea_core::paths;
use rea_core::process::{self, ProcessSpec};
use rea_core::registry::Registry;

/// Maximum argv entries accepted (program plus arguments).
const MAX_ARGV_ITEMS: usize = 64;
/// Per-stream output cap; the rest is counted as truncated.
const OUTPUT_CAP_BYTES: usize = 1_048_576;
/// Hard wall-clock bound for one capture.
const TIMEOUT_SECS: u64 = 60;

/// State subdirectory captures run in.
const WORK_DIR_NAME: &str = "captures";

/// Extract and validate the `command` argument: a non-empty argv
/// whose program is a bare name (no path separators), so the
/// allowlist decision is about a name, never a smuggled path.
fn parse_command(args: &Value) -> Result<Vec<String>, ReaError> {
    let raw = args
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ReaError::new(
                ErrorCode::InvalidRequest,
                "argument 'command' must be an array of strings",
            )
        })?;
    if raw.is_empty() {
        return Err(ReaError::new(
            ErrorCode::InvalidRequest,
            "argument 'command' must not be empty",
        ));
    }
    if raw.len() > MAX_ARGV_ITEMS {
        return Err(ReaError::new(
            ErrorCode::InvalidRequest,
            format!(
                "argument 'command' has {} items; the cap is {MAX_ARGV_ITEMS}",
                raw.len()
            ),
        ));
    }
    let mut argv: Vec<String> = Vec::with_capacity(raw.len());
    for item in raw {
        let text = item.as_str().ok_or_else(|| {
            ReaError::new(
                ErrorCode::InvalidRequest,
                "argument 'command' items must all be strings",
            )
        })?;
        argv.push(text.to_string());
    }
    let program = &argv[0];
    if program.is_empty() || program.contains('/') || program.contains('\\') {
        return Err(ReaError::new(
            ErrorCode::InvalidRequest,
            "the program must be a bare name with no path separators",
        )
        .with_remediation(
            "Allowlist decisions are by program name; pass e.g. \"echo\", not \"/bin/echo\".",
        ));
    }
    Ok(argv)
}

/// Run the capture and build its evidence envelope.
pub fn capture_process(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let argv = parse_command(args)?;
    let program = argv[0].clone();
    if !config.allow_programs.iter().any(|name| name == &program) {
        return Err(ReaError::new(
            ErrorCode::AccessDenied,
            format!("program '{program}' is not in allow_programs"),
        )
        .with_remediation(
            "Add the bare program name to allow_programs in the config to permit captures of it.",
        ));
    }
    let work_dir = paths::state_subdir(config, WORK_DIR_NAME)?;
    let outcome = process::run(&ProcessSpec {
        args: argv[1..].to_vec(),
        cwd: Some(work_dir.clone()),
        env: Vec::new(),
        output_cap: OUTPUT_CAP_BYTES,
        program,
        timeout: Duration::from_secs(TIMEOUT_SECS),
    })?;
    let mut evidence = Evidence::new("capture_process", "observe");
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.add_finding(Finding::new(
        "process_capture",
        Confidence::Observed,
        json!({
            "argv": argv,
            "cwd": work_dir.display().to_string(),
            "duration_ms": outcome.duration_ms,
            "exit_code": outcome.exit_code,
            "signal": outcome.signal,
            "stderr": {
                "bytes": outcome.stderr.len(),
                "sha256": sha256_hex(&outcome.stderr),
                "truncated": outcome.stderr_truncated,
            },
            "stdout": {
                "bytes": outcome.stdout.len(),
                "sha256": sha256_hex(&outcome.stdout),
                "truncated": outcome.stdout_truncated,
            },
            "timed_out": outcome.timed_out,
        }),
    ));
    evidence.add_unknown(
        "pty_capture",
        "PTY observation is scaffolded (SPEC 9.4); capture is pipes-only in this stage",
    );
    evidence.add_unknown(
        "filesystem_diff",
        "filesystem-diff observation is scaffolded (SPEC 9.4); only the confined working directory is provided",
    );
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::config::ConfigFile;
    use rea_core::policy::ToolClass;
    use rea_core::registry::{Registry, descriptor};

    fn config(allow_programs: &[&str]) -> Config {
        let state_dir =
            std::env::temp_dir().join(format!("rea-observe-capture-{}", std::process::id()));
        Config::from_file_form(ConfigFile {
            allow_programs: Some(allow_programs.iter().map(|s| s.to_string()).collect()),
            allow_tools: Some(vec!["capture_process".to_string()]),
            state_dir: Some(state_dir),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn registry() -> Registry {
        let mut registry = Registry::new();
        registry.register(
            descriptor(
                "capture_process",
                ToolClass::Execute,
                "process",
                "test descriptor",
                json!({"type": "object"}),
            ),
            std::sync::Arc::new(capture_process),
        );
        registry
    }

    #[test]
    fn validation_echo_capture_records_exit_and_hashes() {
        let value = registry()
            .call(
                &config(&["echo"]),
                "capture_process",
                &json!({"command": ["echo", "hello"]}),
            )
            .unwrap();
        let finding = &value["findings"][0];
        assert_eq!(finding["kind"], "process_capture");
        assert_eq!(finding["facts"]["exit_code"], 0);
        assert_eq!(finding["facts"]["stdout"]["bytes"], 6);
        assert_eq!(
            finding["facts"]["stdout"]["sha256"],
            sha256_hex(b"hello\n").as_str()
        );
    }

    #[test]
    fn validation_false_exit_code_is_a_finding_not_an_error() {
        let value = registry()
            .call(
                &config(&["false"]),
                "capture_process",
                &json!({"command": ["false"]}),
            )
            .unwrap();
        assert_eq!(value["findings"][0]["facts"]["exit_code"], 1);
    }

    #[test]
    fn adversarial_program_not_allowlisted_is_denied() {
        let err = registry()
            .call(
                &config(&["echo"]),
                "capture_process",
                &json!({"command": ["sh", "-c", "id"]}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
    }

    #[test]
    fn adversarial_program_path_is_rejected() {
        let err = registry()
            .call(
                &config(&["echo"]),
                "capture_process",
                &json!({"command": ["/bin/echo", "hi"]}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_empty_command_is_rejected() {
        let err = registry()
            .call(
                &config(&["echo"]),
                "capture_process",
                &json!({"command": []}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }
}
