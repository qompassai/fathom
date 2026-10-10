//! Bounded child processes (SPEC §8).
//!
//! Providers run only processes they own: each child starts in
//! its own process group, output is captured up to a named cap,
//! and a timeout kills the group — never a process the caller
//! cannot prove it owns.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{ErrorCode, ReaError};

/// What to run, where, and for how long.
#[derive(Clone, Debug)]
pub struct ProcessSpec {
    pub args: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
    pub env: Vec<(String, String)>,
    pub output_cap: usize,
    pub program: String,
    pub timeout: Duration,
}

/// What the run did, including truncation and timeout facts.
#[derive(Clone, Debug)]
pub struct ProcessOutcome {
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub timed_out: bool,
}

fn read_capped(
    mut stream: impl Read + Send + 'static,
    cap: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut kept: Vec<u8> = Vec::new();
        let mut chunk = [0_u8; 8192];
        let mut truncated = false;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if kept.len() < cap {
                        let room = cap - kept.len();
                        let take = room.min(n);
                        kept.extend_from_slice(&chunk[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(_) => break,
            }
        }
        (kept, truncated)
    })
}

#[cfg(unix)]
fn prepare_command(spec: &ProcessSpec) -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    command
}

#[cfg(not(unix))]
fn prepare_command(spec: &ProcessSpec) -> Command {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn kill_owned(child: &mut Child) {
    #[cfg(unix)]
    {
        // The child leads its own process group (process_group(0)),
        // so a negative PID targets exactly the group we created.
        let pgid = child.id();
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{pgid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

/// Run a bounded child process and report exactly what happened.
pub fn run(spec: &ProcessSpec) -> Result<ProcessOutcome, ReaError> {
    let mut command = prepare_command(spec);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    let started = Instant::now();
    let mut child = command.spawn().map_err(|e| {
        ReaError::new(
            ErrorCode::ProviderUnavailable,
            format!("cannot start {}: {e}", spec.program),
        )
    })?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let out_reader = read_capped(stdout, spec.output_cap);
    let err_reader = read_capped(stderr, spec.output_cap);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= spec.timeout {
                    timed_out = true;
                    kill_owned(&mut child);
                    match child.wait() {
                        Ok(status) => break status,
                        Err(e) => {
                            return Err(ReaError::new(
                                ErrorCode::ExecutionFailure,
                                format!("wait after kill failed: {e}"),
                            ));
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(ReaError::new(
                    ErrorCode::ExecutionFailure,
                    format!("cannot wait on {}: {e}", spec.program),
                ));
            }
        }
    };
    let (stdout, stdout_truncated) = out_reader.join().unwrap_or_default();
    let (stderr, stderr_truncated) = err_reader.join().unwrap_or_default();
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;
    Ok(ProcessOutcome {
        duration_ms: started.elapsed().as_millis() as u64,
        exit_code: status.code(),
        signal,
        stderr,
        stderr_truncated,
        stdout,
        stdout_truncated,
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(program: &str, args: &[&str], timeout_ms: u64, cap: usize) -> ProcessSpec {
        ProcessSpec {
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: None,
            env: Vec::new(),
            output_cap: cap,
            program: program.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[test]
    fn adversarial_missing_program_is_provider_unavailable() {
        let err = run(&spec("/nonexistent-rea-program-xyz", &[], 1000, 1024)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProviderUnavailable);
    }

    #[test]
    fn adversarial_timeout_kills_and_reports() {
        let outcome = run(&spec("/bin/sleep", &["30"], 150, 1024)).unwrap();
        assert!(outcome.timed_out);
        assert!(outcome.duration_ms < 10_000);
    }

    #[test]
    fn adversarial_output_cap_truncates_and_reports() {
        let outcome = run(&spec("/bin/echo", &["hello world, this is long"], 5000, 4)).unwrap();
        assert_eq!(outcome.stdout.len(), 4);
        assert!(outcome.stdout_truncated);
    }

    #[test]
    fn validation_echo_round_trip() {
        let outcome = run(&spec("/bin/echo", &["hello"], 5000, 1024)).unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.stdout, b"hello\n");
        assert!(!outcome.timed_out);
    }
}
