//! Bounded child processes (SPEC §8).
//!
//! Providers run only processes they own: each child starts in
//! its own process group, output is captured up to a named cap,
//! and a timeout kills the group — never a process the caller
//! cannot prove it owns.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{ErrorCode, FathomError};

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

/// Parse the proof that `child_pid` leads a process group owned
/// by `caller_pid`, from `/proc/<pid>/stat` text. The fields after
/// the parenthesised comm are: state, ppid, pgrp, ... Ownership
/// means the child's parent is the caller (it is the process we
/// spawned, not a recycled pid now owned by someone else) and the
/// child leads its own group (pgrp == pid), which
/// `process_group(0)` arranged at spawn. Anything else — a
/// recycled pid, a reparented orphan, a group the child merely
/// joined — proves nothing and yields `None`.
#[cfg(unix)]
fn parse_owned_pgid(stat: &str, child_pid: u32, caller_pid: u32) -> Option<u32> {
    let after_comm = stat.rsplit(')').next()?;
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    let ppid: u32 = fields.next()?.parse().ok()?;
    let pgrp: u32 = fields.next()?.parse().ok()?;
    if ppid == caller_pid && pgrp == child_pid {
        Some(pgrp)
    } else {
        None
    }
}

/// The live proof for a spawned child: read its `/proc` stat and
/// check it still names a group we created (see
/// [`parse_owned_pgid`]).
#[cfg(unix)]
fn verified_owned_pgid(child_pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{child_pid}/stat")).ok()?;
    parse_owned_pgid(&stat, child_pid, std::process::id())
}

fn kill_owned(child: &mut Child) {
    #[cfg(unix)]
    {
        // Group-kill only a group we can prove we created: the
        // child still has us as its parent and leads its own
        // group (process_group(0) at spawn). A pid recycled in
        // the interval since spawn fails the proof — the bare
        // `kill -KILL -<pid>` form once landed on the caller's
        // own process group in a fast-recycling pid namespace
        // and detonated the executing session. On any doubt the
        // fallback kills only the child handle we hold, never a
        // group we cannot prove is ours.
        if let Some(pgid) = verified_owned_pgid(child.id()) {
            // The `--` separator is load-bearing: without it,
            // procps `kill` parses `-<pgid>` as something benign
            // and exits 0 having signalled nothing (measured in
            // the sandbox, 2026-10-27) — a timeout would then
            // report a kill that never happened.
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{pgid}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    let _ = child.kill();
}

/// Run a bounded child process and report exactly what happened.
pub fn run(spec: &ProcessSpec) -> Result<ProcessOutcome, FathomError> {
    let mut command = prepare_command(spec);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    let started = Instant::now();
    let mut child = command.spawn().map_err(|e| {
        FathomError::new(
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
                            return Err(FathomError::new(
                                ErrorCode::ExecutionFailure,
                                format!("wait after kill failed: {e}"),
                            ));
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(FathomError::new(
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
    fn adversarial_parse_owned_pgid_rejects_malformed_stat() {
        assert_eq!(parse_owned_pgid("not a stat line", 4242, 1000), None);
        assert_eq!(parse_owned_pgid("4242 (sleep)", 4242, 1000), None);
        assert_eq!(parse_owned_pgid("4242 (sleep) S x y", 4242, 1000), None);
    }

    #[test]
    fn adversarial_parse_owned_pgid_rejects_non_leader() {
        // Our child, but it joined the caller's group (pgrp names
        // the caller, not the child): group-killing it would
        // signal the caller's own group.
        let stat = "4242 (sleep) S 1000 1000 1000 0 -1 4194304";
        assert_eq!(parse_owned_pgid(stat, 4242, 1000), None);
    }

    #[test]
    fn adversarial_parse_owned_pgid_rejects_recycled_pid() {
        // The pid now belongs to a process whose parent is not
        // the caller (recycled after our child exited): its group
        // is someone else's, however leader-shaped it looks.
        let stat = "4242 (sleep) S 1 4242 4242 0 -1 4194304";
        assert_eq!(parse_owned_pgid(stat, 4242, 1000), None);
        // A reparented orphan (parent is another live process)
        // proves nothing either.
        let stat = "4242 (sleep) S 777 4242 4242 0 -1 4194304";
        assert_eq!(parse_owned_pgid(stat, 4242, 1000), None);
    }

    #[test]
    fn adversarial_timeout_group_kill_spares_a_bystander_group() {
        use std::os::unix::process::CommandExt;
        let mut bystander = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let outcome = run(&spec("/bin/sleep", &["30"], 150, 1024)).unwrap();
        assert!(outcome.timed_out);
        assert!(
            bystander.try_wait().unwrap().is_none(),
            "a group we did not create must survive our timeout kill"
        );
        bystander.kill().unwrap();
        bystander.wait().unwrap();
    }

    #[test]
    fn adversarial_timeout_kills_the_whole_group() {
        // The shell backgrounds a grandchild in its own group and
        // waits: if only the shell died, the run would block on
        // the grandchild's inherited pipes until it exits (~30 s).
        let outcome = run(&spec("/bin/sh", &["-c", "sleep 30 & wait"], 200, 1024)).unwrap();
        assert!(outcome.timed_out);
        assert!(outcome.duration_ms < 10_000);
    }

    #[test]
    fn adversarial_missing_program_is_provider_unavailable() {
        let err = run(&spec("/nonexistent-fathom-program-xyz", &[], 1000, 1024)).unwrap_err();
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
    fn validation_parse_owned_pgid_accepts_own_group_leader() {
        // pid 4242, comm with a space in it, parent = caller
        // (1000), group leader of its own group (pgrp == pid).
        let stat = "4242 (sleep 30) S 1000 4242 4242 0 -1 4194304";
        assert_eq!(parse_owned_pgid(stat, 4242, 1000), Some(4242));
    }

    #[test]
    fn validation_echo_round_trip() {
        let outcome = run(&spec("/bin/echo", &["hello"], 5000, 1024)).unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.stdout, b"hello\n");
        assert!(!outcome.timed_out);
    }
}
