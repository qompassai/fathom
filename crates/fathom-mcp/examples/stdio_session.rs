//! stdio_session: drive one modern-era (2026-07-28) MCP session against the fathom server: server/discover -> tools/list -> one read-only session_info call. Expected output: a transcript summary (server name/version, tool count and names, first bytes of the tool result), one line per step.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const META: &str = r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"bench-example","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}"#;
const MAX_RESPONSE_BYTES: usize = 1 << 20;

struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn spawn(program: &str, args: &[String]) -> Result<Session, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn {program}: {e}"))?;
    let stdin = child.stdin.take().ok_or("child stdin missing")?;
    let stdout = child.stdout.take().ok_or("child stdout missing")?;
    Ok(Session {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

impl Session {
    fn request(&mut self, frame: &str) -> Result<String, String> {
        self.stdin
            .write_all(frame.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        self.stdin
            .write_all(b"\n")
            .map_err(|e| format!("write: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;
        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("server closed stdout".to_string());
        }
        if line.len() > MAX_RESPONSE_BYTES {
            return Err("response over bound".to_string());
        }
        Ok(line)
    }
}

fn server_binary() -> String {
    if let Ok(path) = std::env::var("SERVER_BIN") {
        return path;
    }
    // Search ancestors of this executable for the server binary:
    // directly (target/<profile>/<bin>) or under primo's
    // build/<pkg>/<hash>/out/ layout, with a bounded scan.
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..8 {
            let Some(d) = dir else { break };
            let direct = d.join("fathom");
            if direct.is_file() {
                return direct.to_string_lossy().into_owned();
            }
            if let Some(found) = scan_for(&d, "fathom", 4) {
                return found;
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
    }
    "fathom".to_string()
}

fn scan_for(root: &std::path::Path, name: &str, _depth: usize) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    // Primo's cargo layout: <profile>/build/<crate>/<hash>/out/<bin>-<hash>.
    let build = root.join("build");
    let Ok(crates) = std::fs::read_dir(&build) else {
        return None;
    };
    for krate in crates.flatten() {
        if !krate
            .file_name()
            .to_string_lossy()
            .starts_with("fathom-cli")
        {
            continue;
        }
        let Ok(hashes) = std::fs::read_dir(krate.path()) else {
            continue;
        };
        for hash in hashes.flatten() {
            // Skip unit-test artifacts: their fingerprint dir carries
            // output-test-bin-*, the real binary's carries output-bin-*.
            let fingerprint = hash.path().join("fingerprint");
            if let Ok(entries) = std::fs::read_dir(&fingerprint) {
                let names: Vec<String> = entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                if names.iter().any(|n| n.starts_with("output-test-"))
                    && !names.iter().any(|n| n.starts_with("output-bin-"))
                {
                    continue;
                }
            }
            let out = hash.path().join("out");
            let Ok(files) = std::fs::read_dir(&out) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                let file_name = file.file_name();
                let file_name = file_name.to_string_lossy();
                let hashed = file_name.len() > name.len()
                    && file_name.starts_with(name)
                    && file_name.as_bytes()[name.len()] == b'-'
                    && !file_name.ends_with(".d");
                if (file_name == name || hashed)
                    && file
                        .metadata()
                        .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
                {
                    return Some(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    None
}

fn main() {
    let extra: Vec<String> = std::env::args().skip(1).collect();
    let server_args: &[&str] = &["serve"];
    let mut args: Vec<String> = server_args.iter().map(|s| s.to_string()).collect();
    args.extend(extra);
    if let Err(error) = run(&args) {
        eprintln!("stdio_session: {error}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let program = server_binary();
    let mut session = spawn(&program, args)?;
    let discover = session.request(&format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{"_meta":{META}}}}}"#
    ))?;
    println!("discover: {}", summarize(&discover, 300));
    let list = session.request(&format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{"_meta":{META}}}}}"#
    ))?;
    println!("tools/list: {}", summarize(&list, 300));
    let call = session.request(&format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"session_info","arguments":{{}},"_meta":{META}}}}}"#
    ))?;
    println!("tools/call session_info: {}", summarize(&call, 300));
    drop(session.stdin);
    let _ = session.child.kill();
    Ok(())
}

fn summarize(line: &str, bound: usize) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= bound {
        trimmed.to_string()
    } else {
        format!("{}... [{} bytes total]", &trimmed[..bound], trimmed.len())
    }
}
