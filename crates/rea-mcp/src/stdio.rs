//! MCP over stdio: newline-delimited JSON-RPC on stdin/stdout.
//! Diagnostics go to stderr; stdout carries protocol only.

use std::io::{BufRead, Write};

use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::registry::Registry;

use crate::protocol::handle_message;

/// Serve until stdin closes.
pub fn run_stdio(registry: &Registry, config: &Config) -> Result<(), ReaError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| {
            ReaError::new(
                ErrorCode::ExecutionFailure,
                format!("stdin read failed: {e}"),
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let message: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(e) => {
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")},
                });
                writeln!(writer, "{response}").ok();
                writer.flush().ok();
                continue;
            }
        };
        if let Some(response) = handle_message(registry, config, &message) {
            writeln!(writer, "{response}").map_err(|e| {
                ReaError::new(
                    ErrorCode::ExecutionFailure,
                    format!("stdout write failed: {e}"),
                )
            })?;
            writer.flush().ok();
        }
    }
    Ok(())
}
