//! Era guard: the byte-level front door of the server.
//!
//! rmcp's service layer enforces the modern era at the message
//! level (discover negotiation, per-request `_meta` validation)
//! once the handler pins `supported_protocol_versions` to
//! 2026-07-28 — but it silently drops lines it cannot parse, and
//! it will still *answer* an `initialize` request (with the
//! unsupported-version refusal) only by failing the whole serve.
//! This guard sits in front of the SDK on stdio and owns the
//! framing contract the hand-rolled server always had:
//!
//! - malformed JSON → `-32700` carrying the baseline's
//!   `parse error: {detail}` message (id null); the server stays
//!   alive throughout
//! - `initialize` (any version) → the designed modern-only
//!   refusal, `-32022` naming the supported versions; the
//!   connection and the process stay up, so a probe can continue
//!   with modern frames
//! - unknown methods → `-32601` with the baseline's
//!   `method not found: {method}` text; an id with no method →
//!   the baseline's `-32600`; only `server/discover`, `ping`,
//!   `tools/list`, and name-validated `tools/call` frames are
//!   forwarded to the SDK
//! - notifications (no `id`) and non-object frames are dropped
//!   silently, exactly as the baseline dropped them (its core
//!   keyed every response off `id`)
//! - one inbound line is bounded at 4 MiB — a bound the baseline
//!   did not impose (its domain limits live in `limits.rs` and
//!   still fire downstream with their own shapes); an oversized
//!   line is answered `-32700` and drained
//!
//! Forwarded frames pass through byte-for-byte except that a
//! missing or non-object `params` on discover/list/ping is
//! normalized to `{}` (the baseline ignored those params
//! entirely). `tools/call` frames are forwarded untouched once
//! the name checks out — including non-object `arguments`, which
//! the baseline passed to the handlers; the SDK's typed envelope
//! refuses those at framing, an accepted era difference recorded
//! in the migration gate report.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, Stdin, Stdout,
    WriteHalf,
};
use tokio::sync::Mutex;

/// The one protocol version this server speaks.
pub const MODERN_VERSION: &str = "2026-07-28";
/// Maximum bytes in one JSON-RPC line (the fleet bound).
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

const INVALID_PARAMS: i32 = -32602;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const PARSE_ERROR: i32 = -32700;
const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// Stdout shared by the guard (its own error frames) and the pump
/// (SDK responses); one line is written per lock, never interleaved.
pub type SharedStdout = Arc<Mutex<Stdout>>;

/// Response-ordering state shared by the guard and the pump: the
/// ids of forwarded requests whose SDK response has not yet been
/// written to stdout. The guard never writes one of its own frames
/// while an earlier forwarded request is unanswered (without this,
/// a guard frame — answered instantly — overtakes the SDK's first
/// response, which pays the service bootstrap latency).
pub struct Ordering {
    outstanding: Mutex<Vec<Value>>,
    drained: tokio::sync::Notify,
}

impl Ordering {
    pub fn new() -> Arc<Self> {
        Arc::new(Ordering {
            outstanding: Mutex::new(Vec::new()),
            drained: tokio::sync::Notify::new(),
        })
    }

    async fn track(&self, id: Value) {
        self.outstanding.lock().await.push(id);
    }

    async fn complete(&self, id: &Value) {
        {
            let mut queue = self.outstanding.lock().await;
            if let Some(pos) = queue.iter().position(|q| q == id) {
                queue.remove(pos);
            }
        }
        self.drained.notify_waiters();
    }

    /// Wait until no forwarded request is unanswered. Bounded: if
    /// the SDK died mid-request its response will never come, and
    /// the guard must go on answering framing errors regardless.
    async fn wait_drained(&self) {
        let deadline = std::time::Duration::from_secs(5);
        let _ = tokio::time::timeout(deadline, async {
            loop {
                let notified = self.drained.notified();
                if self.outstanding.lock().await.is_empty() {
                    return;
                }
                notified.await;
            }
        })
        .await;
    }
}

fn error_frame(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// The designed refusal of legacy-era contact (CHECKLIST 1.8 shape:
/// the SDK's own `unsupported_protocol_version` payload).
fn unsupported_version_frame(id: Value, requested: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": UNSUPPORTED_PROTOCOL_VERSION,
            "message": "Unsupported protocol version",
            "data": {"requested": requested, "supported": [MODERN_VERSION]}
        }
    })
}

/// What the guard does with one inbound line.
#[derive(Debug, PartialEq)]
enum Action {
    /// Forward this (possibly params-normalized) frame to the SDK.
    Forward(Value),
    /// Answer it here; the SDK never sees it.
    Respond(Value),
    /// Drop silently (blank line, notification, non-object frame).
    Drop,
}

/// Classify one line. Pure: unit-tested without any transport.
fn classify(line: &[u8]) -> Action {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Action::Drop;
    }
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return Action::Respond(error_frame(
                Value::Null,
                PARSE_ERROR,
                &format!("parse error: {e}"),
            ));
        }
    };
    // The baseline keyed every response off `id`: a frame with no
    // `id` — notification or non-object — was dropped unanswered.
    let Some(object) = value.as_object() else {
        return Action::Drop;
    };
    if !object.contains_key("id") {
        return Action::Drop;
    }
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Action::Respond(error_frame(
            id,
            INVALID_REQUEST,
            "invalid request: no method",
        ));
    };
    match method {
        "initialize" => {
            let requested = object
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .map_or(Value::Null, |v| Value::String(v.to_string()));
            Action::Respond(unsupported_version_frame(id, requested))
        }
        "server/discover" | "ping" | "tools/list" => Action::Forward(normalize_params(value)),
        "tools/call" => match validate_call(object) {
            Ok(()) => Action::Forward(value),
            Err(message) => Action::Respond(error_frame(id, INVALID_PARAMS, &message)),
        },
        other => Action::Respond(error_frame(
            id,
            METHOD_NOT_FOUND,
            &format!("method not found: {other}"),
        )),
    }
}

/// The baseline ignored `params` on discover/list/ping entirely; a
/// missing or non-object value is normalized to `{}` so the SDK's
/// typed envelope always parses.
fn normalize_params(mut value: Value) -> Value {
    let object = value.as_object_mut().expect("classified object");
    match object.get("params") {
        Some(p) if p.is_object() => {}
        _ => {
            object.insert("params".to_string(), json!({}));
        }
    }
    value
}

/// Shape-check a `tools/call` frame against the baseline's params
/// contract: a string `name` must be present. Everything else —
/// including non-object `arguments`, which the baseline passed to
/// the handlers — is forwarded untouched.
fn validate_call(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    let name = object
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str);
    match name {
        Some(_) => Ok(()),
        None => Err("invalid params: tools/call needs a name".to_string()),
    }
}

async fn write_frame(stdout: &SharedStdout, frame: &Value) {
    let mut line = serde_json::to_string(frame).unwrap_or_default();
    line.push('\n');
    let mut out = stdout.lock().await;
    let _ = out.write_all(line.as_bytes()).await;
    let _ = out.flush().await;
}

async fn write_bytes(stdout: &SharedStdout, bytes: &[u8]) {
    let mut out = stdout.lock().await;
    let _ = out.write_all(bytes).await;
    let _ = out.flush().await;
}

/// One inbound line, bounded at [`MAX_LINE_BYTES`]: the error
/// trips when the content (excluding the newline) reaches the
/// bound; an oversized line's remainder is drained.
enum LineOutcome {
    Line(Vec<u8>),
    Oversized,
    Eof,
}

async fn next_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<LineOutcome> {
    let mut out: Vec<u8> = Vec::new();
    let mut content_len = 0usize;
    let mut oversized = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if oversized {
                LineOutcome::Oversized
            } else if out.is_empty() && content_len == 0 {
                LineOutcome::Eof
            } else {
                LineOutcome::Line(out)
            });
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                content_len += pos;
                if content_len >= MAX_LINE_BYTES {
                    oversized = true;
                }
                if !oversized {
                    out.extend_from_slice(&chunk[..pos]);
                }
                reader.consume(pos + 1);
                return Ok(if oversized {
                    LineOutcome::Oversized
                } else {
                    LineOutcome::Line(out)
                });
            }
            None => {
                let len = chunk.len();
                content_len += len;
                if content_len >= MAX_LINE_BYTES {
                    oversized = true;
                    out.clear();
                } else {
                    out.extend_from_slice(chunk);
                }
                reader.consume(len);
            }
        }
    }
}

/// Run the guard until stdin reaches EOF, then shut the duplex
/// write side down: a split write half signals end-of-input to
/// the SDK service only through an explicit shutdown, never by
/// being dropped (both halves share ownership of the stream).
pub async fn run(
    stdin: Stdin,
    mut to_server: WriteHalf<DuplexStream>,
    stdout: SharedStdout,
    ordering: Arc<Ordering>,
) -> std::io::Result<()> {
    let result = forward_loop(stdin, &mut to_server, &stdout, &ordering).await;
    let _ = to_server.shutdown().await;
    result
}

async fn forward_loop(
    stdin: Stdin,
    to_server: &mut WriteHalf<DuplexStream>,
    stdout: &SharedStdout,
    ordering: &Ordering,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stdin);
    loop {
        match next_line(&mut reader).await? {
            LineOutcome::Eof => return Ok(()),
            LineOutcome::Oversized => {
                ordering.wait_drained().await;
                write_frame(
                    stdout,
                    &error_frame(Value::Null, PARSE_ERROR, "request line exceeds size bound"),
                )
                .await;
            }
            LineOutcome::Line(bytes) => match classify(&bytes) {
                Action::Drop => {}
                Action::Respond(frame) => {
                    ordering.wait_drained().await;
                    write_frame(stdout, &frame).await;
                }
                Action::Forward(frame) => {
                    if let Some(id) = frame.get("id").cloned() {
                        ordering.track(id).await;
                    }
                    let mut line = serde_json::to_string(&frame).unwrap_or_default();
                    line.push('\n');
                    to_server.write_all(line.as_bytes()).await?;
                    to_server.flush().await?;
                }
            },
        }
    }
}

/// Copy SDK responses from the duplex to stdout, one line at a
/// time, marking each answered request id complete for the guard's
/// ordering wait.
pub async fn pump(
    mut from_server: ReadHalf<DuplexStream>,
    stdout: SharedStdout,
    ordering: Arc<Ordering>,
) {
    let mut reader = BufReader::new(&mut from_server);
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                write_bytes(&stdout, &line).await;
                if let Ok(frame) = serde_json::from_slice::<Value>(&line)
                    && let Some(id) = frame.get("id")
                {
                    ordering.complete(id).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_str(s: &str) -> Action {
        classify(s.as_bytes())
    }

    #[test]
    fn adversarial_malformed_calls_get_the_baseline_params_error() {
        for frame in [
            "{\"id\":1,\"method\":\"tools/call\",\"params\":{}}",
            "{\"id\":1,\"method\":\"tools/call\"}",
            "{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":42}}",
            "{\"id\":1,\"method\":\"tools/call\",\"params\":\"nope\"}",
        ] {
            match classify_str(frame) {
                Action::Respond(f) => {
                    assert_eq!(f["error"]["code"], INVALID_PARAMS);
                    assert_eq!(
                        f["error"]["message"],
                        "invalid params: tools/call needs a name"
                    );
                }
                other => panic!("expected respond for {frame}, got {other:?}"),
            }
        }
    }

    #[test]
    fn adversarial_unknown_method_names_the_method() {
        match classify_str("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"resources/list\"}") {
            Action::Respond(f) => {
                assert_eq!(f["error"]["code"], METHOD_NOT_FOUND);
                assert_eq!(f["error"]["message"], "method not found: resources/list");
            }
            other => panic!("expected respond, got {other:?}"),
        }
        // An id with no method is the baseline's invalid request.
        match classify_str("{\"id\":1,\"jsonrpc\":\"2.0\"}") {
            Action::Respond(f) => {
                assert_eq!(f["error"]["code"], INVALID_REQUEST);
                assert_eq!(f["error"]["message"], "invalid request: no method");
            }
            other => panic!("expected respond, got {other:?}"),
        }
    }

    #[test]
    fn blank_lines_notifications_and_non_objects_drop() {
        assert_eq!(classify_str("  \n"), Action::Drop);
        assert_eq!(
            classify_str("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"),
            Action::Drop
        );
        // Even a notification-shaped initialize is a notification.
        assert_eq!(
            classify_str("{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{}}"),
            Action::Drop
        );
        // A notification-shaped tools/call is dropped UNEXECUTED.
        assert_eq!(
            classify_str(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"session_info\"}}"
            ),
            Action::Drop
        );
        // The baseline keyed responses off `id`; a non-object
        // frame has none and was dropped, never answered.
        assert_eq!(classify_str("[1,2,3]"), Action::Drop);
        assert_eq!(classify_str("42"), Action::Drop);
    }

    #[test]
    fn framing_errors_match_the_baseline() {
        match classify_str("this is not json") {
            Action::Respond(f) => {
                assert_eq!(f["error"]["code"], PARSE_ERROR);
                assert_eq!(f["id"], Value::Null);
                let message = f["error"]["message"].as_str().unwrap();
                assert!(
                    message.starts_with("parse error: "),
                    "message was: {message}"
                );
            }
            other => panic!("expected respond, got {other:?}"),
        }
    }

    #[test]
    fn initialize_is_refused_with_supported_versions() {
        let frame = "{\"id\":7,\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}";
        match classify_str(frame) {
            Action::Respond(f) => {
                assert_eq!(f["id"], 7);
                assert_eq!(f["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION);
                assert_eq!(f["error"]["data"]["requested"], "2025-06-18");
                assert_eq!(f["error"]["data"]["supported"], json!(["2026-07-28"]));
            }
            other => panic!("expected respond, got {other:?}"),
        }
    }

    #[test]
    fn valid_modern_frames_forward() {
        for frame in [
            "{\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{}}}",
            "{\"id\":2,\"method\":\"tools/list\",\"params\":{\"_meta\":{}}}",
            "{\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"session_info\",\"arguments\":{},\"_meta\":{}}}",
            "{\"id\":4,\"method\":\"ping\"}",
        ] {
            match classify_str(frame) {
                Action::Forward(_) => {}
                other => panic!("expected forward for {frame}, got {other:?}"),
            }
        }
        // Non-object params on tools/list normalize to {}.
        match classify_str("{\"id\":9,\"method\":\"tools/list\",\"params\":\"x\"}") {
            Action::Forward(f) => assert_eq!(f["params"], json!({})),
            other => panic!("expected forward, got {other:?}"),
        }
        // Non-object arguments forward untouched: the baseline
        // passed them to the handlers (the SDK refuses them at
        // framing — the recorded era exception).
        match classify_str(
            "{\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"session_info\",\"arguments\":\"nope\"}}",
        ) {
            Action::Forward(f) => assert_eq!(f["params"]["arguments"], json!("nope")),
            other => panic!("expected forward, got {other:?}"),
        }
    }
}
