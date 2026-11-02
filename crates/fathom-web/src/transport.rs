//! The fetch transport: an owned `curl` child under a fixed
//! flag template (the fathom-video §4.2 discipline, applied to
//! HTTPS reads).
//!
//! The template's safety is by construction: `--disable` (no
//! curlrc), the protocol pinned to HTTPS for the request and
//! any redirect, no cookie flags, no config flags, no proxy
//! flags, no credential slot anywhere — the only variable
//! parts are the URL (host-validated by [`crate::url`]), the
//! chunk body (built by this crate from a shape-proven page
//! id and the server's own cursor tokens), and nothing else.
//! The child runs with a scrubbed environment (`HOME` is the
//! scratch dir) in the scratch dir as cwd, under
//! `fathom_core::process`'s bounded run.
//!
//! The [`NotionTransport`] trait is the test seam: unit tests
//! inject recorded fixtures and never touch the network.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::limits::{WEB_CHUNK_BYTES_MAX, WEB_FETCH_TIMEOUT_SECS, WEB_PAGE_HTML_BYTES_MAX};
use fathom_core::process::{ProcessSpec, run};

use crate::url::{API_HOST, CHUNK_PATH};

/// The browser user-agent the public site serves its bootstrap
/// HTML to.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

/// The status trailer curl appends after the body, so the HTTP
/// status is known exactly (never inferred from curl's exit).
const STATUS_TRAILER: &str = "\n<<<FATHOM-STATUS:";
const STATUS_TRAILER_END: &str = ">>>";

/// One page/chunk source. Implementations must fail with typed
/// errors and return bodies within the named byte caps.
pub trait NotionTransport {
    /// Fetch one page chunk: the `loadCachedPageChunkV2`
    /// document for `page_id` at `chunk_number`, continuing
    /// from `cursor_stack` (the previous response's stack, or
    /// an empty array for the first chunk).
    fn fetch_chunk(
        &self,
        page_id: &str,
        chunk_number: u64,
        cursor_stack: &Value,
    ) -> Result<Value, FathomError>;

    /// Fetch a public page's HTML bootstrap document.
    fn fetch_page_html(&self, url: &str) -> Result<String, FathomError>;
}

/// The chunk request body: built only from the shape-proven
/// page id, the chunk counter, and cursor tokens the server
/// itself returned (serialized by serde_json, never string-
/// interpolated).
pub fn chunk_request_body(page_id: &str, chunk_number: u64, cursor_stack: &Value) -> String {
    json!({
        "chunkNumber": chunk_number,
        "cursor": {"stack": cursor_stack},
        "limit": 100,
        "pageId": page_id,
        "verticalColumns": false,
    })
    .to_string()
}

/// The fixed curl argument template for the page GET. The URL
/// is the only caller-derived element.
pub fn page_get_args(url: &str) -> Vec<String> {
    vec![
        "--disable".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        "--proto".to_string(),
        "=https".to_string(),
        "--max-time".to_string(),
        format!("{}", WEB_FETCH_TIMEOUT_SECS.saturating_sub(5).max(5)),
        "--user-agent".to_string(),
        USER_AGENT.to_string(),
        "--write-out".to_string(),
        format!("{STATUS_TRAILER}%{{http_code}}{STATUS_TRAILER_END}"),
        url.to_string(),
    ]
}

/// The fixed curl argument template for the chunk POST: the
/// API URL is a constant of this crate; the body is built by
/// [`chunk_request_body`].
pub fn chunk_post_args(body: &str) -> Vec<String> {
    vec![
        "--disable".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        "--proto".to_string(),
        "=https".to_string(),
        "--max-time".to_string(),
        format!("{}", WEB_FETCH_TIMEOUT_SECS.saturating_sub(5).max(5)),
        "--user-agent".to_string(),
        USER_AGENT.to_string(),
        "--header".to_string(),
        "Content-Type: application/json".to_string(),
        "--data-binary".to_string(),
        body.to_string(),
        "--write-out".to_string(),
        format!("{STATUS_TRAILER}%{{http_code}}{STATUS_TRAILER_END}"),
        format!("https://{API_HOST}{CHUNK_PATH}"),
    ]
}

/// Split a curl stdout capture into (body, HTTP status) via
/// the status trailer.
pub fn split_status_trailer(stdout: &[u8]) -> Result<(Vec<u8>, u32), FathomError> {
    let text = String::from_utf8_lossy(stdout);
    let start = text.rfind(STATUS_TRAILER).ok_or_else(|| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            "the fetch child returned no HTTP status trailer",
        )
    })?;
    let status_text = &text[start + STATUS_TRAILER.len()..];
    let status: u32 = status_text
        .trim_end_matches(STATUS_TRAILER_END)
        .trim()
        .parse()
        .map_err(|_| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                "the fetch child's HTTP status trailer is malformed",
            )
        })?;
    Ok((text[..start].as_bytes().to_vec(), status))
}

/// The live transport: `curl` as an owned child.
pub struct CurlTransport {
    /// The fetcher program (operator configuration, default
    /// `curl`).
    pub program: PathBuf,
    /// Scratch dir: the child's cwd and its whole `HOME`.
    pub scratch: PathBuf,
}

impl CurlTransport {
    fn run_curl(&self, args: &[String], output_cap: usize) -> Result<(Vec<u8>, u32), FathomError> {
        let spec = ProcessSpec {
            args: args.to_vec(),
            cwd: Some(self.scratch.clone()),
            env: vec![(
                "HOME".to_string(),
                self.scratch.to_string_lossy().into_owned(),
            )],
            output_cap,
            program: self.program.to_string_lossy().into_owned(),
            timeout: Duration::from_secs(WEB_FETCH_TIMEOUT_SECS),
        };
        let outcome = run(&spec)?;
        if outcome.timed_out {
            return Err(FathomError::new(
                ErrorCode::ProviderTimeout,
                format!(
                    "the fetch child exceeded its {WEB_FETCH_TIMEOUT_SECS}s bound and was killed"
                ),
            ));
        }
        if outcome.exit_code != Some(0) {
            let stderr = String::from_utf8_lossy(&outcome.stderr);
            let detail: String = stderr.chars().take(300).collect();
            return Err(FathomError::new(
                ErrorCode::ProviderUnavailable,
                format!(
                    "the fetch child exited {:?}: {}",
                    outcome.exit_code,
                    detail.trim()
                ),
            ));
        }
        if outcome.stdout_truncated {
            return Err(FathomError::new(
                ErrorCode::ResourceConstraint,
                format!("the fetched document exceeded its {output_cap}-byte cap"),
            ));
        }
        split_status_trailer(&outcome.stdout)
    }
}

impl NotionTransport for CurlTransport {
    fn fetch_chunk(
        &self,
        page_id: &str,
        chunk_number: u64,
        cursor_stack: &Value,
    ) -> Result<Value, FathomError> {
        let body = chunk_request_body(page_id, chunk_number, cursor_stack);
        let (bytes, status) = self.run_curl(&chunk_post_args(&body), WEB_CHUNK_BYTES_MAX)?;
        if status != 200 {
            return Err(FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("the chunk endpoint answered HTTP {status} for page {page_id}"),
            ));
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                format!("the chunk endpoint's answer for page {page_id} is not JSON: {e}"),
            )
        })
    }

    fn fetch_page_html(&self, url: &str) -> Result<String, FathomError> {
        let (bytes, status) = self.run_curl(&page_get_args(url), WEB_PAGE_HTML_BYTES_MAX)?;
        if status != 200 {
            return Err(FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("the page answered HTTP {status}: {url}"),
            ));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_chunk_body_escapes_via_serializer() {
        // A hostile cursor token must arrive as data, never as
        // structure: the body is serde_json output, so quotes in
        // the token are escaped and the shape is unchanged.
        let stack = json!(["x\"}); DROP"]);
        let body = chunk_request_body("36a2ccea-40b1-809c-b319-cbf3a8792508", 3, &stack);
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["cursor"]["stack"][0], "x\"}); DROP");
        assert_eq!(parsed["chunkNumber"], 3);
        assert_eq!(parsed["pageId"], "36a2ccea-40b1-809c-b319-cbf3a8792508");
    }

    #[test]
    fn adversarial_templates_carry_no_credential_or_config_flags() {
        let joined = page_get_args("https://noggi3d.notion.site/x").join(" ");
        let posted = chunk_post_args("{}").join(" ");
        for forbidden in [
            "--cookies",
            "--netrc",
            "--proxy",
            "--config",
            "--cert",
            "--key",
        ] {
            assert!(!joined.contains(forbidden), "page template: {forbidden}");
            assert!(!posted.contains(forbidden), "chunk template: {forbidden}");
        }
    }

    #[test]
    fn validation_chunk_body_shape() {
        let body = chunk_request_body("36a2ccea-40b1-809c-b319-cbf3a8792508", 0, &json!([]));
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["limit"], 100);
        assert_eq!(parsed["verticalColumns"], false);
        assert_eq!(parsed["cursor"]["stack"], json!([]));
    }

    #[test]
    fn validation_status_trailer_splits() {
        let raw = b"<html>body</html>\n<<<FATHOM-STATUS:200>>>";
        let (body, status) = split_status_trailer(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"<html>body</html>");
    }

    #[test]
    fn adversarial_missing_trailer_is_unreadable() {
        let err = split_status_trailer(b"no trailer here").unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
    }
}
