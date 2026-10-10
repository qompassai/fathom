//! `inspect_web_capture` (SPEC §9.4): HAR 1.2 reading — entry,
//! request, and response inventories plus payload exposure
//! flags. Exposure flags are `derived`: rules over observed
//! capture content, each carrying the entry indexes it fired on.
//! mitmproxy native captures are scaffolded (they need an
//! external `mitmdump` reader).

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

use rea_core::config::Config;
use rea_core::error::{ErrorCode, ReaError};
use rea_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use rea_core::paths;
use rea_core::registry::{Registry, require_str};

/// Largest capture file read, in bytes.
const MAX_HAR_BYTES: u64 = 67_108_864;
/// Entries examined per capture; the rest is a coverage fact.
const MAX_ENTRIES_EXAMINED: usize = 10_000;
/// Entry indexes listed per exposure flag.
const MAX_FLAGGED_INDEXES: usize = 50;
/// Query parameter names that mark credentials in a URL.
const SENSITIVE_PARAMS: [&str; 10] = [
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "passwd",
    "password",
    "pwd",
    "secret",
    "session",
    "token",
];

/// Whether a URL carries credentials: userinfo in the authority
/// or a sensitive query parameter name.
fn url_has_credentials(url: &str) -> bool {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return true;
    }
    let Some(query) = url.split('?').nth(1) else {
        return false;
    };
    let query = query.split('#').next().unwrap_or(query);
    query.split('&').any(|pair| {
        let name = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
        SENSITIVE_PARAMS.contains(&name.as_str())
    })
}

/// Append an entry index to a flag's list, under the listing cap.
fn flag(indexes: &mut Vec<usize>, index: usize) {
    if indexes.len() < MAX_FLAGGED_INDEXES {
        indexes.push(index);
    }
}

/// Read and inventory one HAR capture.
pub fn inspect_web_capture(_: &Registry, config: &Config, args: &Value) -> Result<Value, ReaError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let size = std::fs::metadata(&path)
        .map_err(|e| {
            ReaError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot stat target: {e}"),
            )
        })?
        .len();
    if size > MAX_HAR_BYTES {
        return Err(ReaError::new(
            ErrorCode::ResourceConstraint,
            format!("capture is {size} bytes; the cap is {MAX_HAR_BYTES}"),
        ));
    }
    let raw = std::fs::read(&path).map_err(|e| {
        ReaError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    let document: Value = serde_json::from_slice(&raw).map_err(|e| {
        ReaError::new(
            ErrorCode::UnsupportedTarget,
            format!("not a HAR document: {e}"),
        )
    })?;
    let entries = document
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ReaError::new(
                ErrorCode::UnsupportedTarget,
                "not a HAR 1.2 document: log.entries is missing or not an array",
            )
        })?;

    let mut methods: BTreeMap<String, u64> = BTreeMap::new();
    let mut mime_types: BTreeMap<String, u64> = BTreeMap::new();
    let mut status_classes: BTreeMap<String, u64> = BTreeMap::new();
    let mut cleartext_http: Vec<usize> = Vec::new();
    let mut credentials_in_url: Vec<usize> = Vec::new();
    let mut request_body_captured: Vec<usize> = Vec::new();
    let mut response_body_captured: Vec<usize> = Vec::new();

    let examined = entries.len().min(MAX_ENTRIES_EXAMINED);
    for (index, entry) in entries.iter().take(examined).enumerate() {
        let request = entry.get("request");
        let response = entry.get("response");
        if let Some(method) = request
            .and_then(|r| r.get("method"))
            .and_then(Value::as_str)
        {
            *methods.entry(method.to_string()).or_default() += 1;
        }
        if let Some(status) = response
            .and_then(|r| r.get("status"))
            .and_then(Value::as_u64)
        {
            let class = match status {
                100..=199 => "1xx",
                200..=299 => "2xx",
                300..=399 => "3xx",
                400..=499 => "4xx",
                500..=599 => "5xx",
                _ => "other",
            };
            *status_classes.entry(class.to_string()).or_default() += 1;
        }
        if let Some(mime) = response
            .and_then(|r| r.pointer("/content/mimeType"))
            .and_then(Value::as_str)
        {
            *mime_types.entry(mime.to_string()).or_default() += 1;
        }
        if let Some(url) = request.and_then(|r| r.get("url")).and_then(Value::as_str) {
            if url.starts_with("http://") {
                flag(&mut cleartext_http, index);
            }
            if url_has_credentials(url) {
                flag(&mut credentials_in_url, index);
            }
        }
        if request
            .and_then(|r| r.pointer("/postData/text"))
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
        {
            flag(&mut request_body_captured, index);
        }
        if response
            .and_then(|r| r.pointer("/content/text"))
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
        {
            flag(&mut response_body_captured, index);
        }
    }

    let mut evidence = Evidence::new("inspect_web_capture", "web");
    evidence.subject = Some(subject);
    evidence.coverage.examined = examined as u64;
    evidence.coverage.total = entries.len() as u64;
    evidence.add_finding(Finding::new(
        "har_inventory",
        Confidence::Observed,
        json!({
            "entries_examined": examined,
            "entries_total": entries.len(),
            "methods": methods,
            "mime_types": mime_types,
            "status_classes": status_classes,
        }),
    ));
    for (flag_name, indexes) in [
        ("cleartext_http", &cleartext_http),
        ("credentials_in_url", &credentials_in_url),
        ("request_body_captured", &request_body_captured),
        ("response_body_captured", &response_body_captured),
    ] {
        if !indexes.is_empty() {
            evidence.add_finding(Finding::new(
                "payload_exposure",
                Confidence::Derived,
                json!({
                    "entries": indexes,
                    "flag": flag_name,
                }),
            ));
        }
    }
    evidence.add_unknown(
        "mitmproxy_captures",
        "mitmproxy native captures are scaffolded (SPEC 9.4); only HAR 1.2 documents are read in this stage",
    );
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::config::ConfigFile;
    use std::io::Write;

    fn fixture_config(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            state_dir: Some(root.join("state")),
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn write_fixture(root: &Path, body: &str) -> Config {
        std::fs::create_dir_all(root).unwrap();
        let mut file = std::fs::File::create(root.join("capture.har")).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        fixture_config(root)
    }

    const HAR: &str = r#"{
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://example.test/a"},
                    "response": {"status": 200, "content": {"mimeType": "text/html", "text": "<html/>"}}
                },
                {
                    "request": {"method": "POST", "url": "http://example.test/login?token=abc",
                                "postData": {"text": "user=x"}},
                    "response": {"status": 404, "content": {"mimeType": "application/json"}}
                }
            ]
        }
    }"#;

    #[test]
    fn validation_har_inventory_and_exposure_flags() {
        let root = std::env::temp_dir().join(format!("rea-observe-har-{}", std::process::id()));
        let config = write_fixture(&root, HAR);
        let value = inspect_web_capture(
            &Registry::new(),
            &config,
            &json!({"target": root.join("capture.har").to_str().unwrap()}),
        )
        .unwrap();
        let inventory = &value["findings"][0];
        assert_eq!(inventory["facts"]["entries_total"], 2);
        assert_eq!(inventory["facts"]["methods"]["GET"], 1);
        assert_eq!(inventory["facts"]["status_classes"]["4xx"], 1);
        let flags: Vec<&str> = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["kind"] == "payload_exposure")
            .map(|f| f["facts"]["flag"].as_str().unwrap())
            .collect();
        assert_eq!(
            flags,
            vec![
                "cleartext_http",
                "credentials_in_url",
                "request_body_captured",
                "response_body_captured"
            ]
        );
    }

    #[test]
    fn adversarial_non_har_json_is_unsupported() {
        let root = std::env::temp_dir().join(format!("rea-observe-har-bad-{}", std::process::id()));
        let config = write_fixture(&root, "{\"hello\": true}");
        let err = inspect_web_capture(
            &Registry::new(),
            &config,
            &json!({"target": root.join("capture.har").to_str().unwrap()}),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
    }

    #[test]
    fn adversarial_credentials_detection_covers_userinfo() {
        assert!(url_has_credentials("https://user:pw@example.test/x"));
        assert!(url_has_credentials("https://example.test/x?api_key=1"));
        assert!(!url_has_credentials("https://example.test/x?page=1"));
    }
}
