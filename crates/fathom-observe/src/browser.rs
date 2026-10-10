//! `observe_browser` (SPEC §9.4): Chromium-headless page inventory.
//!
//! Chromium is an owned child process under the bounded runner.
//! The provider inventories the serialized DOM Chromium returns:
//! title, meta tags, scripts, link elements, anchors, and forms.
//! It does not claim a network log, a response status, or a
//! screenshot — Chromium's dump-dom surface does not expose them.

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::paths;
use fathom_core::process::{self, ProcessSpec};
use fathom_core::registry::{Registry, require_str};

/// Serialized DOM bytes retained from Chromium.
const BROWSER_OUTPUT_BYTES_MAX: usize = 2_097_152;
/// Wall-clock bound for one Chromium observation.
const BROWSER_TIMEOUT_SECS: u64 = 20;
/// Virtual time Chromium may spend settling the page.
const BROWSER_VIRTUAL_TIME_BUDGET_MS: u64 = 5_000;
/// Forms inventoried from one page.
const FORM_COUNT_MAX: usize = 128;
/// Fields inventoried from one form.
const FORM_FIELD_COUNT_MAX: usize = 128;
/// Anchors and link elements inventoried from one page.
const LINK_COUNT_MAX: usize = 512;
/// Meta tags inventoried from one page.
const META_COUNT_MAX: usize = 128;
/// Scripts inventoried from one page.
const SCRIPT_COUNT_MAX: usize = 512;
/// Characters retained from a title or anchor text.
const TEXT_CHARS_MAX: usize = 512;
/// Characters accepted in one URL argument.
const URL_CHARS_MAX: usize = 4_096;
/// Characters retained from one attribute value in evidence.
const VALUE_CHARS_MAX: usize = 2_048;

#[derive(Debug, Default, Serialize)]
struct Anchor {
    href: String,
    text: String,
}

#[derive(Debug, Default, Serialize)]
struct BrowserInventory {
    anchors: Vec<Anchor>,
    dom_bytes: usize,
    dom_sha256: String,
    forms: Vec<Form>,
    link_elements: Vec<LinkElement>,
    meta: Vec<MetaTag>,
    scripts: Vec<Script>,
    title: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct Form {
    action: String,
    fields: Vec<FormField>,
    method: String,
}

#[derive(Debug, Default, Serialize)]
struct FormField {
    id: Option<String>,
    name: Option<String>,
    required: bool,
    #[serde(rename = "type")]
    field_type: String,
}

#[derive(Debug, Default, Serialize)]
struct LinkElement {
    href: String,
    rel: Option<String>,
    #[serde(rename = "type")]
    element_type: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct MetaTag {
    charset: Option<String>,
    content: Option<String>,
    http_equiv: Option<String>,
    name: Option<String>,
    property: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct Script {
    kind: String,
    sha256: Option<String>,
    size_bytes: Option<usize>,
    source: Option<String>,
}

#[derive(Debug)]
struct Tag {
    attrs: BTreeMap<String, String>,
    closing: bool,
    end: usize,
    name: String,
}

/// Observe one page through Chromium headless and inventory its DOM.
pub(crate) fn observe_browser(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let requested_url = validate_url(require_str(args, "url")?)?;
    let work_dir = paths::state_subdir(config, "browser-work")?;
    let profile_dir = browser_profile_dir(config)?;
    let outcome = process::run(&ProcessSpec {
        args: vec![
            "--headless=new".to_string(),
            "--disable-gpu".to_string(),
            "--disable-dev-shm-usage".to_string(),
            "--disable-extensions".to_string(),
            "--no-default-browser-check".to_string(),
            "--no-first-run".to_string(),
            format!("--user-data-dir={}", profile_dir.display()),
            format!("--virtual-time-budget={BROWSER_VIRTUAL_TIME_BUDGET_MS}"),
            "--dump-dom".to_string(),
            requested_url.clone(),
        ],
        cwd: Some(work_dir),
        env: Vec::new(),
        output_cap: BROWSER_OUTPUT_BYTES_MAX,
        program: "chromium".to_string(),
        timeout: Duration::from_secs(BROWSER_TIMEOUT_SECS),
    });
    let cleanup_failed = std::fs::remove_dir_all(&profile_dir).is_err();
    let outcome = outcome?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!("chromium did not finish within {BROWSER_TIMEOUT_SECS} seconds"),
        )
        .with_target(requested_url));
    }
    if outcome.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&outcome.stderr);
        return Err(FathomError::new(
            ErrorCode::ProviderUnavailable,
            format!(
                "chromium returned no DOM (exit {:?}, signal {:?}): {}",
                outcome.exit_code,
                outcome.signal,
                truncate_text(stderr.trim(), 512)
            ),
        )
        .with_target(requested_url));
    }
    let dom = String::from_utf8_lossy(&outcome.stdout).into_owned();
    let mut inventory = parse_dom(&dom, &requested_url);
    inventory.dom_bytes = outcome.stdout.len();
    inventory.dom_sha256 = sha256_hex(&outcome.stdout);
    let mut evidence = Evidence::new("observe_browser", "browser");
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    let mut finding = Finding::new(
        "browser_inventory",
        Confidence::Observed,
        json!({
            "anchors": inventory.anchors,
            "cleanup_failed": cleanup_failed,
            "dom_bytes": inventory.dom_bytes,
            "dom_sha256": inventory.dom_sha256,
            "dom_truncated": outcome.stdout_truncated,
            "duration_ms": outcome.duration_ms,
            "exit_code": outcome.exit_code,
            "forms": inventory.forms,
            "link_elements": inventory.link_elements,
            "meta": inventory.meta,
            "requested_url": requested_url,
            "scripts": inventory.scripts,
            "signal": outcome.signal,
            "title": inventory.title,
        }),
    )
    .with_limitation(
        "Inventory is parsed from Chromium's serialized DOM after its virtual-time budget; it is not a network log, response record, or screenshot.",
    );
    if outcome.stdout_truncated {
        finding = finding.with_limitation(format!(
            "Serialized DOM was truncated at {BROWSER_OUTPUT_BYTES_MAX} bytes; counts cover the retained prefix only."
        ));
    }
    evidence.add_finding(finding);
    evidence.add_unknown(
        "network_requests",
        "Chromium dump-dom does not expose the request/response log in this provider",
    );
    evidence.add_unknown(
        "response_status",
        "Chromium dump-dom does not expose the final HTTP status or redirect chain in this provider",
    );
    evidence.add_unknown(
        "screenshots",
        "screenshots are not collected by this provider run",
    );
    Ok(evidence.to_value())
}

/// Validate an HTTP(S) URL and remove its fragment. Credentials in
/// the authority are rejected: they are data the evidence would
/// otherwise carry, and browser observation is data-minimizing.
fn validate_url(raw: &str) -> Result<String, FathomError> {
    let invalid = |message: &str| {
        FathomError::new(ErrorCode::InvalidRequest, message.to_string())
            .with_target("observe_browser")
    };
    if raw.is_empty() || raw.chars().count() > URL_CHARS_MAX {
        return Err(invalid("url is empty or exceeds the length bound"));
    }
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid("url contains whitespace or control characters"));
    }
    if raw.contains('\\') {
        return Err(invalid("url must use forward slashes"));
    }
    let lower = raw.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("https://") {
        8
    } else if lower.starts_with("http://") {
        7
    } else {
        return Err(invalid("only http:// and https:// URLs are observable"));
    };
    let without_fragment = raw.split('#').next().unwrap_or(raw);
    let authority = without_fragment[scheme_len..]
        .split(['/', '?'])
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return Err(invalid("url has no authority"));
    }
    if authority.contains('@') {
        return Err(invalid("urls with userinfo credentials are rejected"));
    }
    if let Some(port) = authority_port(authority) {
        if port.parse::<u16>().is_err() {
            return Err(invalid("url port is not a valid u16"));
        }
    }
    Ok(without_fragment.to_string())
}

fn authority_port(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        return rest[close + 1..].strip_prefix(':');
    }
    authority
        .rsplit(':')
        .next()
        .filter(|_| authority.matches(':').count() == 1)
}

fn browser_profile_dir(config: &Config) -> Result<PathBuf, FathomError> {
    let runs = config.state_dir.join("browser-runs");
    std::fs::create_dir_all(&runs).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create browser profile root {}: {e}", runs.display()),
        )
    })?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = runs.join(format!("run-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create browser profile {}: {e}", dir.display()),
        )
    })?;
    Ok(dir)
}

/// Parse the bounded HTML subset the inventory reports. The parser
/// is a scanner, not a browser: malformed or truncated markup is
/// skipped at tag granularity and can never panic the provider.
fn parse_dom(dom: &str, base_url: &str) -> BrowserInventory {
    let bytes = dom.as_bytes();
    let mut inventory = BrowserInventory::default();
    let mut current_form: Option<Form> = None;
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let Some(open_offset) = find_byte(bytes, b'<', cursor) else {
            break;
        };
        let open = cursor + open_offset;
        if dom[open..].starts_with("<!--") {
            let Some(close_offset) = find_subslice(&bytes[open + 4..], b"-->") else {
                break;
            };
            cursor = open + 4 + close_offset + 3;
            continue;
        }
        let Some(tag) = parse_tag(dom, open) else {
            cursor = open + 1;
            continue;
        };
        cursor = tag.end;
        if tag.closing {
            if tag.name == "form"
                && let Some(form) = current_form.take()
            {
                push_capped(&mut inventory.forms, form, FORM_COUNT_MAX);
            }
            continue;
        }
        match tag.name.as_str() {
            "a" => {
                if let Some(href) = tag.attrs.get("href") {
                    let text = element_text(dom, tag.end, "a");
                    push_capped(
                        &mut inventory.anchors,
                        Anchor {
                            href: resolve_url(base_url, href),
                            text: truncate_text(&text, TEXT_CHARS_MAX),
                        },
                        LINK_COUNT_MAX,
                    );
                }
            }
            "button" | "input" | "select" | "textarea" => {
                if let Some(form) = &mut current_form {
                    if form.fields.len() < FORM_FIELD_COUNT_MAX {
                        form.fields.push(FormField {
                            id: tag
                                .attrs
                                .get("id")
                                .map(|v| truncate_text(v, VALUE_CHARS_MAX)),
                            name: tag
                                .attrs
                                .get("name")
                                .map(|v| truncate_text(v, VALUE_CHARS_MAX)),
                            required: tag.attrs.contains_key("required"),
                            field_type: if tag.name == "input" {
                                tag.attrs
                                    .get("type")
                                    .cloned()
                                    .unwrap_or_else(|| "text".to_string())
                            } else {
                                tag.name.clone()
                            },
                        });
                    }
                }
            }
            "form" => {
                if current_form.is_none() {
                    current_form = Some(Form {
                        action: tag
                            .attrs
                            .get("action")
                            .map(|action| resolve_url(base_url, action))
                            .unwrap_or_else(|| base_url.to_string()),
                        fields: Vec::new(),
                        method: tag
                            .attrs
                            .get("method")
                            .map(|method| method.to_ascii_uppercase())
                            .unwrap_or_else(|| "GET".to_string()),
                    });
                }
            }
            "link" => {
                if let Some(href) = tag.attrs.get("href") {
                    push_capped(
                        &mut inventory.link_elements,
                        LinkElement {
                            href: resolve_url(base_url, href),
                            rel: tag.attrs.get("rel").cloned(),
                            element_type: tag.attrs.get("type").cloned(),
                        },
                        LINK_COUNT_MAX,
                    );
                }
            }
            "meta" => {
                let meta = MetaTag {
                    charset: tag.attrs.get("charset").cloned(),
                    content: tag
                        .attrs
                        .get("content")
                        .map(|v| truncate_text(v, VALUE_CHARS_MAX)),
                    http_equiv: tag.attrs.get("http-equiv").cloned(),
                    name: tag.attrs.get("name").cloned(),
                    property: tag.attrs.get("property").cloned(),
                };
                if meta.charset.is_some()
                    || meta.content.is_some()
                    || meta.http_equiv.is_some()
                    || meta.name.is_some()
                    || meta.property.is_some()
                {
                    push_capped(&mut inventory.meta, meta, META_COUNT_MAX);
                }
            }
            "script" => {
                if inventory.scripts.len() < SCRIPT_COUNT_MAX {
                    if let Some(source) = tag.attrs.get("src") {
                        inventory.scripts.push(Script {
                            kind: "external".to_string(),
                            sha256: None,
                            size_bytes: None,
                            source: Some(resolve_url(base_url, source)),
                        });
                    } else {
                        let body = element_raw(dom, tag.end, "script");
                        inventory.scripts.push(Script {
                            kind: "inline".to_string(),
                            sha256: Some(sha256_hex(body.as_bytes())),
                            size_bytes: Some(body.len()),
                            source: None,
                        });
                    }
                }
            }
            "title" if inventory.title.is_none() => {
                let text = element_text(dom, tag.end, "title");
                inventory.title = Some(truncate_text(&text, TEXT_CHARS_MAX));
            }
            _ => {}
        }
    }
    if let Some(form) = current_form.take() {
        push_capped(&mut inventory.forms, form, FORM_COUNT_MAX);
    }
    inventory
}

fn parse_tag(dom: &str, open: usize) -> Option<Tag> {
    let bytes = dom.as_bytes();
    let mut cursor = open + 1;
    if cursor >= bytes.len() {
        return None;
    }
    let closing = bytes[cursor] == b'/';
    if closing {
        cursor += 1;
    }
    if cursor >= bytes.len() || !bytes[cursor].is_ascii_alphabetic() {
        return None;
    }
    let name_start = cursor;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'-' | b'_' | b':'))
    {
        cursor += 1;
    }
    let name = dom[name_start..cursor].to_ascii_lowercase();
    let mut attrs = BTreeMap::new();
    let mut quote: Option<u8> = None;
    let mut end = None;
    let mut scan = cursor;
    while scan < bytes.len() {
        let byte = bytes[scan];
        if let Some(active_quote) = quote {
            if byte == active_quote {
                quote = None;
            }
        } else if byte == b'"' || byte == b'\'' {
            quote = Some(byte);
        } else if byte == b'>' {
            end = Some(scan + 1);
            break;
        }
        scan += 1;
    }
    let end = end?;
    if !closing {
        attrs = parse_attrs(&dom[cursor..end.saturating_sub(1)]);
    }
    Some(Tag {
        attrs,
        closing,
        end,
        name,
    })
}

fn parse_attrs(text: &str) -> BTreeMap<String, String> {
    let bytes = text.as_bytes();
    let mut attrs = BTreeMap::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        while cursor < bytes.len() && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b'/')
        {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        let name_start = cursor;
        while cursor < bytes.len()
            && !bytes[cursor].is_ascii_whitespace()
            && bytes[cursor] != b'='
            && bytes[cursor] != b'/'
        {
            cursor += 1;
        }
        if name_start == cursor {
            cursor += 1;
            continue;
        }
        let name = text[name_start..cursor].to_ascii_lowercase();
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let mut value = String::new();
        if cursor < bytes.len() && bytes[cursor] == b'=' {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                let quote = bytes[cursor];
                cursor += 1;
                let value_start = cursor;
                while cursor < bytes.len() && bytes[cursor] != quote {
                    cursor += 1;
                }
                value = decode_entities(&text[value_start..cursor]);
                if cursor < bytes.len() {
                    cursor += 1;
                }
            } else {
                let value_start = cursor;
                while cursor < bytes.len()
                    && !bytes[cursor].is_ascii_whitespace()
                    && bytes[cursor] != b'/'
                {
                    cursor += 1;
                }
                value = decode_entities(&text[value_start..cursor]);
            }
        }
        attrs.insert(name, truncate_text(&value, VALUE_CHARS_MAX));
    }
    attrs
}

fn element_raw(dom: &str, start: usize, name: &str) -> String {
    let lower = dom.to_ascii_lowercase();
    let needle = format!("</{name}");
    let Some(close_offset) = lower[start.min(lower.len())..].find(&needle) else {
        return String::new();
    };
    dom[start..start + close_offset].to_string()
}

fn element_text(dom: &str, start: usize, name: &str) -> String {
    let raw = element_raw(dom, start, name);
    let mut text = String::new();
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(ch),
            _ => {}
        }
    }
    decode_entities(&text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let Some(end_offset) = tail.find(';') else {
            out.push_str(tail);
            rest = "";
            break;
        };
        let entity = &tail[1..end_offset];
        let decoded = match entity {
            "amp" => Some("&".to_string()),
            "apos" => Some("'".to_string()),
            "gt" => Some(">".to_string()),
            "lt" => Some("<".to_string()),
            "nbsp" => Some(" ".to_string()),
            "quot" => Some("\"".to_string()),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(|c| c.to_string())
            }
            _ if entity.starts_with('#') => entity[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(|c| c.to_string()),
            _ => None,
        };
        match decoded {
            Some(value) => out.push_str(&value),
            None => out.push_str(&tail[..=end_offset]),
        }
        rest = &tail[end_offset + 1..];
    }
    out.push_str(rest);
    out
}

/// Resolve a same-page reference against the page URL with the
/// small URL subset HTML attributes use. Unrecognized references
/// are returned as written rather than dropped.
fn resolve_url(base: &str, reference: &str) -> String {
    let reference = reference.trim();
    if reference.is_empty() {
        return base.split('#').next().unwrap_or(base).to_string();
    }
    if has_scheme(reference) {
        return reference.to_string();
    }
    let Some(scheme_end) = base.find("://") else {
        return reference.to_string();
    };
    let scheme = &base[..scheme_end];
    let after_scheme = &base[scheme_end + 3..];
    let authority_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if let Some(rest) = reference.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    if reference.starts_with('/') {
        return format!("{scheme}://{authority}{reference}");
    }
    let path_and_query = &after_scheme[authority_end..];
    let path = path_and_query.split(['?', '#']).next().unwrap_or("");
    if reference.starts_with('?') || reference.starts_with('#') {
        return format!("{scheme}://{authority}{path}{reference}");
    }
    let directory = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
    let joined = format!("{directory}/{reference}");
    format!("{scheme}://{authority}{}", normalize_path(&joined))
}

fn has_scheme(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    colon > 0
        && value[..colon].chars().enumerate().all(|(index, ch)| {
            if index == 0 {
                ch.is_ascii_alphabetic()
            } else {
                ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')
            }
        })
}

fn normalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut normalized = String::from("/");
    normalized.push_str(&segments.join("/"));
    if path.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

fn push_capped<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() < cap {
        items.push(item);
    }
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

fn find_byte(bytes: &[u8], needle: u8, start: usize) -> Option<usize> {
    bytes[start.min(bytes.len())..]
        .iter()
        .position(|byte| *byte == needle)
}

fn find_subslice(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || bytes.len() < needle.len() {
        return None;
    }
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<!doctype html>
<html><head>
<title> Tom &amp; Jerry </title>
<meta name="description" content="A test page">
<meta charset="utf-8">
<link rel="stylesheet" href="/app.css">
<script src="../main.js"></script>
<script>const answer = 42;</script>
</head><body>
<a href="next.html"> Next &gt; </a>
<form action="/login" method="post">
  <input name="user" type="text" required>
  <input name="pass" type="password">
  <select name="role"><option>admin</option></select>
</form>
</body></html>"#;

    #[test]
    fn validation_parse_dom_collects_inventory() {
        let inventory = parse_dom(PAGE, "https://example.test/app/index.html");
        assert_eq!(inventory.title.as_deref(), Some("Tom & Jerry"));
        assert_eq!(inventory.meta.len(), 2);
        assert_eq!(
            inventory.link_elements[0].href,
            "https://example.test/app.css"
        );
        assert_eq!(inventory.scripts.len(), 2);
        assert_eq!(
            inventory.scripts[0].source.as_deref(),
            Some("https://example.test/main.js")
        );
        assert_eq!(inventory.scripts[1].kind, "inline");
        assert_eq!(
            inventory.anchors[0].href,
            "https://example.test/app/next.html"
        );
        assert_eq!(inventory.anchors[0].text, "Next >");
        assert_eq!(inventory.forms.len(), 1);
        assert_eq!(inventory.forms[0].method, "POST");
        assert_eq!(inventory.forms[0].fields.len(), 3);
        assert!(inventory.forms[0].fields[0].required);
    }

    #[test]
    fn validation_resolve_url_handles_reference_shapes() {
        let base = "https://example.test/a/b/page.html?x=1";
        assert_eq!(
            resolve_url(base, "//cdn.test/x.js"),
            "https://cdn.test/x.js"
        );
        assert_eq!(
            resolve_url(base, "/root.js"),
            "https://example.test/root.js"
        );
        assert_eq!(
            resolve_url(base, "./same.js"),
            "https://example.test/a/b/same.js"
        );
        assert_eq!(
            resolve_url(base, "https://other.test/y"),
            "https://other.test/y"
        );
    }

    #[test]
    fn validation_url_strips_fragment_and_keeps_query() {
        assert_eq!(
            validate_url("https://example.test/a?x=1#part").unwrap(),
            "https://example.test/a?x=1"
        );
    }

    #[test]
    fn adversarial_url_rejects_credentials_and_other_schemes() {
        assert_eq!(
            validate_url("https://user:pw@example.test/")
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            validate_url("file:///etc/passwd").unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            validate_url("https://example.test:99999/")
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn adversarial_truncated_markup_is_skipped_without_panic() {
        let inventory = parse_dom(
            "<title>ok</title><a href=\"/x\" <script src=",
            "https://example.test/",
        );
        assert_eq!(inventory.title.as_deref(), Some("ok"));
        assert!(inventory.scripts.is_empty());
    }

    #[test]
    fn adversarial_oversized_attribute_is_truncated() {
        let long = "x".repeat(VALUE_CHARS_MAX + 25);
        let html = format!("<meta name=\"description\" content=\"{long}\">");
        let inventory = parse_dom(&html, "https://example.test/");
        assert_eq!(
            inventory.meta[0].content.as_ref().unwrap().chars().count(),
            VALUE_CHARS_MAX
        );
    }
}
