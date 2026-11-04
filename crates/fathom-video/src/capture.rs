//! Screened Danbooru capture into a quarantined RE area.
//!
//! The screen is the gate, not a courtesy: a post id is checked
//! against the caller's D-555/D-874 screen record before any
//! network byte moves. Excluded and unscreened ids are refused
//! with typed details and no fetch is attempted. Captured media
//! lands only inside the named quarantine directory; the
//! provenance record is the media's identity and the observation
//! lane's only handle on it.
//!
//! Bounds: one post per call, at most
//! [`CAPTURE_MEDIA_BYTES_MAX`] media bytes, at most
//! [`CAPTURE_POST_JSON_BYTES_MAX`] metadata bytes, and a fixed
//! [`CAPTURE_REQUEST_GAP_SECS`]-second gap between the two
//! Danbooru requests (metadata, then media). HTTP 429 stops the
//! capture with a typed refusal; there are no retries.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Completeness, Confidence, Coverage, Evidence, Finding, Subject, hash_file_with_bound,
    sha256_hex,
};
use fathom_core::limits::OUTPUT_BYTES_MAX;
use fathom_core::paths::validate_output_dir;
use fathom_core::proof;
use fathom_core::registry::require_str;

use crate::document::utc_now;
use crate::fetch::process_run_with;

/// Media bytes accepted by one capture.
pub const CAPTURE_MEDIA_BYTES_MAX: u64 = 536_870_912;

/// Bytes accepted for one Danbooru post metadata document.
pub const CAPTURE_POST_JSON_BYTES_MAX: u64 = 1_048_576;

/// Seconds between the metadata request and the media request.
pub const CAPTURE_REQUEST_GAP_SECS: u64 = 2;

/// Wall-clock bound for the metadata request, seconds.
pub const CAPTURE_METADATA_TIMEOUT_SECS: u64 = 120;

/// Wall-clock bound for the media request, seconds.
pub const CAPTURE_MEDIA_TIMEOUT_SECS: u64 = 900;

const API_HOST: &str = "danbooru.donmai.us";
const CDN_HOST: &str = "cdn.donmai.us";
const QUARANTINE_DIR_NAME: &str = "danbooru-re";
const USER_AGENT: &str = "pax-fathom-media-capture/1.0 (clean-room RE observation)";

const MEDIA_EXTENSIONS: [&str; 6] = ["gif", "jpeg", "jpg", "mp4", "png", "webm"];

const EXPLICIT_TAGS: [&str; 16] = [
    "ahegao", "anal", "breasts", "fellatio", "nipples", "nude", "oral", "penis", "pussy", "sex",
    "sexual", "torogao", "vaginal", "x-ray", "x_ray", "yaoi",
];

/// The verdict a screen record carries for one post id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScreenVerdict {
    Cleared,
    Excluded,
    Missing,
}

/// A typed refusal carrying a stable machine-readable code in
/// its details, so callers (and gates) never parse prose.
fn refusal(code: ErrorCode, refusal_code: &str, message: String, post_id: u64) -> FathomError {
    FathomError::new(code, message).with_details(json!({
        "post_id": post_id,
        "refusal_code": refusal_code,
    }))
}

/// Read one post's verdict from a parsed screen record. The
/// record may be the D-874 census shape (an object mapping post
/// id strings to verdict strings or verdict objects) or an array
/// of per-post objects. Anything else is malformed, and a post
/// absent from a well-formed record is `Missing` — the screen
/// never defaults to cleared.
pub fn screen_verdict(screen: &Value, post_id: u64) -> Result<ScreenVerdict, FathomError> {
    let malformed = || {
        FathomError::new(
            ErrorCode::InvalidRequest,
            "the screen record is not a recognised screen shape",
        )
        .with_details(json!({"post_id": post_id, "refusal_code": "screen_malformed"}))
    };
    let verdict_of = |value: &Value| -> Option<ScreenVerdict> {
        let text = match value {
            Value::String(text) => Some(text.as_str()),
            Value::Object(object) => ["verdict", "status", "decision", "screen"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str)),
            _ => None,
        }?;
        match text.to_ascii_uppercase().as_str() {
            "CLEARED" | "CLEAR" | "PASS" => Some(ScreenVerdict::Cleared),
            "EXCLUDED" | "EXCLUDE" | "REFUSED" | "BLOCKED" => Some(ScreenVerdict::Excluded),
            _ => None,
        }
    };
    match screen {
        Value::Object(object) => {
            let key = post_id.to_string();
            match object.get(&key) {
                Some(value) => verdict_of(value).ok_or_else(malformed),
                None => Ok(ScreenVerdict::Missing),
            }
        }
        Value::Array(entries) => {
            for entry in entries {
                let entry_id = entry
                    .get("post_id")
                    .or_else(|| entry.get("id"))
                    .and_then(Value::as_u64);
                if entry_id == Some(post_id) {
                    return verdict_of(entry).ok_or_else(malformed);
                }
            }
            Ok(ScreenVerdict::Missing)
        }
        _ => Err(malformed()),
    }
}

/// Validate the screen gate for one capture: the screen file
/// must live inside the quarantine, hash to the caller's stated
/// digest when one is given, and carry a CLEARED verdict for the
/// post. This runs before any network access.
pub fn validate_screen(
    quarantine: &Path,
    screen_path: &Path,
    expected_sha256: Option<&str>,
    post_id: u64,
) -> Result<(String, String), FathomError> {
    let canonical = screen_path.canonicalize().map_err(|error| {
        refusal(
            ErrorCode::TargetUnavailable,
            "screen_missing",
            format!("the screen record cannot be resolved: {error}"),
            post_id,
        )
    })?;
    if !canonical.starts_with(quarantine) {
        return Err(refusal(
            ErrorCode::AccessDenied,
            "screen_outside_quarantine",
            "the screen record must live inside the quarantine directory".to_string(),
            post_id,
        ));
    }
    let (sha256, _size) = hash_file_with_bound(&canonical, CAPTURE_POST_JSON_BYTES_MAX * 64)?;
    if let Some(expected) = expected_sha256
        && expected != sha256.as_str()
    {
        return Err(refusal(
            ErrorCode::EvidenceIntegrityMismatch,
            "screen_hash_mismatch",
            "the screen record does not hash to the stated digest".to_string(),
            post_id,
        ));
    }
    let bytes = std::fs::read(&canonical).map_err(|error| {
        refusal(
            ErrorCode::TargetUnavailable,
            "screen_missing",
            format!("the screen record cannot be read: {error}"),
            post_id,
        )
    })?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
        refusal(
            ErrorCode::InvalidRequest,
            "screen_malformed",
            format!("the screen record is not valid JSON: {error}"),
            post_id,
        )
    })?;
    match screen_verdict(&document, post_id)? {
        ScreenVerdict::Cleared => {
            let relative = canonical
                .strip_prefix(quarantine)
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| canonical.display().to_string());
            Ok((relative, sha256))
        }
        ScreenVerdict::Excluded => Err(refusal(
            ErrorCode::AccessDenied,
            "screen_excluded",
            format!(
                "post {post_id} is EXCLUDED by the screen record; excluded posts are never captured"
            ),
            post_id,
        )),
        ScreenVerdict::Missing => Err(refusal(
            ErrorCode::InvalidRequest,
            "screen_missing",
            format!(
                "post {post_id} has no verdict in the screen record; unscreened posts are never captured"
            ),
            post_id,
        )),
    }
}

/// Resolve and fence the quarantine directory: it must sit under
/// a configured target root and be named `danbooru-re`, so no
/// ordinary output directory can silently become a quarantine.
pub fn quarantine_dir(config: &Config, raw: &str) -> Result<PathBuf, FathomError> {
    let resolved = validate_output_dir(config, Path::new(raw))?;
    if resolved.file_name().and_then(|name| name.to_str()) != Some(QUARANTINE_DIR_NAME) {
        return Err(FathomError::new(
            ErrorCode::AccessDenied,
            format!(
                "the quarantine directory must be named {QUARANTINE_DIR_NAME}; \
                 captured media is fenced to that named area"
            ),
        )
        .with_target(raw.to_string()));
    }
    for sub in ["media", "records", "scratch", "screen"] {
        std::fs::create_dir_all(resolved.join(sub)).map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot create the quarantine {sub} dir: {error}"),
            )
        })?;
    }
    Ok(resolved)
}

/// The digest of a record: SHA-256 over the canonical JSON of
/// the record with its `record_digest` field removed.
pub fn record_digest(record: &Value) -> String {
    let mut stripped = record.clone();
    if let Some(object) = stripped.as_object_mut() {
        object.remove("record_digest");
    }
    sha256_hex(proof::canonical_json(&stripped).as_bytes())
}

/// Write one JSON record atomically: temp file in the same
/// directory, then rename over the destination.
pub fn write_json_atomic(path: &Path, record: &Value) -> Result<(), FathomError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot create the record dir: {error}"),
            )
        })?;
    }
    let temp = path.with_extension("json.part");
    std::fs::write(&temp, proof::canonical_json(record)).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot write the record temp file: {error}"),
        )
    })?;
    std::fs::rename(&temp, path).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot commit the record file: {error}"),
        )
    })
}

/// Capture ids are generated, never caller-shaped.
pub fn validate_capture_id(raw: &str) -> Result<&str, FathomError> {
    let valid = raw.len() == 19
        && raw.starts_with("dc_")
        && raw[3..].chars().all(|c| c.is_ascii_hexdigit());
    if valid {
        Ok(raw)
    } else {
        Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'capture_id' is not a generated capture id",
        ))
    }
}

/// A loaded, integrity-verified capture: the provenance record,
/// the media path it names, and the quarantine it lives in.
pub struct LoadedCapture {
    pub media_path: PathBuf,
    pub quarantine: PathBuf,
    pub record: Value,
    pub record_path: PathBuf,
}

/// Load one capture record and re-verify the media against it:
/// the record digest must recompute and the retained media must
/// still hash to the recorded subject identity.
pub fn load_capture(
    config: &Config,
    quarantine_raw: &str,
    capture_id: &str,
) -> Result<LoadedCapture, FathomError> {
    validate_capture_id(capture_id)?;
    let quarantine = quarantine_dir(config, quarantine_raw)?;
    let record_path = quarantine
        .join("records")
        .join(format!("{capture_id}.json"));
    let bytes = std::fs::read(&record_path).map_err(|error| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("no retained capture '{capture_id}' in this quarantine: {error}"),
        )
    })?;
    if bytes.len() as u64 > CAPTURE_POST_JSON_BYTES_MAX * 64 {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            "the capture record exceeds its size bound",
        ));
    }
    let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("the capture record is not valid JSON: {error}"),
        )
    })?;
    if record.get("record_type").and_then(Value::as_str) != Some("danbooru-capture/1") {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "the named record is not a danbooru-capture/1 record",
        ));
    }
    let stated = record
        .get("record_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if stated != record_digest(&record) {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the capture record digest does not recompute; the record was altered",
        ));
    }
    let relative = record
        .pointer("/subject/relative_path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                "the capture record names no media path",
            )
        })?;
    if relative.contains("..") {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the capture record's media path escapes the quarantine",
        ));
    }
    let media_path = quarantine.join(relative);
    let canonical = media_path.canonicalize().map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("the captured media cannot be resolved: {error}"),
        )
    })?;
    if !canonical.starts_with(quarantine.join("media")) {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the captured media resolves outside the quarantine media dir",
        ));
    }
    let (sha256, size) = hash_file_with_bound(&canonical, CAPTURE_MEDIA_BYTES_MAX)?;
    let recorded_sha = record
        .pointer("/subject/sha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let recorded_size = record
        .pointer("/subject/size_bytes")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if sha256 != recorded_sha || size != recorded_size {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the captured media no longer hashes to the capture record's subject identity",
        ));
    }
    Ok(LoadedCapture {
        media_path: canonical,
        quarantine,
        record,
        record_path,
    })
}

/// Validate a Danbooru media URL: HTTPS on the CDN host only, no
/// credentials, query, or fragment. Anything else is refused
/// before a request is shaped.
pub fn validate_media_url(raw: &str, extension: &str) -> Result<String, FathomError> {
    let invalid = |reason: &str| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("the post's media URL is not capturable: {reason}"),
        )
    };
    let rest = raw
        .strip_prefix("https://")
        .ok_or_else(|| invalid("not an HTTPS URL"))?;
    let (host, _path) = rest.split_once('/').ok_or_else(|| invalid("no path"))?;
    if host != CDN_HOST {
        return Err(invalid("host is not the Danbooru CDN"));
    }
    if raw.contains(['?', '#', '@']) {
        return Err(invalid("query, fragment, or credentials present"));
    }
    if !raw.ends_with(&format!(".{extension}")) {
        return Err(invalid("path does not end with the post's media extension"));
    }
    Ok(raw.to_string())
}

/// The lane stamp for one post, from its rating and tag string.
/// Anything not plainly safe-rated and free of explicit tags is
/// NSFW — unclassified defaults NSFW, fail closed (lane law).
pub fn classify_post(metadata: &Value) -> (String, String) {
    let rating = metadata.get("rating").and_then(Value::as_str).unwrap_or("");
    let tags = post_tags(metadata);
    let explicit = tags.iter().any(|tag| EXPLICIT_TAGS.contains(&tag.as_str()));
    if rating == "s" && !explicit {
        ("sfw".to_string(), "sfw".to_string())
    } else {
        ("nsfw".to_string(), "nsfw".to_string())
    }
}

/// Every tag on the post, from the flat tag string plus the
/// categorised tag strings when the document carries them.
pub fn post_tags(metadata: &Value) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for field in [
        "tag_string",
        "tag_string_general",
        "tag_string_character",
        "tag_string_copyright",
        "tag_string_artist",
        "tag_string_meta",
    ] {
        if let Some(text) = metadata.get(field).and_then(Value::as_str) {
            for tag in text.split_whitespace() {
                tags.insert(tag.to_string());
            }
        }
    }
    tags
}

/// Run the configured curl once, writing the body to `output`
/// and returning the HTTP status it reported.
fn http_fetch(
    config: &Config,
    url: &str,
    output: &Path,
    scratch: &Path,
    timeout_secs: u64,
    post_id: u64,
) -> Result<u16, FathomError> {
    let args: Vec<String> = vec![
        "--silent".to_string(),
        "--show-error".to_string(),
        "--max-time".to_string(),
        timeout_secs.to_string(),
        "--user-agent".to_string(),
        USER_AGENT.to_string(),
        "--output".to_string(),
        output.to_string_lossy().into_owned(),
        "--write-out".to_string(),
        "%{http_code}".to_string(),
        url.to_string(),
    ];
    let outcome = process_run_with(
        config.web.fetcher_program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(timeout_secs + 30),
        OUTPUT_BYTES_MAX,
    )?;
    if outcome.timed_out {
        return Err(refusal(
            ErrorCode::ProviderTimeout,
            "fetch_timeout",
            format!("the Danbooru fetch exceeded {timeout_secs} seconds"),
            post_id,
        ));
    }
    let status: u16 = String::from_utf8_lossy(&outcome.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    if status == 429 {
        return Err(refusal(
            ErrorCode::ProviderUnavailable,
            "rate_limited",
            "Danbooru answered HTTP 429; the capture stops here (no retry)".to_string(),
            post_id,
        ));
    }
    if outcome.exit_code != Some(0) || status == 0 {
        return Err(refusal(
            ErrorCode::ProviderUnavailable,
            "fetch_failed",
            format!(
                "the Danbooru fetch failed: {}",
                String::from_utf8_lossy(&outcome.stderr)
                    .chars()
                    .take(300)
                    .collect::<String>()
            ),
            post_id,
        ));
    }
    Ok(status)
}

/// Fetch and validate the post metadata document. The URL is
/// built from the validated post id only — no caller-shaped URL
/// ever reaches the fetcher.
fn fetch_post_metadata(
    config: &Config,
    post_id: u64,
    scratch: &Path,
) -> Result<Value, FathomError> {
    let url = format!("https://{API_HOST}/posts/{post_id}.json");
    let output = scratch.join("post.json");
    let status = http_fetch(
        config,
        &url,
        &output,
        scratch,
        CAPTURE_METADATA_TIMEOUT_SECS,
        post_id,
    )?;
    if status != 200 {
        return Err(refusal(
            ErrorCode::TargetUnavailable,
            "post_unavailable",
            format!("Danbooru answered HTTP {status} for post {post_id}"),
            post_id,
        ));
    }
    let metadata_len = std::fs::metadata(&output)
        .map(|meta| meta.len())
        .unwrap_or(0);
    if metadata_len > CAPTURE_POST_JSON_BYTES_MAX {
        return Err(refusal(
            ErrorCode::ResourceConstraint,
            "metadata_too_large",
            "the post metadata exceeds CAPTURE_POST_JSON_BYTES_MAX".to_string(),
            post_id,
        ));
    }
    let bytes = std::fs::read(&output).map_err(|error| {
        refusal(
            ErrorCode::UnreadableOutput,
            "metadata_unreadable",
            format!("the fetched metadata cannot be read: {error}"),
            post_id,
        )
    })?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
        refusal(
            ErrorCode::ProviderUnavailable,
            "metadata_unparseable",
            format!("the fetched metadata is not valid JSON: {error}"),
            post_id,
        )
    })?;
    if document.get("id").and_then(Value::as_u64) != Some(post_id) {
        return Err(refusal(
            ErrorCode::EvidenceIntegrityMismatch,
            "metadata_id_mismatch",
            "Danbooru answered for a different post than the one screened".to_string(),
            post_id,
        ));
    }
    Ok(document)
}

/// `capture_danbooru_media`: screen first, then fetch one
/// cleared post's media into the quarantine and write its
/// provenance record.
pub fn capture_danbooru_media(
    _registry: &fathom_core::registry::Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let post_id = args.get("post_id").and_then(Value::as_u64).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'post_id' is required and must be a positive integer",
        )
    })?;
    if post_id == 0 {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'post_id' must be a positive integer",
        ));
    }
    let quarantine = quarantine_dir(config, require_str(args, "quarantine_dir")?)?;
    let screen_raw = require_str(args, "screen_path")?;
    let screen_path = if Path::new(screen_raw).is_absolute() {
        PathBuf::from(screen_raw)
    } else {
        quarantine.join(screen_raw)
    };
    let expected_sha = args.get("screen_sha256").and_then(Value::as_str);
    // THE GATE: verdict (and digest, when stated) are proven
    // before the fetcher is even resolved.
    let (screen_relative, screen_sha256) =
        validate_screen(&quarantine, &screen_path, expected_sha, post_id)?;

    let scratch = quarantine
        .join("scratch")
        .join(format!("capture-{post_id}-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create the capture scratch dir: {error}"),
        )
    })?;
    let result = capture_inner(
        config,
        post_id,
        &quarantine,
        &scratch,
        &screen_relative,
        &screen_sha256,
    );
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn capture_inner(
    config: &Config,
    post_id: u64,
    quarantine: &Path,
    scratch: &Path,
    screen_relative: &str,
    screen_sha256: &str,
) -> Result<Value, FathomError> {
    let metadata = fetch_post_metadata(config, post_id, scratch)?;
    let extension = metadata
        .get("file_ext")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !MEDIA_EXTENSIONS.contains(&extension.as_str()) {
        return Err(refusal(
            ErrorCode::UnsupportedTarget,
            "media_kind_unsupported",
            format!(
                "post {post_id} media kind '{extension}' is not capturable by this lane \
                 (supported: {})",
                MEDIA_EXTENSIONS.join(", ")
            ),
            post_id,
        ));
    }
    let file_url = metadata
        .get("file_url")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            refusal(
                ErrorCode::TargetUnavailable,
                "media_url_missing",
                "the post metadata names no media URL".to_string(),
                post_id,
            )
        })?;
    let media_url = validate_media_url(file_url, &extension).map_err(|error| {
        refusal(
            ErrorCode::InvalidRequest,
            "media_url_refused",
            error.message.clone(),
            post_id,
        )
    })?;
    let stated_size = metadata
        .get("file_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            refusal(
                ErrorCode::UnreadableOutput,
                "media_size_missing",
                "the post metadata states no media size".to_string(),
                post_id,
            )
        })?;
    if stated_size == 0 || stated_size > CAPTURE_MEDIA_BYTES_MAX {
        return Err(refusal(
            ErrorCode::ResourceConstraint,
            "media_too_large",
            format!(
                "the post's stated size {stated_size} is outside 1..={CAPTURE_MEDIA_BYTES_MAX}"
            ),
            post_id,
        ));
    }
    // The rate discipline: a fixed gap between the metadata
    // request and the media request.
    std::thread::sleep(Duration::from_secs(CAPTURE_REQUEST_GAP_SECS));
    let partial = scratch.join("media.part");
    let status = http_fetch(
        config,
        &media_url,
        &partial,
        scratch,
        CAPTURE_MEDIA_TIMEOUT_SECS,
        post_id,
    )?;
    if status != 200 {
        let _ = std::fs::remove_file(&partial);
        return Err(refusal(
            ErrorCode::TargetUnavailable,
            "media_unavailable",
            format!("the media CDN answered HTTP {status} for post {post_id}"),
            post_id,
        ));
    }
    let (sha256, size) = hash_file_with_bound(&partial, CAPTURE_MEDIA_BYTES_MAX)?;
    if size != stated_size {
        let _ = std::fs::remove_file(&partial);
        return Err(refusal(
            ErrorCode::EvidenceIntegrityMismatch,
            "media_size_mismatch",
            format!("the fetched media is {size} bytes; the post metadata states {stated_size}"),
            post_id,
        ));
    }
    let relative = format!("media/{post_id}-{}.{extension}", &sha256[..12]);
    let final_path = quarantine.join(&relative);
    if final_path.exists() {
        let (existing_sha, _) = hash_file_with_bound(&final_path, CAPTURE_MEDIA_BYTES_MAX)?;
        if existing_sha != sha256 {
            return Err(refusal(
                ErrorCode::EvidenceIntegrityMismatch,
                "media_store_collision",
                "the quarantine already holds different bytes at this media path".to_string(),
                post_id,
            ));
        }
        let _ = std::fs::remove_file(&partial);
    } else {
        std::fs::rename(&partial, &final_path).map_err(|error| {
            refusal(
                ErrorCode::ExecutionFailure,
                "media_store_failed",
                format!("cannot commit the captured media: {error}"),
                post_id,
            )
        })?;
    }
    let captured_at = utc_now();
    let capture_id = format!(
        "dc_{}",
        &sha256_hex(format!("danbooru:{post_id}:{sha256}:{captured_at}").as_bytes())[..16]
    );
    let (lane, content_label) = classify_post(&metadata);
    let mut record = json!({
        "captured_at": captured_at,
        "capture_id": capture_id,
        "content_label": content_label,
        "lane": lane,
        "origin": {
            "origin_lane": "danbooru-reference",
            "post_id": post_id,
            "source": "danbooru",
        },
        "post": {
            "artist": metadata.get("tag_string_artist").cloned().unwrap_or(Value::Null),
            "file_ext": extension,
            "height": metadata.get("image_height").cloned().unwrap_or(Value::Null),
            "md5_stated": metadata.get("md5").cloned().unwrap_or(Value::Null),
            "rating": metadata.get("rating").cloned().unwrap_or(Value::Null),
            "source_url": format!("https://{API_HOST}/posts/{post_id}"),
            "tag_string": metadata.get("tag_string").cloned().unwrap_or(Value::Null),
            "tag_string_character": metadata.get("tag_string_character").cloned().unwrap_or(Value::Null),
            "tag_string_copyright": metadata.get("tag_string_copyright").cloned().unwrap_or(Value::Null),
            "tag_string_general": metadata.get("tag_string_general").cloned().unwrap_or(Value::Null),
            "tag_string_meta": metadata.get("tag_string_meta").cloned().unwrap_or(Value::Null),
            "width": metadata.get("image_width").cloned().unwrap_or(Value::Null),
        },
        "producer": {
            "fetcher_program": config.web.fetcher_program.display().to_string(),
            "fathom_version": fathom_core::VERSION,
            "tool": "capture_danbooru_media",
        },
        "quarantine": {
            "exit": "observation records only; media never leaves the quarantine",
            "fence": "no pipe, game tree, dataset, or training path may read captured media",
        },
        "record_type": "danbooru-capture/1",
        "screen": {
            "path": screen_relative,
            "sha256": screen_sha256,
            "verdict": "CLEARED",
        },
        "subject": {
            "relative_path": relative,
            "sha256": sha256,
            "size_bytes": size,
        },
        "version": 1,
    });
    let digest = record_digest(&record);
    record["record_digest"] = json!(digest);
    let record_path = quarantine
        .join("records")
        .join(format!("{capture_id}.json"));
    write_json_atomic(&record_path, &record)?;

    let mut evidence = Evidence::new("capture_danbooru_media", "video");
    evidence.status = Completeness::Complete;
    evidence = evidence.with_subject(Subject {
        path: final_path.display().to_string(),
        sha256: record["subject"]["sha256"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        size_bytes: size,
    });
    evidence.add_finding(Finding::new(
        "danbooru_capture",
        Confidence::Observed,
        json!({
            "capture_id": record["capture_id"],
            "captured_at": record["captured_at"],
            "content_label": record["content_label"],
            "lane": record["lane"],
            "post_id": post_id,
            "record_digest": digest,
            "record_path": record_path.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "screen_gate",
        Confidence::Observed,
        json!({
            "screen_path": screen_relative,
            "screen_sha256": screen_sha256,
            "verdict": "CLEARED",
        }),
    ));
    evidence.coverage = Coverage {
        examined: 1,
        total: 1,
        exhaustive: true,
    };
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_screen_map_shapes() {
        let screen = json!({"12301369": "CLEARED", "11383665": "EXCLUDED"});
        assert_eq!(
            screen_verdict(&screen, 12301369).unwrap(),
            ScreenVerdict::Cleared
        );
        assert_eq!(
            screen_verdict(&screen, 11383665).unwrap(),
            ScreenVerdict::Excluded
        );
        assert_eq!(screen_verdict(&screen, 42).unwrap(), ScreenVerdict::Missing);
    }

    #[test]
    fn validation_screen_object_and_array_shapes() {
        let screen = json!([{"post_id": 7, "verdict": "CLEARED"}]);
        assert_eq!(screen_verdict(&screen, 7).unwrap(), ScreenVerdict::Cleared);
        let screen = json!({"9": {"status": "excluded"}});
        assert_eq!(screen_verdict(&screen, 9).unwrap(), ScreenVerdict::Excluded);
    }

    #[test]
    fn adversarial_screen_malformed_is_typed() {
        let err = screen_verdict(&json!({"9": "MAYBE"}), 9).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert_eq!(err.details.unwrap()["refusal_code"], "screen_malformed");
        let err = screen_verdict(&json!(42), 9).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_media_url_is_cdn_only() {
        assert!(validate_media_url("https://cdn.donmai.us/original/cf/af/hash.mp4", "mp4").is_ok());
        assert!(validate_media_url("https://example.com/x.mp4", "mp4").is_err());
        assert!(validate_media_url("http://cdn.donmai.us/x.mp4", "mp4").is_err());
        assert!(validate_media_url("https://cdn.donmai.us/x.mp4?y=1", "mp4").is_err());
        assert!(validate_media_url("https://cdn.donmai.us/x.webm", "mp4").is_err());
    }

    #[test]
    fn validation_classification_defaults_nsfw() {
        let safe = json!({"rating": "s", "tag_string": "1girl scenery"});
        assert_eq!(classify_post(&safe).0, "sfw");
        let explicit = json!({"rating": "e", "tag_string": "1girl"});
        assert_eq!(classify_post(&explicit).0, "nsfw");
        let unrated = json!({"tag_string": "1girl"});
        assert_eq!(classify_post(&unrated).0, "nsfw");
        let tagged = json!({"rating": "s", "tag_string": "1girl torogao"});
        assert_eq!(classify_post(&tagged).0, "nsfw");
    }

    #[test]
    fn validation_capture_id_shape() {
        assert!(validate_capture_id("dc_0123456789abcdef").is_ok());
        assert!(validate_capture_id("../escape").is_err());
        assert!(validate_capture_id("dc_xyz").is_err());
    }
}
