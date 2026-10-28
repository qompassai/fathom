//! The yt-dlp fetch provider (§4.2): an owned child under a
//! fixed flag template. The template's safety is by
//! construction — `--no-cookies`, `--ignore-config`, a
//! scrubbed environment, the scratch dir as cwd — and the
//! forbidden flags (`--cookies`, `--cookies-from-browser`,
//! `--netrc`, `--proxy`, `--exec`) exist nowhere in this
//! crate: there is no credential slot to fill.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::limits::{
    OUTPUT_BYTES_MAX, VIDEO_BYTES_MAX, VIDEO_DURATION_SECS_MAX, VIDEO_FETCH_TIMEOUT_SECS,
    VIDEO_METADATA_BYTES_MAX,
};
use fathom_core::process::{ProcessOutcome, ProcessSpec};

use crate::url::VideoRef;

/// One format the platform offers, reduced to the fields the
/// pre-flight estimate and provenance need.
#[derive(Clone, Debug)]
pub struct FormatInfo {
    pub filesize: Option<u64>,
    pub format_id: String,
    pub has_audio: bool,
    pub has_video: bool,
    pub height: Option<u64>,
}

/// One chapter marker from the platform metadata.
#[derive(Clone, Debug)]
pub struct ChapterInfo {
    pub end_ms: u64,
    pub start_ms: u64,
    pub title: String,
}

/// The platform metadata the lane consumes, parsed from
/// `--dump-single-json`. Everything here is platform-asserted
/// (confidence: observed, with the §4.6 limitation).
#[derive(Clone, Debug)]
pub struct VideoInfo {
    pub automatic_captions: BTreeMap<String, Vec<String>>,
    pub availability: Option<String>,
    pub channel: Option<String>,
    pub channel_id: Option<String>,
    pub chapters: Vec<ChapterInfo>,
    pub duration_secs: Option<f64>,
    pub formats: Vec<FormatInfo>,
    pub id: String,
    pub is_live: bool,
    pub language: Option<String>,
    pub like_count: Option<u64>,
    pub live_status: Option<String>,
    pub subtitles: BTreeMap<String, Vec<String>>,
    pub title: Option<String>,
    pub upload_date: Option<String>,
    pub uploader: Option<String>,
    pub view_count: Option<u64>,
    pub webpage_url: Option<String>,
}

/// What the pre-flight established before any media byte
/// moved.
#[derive(Clone, Debug)]
pub struct PreflightFacts {
    /// Sum of the selected formats' stated sizes, when both
    /// legs state one; `None` is reported as an unknown
    /// estimate, never treated as zero.
    pub estimated_bytes: Option<u64>,
}

/// A caption track the fetch will ask for: `manual` (creator
/// or community) ranks above `asr` (platform) per §4.4.
#[derive(Clone, Debug)]
pub struct CaptionChoice {
    pub kind: &'static str,
    pub language: String,
}

/// One downloaded caption file in the scratch dir.
#[derive(Clone, Debug)]
pub struct CaptionFile {
    pub kind: String,
    pub language: String,
    pub path: PathBuf,
}

/// The media leg's yield: the media file and the info JSON
/// the fetcher wrote beside it.
#[derive(Clone, Debug)]
pub struct FetchedMedia {
    pub info_json_path: PathBuf,
    pub media_path: PathBuf,
}

fn bounded_stderr(outcome: &ProcessOutcome) -> String {
    let text = String::from_utf8_lossy(&outcome.stderr);
    text.chars().take(300).collect()
}

/// Every fetcher run shares the §4.2 environment discipline:
/// cwd is the scratch dir and the environment is scrubbed to
/// `HOME=<scratch>` — no cookies, no config, no ambient
/// credentials can reach the child.
fn run_fetcher(
    config: &Config,
    args: &[String],
    scratch: &Path,
) -> Result<ProcessOutcome, FathomError> {
    process_run(config.video.fetcher_program.as_os_str(), args, scratch)
}

/// Run an owned child with the lane's environment discipline.
pub(crate) fn process_run(
    program: &std::ffi::OsStr,
    args: &[String],
    scratch: &Path,
) -> Result<ProcessOutcome, FathomError> {
    process_run_with(
        program,
        args,
        scratch,
        Duration::from_secs(VIDEO_FETCH_TIMEOUT_SECS),
        OUTPUT_BYTES_MAX,
    )
}

pub(crate) fn process_run_with(
    program: &std::ffi::OsStr,
    args: &[String],
    scratch: &Path,
    timeout: Duration,
    output_cap: usize,
) -> Result<ProcessOutcome, FathomError> {
    let spec = ProcessSpec {
        args: args.to_vec(),
        cwd: Some(scratch.to_path_buf()),
        env: vec![("HOME".to_string(), scratch.to_string_lossy().into_owned())],
        output_cap,
        program: program.to_string_lossy().into_owned(),
        timeout,
    };
    fathom_core::process::run(&spec)
}

/// The fetcher's version string, for the ingest document's
/// producer block; `None` when the program does not answer.
pub fn fetcher_version(config: &Config, scratch: &Path) -> Option<String> {
    let outcome = run_fetcher(config, &["--version".to_string()], scratch).ok()?;
    let text = String::from_utf8_lossy(&outcome.stdout);
    text.lines().next().map(|line| line.trim().to_string())
}

fn track_map(info: &Value, field: &str) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    if let Some(tracks) = info.get(field).and_then(Value::as_object) {
        for (language, formats) in tracks {
            let exts = formats
                .as_array()
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| {
                            entry.get("ext").and_then(Value::as_str).map(str::to_string)
                        })
                        .collect()
                })
                .unwrap_or_default();
            map.insert(language.clone(), exts);
        }
    }
    map
}

/// Parse the `--dump-single-json` document into the typed
/// metadata the lane consumes.
pub fn parse_info(document: &Value) -> VideoInfo {
    let str_field = |name: &str| {
        document
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let u64_field = |name: &str| document.get(name).and_then(Value::as_u64);
    let formats = document
        .get("formats")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| FormatInfo {
                    filesize: entry
                        .get("filesize")
                        .and_then(Value::as_u64)
                        .or_else(|| entry.get("filesize_approx").and_then(Value::as_u64)),
                    format_id: entry
                        .get("format_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    has_audio: entry.get("acodec").and_then(Value::as_str) != Some("none")
                        && entry.get("acodec").is_some(),
                    has_video: entry.get("vcodec").and_then(Value::as_str) != Some("none")
                        && entry.get("vcodec").is_some(),
                    height: entry.get("height").and_then(Value::as_u64),
                })
                .collect()
        })
        .unwrap_or_default();
    let chapters = document
        .get("chapters")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    let start = entry
                        .get("start_time")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let end = entry.get("end_time").and_then(Value::as_f64).unwrap_or(0.0);
                    ChapterInfo {
                        end_ms: (end * 1000.0).round() as u64,
                        start_ms: (start * 1000.0).round() as u64,
                        title: entry
                            .get("title")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    VideoInfo {
        automatic_captions: track_map(document, "automatic_captions"),
        availability: str_field("availability"),
        channel: str_field("channel"),
        channel_id: str_field("channel_id"),
        chapters,
        duration_secs: document.get("duration").and_then(Value::as_f64),
        formats,
        id: str_field("id").unwrap_or_default(),
        is_live: document
            .get("is_live")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        language: str_field("language"),
        like_count: u64_field("like_count"),
        live_status: str_field("live_status"),
        subtitles: track_map(document, "subtitles"),
        title: str_field("title"),
        upload_date: str_field("upload_date"),
        uploader: str_field("uploader"),
        view_count: u64_field("view_count"),
        webpage_url: str_field("webpage_url"),
    }
}

/// The metadata pre-flight (§4.1): one `--dump-single-json`
/// run, classified. Sign-in-class failures are
/// `unsupported_target` — the refusal is the platform's,
/// stated in its own words, and never worked around.
pub fn metadata(
    config: &Config,
    video: &VideoRef,
    scratch: &Path,
) -> Result<VideoInfo, FathomError> {
    let args: Vec<String> = [
        "--dump-single-json",
        "--no-playlist",
        "--no-cookies",
        "--ignore-config",
        video.canonical_url.as_str(),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let outcome = process_run_with(
        config.video.fetcher_program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(VIDEO_FETCH_TIMEOUT_SECS),
        VIDEO_METADATA_BYTES_MAX,
    )?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!(
                "the metadata fetch exceeded VIDEO_FETCH_TIMEOUT_SECS ({VIDEO_FETCH_TIMEOUT_SECS})"
            ),
        ));
    }
    if outcome.stdout_truncated {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "the metadata document exceeds VIDEO_METADATA_BYTES_MAX \
                 ({VIDEO_METADATA_BYTES_MAX} bytes captured)"
            ),
        ));
    }
    if outcome.exit_code != Some(0) {
        let stderr = bounded_stderr(&outcome);
        let lowered = stderr.to_lowercase();
        let sign_in_class = [
            "sign in",
            "age",
            "private video",
            "members-only",
            "join this channel",
            "login required",
        ]
        .iter()
        .any(|marker| lowered.contains(marker));
        if sign_in_class {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!("the platform refuses anonymous access to this video: {stderr}"),
            ));
        }
        return Err(FathomError::new(
            ErrorCode::ProviderUnavailable,
            format!("the metadata fetch failed: {stderr}"),
        ));
    }
    let document: Value = serde_json::from_slice(&outcome.stdout).map_err(|error| {
        FathomError::new(
            ErrorCode::ProviderUnavailable,
            format!("the metadata fetch returned unparseable JSON: {error}"),
        )
    })?;
    let info = parse_info(&document);
    if info.id != video.video_id {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!(
                "the platform answered for video '{}' when '{}' was asked",
                info.id, video.video_id
            ),
        ));
    }
    Ok(info)
}

/// The §11 refusals that must land before any media byte
/// moves: duration, liveness, gated availability, and the
/// size estimate of the rendition the template will select.
pub fn preflight(info: &VideoInfo, config: &Config) -> Result<PreflightFacts, FathomError> {
    if let Some(duration) = info.duration_secs
        && duration.ceil() as u64 > VIDEO_DURATION_SECS_MAX
    {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "duration {}s exceeds VIDEO_DURATION_SECS_MAX ({VIDEO_DURATION_SECS_MAX})",
                duration.ceil() as u64
            ),
        ));
    }
    if info.is_live || matches!(info.live_status.as_deref(), Some("is_live" | "is_upcoming")) {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "live and upcoming videos are not ingestible in v1 (a stream has no fixed bytes)",
        ));
    }
    if let Some(availability) = &info.availability
        && matches!(
            availability.as_str(),
            "needs_auth" | "premium_only" | "subscriber_only" | "private"
        )
    {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "the platform gates this video (availability: {availability}); \
                 anonymous ingest is refused, never credentialed"
            ),
        ));
    }
    let estimate = estimate_bytes(info, config.video.max_height);
    if let Some(bytes) = estimate
        && bytes > VIDEO_BYTES_MAX
    {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "the selected rendition's stated size {bytes} exceeds \
                 VIDEO_BYTES_MAX ({VIDEO_BYTES_MAX})"
            ),
        ));
    }
    Ok(PreflightFacts {
        estimated_bytes: estimate,
    })
}

/// The stated size of the rendition the fetch template
/// selects: the tallest video leg at or under the cap plus
/// the largest audio leg, each by its stated (exact or
/// approximate) size. `None` when either leg states no size.
fn estimate_bytes(info: &VideoInfo, max_height: u32) -> Option<u64> {
    let video = info
        .formats
        .iter()
        .filter(|format| {
            format.has_video && format.height.is_some_and(|h| h <= u64::from(max_height))
        })
        .max_by_key(|format| (format.height, format.filesize));
    let audio = info
        .formats
        .iter()
        .filter(|format| format.has_audio && !format.has_video)
        .max_by_key(|format| format.filesize);
    match (video, audio) {
        (Some(video), Some(audio)) => Some(video.filesize? + audio.filesize?),
        (Some(video), None) => {
            if video.has_audio {
                video.filesize
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The format ids the template's selection names (§4.3:
/// selected format ids are provenance facts) — the tallest
/// video leg at or under the cap and the largest audio leg,
/// mirroring `estimate_bytes`' selection.
pub fn selected_format_ids(info: &VideoInfo, max_height: u32) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(video) = info
        .formats
        .iter()
        .filter(|format| {
            format.has_video && format.height.is_some_and(|h| h <= u64::from(max_height))
        })
        .max_by_key(|format| (format.height, format.filesize))
    {
        ids.push(video.format_id.clone());
        if !video.has_audio
            && let Some(audio) = info
                .formats
                .iter()
                .filter(|format| format.has_audio && !format.has_video)
                .max_by_key(|format| format.filesize)
        {
            ids.push(audio.format_id.clone());
        }
    }
    ids
}

/// The one rendition policy (§4.3): best combined rendition
/// at or under the configured height cap, unless the
/// operator's config carries a whole-string override (the
/// obligation-2 archival reproduction case).
pub fn format_string(config: &Config) -> String {
    if let Some(overridden) = &config.video.format_override {
        return overridden.clone();
    }
    let cap = config.video.max_height;
    format!("bv*[height<={cap}]+ba/b[height<={cap}]")
}

/// Fetch the media itself under the §4.2 template. A failed
/// or timed-out fetch retains nothing — the caller discards
/// the whole scratch dir (§4.2's partial-media rule).
pub fn fetch_media(
    config: &Config,
    video: &VideoRef,
    scratch: &Path,
) -> Result<FetchedMedia, FathomError> {
    let output_template = scratch
        .join(format!("{}.%(ext)s", video.video_id))
        .to_string_lossy()
        .into_owned();
    let args: Vec<String> = vec![
        "--no-playlist".to_string(),
        "--no-cookies".to_string(),
        "--ignore-config".to_string(),
        "--write-info-json".to_string(),
        "--format".to_string(),
        format_string(config),
        "--output".to_string(),
        output_template,
        video.canonical_url.clone(),
    ];
    let outcome = run_fetcher(config, &args, scratch)?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!(
                "the media fetch exceeded VIDEO_FETCH_TIMEOUT_SECS ({VIDEO_FETCH_TIMEOUT_SECS}); \
                 partial media is discarded"
            ),
        ));
    }
    if outcome.exit_code != Some(0) {
        return Err(FathomError::new(
            ErrorCode::ProviderUnavailable,
            format!("the media fetch failed: {}", bounded_stderr(&outcome)),
        ));
    }
    let info_json_path = scratch.join(format!("{}.info.json", video.video_id));
    let mut media_path: Option<PathBuf> = None;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(scratch)
        .map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot list the fetch scratch dir: {error}"),
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with(&video.video_id) && !name.ends_with(".info.json") {
            media_path = Some(path);
            break;
        }
    }
    let media_path = media_path.ok_or_else(|| {
        FathomError::new(
            ErrorCode::ProviderUnavailable,
            "the fetcher reported success but produced no media file",
        )
    })?;
    if !info_json_path.exists() {
        return Err(FathomError::new(
            ErrorCode::ProviderUnavailable,
            "the fetcher reported success but produced no info JSON",
        ));
    }
    Ok(FetchedMedia {
        info_json_path,
        media_path,
    })
}

/// Choose the caption tracks §4.4 ranks: at most one manual
/// track (inventory of record when present) and at most one
/// platform-ASR track, each preferring the video's original
/// language, then the configured fallback, then the first
/// language served.
pub fn choose_caption_tracks(info: &VideoInfo, config: &Config) -> Vec<CaptionChoice> {
    let pick = |tracks: &BTreeMap<String, Vec<String>>| -> Option<String> {
        if tracks.is_empty() {
            return None;
        }
        let preferred = [
            info.language.clone(),
            Some(config.video.caption_fallback_language.clone()),
        ];
        for candidate in preferred.into_iter().flatten() {
            if tracks.contains_key(&candidate) {
                return Some(candidate);
            }
            // A served regional variant (en-US for en) is the
            // same language for ranking purposes.
            if let Some(variant) = tracks
                .keys()
                .find(|key| key.starts_with(&format!("{candidate}-")))
            {
                return Some(variant.clone());
            }
        }
        tracks.keys().next().cloned()
    };
    let mut choices = Vec::new();
    if let Some(language) = pick(&info.subtitles) {
        choices.push(CaptionChoice {
            kind: "manual",
            language,
        });
    }
    if let Some(language) = pick(&info.automatic_captions) {
        choices.push(CaptionChoice {
            kind: "asr",
            language,
        });
    }
    choices
}

/// Download the chosen caption tracks (json3). Each track
/// is fetched in its own run into its own scratch subdir:
/// the fetcher names manual and automatic files identically
/// (`<id>.<lang>.json3`), so a combined run would let one
/// track silently stand in for the other — exactly the
/// confusion the §4.4 ranking exists to keep visible.
pub fn fetch_captions(
    config: &Config,
    video: &VideoRef,
    choices: &[CaptionChoice],
    scratch: &Path,
) -> Result<Vec<CaptionFile>, FathomError> {
    let mut files = Vec::new();
    for choice in choices {
        let dir = scratch.join(format!("captions-{}", choice.kind));
        std::fs::create_dir_all(&dir).map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot create the caption scratch dir: {error}"),
            )
        })?;
        let mut args: Vec<String> = vec![
            "--skip-download".to_string(),
            "--no-playlist".to_string(),
            "--no-cookies".to_string(),
            "--ignore-config".to_string(),
            if choice.kind == "manual" {
                "--write-subs".to_string()
            } else {
                "--write-auto-subs".to_string()
            },
            "--sub-format".to_string(),
            "json3".to_string(),
            "--sub-langs".to_string(),
            choice.language.clone(),
            "--output".to_string(),
            dir.join(&video.video_id).to_string_lossy().into_owned(),
        ];
        args.push(video.canonical_url.clone());
        let outcome = run_fetcher(config, &args, &dir)?;
        if outcome.timed_out || outcome.exit_code != Some(0) {
            return Err(FathomError::new(
                ErrorCode::ProviderUnavailable,
                format!(
                    "the {} caption fetch failed: {}",
                    choice.kind,
                    bounded_stderr(&outcome)
                ),
            ));
        }
        let path = dir.join(format!("{}.{}.json3", video.video_id, choice.language));
        if path.exists() {
            files.push(CaptionFile {
                kind: choice.kind.to_string(),
                language: choice.language.clone(),
                path,
            });
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with(duration: Option<f64>) -> VideoInfo {
        VideoInfo {
            automatic_captions: BTreeMap::new(),
            availability: None,
            channel: None,
            channel_id: None,
            chapters: Vec::new(),
            duration_secs: duration,
            formats: Vec::new(),
            id: "s9f9oa3Ae6c".to_string(),
            is_live: false,
            language: Some("en".to_string()),
            like_count: None,
            live_status: None,
            subtitles: BTreeMap::new(),
            title: None,
            upload_date: None,
            uploader: None,
            view_count: None,
            webpage_url: None,
        }
    }

    fn config() -> Config {
        Config::restrictive_default()
    }

    #[test]
    fn validation_preflight_admits_an_ordinary_video() {
        let facts = preflight(&info_with(Some(254.0)), &config()).unwrap();
        assert_eq!(facts.estimated_bytes, None);
    }

    #[test]
    fn adversarial_over_duration_is_refused_at_preflight() {
        let err = preflight(&info_with(Some(7200.0)), &config()).unwrap_err();
        assert_eq!(err.code, ErrorCode::ResourceConstraint);
    }

    #[test]
    fn adversarial_live_and_gated_videos_are_refused_at_preflight() {
        let mut live = info_with(Some(60.0));
        live.live_status = Some("is_upcoming".to_string());
        assert_eq!(
            preflight(&live, &config()).unwrap_err().code,
            ErrorCode::UnsupportedTarget
        );
        let mut gated = info_with(Some(60.0));
        gated.availability = Some("needs_auth".to_string());
        assert_eq!(
            preflight(&gated, &config()).unwrap_err().code,
            ErrorCode::UnsupportedTarget
        );
    }

    #[test]
    fn validation_caption_choice_prefers_original_then_fallback_language() {
        let mut info = info_with(Some(60.0));
        info.subtitles
            .insert("fr".to_string(), vec!["json3".to_string()]);
        info.subtitles
            .insert("en".to_string(), vec!["json3".to_string()]);
        info.automatic_captions
            .insert("en-US".to_string(), vec!["json3".to_string()]);
        let choices = choose_caption_tracks(&info, &config());
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].kind, "manual");
        assert_eq!(choices[0].language, "en");
        assert_eq!(choices[1].kind, "asr");
        assert_eq!(choices[1].language, "en-US");
    }

    #[test]
    fn validation_format_string_is_the_analysis_rendition() {
        assert_eq!(
            format_string(&config()),
            "bv*[height<=1080]+ba/b[height<=1080]"
        );
    }
}
