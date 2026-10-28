//! The Y1 ingest pipeline and the operator delete verb.
//!
//! Order is the §4.2/§4.7 contract: URL grammar → metadata
//! pre-flight (refusals land before any media byte moves) →
//! media fetch (a failed fetch retains nothing) → the legs
//! (captions, local ASR, chapters, frames), each of which may
//! degrade the ingest to `partial` but never fails it →
//! assembly and retention.

use std::path::Path;

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, Subject, hash_file_with_bound, sha256_hex,
    subject_for_file_with_bound,
};
use fathom_core::limits::VIDEO_BYTES_MAX;
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, optional_str, require_str};

use crate::captions::{ParsedTrack, dedup_asr, parse_json3, track_id};
use crate::document::{AssembleInputs, TrackData};
use crate::fetch;
use crate::url::parse_video_url;

/// Run one ingest end to end.
pub fn ingest_youtube_video(
    registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let video = parse_video_url(require_str(args, "url")?)?;
    let retrieved_at = crate::document::utc_now();
    let scratch_root = paths::state_subdir(config, "video-scratch")?;
    let scratch = scratch_root.join(format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&scratch).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create the ingest scratch dir: {error}"),
        )
    })?;
    let result = run_ingest(registry, config, &video, &retrieved_at, &scratch);
    // The scratch dir dies with the run either way: on
    // success everything retained was moved out; on failure
    // §4.2 retains nothing.
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn run_ingest(
    registry: &Registry,
    config: &Config,
    video: &crate::url::VideoRef,
    retrieved_at: &str,
    scratch: &Path,
) -> Result<Value, FathomError> {
    // Pre-flight: refusals here precede any media byte.
    let info = fetch::metadata(config, video, scratch)?;
    let preflight = fetch::preflight(&info, config)?;
    // Media: a failed fetch propagates and retains nothing.
    let fetched = fetch::fetch_media(config, video, scratch)?;
    let info_json_bytes = std::fs::read(&fetched.info_json_path).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read the fetcher's info JSON: {error}"),
        )
    })?;
    let info_json_sha256 = sha256_hex(&info_json_bytes);
    let (subject_sha256, subject_size) =
        hash_file_with_bound(&fetched.media_path, VIDEO_BYTES_MAX)?;
    let media_ext = fetched
        .media_path
        .extension()
        .map(|ext| ext.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bin".to_string());

    // From here on the media is whole: leg failures degrade
    // to a partial ingest (§4.7), never an error.
    let id = crate::document::ingest_id(&video.canonical_url, retrieved_at, &subject_sha256);
    let payload = crate::document::payload_dir(config, &subject_sha256, &id);
    std::fs::create_dir_all(&payload).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create the ingest payload dir: {error}"),
        )
    })?;
    let media_store_path = payload.join(format!("media.{media_ext}"));
    std::fs::rename(&fetched.media_path, &media_store_path).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot retain the fetched media: {error}"),
        )
    })?;
    std::fs::write(payload.join("info.json"), &info_json_bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot retain the fetcher's info JSON: {error}"),
        )
    })?;

    let mut unknowns: Vec<(String, String)> = Vec::new();
    // §4.7: the document is partial when a processing leg
    // failed — not merely when an unknown is recorded (a
    // source property like absent chapters is an unknown,
    // not a failure).
    let mut partial = false;

    // Captions leg (§4.4 ranks 1–2).
    let mut tracks: Vec<TrackData> = Vec::new();
    let choices = fetch::choose_caption_tracks(&info, config);
    match fetch::fetch_captions(config, video, &choices, scratch) {
        Ok(files) => {
            for file in files {
                match load_caption_track(&file.path, &file.kind, &file.language, &payload) {
                    Ok(track) => tracks.push(track),
                    Err(reason) => {
                        partial = true;
                        unknowns.push(("transcript".to_string(), reason));
                    }
                }
            }
        }
        Err(error) => {
            if !choices.is_empty() {
                partial = true;
                unknowns.push(("transcript".to_string(), error.message.clone()));
            }
        }
    }

    // Local-ASR leg (§4.4 rank 3): only when no caption
    // track yielded spans.
    let mut audio_component: Option<Value> = None;
    if tracks.is_empty() {
        match crate::asr::extract_audio(config, &media_store_path, scratch) {
            Ok(wav) => {
                let (wav_sha, wav_size) = hash_file_with_bound(&wav, VIDEO_BYTES_MAX)?;
                let audio_store_path = payload.join("audio.wav");
                std::fs::rename(&wav, &audio_store_path).map_err(|error| {
                    FathomError::new(
                        ErrorCode::ExecutionFailure,
                        format!("cannot retain the extracted audio: {error}"),
                    )
                })?;
                audio_component = Some(json!({
                    "sha256": wav_sha,
                    "size_bytes": wav_size,
                }));
                if crate::asr::configured(config) {
                    match crate::asr::transcribe(config, &audio_store_path, scratch) {
                        Ok(spans) => {
                            let raw_span_count = spans.len();
                            tracks.push(TrackData {
                                of_record: false,
                                parsed: ParsedTrack {
                                    deduplicated: false,
                                    kind: "local_asr".to_string(),
                                    language: config.video.caption_fallback_language.clone(),
                                    raw_span_count,
                                    spans,
                                    track_id: track_id(
                                        "local_asr",
                                        &config.video.caption_fallback_language,
                                    ),
                                },
                                sha256: wav_sha,
                            });
                        }
                        Err(reason) => {
                            partial = true;
                            unknowns.push(("transcript".to_string(), reason));
                        }
                    }
                } else {
                    // No engine configured: the transcript leg
                    // yields nothing — the ingest is partial
                    // (§13 Y1.5: ingests partial-honestly).
                    partial = true;
                    unknowns.push((
                        "transcript".to_string(),
                        "no caption track was served and no local ASR engine is \
                         configured (providers.video.asr_program)"
                            .to_string(),
                    ));
                }
            }
            Err(reason) => {
                partial = true;
                unknowns.push(("transcript".to_string(), reason));
            }
        }
    }
    // Exactly one track is the inventory of record: the
    // highest §4.4 rank retained.
    if let Some(best) = tracks
        .iter_mut()
        .min_by_key(|track| match track.parsed.kind.as_str() {
            "manual" => 0_u8,
            "asr" => 1,
            _ => 2,
        })
    {
        best.of_record = true;
    }

    // Chapters leg: absent chapters are an unknown (§4.6).
    let chapters: Option<Vec<Value>> = if info.chapters.is_empty() {
        unknowns.push((
            "chapters".to_string(),
            "the platform metadata carries no chapter markers for this video".to_string(),
        ));
        None
    } else {
        Some(
            info.chapters
                .iter()
                .enumerate()
                .map(|(index, chapter)| {
                    json!({
                        "end_ms": chapter.end_ms,
                        "index": index,
                        "start_ms": chapter.start_ms,
                        "title": chapter.title,
                    })
                })
                .collect(),
        )
    };

    // Frames leg (§4.5).
    let frames_dir = payload.join("frames");
    let frames = crate::frames::sample_frames(
        config,
        &media_store_path,
        info.duration_secs.unwrap_or(0.0),
        scratch,
        &frames_dir,
    );
    if !frames.unknowns.is_empty() {
        partial = true;
    }
    unknowns.extend(frames.unknowns.iter().cloned());

    let producer = json!({
        "catalog_digest": registry.catalog_digest(),
        "ffmpeg_version": crate::frames::sampler_version(config, scratch)
            .unwrap_or_else(|| "unavailable".to_string()),
        "fetcher": "yt-dlp",
        "fetcher_version": fetch::fetcher_version(config, scratch)
            .unwrap_or_else(|| "unavailable".to_string()),
        "server": fathom_core::PRODUCT_NAME,
        "source_revision": fathom_core::SOURCE_REVISION,
        "version": fathom_core::VERSION,
    });
    let format_ids = fetch::selected_format_ids(&info, config.video.max_height);
    let (document, digest) = crate::document::assemble(AssembleInputs {
        audio: audio_component,
        chapters,
        estimated_bytes: preflight.estimated_bytes,
        format_ids,
        format_selection: fetch::format_string(config),
        frames,
        info,
        info_json_sha256,
        partial,
        producer,
        retrieved_at: retrieved_at.to_string(),
        subject_path: media_store_path.to_string_lossy().into_owned(),
        subject_sha256: subject_sha256.clone(),
        subject_size,
        tracks,
        unknowns,
        video: video.clone(),
    });
    let document_path = crate::document::document_path(config, &subject_sha256, &id);
    crate::document::write_document(&document_path, &document)?;

    let mut evidence = Evidence::new("ingest_youtube_video", "video");
    evidence.subject = Some(Subject {
        path: media_store_path.to_string_lossy().into_owned(),
        sha256: subject_sha256,
        size_bytes: subject_size,
    });
    evidence.coverage.examined = document["coverage"]["examined"].as_u64().unwrap_or(0);
    evidence.coverage.total = document["coverage"]["total"].as_u64().unwrap_or(0);
    evidence.coverage.exhaustive = document["coverage"]["exhaustive"]
        .as_bool()
        .unwrap_or(false);
    let inventories = &document["inventories"];
    let count = |name: &str| inventories[name].as_array().map_or(0, Vec::len);
    evidence.add_finding(
        Finding::new(
            "ingest",
            Confidence::Observed,
            json!({
                "document_digest": digest,
                "format_selection": document["provenance"]["format_selection"],
                "ingest_id": id,
                "inventories": {
                    "chapters": count("chapters"),
                    "coverage_gaps": count("coverage_gaps"),
                    "demonstration_events": count("demonstration_events"),
                    "frames": count("frames"),
                    "transcript_disagreements": count("transcript_disagreements"),
                    "transcript_spans": count("transcript_spans"),
                },
                "status": document["status"],
            }),
        )
        .with_limitation(
            "metadata is platform-asserted (the platform's own fields, observed); \
             frame sampling names changes, not content; machine transcripts (platform \
             ASR, local ASR) may misstate wording",
        ),
    );
    if let Some(metadata) = inventories["metadata"].as_object() {
        for (field, value) in metadata {
            evidence.add_finding(Finding::new(
                "metadata_fact",
                Confidence::Observed,
                json!({"field": field, "value": value}),
            ));
        }
    }
    if let Some(chapter_records) = inventories["chapters"].as_array() {
        for chapter in chapter_records {
            evidence.add_finding(Finding::new(
                "chapter",
                Confidence::Observed,
                chapter.clone(),
            ));
        }
    }
    if let Some(records) = inventories["transcript_disagreements"].as_array() {
        for record in records {
            evidence.add_finding(Finding::new(
                "transcript_disagreement",
                Confidence::Derived,
                record.clone(),
            ));
        }
    }
    if let Some(records) = document["unknowns"].as_array() {
        for unknown in records {
            evidence.add_unknown(
                unknown["aspect"].as_str().unwrap_or(""),
                unknown["reason"].as_str().unwrap_or(""),
            );
        }
    }
    Ok(evidence.to_value())
}

/// Read one downloaded caption file into a retained track:
/// raw bytes bounded (§11), parsed, de-duplicated when the
/// track is platform ASR, and the raw file retained under
/// the payload's captions dir.
fn load_caption_track(
    path: &Path,
    kind: &str,
    language: &str,
    payload: &Path,
) -> Result<TrackData, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read a caption track: {error}"))?;
    if bytes.len() > fathom_core::limits::VIDEO_TRANSCRIPT_BYTES_MAX {
        return Err(format!(
            "a caption track exceeds VIDEO_TRANSCRIPT_BYTES_MAX ({} bytes)",
            fathom_core::limits::VIDEO_TRANSCRIPT_BYTES_MAX
        ));
    }
    let raw_spans = parse_json3(&bytes)?;
    let raw_span_count = raw_spans.len();
    let (spans, deduplicated) = if kind == "asr" {
        dedup_asr(raw_spans)
    } else {
        (raw_spans, false)
    };
    let id = track_id(kind, language);
    let captions_dir = payload.join("captions");
    std::fs::create_dir_all(&captions_dir)
        .map_err(|error| format!("cannot create the captions store dir: {error}"))?;
    std::fs::write(captions_dir.join(format!("{id}.json3")), &bytes)
        .map_err(|error| format!("cannot retain a caption track: {error}"))?;
    Ok(TrackData {
        of_record: false,
        parsed: ParsedTrack {
            deduplicated,
            kind: kind.to_string(),
            language: language.to_string(),
            raw_span_count,
            spans,
            track_id: id,
        },
        sha256: sha256_hex(&bytes),
    })
}

/// Delete one ingest (by id) or every ingest of one subject
/// (by media target). Deleting what is not retained is an
/// `invalid_request`, never a silent success (§4.6).
pub fn delete_video_ingest(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let ingest_id_arg = optional_str(args, "ingest_id");
    let target_arg = optional_str(args, "target");
    if ingest_id_arg.is_some() == target_arg.is_some() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "supply exactly one of 'ingest_id' or 'target'",
        ));
    }
    let mut evidence = Evidence::new("delete_video_ingest", "video");
    if let Some(ingest_id) = ingest_id_arg {
        let loaded = crate::document::load_ingest(config, ingest_id)?;
        std::fs::remove_file(&loaded.document_path).map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot delete the ingest document: {error}"),
            )
        })?;
        if loaded.payload_dir.exists() {
            std::fs::remove_dir_all(&loaded.payload_dir).map_err(|error| {
                FathomError::new(
                    ErrorCode::ExecutionFailure,
                    format!("cannot delete the ingest payload: {error}"),
                )
            })?;
        }
        // An emptied subject directory goes too; other
        // ingests of the same subject are untouched.
        let subject_dir = proof::video_ingest_dir(config, &loaded.subject_sha256);
        let remaining = std::fs::read_dir(&subject_dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        if !remaining {
            let _ = std::fs::remove_dir_all(&subject_dir);
        }
        evidence.coverage.examined = 1;
        evidence.coverage.total = 1;
        evidence.coverage.exhaustive = true;
        evidence.add_finding(Finding::new(
            "deleted",
            Confidence::Observed,
            json!({
                "ingest_id": ingest_id,
                "subject_sha256": loaded.subject_sha256,
            }),
        ));
        return Ok(evidence.to_value());
    }
    let target = target_arg.expect("checked above");
    let path = paths::validate_target(config, Path::new(target))?;
    let subject = subject_for_file_with_bound(&path, VIDEO_BYTES_MAX)?;
    let subject_dir = proof::video_ingest_dir(config, &subject.sha256);
    if !subject_dir.exists() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "no ingest is retained for this subject",
        ));
    }
    let documents_removed = std::fs::read_dir(&subject_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.path().extension().and_then(|ext| ext.to_str()) == Some("json")
                })
                .count()
        })
        .unwrap_or(0);
    std::fs::remove_dir_all(&subject_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot delete the subject's ingest store: {error}"),
        )
    })?;
    evidence.coverage.examined = documents_removed as u64;
    evidence.coverage.total = documents_removed as u64;
    evidence.coverage.exhaustive = true;
    evidence.add_finding(Finding::new(
        "deleted",
        Confidence::Observed,
        json!({
            "documents_removed": documents_removed,
            "subject_sha256": subject.sha256,
        }),
    ));
    Ok(evidence.to_value())
}
