//! The ingest document (§4.6): assembly from the legs'
//! yields, the deterministic derived records
//! (`demonstration_events`, `coverage_gaps`), and the store
//! IO every reader goes through — digest verification on the
//! document and re-hash verification on the media, on every
//! load (§12's integrity posture).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{hash_file_with_bound, sha256_hex};
use fathom_core::limits::{VIDEO_BYTES_MAX, VIDEO_CHAPTERS_MAX, VIDEO_TRANSCRIPT_SPANS_MAX};
use fathom_core::proof;

use crate::captions::{ParsedTrack, wording_agrees};
use crate::fetch::VideoInfo;
use crate::frames::FrameOutcome;
use crate::url::VideoRef;

/// Silence longer than this splits two span clusters
/// (the §6.2(b) clustering rule, as a named rule constant).
pub const CLUSTER_GAP_MS: u64 = 1_500;

/// An uncovered window at least this long is a coverage gap
/// (the §6.3 gap rule's substrate).
pub const GAP_WINDOW_MIN_MS: u64 = 20_000;

/// One caption track as the document records it: the parsed
/// spans and the raw file's identity.
pub struct TrackData {
    pub of_record: bool,
    pub parsed: ParsedTrack,
    pub sha256: String,
}

/// Everything one ingest run hands to assembly.
pub struct AssembleInputs {
    pub audio: Option<Value>,
    pub chapters: Option<Vec<Value>>,
    pub estimated_bytes: Option<u64>,
    pub format_ids: Vec<String>,
    pub format_selection: String,
    pub frames: FrameOutcome,
    pub info: VideoInfo,
    pub info_json_sha256: String,
    /// §4.7: a processing leg failed (or yielded nothing for
    /// want of a configured engine); unknowns alone do not
    /// make an ingest partial.
    pub partial: bool,
    pub producer: Value,
    pub retrieved_at: String,
    pub subject_path: String,
    pub subject_sha256: String,
    pub subject_size: u64,
    pub tracks: Vec<TrackData>,
    pub unknowns: Vec<(String, String)>,
    pub video: VideoRef,
}

/// Format epoch seconds as an ISO-8601 UTC stamp. The civil
/// conversion is Howard Hinnant's days-from-civil inverse;
/// no clock crate exists in this workspace and none is
/// needed for a formatter.
pub fn format_utc(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs = epoch_secs % 86_400;
    let (hour, minute, second) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The current UTC stamp, for provenance.
pub fn utc_now() -> String {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format_utc(epoch)
}

/// The ingest id: derived from the canonical URL, the
/// retrieval stamp, and the subject hash, so re-ingesting
/// the same bytes in the same second is the same ingest.
pub fn ingest_id(canonical_url: &str, retrieved_at: &str, subject_sha256: &str) -> String {
    let digest = sha256_hex(format!("{canonical_url}|{retrieved_at}|{subject_sha256}").as_bytes());
    format!("vi_{}", &digest[..16])
}

/// Ingest ids are generated, never caller-shaped: the read
/// and delete tools validate before touching the store.
pub fn validate_ingest_id(raw: &str) -> Result<&str, FathomError> {
    let valid = !raw.is_empty()
        && raw.len() <= 64
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(raw)
    } else {
        Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'ingest_id' is not a generated ingest id",
        ))
    }
}

/// The document's path in the store.
pub fn document_path(config: &Config, subject_sha256: &str, ingest_id: &str) -> PathBuf {
    proof::video_ingest_dir(config, subject_sha256).join(format!("{ingest_id}.json"))
}

/// The payload directory (media, captions, frames, audio)
/// for one ingest.
pub fn payload_dir(config: &Config, subject_sha256: &str, ingest_id: &str) -> PathBuf {
    proof::video_ingest_dir(config, subject_sha256).join(ingest_id)
}

/// Cluster the of-record spans on silence gaps and mark the
/// clusters a scene-leg frame falls in: those are the
/// §5.1 `demonstration_event` records (derived, rule named
/// on the record). Frame-only stretches become events with
/// no spans — §6.2(d) findings, never steps.
pub fn derive_events(spans: &[Value], frames: &[Value], grid_interval_ms: u64) -> Vec<Value> {
    let scene_frames: Vec<&Value> = frames
        .iter()
        .filter(|frame| frame.get("source").and_then(Value::as_str) == Some("scene"))
        .collect();
    let frame_ts = |frame: &Value| {
        frame
            .get("timestamp_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let frame_key = |frame: &Value| {
        frame
            .get("frame_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    // Clusters: maximal runs whose inter-span silence is at
    // most CLUSTER_GAP_MS.
    let mut clusters: Vec<Vec<&Value>> = Vec::new();
    for span in spans {
        let start = span.get("start_ms").and_then(Value::as_u64).unwrap_or(0);
        let extends = match clusters.last() {
            Some(cluster) => {
                let cluster_end = cluster
                    .iter()
                    .map(|s| s.get("end_ms").and_then(Value::as_u64).unwrap_or(0))
                    .max()
                    .unwrap_or(0);
                start <= cluster_end.saturating_add(CLUSTER_GAP_MS)
            }
            None => false,
        };
        if extends {
            clusters.last_mut().expect("checked above").push(span);
        } else {
            clusters.push(vec![span]);
        }
    }
    let mut events: Vec<Value> = Vec::new();
    let mut covered_frames: Vec<String> = Vec::new();
    for cluster in &clusters {
        let start = cluster
            .iter()
            .map(|s| s.get("start_ms").and_then(Value::as_u64).unwrap_or(0))
            .min()
            .unwrap_or(0);
        let end = cluster
            .iter()
            .map(|s| s.get("end_ms").and_then(Value::as_u64).unwrap_or(0))
            .max()
            .unwrap_or(0);
        let inside: Vec<&&Value> = scene_frames
            .iter()
            .filter(|frame| {
                let ts = frame_ts(frame);
                ts >= start && ts <= end
            })
            .collect();
        if inside.is_empty() {
            continue;
        }
        let frame_keys: Vec<String> = inside.iter().map(|frame| frame_key(frame)).collect();
        covered_frames.extend(frame_keys.iter().cloned());
        events.push(json!({
            "end_ms": end,
            "event_key": format!("de_{:04}", events.len() + 1),
            "frame_keys": frame_keys,
            "rule": "span_cluster_frame_change",
            "span_keys": cluster.iter().map(|s| {
                s.get("span_key").and_then(Value::as_str).unwrap_or("").to_string()
            }).collect::<Vec<_>>(),
            "start_ms": start,
        }));
    }
    // Frame-only runs: scene frames in no cluster window,
    // grouped while consecutive frames sit within two grid
    // intervals of each other.
    let uncovered: Vec<&&Value> = scene_frames
        .iter()
        .filter(|frame| !covered_frames.contains(&frame_key(frame)))
        .collect();
    let mut run: Vec<&&Value> = Vec::new();
    let flush = |run: &Vec<&&Value>, events: &mut Vec<Value>| {
        if run.is_empty() {
            return;
        }
        let frame_keys: Vec<String> = run.iter().map(|frame| frame_key(frame)).collect();
        events.push(json!({
            "end_ms": frame_ts(run[run.len() - 1]),
            "event_key": format!("de_{:04}", events.len() + 1),
            "frame_keys": frame_keys,
            "rule": "frame_change_no_spans",
            "span_keys": [],
            "start_ms": frame_ts(run[0]),
        }));
    };
    for frame in uncovered {
        let split = match run.last() {
            Some(previous) => {
                frame_ts(frame) > frame_ts(previous).saturating_add(grid_interval_ms * 2)
            }
            None => false,
        };
        if split {
            flush(&run, &mut events);
            run.clear();
        }
        run.push(frame);
    }
    flush(&run, &mut events);
    events.sort_by_key(|event| event.get("start_ms").and_then(Value::as_u64).unwrap_or(0));
    // Keys were assigned in construction order; reassign in
    // window order so keys are a pure function of the sorted
    // records.
    for (index, event) in events.iter_mut().enumerate() {
        event["event_key"] = json!(format!("de_{:04}", index + 1));
    }
    events
}

/// Maximal windows with no of-record span and no scene-leg
/// frame, at least `GAP_WINDOW_MIN_MS` long: the coverage
/// gaps the §6.3 gap rule binds against.
pub fn derive_gaps(spans: &[Value], frames: &[Value], duration_ms: u64) -> Vec<Value> {
    let mut covered: Vec<(u64, u64)> = spans
        .iter()
        .map(|span| {
            (
                span.get("start_ms").and_then(Value::as_u64).unwrap_or(0),
                span.get("end_ms").and_then(Value::as_u64).unwrap_or(0),
            )
        })
        .collect();
    for frame in frames {
        if frame.get("source").and_then(Value::as_str) == Some("scene") {
            let ts = frame
                .get("timestamp_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            covered.push((ts, ts));
        }
    }
    covered.sort();
    let mut gaps = Vec::new();
    let mut cursor = 0_u64;
    for (start, end) in covered {
        if start > cursor && start - cursor >= GAP_WINDOW_MIN_MS {
            gaps.push(json!({
                "end_ms": start,
                "gap_key": format!("gap_{:04}", gaps.len() + 1),
                "reason": "no transcript spans and no scene-change frames in this window",
                "start_ms": cursor,
            }));
        }
        cursor = cursor.max(end);
    }
    if duration_ms > cursor && duration_ms - cursor >= GAP_WINDOW_MIN_MS {
        gaps.push(json!({
            "end_ms": duration_ms,
            "gap_key": format!("gap_{:04}", gaps.len() + 1),
            "reason": "no transcript spans and no scene-change frames in this window",
            "start_ms": cursor,
        }));
    }
    gaps
}

/// The metadata inventory record: platform-asserted facts,
/// absent fields omitted rather than nulled.
fn metadata_record(info: &VideoInfo, video_id: &str) -> Value {
    let mut record = serde_json::Map::new();
    let mut put = |key: &str, value: Value| {
        if !value.is_null() {
            record.insert(key.to_string(), value);
        }
    };
    put("availability", json!(info.availability));
    put("channel", json!(info.channel));
    put("channel_id", json!(info.channel_id));
    put(
        "duration_secs",
        info.duration_secs
            .map(|d| json!(d.round() as u64))
            .unwrap_or(Value::Null),
    );
    put("is_live", json!(info.is_live));
    put("language", json!(info.language));
    put("like_count", json!(info.like_count));
    put("live_status", json!(info.live_status));
    put("title", json!(info.title));
    put("upload_date", json!(info.upload_date));
    put("uploader", json!(info.uploader));
    put("video_id", json!(video_id));
    put("view_count", json!(info.view_count));
    put("webpage_url", json!(info.webpage_url));
    Value::Object(record)
}

/// Assemble the §4.6 ingest document. The document digest is
/// computed over the digest-less form and stored on the
/// document; every later load recomputes it.
pub fn assemble(inputs: AssembleInputs) -> (Value, String) {
    let duration_ms = inputs
        .info
        .duration_secs
        .map(|d| (d * 1000.0).round() as u64)
        .unwrap_or(0);
    // Span records: tracks ordered by §4.4 rank, spans by
    // start; keys are one global sequence in that order.
    let mut ordered_tracks: Vec<&TrackData> = inputs.tracks.iter().collect();
    ordered_tracks.sort_by_key(|track| match track.parsed.kind.as_str() {
        "manual" => 0_u8,
        "asr" => 1,
        _ => 2,
    });
    let mut span_records: Vec<Value> = Vec::new();
    let mut spans_total = 0_usize;
    let mut spans_truncated = false;
    for track in &ordered_tracks {
        let mut spans: Vec<_> = track.parsed.spans.iter().collect();
        spans.sort_by_key(|span| span.start_ms);
        spans_total += spans.len();
        for span in spans {
            if span_records.len() >= VIDEO_TRANSCRIPT_SPANS_MAX {
                spans_truncated = true;
                continue;
            }
            span_records.push(json!({
                "end_ms": span.end_ms,
                "language": track.parsed.language,
                "span_key": format!("sp_{:04}", span_records.len() + 1),
                "start_ms": span.start_ms,
                "text": span.text,
                "track_id": track.parsed.track_id,
                "track_kind": track.parsed.kind,
            }));
        }
    }
    // Chapter records, capped whole (§4.6: absent chapters
    // are an unknown the caller states, not an empty list
    // presented as coverage).
    let (chapter_records, chapters_total) = match &inputs.chapters {
        Some(records) => {
            let total = records.len();
            let mut kept = records.clone();
            kept.truncate(VIDEO_CHAPTERS_MAX);
            (kept, total)
        }
        None => (Vec::new(), 0),
    };
    // The disagreement derivation (§4.4): for each span of
    // the record track, the platform-ASR spans overlapping
    // its window are joined and compared by normalized
    // wording. One record per divergent (record span,
    // overlapping ASR span set) pair.
    let record_track_id = ordered_tracks
        .iter()
        .find(|track| track.parsed.kind == "manual")
        .map(|track| track.parsed.track_id.clone());
    let asr_spans: Vec<&Value> = span_records
        .iter()
        .filter(|span| span.get("track_kind").and_then(Value::as_str) == Some("asr"))
        .collect();
    let mut disagreements: Vec<Value> = Vec::new();
    if let Some(record_track_id) = &record_track_id {
        for span in &span_records {
            if span.get("track_id").and_then(Value::as_str) != Some(record_track_id.as_str()) {
                continue;
            }
            let (start, end) = (
                span.get("start_ms").and_then(Value::as_u64).unwrap_or(0),
                span.get("end_ms").and_then(Value::as_u64).unwrap_or(0),
            );
            let overlapping: Vec<&&Value> = asr_spans
                .iter()
                .filter(|other| {
                    let (o_start, o_end) = (
                        other.get("start_ms").and_then(Value::as_u64).unwrap_or(0),
                        other.get("end_ms").and_then(Value::as_u64).unwrap_or(0),
                    );
                    o_start < end && o_end > start
                })
                .collect();
            if overlapping.is_empty() {
                continue;
            }
            let joined = overlapping
                .iter()
                .map(|other| other.get("text").and_then(Value::as_str).unwrap_or(""))
                .collect::<Vec<_>>()
                .join(" ");
            let own_text = span.get("text").and_then(Value::as_str).unwrap_or("");
            if !wording_agrees(own_text, &joined) {
                disagreements.push(json!({
                    "aspect": "wording",
                    "asr_span_keys": overlapping.iter().map(|other| {
                        other.get("span_key").and_then(Value::as_str).unwrap_or("").to_string()
                    }).collect::<Vec<_>>(),
                    "disagreement_key": format!("td_{:04}", disagreements.len() + 1),
                    "span_key_a": span.get("span_key").and_then(Value::as_str).unwrap_or(""),
                    "span_key_b": overlapping[0].get("span_key").and_then(Value::as_str).unwrap_or(""),
                }));
            }
        }
    }
    // Demonstration and gap derivation runs over the track
    // of record: the manual track when one exists, else the
    // best retained fallback (the ingest flags exactly one).
    let of_record_track_id = inputs
        .tracks
        .iter()
        .find(|track| track.of_record)
        .map(|track| track.parsed.track_id.clone());
    let of_record_spans: Vec<Value> = match &of_record_track_id {
        Some(track_id) => span_records
            .iter()
            .filter(|span| span.get("track_id").and_then(Value::as_str) == Some(track_id.as_str()))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    let grid_interval_ms =
        crate::frames::grid_interval_secs(inputs.info.duration_secs.unwrap_or(0.0)) * 1000;
    let events = derive_events(&of_record_spans, &inputs.frames.records, grid_interval_ms);
    let gaps = derive_gaps(&of_record_spans, &inputs.frames.records, duration_ms);
    let frame_total = inputs.frames.total;
    let frames_truncated = inputs.frames.truncated;
    let examined =
        (span_records.len() + inputs.frames.records.len() + chapter_records.len()) as u64;
    let total = (spans_total + frame_total + chapters_total) as u64;
    let status = if inputs.partial {
        "partial"
    } else {
        "complete"
    };
    let exhaustive = !spans_truncated && !frames_truncated && status == "complete";
    let mut caption_components: Vec<Value> = Vec::new();
    for track in &ordered_tracks {
        caption_components.push(json!({
            "deduplicated": track.parsed.deduplicated,
            "kind": track.parsed.kind,
            "language": track.parsed.language,
            "of_record": track.of_record,
            "raw_span_count": track.parsed.raw_span_count,
            "sha256": track.sha256,
            "track_id": track.parsed.track_id,
        }));
    }
    let id = ingest_id(
        &inputs.video.canonical_url,
        &inputs.retrieved_at,
        &inputs.subject_sha256,
    );
    let mut document = json!({
        "components": {
            "audio": inputs.audio,
            "captions": caption_components,
            "info_json_sha256": inputs.info_json_sha256,
            "media": {
                "sha256": inputs.subject_sha256,
                "size_bytes": inputs.subject_size,
            },
        },
        "coverage": {
            "examined": examined,
            "exhaustive": exhaustive,
            "total": total,
        },
        "ingest_id": id,
        "inventories": {
            "chapters": chapter_records,
            "chapters_total": chapters_total,
            "chapters_truncated": chapters_total > VIDEO_CHAPTERS_MAX,
            "coverage_gaps": gaps,
            "coverage_gaps_total": 0,
            "demonstration_events": events,
            "demonstration_events_total": 0,
            "frames": inputs.frames.records,
            "frames_total": frame_total,
            "frames_truncated": frames_truncated,
            "metadata": metadata_record(&inputs.info, &inputs.video.video_id),
            "transcript_disagreements": disagreements,
            "transcript_disagreements_total": 0,
            "transcript_spans": span_records,
            "transcript_spans_total": spans_total,
            "transcript_spans_truncated": spans_truncated,
        },
        "producer": inputs.producer,
        "provenance": {
            "estimated_bytes": inputs.estimated_bytes,
            "format_ids": inputs.format_ids,
            "format_selection": inputs.format_selection,
            "retrieved_at": inputs.retrieved_at,
            "url": inputs.video.canonical_url,
            "video_id": inputs.video.video_id,
        },
        "status": status,
        "subject": {
            "path": inputs.subject_path,
            "sha256": inputs.subject_sha256,
            "size_bytes": inputs.subject_size,
        },
        "unknowns": inputs.unknowns.iter().map(|(aspect, reason)| {
            json!({"aspect": aspect, "reason": reason})
        }).collect::<Vec<_>>(),
        "version": 1,
    });
    // Totals for the derived inventories are their own
    // lengths (nothing is capped after derivation).
    let gap_total = document["inventories"]["coverage_gaps"]
        .as_array()
        .map_or(0, Vec::len);
    let event_total = document["inventories"]["demonstration_events"]
        .as_array()
        .map_or(0, Vec::len);
    let disagreement_total = document["inventories"]["transcript_disagreements"]
        .as_array()
        .map_or(0, Vec::len);
    document["inventories"]["coverage_gaps_total"] = json!(gap_total);
    document["inventories"]["demonstration_events_total"] = json!(event_total);
    document["inventories"]["transcript_disagreements_total"] = json!(disagreement_total);
    let digest = proof::video_ingest_digest(&document);
    document["document_digest"] = json!(digest);
    (document, digest)
}

/// Write one ingest document in canonical form.
pub fn write_document(path: &Path, document: &Value) -> Result<(), FathomError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot create the ingest store dir: {error}"),
            )
        })?;
    }
    std::fs::write(path, proof::canonical_json(document)).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot write the ingest document: {error}"),
        )
    })
}

/// A loaded, integrity-verified ingest.
pub struct LoadedIngest {
    pub document: Value,
    pub document_path: PathBuf,
    pub payload_dir: PathBuf,
    pub subject_sha256: String,
}

/// Find an ingest document by id across the store's subject
/// directories (ids embed a subject-derived prefix hash, so
/// the scan is the honest route).
fn find_document_path(config: &Config, ingest_id: &str) -> Option<PathBuf> {
    let root = config.state_dir.join("video-ingests");
    let mut subject_dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    subject_dirs.sort();
    for dir in subject_dirs {
        let candidate = dir.join(format!("{ingest_id}.json"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Load one ingest with both integrity checks of §12: the
/// stored document digest must recompute, and the retained
/// media must still hash to the subject identity. Either
/// failure is `evidence_integrity_mismatch` — never a
/// quietly repaired read (obligation 14's tamper leg).
pub fn load_ingest(config: &Config, ingest_id: &str) -> Result<LoadedIngest, FathomError> {
    validate_ingest_id(ingest_id)?;
    let path = find_document_path(config, ingest_id).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("no retained ingest '{ingest_id}' in this host's store"),
        )
    })?;
    let bytes = std::fs::read(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot read the ingest document: {error}"),
        )
    })?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
        FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("the retained ingest document is not JSON: {error}"),
        )
    })?;
    let stored_digest = document
        .get("document_digest")
        .and_then(Value::as_str)
        .unwrap_or("");
    if proof::video_ingest_digest(&document) != stored_digest {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the retained ingest document no longer digests to its stored \
             document_digest; the store has been modified outside the tools",
        ));
    }
    let subject_sha256 = document
        .get("subject")
        .and_then(|subject| subject.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let media_path = document
        .get("subject")
        .and_then(|subject| subject.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (media_sha, _) =
        hash_file_with_bound(Path::new(&media_path), VIDEO_BYTES_MAX).map_err(|_| {
            FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                "the retained media for this ingest is missing or unreadable",
            )
        })?;
    if media_sha != subject_sha256 {
        return Err(FathomError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            "the retained media no longer hashes to the ingest's subject identity",
        ));
    }
    let payload = payload_dir(config, &subject_sha256, ingest_id);
    Ok(LoadedIngest {
        document,
        document_path: path,
        payload_dir: payload,
        subject_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_utc_format_matches_known_epochs() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_767_225_600), "2026-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn validation_gaps_cover_uncovered_windows_only() {
        let spans = vec![json!({"start_ms": 0, "end_ms": 10_000, "span_key": "sp_0001"})];
        let gaps = derive_gaps(&spans, &[], 100_000);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["start_ms"], 10_000);
        assert_eq!(gaps[0]["end_ms"], 100_000);
        // A short tail is not a gap.
        assert!(derive_gaps(&spans, &[], 25_000).is_empty());
    }

    #[test]
    fn validation_events_require_a_scene_frame_in_the_cluster() {
        let spans = vec![
            json!({"start_ms": 0, "end_ms": 2_000, "span_key": "sp_0001"}),
            json!({"start_ms": 2_500, "end_ms": 4_000, "span_key": "sp_0002"}),
            json!({"start_ms": 40_000, "end_ms": 42_000, "span_key": "sp_0003"}),
        ];
        let frames = vec![
            json!({"frame_key": "f_0001", "source": "scene", "timestamp_ms": 3_000}),
            json!({"frame_key": "f_0002", "source": "grid", "timestamp_ms": 41_000}),
        ];
        let events = derive_events(&spans, &frames, 2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["rule"], "span_cluster_frame_change");
        assert_eq!(events[0]["span_keys"], json!(["sp_0001", "sp_0002"]));
    }

    #[test]
    fn adversarial_ingest_id_shape_is_validated() {
        assert!(validate_ingest_id("vi_0123456789abcdef").is_ok());
        assert!(validate_ingest_id("../escape").is_err());
        assert!(validate_ingest_id("").is_err());
        assert!(validate_ingest_id(&"x".repeat(65)).is_err());
    }
}
