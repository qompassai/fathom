//! Clean-room observation of captured media.
//!
//! One capture in, one `media-observation/1` record out, with
//! four record classes: motion, character, object, and audio.
//! The observation is measurement and vocabulary — sampled
//! frame differences, tag-anchored expression timelines in the
//! estate face-state vocabulary, tag-derived object candidates,
//! and silent audio descriptors. What the lane cannot measure
//! (pixel-level face segmentation, body landmarks) is recorded
//! as an unknown with its reason, never inferred into a fact.
//!
//! Audio analysis is silent by construction: the media is
//! decoded to numbers by ffmpeg and never played. The
//! observation record is the only exit from the quarantine.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Completeness, Confidence, Coverage, Evidence, Finding, Subject};
use fathom_core::limits::OUTPUT_BYTES_MAX;
use fathom_core::registry::require_str;

use crate::capture::{load_capture, post_tags, record_digest, write_json_atomic};
use crate::document::utc_now;
use crate::fetch::process_run_with;

/// Analysis frame width in pixels (the motion grid).
pub const OBSERVE_FRAME_WIDTH: usize = 96;

/// Analysis frame height in pixels.
pub const OBSERVE_FRAME_HEIGHT: usize = 54;

/// Sampled frames analysed by one observation at most.
pub const OBSERVE_FRAMES_MAX: usize = 1_024;

/// Sample rate ceiling for motion sampling, frames per second.
pub const OBSERVE_SAMPLE_FPS_MAX: f64 = 12.0;

/// Peak windows retained in one motion grammar.
pub const OBSERVE_PEAK_WINDOWS_MAX: usize = 8;

/// Object candidates retained in one observation.
pub const OBSERVE_OBJECT_CANDIDATES_MAX: usize = 128;

/// Envelope bins retained in one audio record.
pub const OBSERVE_ENVELOPE_BINS_MAX: usize = 256;

/// Sample rate the audio leg decodes to, hertz.
pub const OBSERVE_AUDIO_SAMPLE_RATE_HZ: u32 = 8_000;

const SPECTRAL_BANDS_HZ: [u32; 12] = [
    50, 100, 150, 220, 330, 500, 750, 1000, 1500, 2200, 3000, 4000,
];

fn r4(value: f64) -> f64 {
    if value.is_finite() {
        (value * 10_000.0).round() / 10_000.0
    } else {
        0.0
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn percentile(values: &[f64], fraction: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// Pearson autocorrelation of a series at one lag; 0 when the
/// series is flat or too short to say anything.
pub fn autocorrelation(values: &[f64], lag: usize) -> f64 {
    if lag == 0 || values.len() <= lag + 2 {
        return 0.0;
    }
    let average = mean(values);
    let mut numerator = 0.0;
    let mut denominator = 0.0;
    for (index, value) in values.iter().enumerate() {
        let centred = value - average;
        denominator += centred * centred;
        if index + lag < values.len() {
            numerator += centred * (values[index + lag] - average);
        }
    }
    if denominator <= f64::EPSILON {
        0.0
    } else {
        numerator / denominator
    }
}

/// The strongest loop candidate in a series over a lag range.
pub fn best_loop(values: &[f64], min_lag: usize, max_lag: usize) -> Option<(usize, f64)> {
    let mut best: Option<(usize, f64)> = None;
    for lag in min_lag..=max_lag.min(values.len().saturating_sub(3)) {
        let score = autocorrelation(values, lag);
        if best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((lag, score));
        }
    }
    best
}

/// Goertzel power of one frequency band over PCM samples,
/// normalised by the squared sample count.
pub fn goertzel_power(samples: &[i16], sample_rate_hz: u32, frequency_hz: u32) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let count = samples.len() as f64;
    let omega = 2.0 * std::f64::consts::PI * f64::from(frequency_hz) / f64::from(sample_rate_hz);
    let coefficient = 2.0 * omega.cos();
    let mut s1 = 0.0;
    let mut s2 = 0.0;
    for sample in samples {
        let s0 = f64::from(*sample) / 32_768.0 + coefficient * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let power = s1 * s1 + s2 * s2 - coefficient * s1 * s2;
    (power / (count * count)).max(0.0)
}

struct Probe {
    audio_codec: Option<String>,
    duration_secs: f64,
    fps: Option<f64>,
    has_audio: bool,
    height: Option<u64>,
    native_frames: Option<u64>,
    video_codec: Option<String>,
    width: Option<u64>,
}

fn ffprobe_program(config: &Config) -> PathBuf {
    let sampler = config.video.sampler_program.as_path();
    if sampler.file_name().and_then(|name| name.to_str()) == Some("ffmpeg") {
        sampler.with_file_name("ffprobe")
    } else {
        PathBuf::from("ffprobe")
    }
}

fn parse_frame_rate(raw: Option<&str>) -> Option<f64> {
    let raw = raw?;
    if let Some((top, bottom)) = raw.split_once('/') {
        let top: f64 = top.parse().ok()?;
        let bottom: f64 = bottom.parse().ok()?;
        if bottom > 0.0 && top > 0.0 {
            return Some(top / bottom);
        }
        return None;
    }
    raw.parse::<f64>().ok().filter(|value| *value > 0.0)
}

fn probe_media(
    config: &Config,
    media: &Path,
    scratch: &Path,
) -> Result<(Probe, Value), FathomError> {
    let program = ffprobe_program(config);
    let args: Vec<String> = vec![
        "-v".to_string(),
        "error".to_string(),
        "-show_streams".to_string(),
        "-show_format".to_string(),
        "-of".to_string(),
        "json".to_string(),
        media.to_string_lossy().into_owned(),
    ];
    let outcome = process_run_with(
        program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(120),
        OUTPUT_BYTES_MAX,
    )?;
    if outcome.timed_out || outcome.exit_code != Some(0) {
        return Err(FathomError::new(
            ErrorCode::ProviderUnavailable,
            format!(
                "ffprobe could not read the captured media: {}",
                String::from_utf8_lossy(&outcome.stderr)
                    .chars()
                    .take(300)
                    .collect::<String>()
            ),
        ));
    }
    let document: Value = serde_json::from_slice(&outcome.stdout).map_err(|error| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("ffprobe returned unparseable JSON: {error}"),
        )
    })?;
    let streams = document
        .get("streams")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let video = streams
        .iter()
        .find(|stream| stream.get("codec_type").and_then(Value::as_str) == Some("video"));
    let audio = streams
        .iter()
        .find(|stream| stream.get("codec_type").and_then(Value::as_str) == Some("audio"));
    let duration = document
        .pointer("/format/duration")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<f64>().ok())
        .or_else(|| {
            video
                .and_then(|s| s.get("duration"))
                .and_then(Value::as_f64)
        })
        .unwrap_or(0.0);
    let fps = video.and_then(|stream| {
        parse_frame_rate(stream.get("avg_frame_rate").and_then(Value::as_str))
            .or_else(|| parse_frame_rate(stream.get("r_frame_rate").and_then(Value::as_str)))
    });
    let native_frames = video
        .and_then(|stream| stream.get("nb_frames"))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
        })
        .or_else(|| match (fps, duration) {
            (Some(rate), secs) if secs > 0.0 => Some((rate * secs).round() as u64),
            _ => None,
        });
    let probe = Probe {
        audio_codec: audio
            .and_then(|stream| stream.get("codec_name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        duration_secs: duration,
        fps,
        has_audio: audio.is_some(),
        height: video
            .and_then(|stream| stream.get("height"))
            .and_then(Value::as_u64),
        native_frames,
        video_codec: video
            .and_then(|stream| stream.get("codec_name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        width: video
            .and_then(|stream| stream.get("width"))
            .and_then(Value::as_u64),
    };
    Ok((probe, document))
}

struct FrameSample {
    fps: f64,
    frames: Vec<Vec<u8>>,
    truncated: bool,
}

fn sample_frames(
    config: &Config,
    media: &Path,
    duration_secs: f64,
    scratch: &Path,
) -> Result<FrameSample, FathomError> {
    let fps = if duration_secs > 0.0 {
        (OBSERVE_FRAMES_MAX as f64 / duration_secs).min(OBSERVE_SAMPLE_FPS_MAX)
    } else {
        1.0
    };
    let scale = format!(
        "scale={OBSERVE_FRAME_WIDTH}:{OBSERVE_FRAME_HEIGHT}:force_original_aspect_ratio=decrease,\
         pad={OBSERVE_FRAME_WIDTH}:{OBSERVE_FRAME_HEIGHT}:(ow-iw)/2:(oh-ih)/2,format=gray"
    );
    let filter = if duration_secs > 0.0 {
        format!("fps={fps:.6},{scale}")
    } else {
        scale
    };
    let mut args: Vec<String> = vec![
        "-v".to_string(),
        "error".to_string(),
        "-i".to_string(),
        media.to_string_lossy().into_owned(),
        "-vf".to_string(),
        filter,
        "-an".to_string(),
    ];
    if duration_secs <= 0.0 {
        args.push("-frames:v".to_string());
        args.push("1".to_string());
    }
    args.extend(["-f".to_string(), "rawvideo".to_string(), "-".to_string()]);
    let outcome = process_run_with(
        config.video.sampler_program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(600),
        OUTPUT_BYTES_MAX,
    )?;
    if outcome.timed_out || outcome.exit_code != Some(0) {
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "the frame sampling leg failed: {}",
                String::from_utf8_lossy(&outcome.stderr)
                    .chars()
                    .take(300)
                    .collect::<String>()
            ),
        ));
    }
    let frame_len = OBSERVE_FRAME_WIDTH * OBSERVE_FRAME_HEIGHT;
    let count = outcome.stdout.len() / frame_len;
    if count == 0 {
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            "the frame sampling leg produced no complete frames",
        ));
    }
    let frames: Vec<Vec<u8>> = outcome
        .stdout
        .chunks_exact(frame_len)
        .take(OBSERVE_FRAMES_MAX)
        .map(|chunk| chunk.to_vec())
        .collect();
    Ok(FrameSample {
        fps,
        truncated: outcome.stdout_truncated || outcome.stdout.len() % frame_len != 0,
        frames,
    })
}

/// Motion measurements over the sampled grayscale frames, plus
/// the peak windows the character timeline anchors to.
fn motion_record(sample: &FrameSample, duration_secs: f64) -> (Value, Vec<(f64, f64)>, Vec<Value>) {
    let frame_len = OBSERVE_FRAME_WIDTH * OBSERVE_FRAME_HEIGHT;
    let mut diffs: Vec<f64> = Vec::new();
    let mut centroids: Vec<(f64, f64)> = Vec::new();
    for pair in sample.frames.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        let mut total = 0.0;
        let mut weight = 0.0;
        let mut x_sum = 0.0;
        let mut y_sum = 0.0;
        for index in 0..frame_len {
            let delta = f64::from(after[index]) - f64::from(before[index]);
            let magnitude = delta.abs();
            total += magnitude;
            if magnitude >= 2.0 {
                let x = (index % OBSERVE_FRAME_WIDTH) as f64 / OBSERVE_FRAME_WIDTH as f64;
                let y = (index / OBSERVE_FRAME_WIDTH) as f64 / OBSERVE_FRAME_HEIGHT as f64;
                weight += magnitude;
                x_sum += magnitude * x;
                y_sum += magnitude * y;
            }
        }
        diffs.push(total / frame_len as f64);
        if weight > 0.0 {
            centroids.push((x_sum / weight, y_sum / weight));
        }
    }
    if diffs.is_empty() {
        return (
            json!({
                "camera": {"basis": "single frame", "class": "still"},
                "kind": "still",
                "sampled_frames": sample.frames.len(),
            }),
            Vec::new(),
            Vec::new(),
        );
    }
    let fps = sample.fps;
    let average = mean(&diffs);
    let variance = mean(
        &diffs
            .iter()
            .map(|value| (value - average).powi(2))
            .collect::<Vec<_>>(),
    );
    let std_dev = variance.sqrt();
    let (max_diff, max_index) =
        diffs
            .iter()
            .enumerate()
            .fold((0.0_f64, 0_usize), |(best, best_index), (index, value)| {
                if *value > best {
                    (*value, index)
                } else {
                    (best, best_index)
                }
            });
    let active_ratio =
        diffs.iter().filter(|value| **value >= 2.0).count() as f64 / diffs.len() as f64;
    // Peak windows: strongest differences first, separated by
    // at least half a second, capped.
    let separation = ((0.5 * fps).ceil() as usize).max(1);
    let mut by_strength: Vec<usize> = (0..diffs.len()).collect();
    by_strength.sort_by(|a, b| {
        diffs[*b]
            .partial_cmp(&diffs[*a])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut chosen: Vec<usize> = Vec::new();
    for index in by_strength {
        if chosen
            .iter()
            .all(|other| index.abs_diff(*other) >= separation)
        {
            chosen.push(index);
            if chosen.len() >= OBSERVE_PEAK_WINDOWS_MAX {
                break;
            }
        }
    }
    chosen.sort_unstable();
    let duration = if duration_secs > 0.0 {
        duration_secs
    } else {
        sample.frames.len() as f64 / fps
    };
    let mut peak_windows: Vec<Value> = Vec::new();
    let mut peak_ranges: Vec<(f64, f64)> = Vec::new();
    for index in &chosen {
        let centre = (*index + 1) as f64 / fps;
        let start = (centre - 0.25).max(0.0);
        let end = (centre + 0.25).min(duration);
        peak_ranges.push((start, end));
        let before_start = index.saturating_sub(separation);
        let preceding = mean(&diffs[before_start..*index]);
        let following_end = (*index + separation).min(diffs.len());
        let following = mean(&diffs[*index + 1..following_end.max(*index + 1)]);
        peak_windows.push(json!({
            "anticipation_ramp": diffs[*index] >= preceding * 1.5,
            "centre_s": r4(centre),
            "end_s": r4(end),
            "overshoot_decay": following <= diffs[*index] * 0.6,
            "peak_mean_abs_diff": r4(diffs[*index]),
            "start_s": r4(start),
        }));
    }
    // Scene cuts: differences past a dynamic threshold.
    let cut_threshold = (average + 2.5 * std_dev).max(24.0);
    let cuts: Vec<Value> = diffs
        .iter()
        .enumerate()
        .filter(|(_, value)| **value >= cut_threshold)
        .take(128)
        .map(|(index, value)| {
            json!({"at_s": r4((index + 1) as f64 / fps), "mean_abs_diff": r4(*value)})
        })
        .collect();
    // Holds: runs below the hold threshold lasting >= 0.25 s.
    let hold_frames_min = ((0.25 * fps).ceil() as usize).max(1);
    let mut holds: Vec<Value> = Vec::new();
    let mut run_start: Option<usize> = None;
    for index in 0..=diffs.len() {
        let holding = index < diffs.len() && diffs[index] < 1.0;
        match (holding, run_start) {
            (true, None) => run_start = Some(index),
            (false, Some(start)) => {
                if index - start >= hold_frames_min && holds.len() < 32 {
                    holds.push(json!({
                        "end_s": r4((index + 1) as f64 / fps),
                        "start_s": r4((start + 1) as f64 / fps),
                    }));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    let loop_candidate = if diffs.len() >= 12 {
        let min_lag = ((0.15 * fps).round() as usize).max(2);
        let max_lag = ((2.0 * fps).round() as usize).min(diffs.len() / 3);
        best_loop(&diffs, min_lag, max_lag)
            .filter(|(_, score)| *score >= 0.35)
            .map(|(lag, score)| {
                json!({
                    "correlation": r4(score),
                    "method": "autocorrelation of the frame-difference series",
                    "period_s": r4(lag as f64 / fps),
                })
            })
    } else {
        None
    };
    let centroid_mean = (
        mean(&centroids.iter().map(|point| point.0).collect::<Vec<_>>()),
        mean(&centroids.iter().map(|point| point.1).collect::<Vec<_>>()),
    );
    let centroid_spread = (
        mean(
            &centroids
                .iter()
                .map(|point| (point.0 - centroid_mean.0).powi(2))
                .collect::<Vec<_>>(),
        )
        .sqrt(),
        mean(
            &centroids
                .iter()
                .map(|point| (point.1 - centroid_mean.1).powi(2))
                .collect::<Vec<_>>(),
        )
        .sqrt(),
    );
    let drift = match (centroids.first(), centroids.last()) {
        (Some(first), Some(last)) if centroids.len() > 1 => {
            ((last.0 - first.0).powi(2) + (last.1 - first.1).powi(2)).sqrt()
        }
        _ => 0.0,
    };
    let camera_class = if centroid_spread.0 <= 0.18 && centroid_spread.1 <= 0.18 && drift <= 0.25 {
        "locked_camera_subject_motion"
    } else {
        "wide_or_moving_motion"
    };
    // The intensity curve: the frame-difference series
    // downsampled to at most 256 mean bins — the curve data the
    // pipes' motion emit consumes.
    let bin_group = diffs.len().div_ceil(256).max(1);
    let intensity_curve: Vec<Value> = diffs
        .chunks(bin_group)
        .enumerate()
        .map(|(index, chunk)| {
            json!({
                "mean_abs_diff": r4(mean(chunk)),
                "t_s": r4((index * bin_group + 1) as f64 / fps),
            })
        })
        .collect();
    let record = json!({
        "camera": {
            "basis": "sampled motion-centroid spread and first-to-last drift; \
                      no phase-correlation estimator in lane v1",
            "centroid_drift": r4(drift),
            "centroid_mean": [r4(centroid_mean.0), r4(centroid_mean.1)],
            "centroid_spread": [r4(centroid_spread.0), r4(centroid_spread.1)],
            "class": camera_class,
        },
        "intensity_curve": intensity_curve,
        "frame_diff": {
            "active_ratio_at_2": r4(active_ratio),
            "max": r4(max_diff),
            "max_at_s": r4((max_index + 1) as f64 / fps),
            "mean": r4(average),
            "median": r4(percentile(&diffs, 0.5)),
            "p95": r4(percentile(&diffs, 0.95)),
            "std_dev": r4(std_dev),
        },
        "kind": "video",
        "sample_fps": r4(fps),
        "sampled_frames": sample.frames.len(),
        "scene_cuts": cuts,
        "timing_grammar": {
            "holds": holds,
            "loop": loop_candidate,
            "peak_windows": peak_windows,
        },
    });
    (record, peak_ranges, peak_windows)
}

fn face_channels(state: &str) -> Value {
    match state {
        "F-05" => json!({
            "blush": "heavy",
            "brow": "raised_inner",
            "gaze": "rolled_up_pupils_visible",
            "lid_band": "wide_or_rolled",
            "mouth": "open_tongue_out",
            "name": "ahegao",
        }),
        "F-07" => json!({
            "blush": "heavy_two_layer",
            "brow": "slanted_down_outer",
            "gaze": "rolled_or_unfocused",
            "lid_band": "half_open_50_75",
            "mouth": "half_open_tongue_candidate",
            "name": "ahetoro",
        }),
        _ => json!({
            "blush": "heavy_two_layer",
            "brow": "slanted_down_outer_relaxed",
            "gaze": "unfocused_distance",
            "lid_band": "half_open_50_75",
            "mouth": "half_open_small",
            "name": "torogao",
        }),
    }
}

fn base_face_state(tags: &BTreeSet<String>) -> Option<&'static str> {
    if tags.contains("ahegao") {
        Some("F-05")
    } else if tags.contains("torogao") {
        Some("F-06")
    } else if tags.contains("rolling_eyes") && tags.contains("tongue_out") {
        Some("F-07")
    } else {
        None
    }
}

/// The character class: tag-anchored identity descriptors and
/// an expression timeline in the estate face-state vocabulary.
/// The timeline's basis is stated on the record: post tags set
/// the states, motion peaks set the blend windows. Pixel-level
/// face segmentation is an unknown, not a claim.
fn character_record(
    capture: &Value,
    tags: &BTreeSet<String>,
    peak_ranges: &[(f64, f64)],
    duration_secs: f64,
) -> (Value, Vec<Value>) {
    let mut unknowns: Vec<Value> = Vec::new();
    let split = |field: &str| -> Vec<String> {
        capture
            .pointer(&format!("/post/{field}"))
            .and_then(Value::as_str)
            .map(|text| text.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    };
    let base = base_face_state(tags);
    let mut timeline: Vec<Value> = Vec::new();
    if let Some(base_state) = base {
        let peak_state = match base_state {
            "F-06" => {
                if tags.contains("rolling_eyes") && tags.contains("tongue_out") {
                    "F-07"
                } else {
                    base_state
                }
            }
            "F-07" => "F-05",
            _ => base_state,
        };
        let duration = duration_secs.max(0.0);
        let mut cursor = 0.0;
        let mut windows: Vec<(f64, f64)> = peak_ranges.to_vec();
        windows.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        for (start, end) in &windows {
            if *start > cursor {
                timeline.push(json!({
                    "basis": "post_tags",
                    "channels": face_channels(base_state),
                    "confidence": "derived",
                    "end_s": r4(*start),
                    "start_s": r4(cursor),
                    "state": base_state,
                }));
            }
            timeline.push(json!({
                "basis": "post_tags+motion_peaks",
                "channels": face_channels(peak_state),
                "confidence": "derived",
                "end_s": r4(*end),
                "start_s": r4((*start).max(cursor)),
                "state": peak_state,
            }));
            cursor = cursor.max(*end);
        }
        if cursor < duration || timeline.is_empty() {
            timeline.push(json!({
                "basis": "post_tags",
                "channels": face_channels(base_state),
                "confidence": "derived",
                "end_s": r4(duration),
                "start_s": r4(cursor),
                "state": base_state,
            }));
        }
    } else {
        unknowns.push(json!({
            "aspect": "expression_timeline",
            "reason": "the post tags name no estate face state \
                       (torogao/ahegao axis); no state is inferred from pixels in lane v1",
        }));
    }
    unknowns.push(json!({
        "aspect": "face_landmarks_and_pose_estimation",
        "reason": "lane v1 carries no face-segmentation or body-landmark estimator; \
                   expression states are tag-anchored and proportions are media-level only",
    }));
    const POSE_TAGS: [&str; 14] = [
        "all_fours",
        "kneeling",
        "leg_up",
        "lying",
        "on_back",
        "on_side",
        "sitting",
        "spread_legs",
        "squatting",
        "standing",
        "straddling",
        "top-down_bottom-up",
        "walking",
        "wariza",
    ];
    let pose: Vec<&str> = POSE_TAGS
        .iter()
        .filter(|tag| tags.iter().any(|owned| owned.as_str() == **tag))
        .copied()
        .collect();
    let width = capture
        .pointer("/post/width")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let height = capture
        .pointer("/post/height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let record = json!({
        "artists": split("tag_string_artist"),
        "characters": split("tag_string_character"),
        "copyrights": split("tag_string_copyright"),
        "expression_timeline": timeline,
        "face_state_vocabulary": "estate face-state/1: F-05 ahegao, F-06 torogao, F-07 ahetoro",
        "pose_descriptors": pose,
        "proportions": {
            "aspect_ratio": if height > 0 { r4(width as f64 / height as f64) } else { 0.0 },
            "basis": "media dimensions only; no body-landmark estimator in lane v1",
            "height_px": height,
            "width_px": width,
        },
    });
    (record, unknowns)
}

fn object_category(tag: &str) -> Option<(&'static str, &'static str)> {
    const EXACT: [(&str, &str, &str); 18] = [
        ("bed", "furniture", "environment"),
        ("chair", "furniture", "environment"),
        ("collar", "restraint", "worn_or_applied"),
        ("gag", "restraint", "worn_or_applied"),
        ("glasses", "eyewear", "worn"),
        ("handcuffs", "restraint", "worn_or_applied"),
        ("leash", "restraint", "held_or_attached"),
        ("rope", "restraint", "worn_or_applied"),
        ("shibari", "restraint", "worn_or_applied"),
        ("sunglasses", "eyewear", "worn"),
        ("table", "furniture", "environment"),
        ("vibrator", "device", "held_or_contact"),
        ("visor_cap", "headwear", "worn"),
        ("wand", "handheld", "held"),
        ("whip", "handheld", "held"),
        ("wine_glass", "tableware", "held"),
        ("book", "handheld", "held"),
        ("umbrella", "handheld", "held"),
    ];
    for (name, category, role) in EXACT {
        if tag == name {
            return Some((category, role));
        }
    }
    const SUFFIXES: [(&str, &str, &str); 14] = [
        ("_cap", "headwear", "worn"),
        ("_collar", "restraint", "worn_or_applied"),
        ("_cuffs", "restraint", "worn_or_applied"),
        ("_dress", "garment", "worn"),
        ("_glasses", "eyewear", "worn"),
        ("_gloves", "garment", "worn"),
        ("_hat", "headwear", "worn"),
        ("_leash", "restraint", "held_or_attached"),
        ("_rope", "restraint", "worn_or_applied"),
        ("_shoes", "garment", "worn"),
        ("_swimsuit", "garment", "worn"),
        ("_uniform", "garment", "worn"),
        ("_boots", "garment", "worn"),
        ("_ribbon", "accessory", "worn"),
    ];
    for (suffix, category, role) in SUFFIXES {
        if tag.ends_with(suffix) {
            return Some((category, role));
        }
    }
    None
}

/// The object class: prop/object census as object-template
/// candidate descriptors, derived from the post's tag
/// vocabulary. Materials are recorded only when a tag names
/// one; everything else about an object stays unclaimed.
pub fn object_candidates(tags: &BTreeSet<String>) -> Vec<Value> {
    const MATERIALS: [&str; 6] = ["lace", "latex", "leather", "metal", "silk", "wooden"];
    let mut candidates: Vec<Value> = Vec::new();
    for tag in tags {
        let Some((category, role)) = object_category(tag) else {
            continue;
        };
        let materials: Vec<&str> = MATERIALS
            .iter()
            .filter(|material| tag.contains(*material))
            .copied()
            .collect();
        candidates.push(json!({
            "candidate_id": format!("obj_{}", &fathom_core::evidence::sha256_hex(tag.as_bytes())[..12]),
            "category": category,
            "interaction_role": role,
            "materials_named": materials,
            "record_format": "object-template/1-candidate",
            "source_tag": tag,
            "status": "candidate",
        }));
        if candidates.len() >= OBSERVE_OBJECT_CANDIDATES_MAX {
            break;
        }
    }
    candidates
}

fn audio_record(
    config: &Config,
    media: &Path,
    probe: &Probe,
    scratch: &Path,
) -> (Value, Vec<Value>) {
    let mut unknowns: Vec<Value> = Vec::new();
    if !probe.has_audio {
        return (
            json!({"analysis": "silent decode only; nothing played", "present": false}),
            unknowns,
        );
    }
    let args: Vec<String> = vec![
        "-v".to_string(),
        "error".to_string(),
        "-i".to_string(),
        media.to_string_lossy().into_owned(),
        "-vn".to_string(),
        "-ac".to_string(),
        "1".to_string(),
        "-ar".to_string(),
        OBSERVE_AUDIO_SAMPLE_RATE_HZ.to_string(),
        "-f".to_string(),
        "s16le".to_string(),
        "-".to_string(),
    ];
    let outcome = match process_run_with(
        config.video.sampler_program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(600),
        OUTPUT_BYTES_MAX,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            unknowns.push(json!({
                "aspect": "audio_decode",
                "reason": format!("the audio leg could not start: {}", error.message),
            }));
            return (json!({"present": true, "status": "unmeasured"}), unknowns);
        }
    };
    if outcome.timed_out || outcome.exit_code != Some(0) {
        unknowns.push(json!({
            "aspect": "audio_decode",
            "reason": "the audio decode leg failed or timed out",
        }));
        return (json!({"present": true, "status": "unmeasured"}), unknowns);
    }
    if outcome.stdout_truncated {
        unknowns.push(json!({
            "aspect": "audio_decode",
            "reason": "the decoded audio exceeded the output bound; \
                       descriptors cover the retained prefix only",
        }));
    }
    let samples: Vec<i16> = outcome
        .stdout
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| i16::from_le_bytes(*chunk))
        .collect();
    if samples.is_empty() {
        return (
            json!({"analysis": "silent decode only; nothing played", "present": true,
                   "status": "empty_decode"}),
            unknowns,
        );
    }
    // Envelope: 0.1 s RMS/peak bins, downsampled to the cap.
    let bin_len = (OBSERVE_AUDIO_SAMPLE_RATE_HZ / 10) as usize;
    let mut bins: Vec<(f64, f64)> = Vec::new();
    for chunk in samples.chunks(bin_len.max(1)) {
        let mut sum_sq = 0.0;
        let mut peak = 0.0_f64;
        for sample in chunk {
            let value = f64::from(*sample) / 32_768.0;
            sum_sq += value * value;
            peak = peak.max(value.abs());
        }
        bins.push(((sum_sq / chunk.len() as f64).sqrt(), peak));
    }
    let group = bins.len().div_ceil(OBSERVE_ENVELOPE_BINS_MAX).max(1);
    let bin_secs = bin_len as f64 / f64::from(OBSERVE_AUDIO_SAMPLE_RATE_HZ);
    let envelope: Vec<Value> = bins
        .chunks(group)
        .enumerate()
        .map(|(index, chunk)| {
            json!({
                "end_s": r4((index + chunk.len()) as f64 * group as f64 * bin_secs),
                "peak": r4(chunk.iter().map(|bin| bin.1).fold(0.0, f64::max)),
                "rms_mean": r4(mean(&chunk.iter().map(|bin| bin.0).collect::<Vec<_>>())),
                "start_s": r4(index as f64 * group as f64 * bin_secs),
            })
        })
        .collect();
    // Spectral: mean Goertzel power per band over 1 s segments.
    let segment_len = OBSERVE_AUDIO_SAMPLE_RATE_HZ as usize;
    let mut band_totals = [0.0_f64; SPECTRAL_BANDS_HZ.len()];
    let mut segments = 0_usize;
    for segment in samples.chunks(segment_len) {
        if segment.len() < segment_len / 2 {
            break;
        }
        segments += 1;
        for (index, band) in SPECTRAL_BANDS_HZ.iter().enumerate() {
            band_totals[index] += goertzel_power(segment, OBSERVE_AUDIO_SAMPLE_RATE_HZ, *band);
        }
    }
    let band_means: Vec<f64> = band_totals
        .iter()
        .map(|total| {
            if segments > 0 {
                total / segments as f64
            } else {
                0.0
            }
        })
        .collect();
    let total_power: f64 = band_means.iter().sum();
    let band_shares: Vec<f64> = band_means
        .iter()
        .map(|value| {
            if total_power > 0.0 {
                value / total_power
            } else {
                0.0
            }
        })
        .collect();
    let dominant_index = band_shares
        .iter()
        .enumerate()
        .fold(0_usize, |best, (index, value)| {
            if *value > band_shares[best] {
                index
            } else {
                best
            }
        });
    // Tempo: autocorrelation of the onset envelope.
    let onsets: Vec<f64> = bins
        .windows(2)
        .map(|pair| (pair[1].0 - pair[0].0).max(0.0))
        .collect();
    let tempo = if onsets.len() >= 30 {
        best_loop(&onsets, 3, 15).map(|(lag, score)| {
            json!({
                "bpm_candidate": r4(60.0 / (lag as f64 * bin_secs)),
                "correlation": r4(score),
                "method": "autocorrelation of the 0.1 s onset envelope, 40-200 BPM range",
                "period_s": r4(lag as f64 * bin_secs),
            })
        })
    } else {
        None
    };
    let record = json!({
        "analysis": "silent decode only; nothing played",
        "codec": probe.audio_codec,
        "duration_s": r4(samples.len() as f64 / f64::from(OBSERVE_AUDIO_SAMPLE_RATE_HZ)),
        "envelope": envelope,
        "envelope_bin_s": r4(bin_secs * group as f64),
        "present": true,
        "rms_mean": r4(mean(&bins.iter().map(|bin| bin.0).collect::<Vec<_>>())),
        "rms_peak": r4(bins.iter().map(|bin| bin.1).fold(0.0, f64::max)),
        "spectral": {
            "bands_hz": SPECTRAL_BANDS_HZ,
            "band_shares": band_shares.iter().map(|value| r4(*value)).collect::<Vec<_>>(),
            "dominant_band_hz": SPECTRAL_BANDS_HZ[dominant_index],
            "method": "Goertzel band power over 1 s segments at 8 kHz mono",
        },
        "tempo": tempo,
    });
    (record, unknowns)
}

/// `observe_captured_media`: run the four observation classes
/// over one verified capture and write the observation record
/// beside the capture record in the quarantine.
pub fn observe_captured_media(
    _registry: &fathom_core::registry::Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let capture_id = require_str(args, "capture_id")?;
    let loaded = load_capture(config, require_str(args, "quarantine_dir")?, capture_id)?;
    let scratch = loaded
        .quarantine
        .join("scratch")
        .join(format!("observe-{capture_id}-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|error| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create the observation scratch dir: {error}"),
        )
    })?;
    let result = observe_inner(config, &loaded, &scratch);
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn observe_inner(
    config: &Config,
    loaded: &crate::capture::LoadedCapture,
    scratch: &Path,
) -> Result<Value, FathomError> {
    let capture = &loaded.record;
    let (probe, _probe_document) = probe_media(config, &loaded.media_path, scratch)?;
    let sample = sample_frames(config, &loaded.media_path, probe.duration_secs, scratch)?;
    let (motion, peak_ranges, _peak_windows) = motion_record(&sample, probe.duration_secs);
    let tags = post_tags(&capture["post"]);
    let (character, mut unknowns) =
        character_record(capture, &tags, &peak_ranges, probe.duration_secs);
    let objects = object_candidates(&tags);
    let object_record = json!({
        "basis": "post tag vocabulary; materials only where a tag names one",
        "candidates": objects,
        "candidates_total": objects.len(),
    });
    let (audio, audio_unknowns) = audio_record(config, &loaded.media_path, &probe, scratch);
    unknowns.extend(audio_unknowns);
    if sample.truncated {
        unknowns.push(json!({
            "aspect": "frame_sampling",
            "reason": "the sampled frame stream exceeded the output bound; \
                       motion measurements cover the retained prefix",
        }));
    }
    let capture_id = capture["capture_id"].as_str().unwrap_or_default();
    let mut record = json!({
        "capture_id": capture_id,
        "classes": {
            "audio": audio,
            "character": character,
            "motion": motion,
            "object": object_record,
        },
        "content_label": capture["content_label"],
        "lane": capture["lane"],
        "media": {
            "audio_codec": probe.audio_codec,
            "duration_s": r4(probe.duration_secs),
            "fps": probe.fps.map(r4),
            "height": probe.height,
            "native_frames": probe.native_frames,
            "video_codec": probe.video_codec,
            "width": probe.width,
        },
        "observed_at": utc_now(),
        "origin": capture["origin"],
        "post_id": capture["origin"]["post_id"],
        "producer": {
            "fathom_version": fathom_core::VERSION,
            "probe_program": ffprobe_program(config).display().to_string(),
            "sampler_program": config.video.sampler_program.display().to_string(),
            "tool": "observe_captured_media",
        },
        "record_type": "media-observation/1",
        "screen": capture["screen"],
        "status": if unknowns.is_empty() { "complete" } else { "partial" },
        "subject": capture["subject"],
        "unknowns": unknowns,
        "version": 1,
    });
    let digest = record_digest(&record);
    record["record_digest"] = json!(digest);
    let record_path = loaded
        .quarantine
        .join("records")
        .join(format!("{capture_id}.observation.json"));
    write_json_atomic(&record_path, &record)?;

    let mut evidence = Evidence::new("observe_captured_media", "video");
    evidence.status = if record["status"] == "complete" {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    evidence = evidence.with_subject(Subject {
        path: loaded.media_path.display().to_string(),
        sha256: capture["subject"]["sha256"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        size_bytes: capture["subject"]["size_bytes"].as_u64().unwrap_or(0),
    });
    evidence.add_finding(Finding::new(
        "media_observation",
        Confidence::Derived,
        json!({
            "capture_id": capture_id,
            "capture_record_path": loaded.record_path.display().to_string(),
            "classes": ["motion", "character", "object", "audio"],
            "lane": record["lane"],
            "content_label": record["content_label"],
            "record_digest": digest,
            "record_path": record_path.display().to_string(),
            "status": record["status"],
        }),
    ));
    evidence.add_finding(Finding::new(
        "motion_summary",
        Confidence::Derived,
        json!({
            "camera_class": record["classes"]["motion"]["camera"]["class"],
            "loop": record["classes"]["motion"]["timing_grammar"]["loop"],
            "sampled_frames": sample.frames.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "object_summary",
        Confidence::Observed,
        json!({"candidates_total": record["classes"]["object"]["candidates_total"]}),
    ));
    evidence.add_finding(Finding::new(
        "audio_summary",
        Confidence::Derived,
        json!({
            "dominant_band_hz": record["classes"]["audio"]["spectral"]["dominant_band_hz"],
            "present": record["classes"]["audio"]["present"],
            "tempo": record["classes"]["audio"]["tempo"],
        }),
    ));
    for unknown in record["unknowns"].as_array().cloned().unwrap_or_default() {
        evidence.add_unknown(
            unknown["aspect"].as_str().unwrap_or_default().to_string(),
            unknown["reason"].as_str().unwrap_or_default().to_string(),
        );
    }
    evidence.coverage = Coverage {
        examined: sample.frames.len() as u64,
        exhaustive: !sample.truncated,
        total: probe.native_frames.unwrap_or(sample.frames.len() as u64),
    };
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_autocorrelation_finds_planted_loop() {
        let pattern: Vec<f64> = (0..120)
            .map(|index| if index % 3 == 0 { 10.0 } else { 1.0 })
            .collect();
        let (lag, score) = best_loop(&pattern, 2, 12).unwrap();
        assert_eq!(lag, 3);
        assert!(score > 0.9, "score {score}");
    }

    #[test]
    fn validation_goertzel_finds_planted_tone() {
        let sample_rate = 8_000_u32;
        let samples: Vec<i16> = (0..8_000)
            .map(|index| {
                let phase = 2.0 * std::f64::consts::PI * 500.0 * index as f64 / 8_000.0;
                (phase.sin() * 16_000.0) as i16
            })
            .collect();
        let at_tone = goertzel_power(&samples, sample_rate, 500);
        let off_tone = goertzel_power(&samples, sample_rate, 150);
        assert!(at_tone > off_tone * 10.0, "{at_tone} vs {off_tone}");
    }

    #[test]
    fn validation_object_candidates_from_tags() {
        let tags: BTreeSet<String> = ["visor_cap", "slingshot_swimsuit", "blush", "leash"]
            .iter()
            .map(|tag| tag.to_string())
            .collect();
        let candidates = object_candidates(&tags);
        assert_eq!(candidates.len(), 3);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate["record_format"] == "object-template/1-candidate")
        );
    }

    #[test]
    fn validation_face_state_axis() {
        let mut tags = BTreeSet::new();
        tags.insert("torogao".to_string());
        assert_eq!(base_face_state(&tags), Some("F-06"));
        tags.insert("ahegao".to_string());
        assert_eq!(base_face_state(&tags), Some("F-05"));
        let mut blend = BTreeSet::new();
        blend.insert("rolling_eyes".to_string());
        blend.insert("tongue_out".to_string());
        assert_eq!(base_face_state(&blend), Some("F-07"));
    }
}
