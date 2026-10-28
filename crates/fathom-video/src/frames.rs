//! Frame sampling (§4.5): two deterministic legs over one
//! media file — scene-change frames and a uniform grid —
//! collapsed, capped, and extracted as PNGs whose hashes are
//! the frame records' identity. The ffmpeg build is part of
//! the sampler's identity and rides the producer block.
//!
//! Determinism note: for fixed media, fixed parameters, and
//! a fixed ffmpeg build, scene detection and grid placement
//! are pure functions of the input (obligation 4). Seeking
//! uses `-ss` before `-i`: ffmpeg seeks to the nearest
//! keyframe and decodes forward, discarding until the exact
//! timestamp — accurate and fast, unlike a post-input seek,
//! which decodes from the start for every frame.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::evidence::sha256_hex;
use fathom_core::limits::{
    OUTPUT_BYTES_MAX, PROCESS_TIMEOUT_SECS, VIDEO_FRAME_BYTES_MAX, VIDEO_FRAME_GRID_SECS,
    VIDEO_FRAMES_MAX,
};

use crate::fetch::process_run_with;

/// The scene-change threshold (§4.5): fixed for the lane,
/// stated as a limitation on the sampling finding.
pub const SCENE_THRESHOLD: &str = "0.4";

/// The frame leg's yield: retained records (as JSON, in
/// timestamp order), the pre-cap candidate total, and the
/// leg's own unknowns — a degraded leg reports here and the
/// ingest proceeds partial (§4.7).
pub struct FrameOutcome {
    pub records: Vec<Value>,
    pub total: usize,
    pub truncated: bool,
    pub unknowns: Vec<(String, String)>,
}

/// The sampler's version line, for the producer block.
pub fn sampler_version(config: &Config, scratch: &Path) -> Option<String> {
    let outcome = process_run_with(
        config.video.sampler_program.as_os_str(),
        &["-version".to_string()],
        scratch,
        Duration::from_secs(PROCESS_TIMEOUT_SECS),
        OUTPUT_BYTES_MAX,
    )
    .ok()?;
    let text = String::from_utf8_lossy(&outcome.stdout);
    text.lines().next().map(|line| line.trim().to_string())
}

/// Enumerate scene-change timestamps via the showinfo
/// filter's stderr. Returns the timestamps and whether the
/// capture truncated (in which case enumeration may be
/// incomplete — stated, never hidden).
pub fn scene_times_ms(
    config: &Config,
    media: &Path,
    scratch: &Path,
) -> Result<(Vec<u64>, bool), String> {
    let args: Vec<String> = vec![
        "-hide_banner".to_string(),
        "-i".to_string(),
        media.to_string_lossy().into_owned(),
        "-vf".to_string(),
        format!("select='gt(scene,{SCENE_THRESHOLD})',showinfo"),
        "-an".to_string(),
        "-f".to_string(),
        "null".to_string(),
        "-".to_string(),
    ];
    let outcome = process_run_with(
        config.video.sampler_program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(fathom_core::limits::VIDEO_FETCH_TIMEOUT_SECS),
        OUTPUT_BYTES_MAX,
    )
    .map_err(|error| format!("the scene leg could not start: {}", error.message))?;
    if outcome.timed_out {
        return Err("the scene leg timed out".to_string());
    }
    if outcome.exit_code != Some(0) {
        return Err(format!(
            "the scene leg failed: {}",
            String::from_utf8_lossy(&outcome.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    let mut times: Vec<u64> = Vec::new();
    for line in stderr.lines() {
        if let Some(marker) = line.find("pts_time:")
            && let Some(token) = line[marker + "pts_time:".len()..].split_whitespace().next()
            && let Ok(secs) = token.parse::<f64>()
        {
            times.push((secs * 1000.0).round() as u64);
        }
    }
    times.sort_unstable();
    times.dedup();
    Ok((times, outcome.stderr_truncated))
}

/// The grid interval for one duration: the §11 floor, raised
/// so the grid leg alone fits three quarters of the frame
/// budget.
pub fn grid_interval_secs(duration_secs: f64) -> u64 {
    let budget = (VIDEO_FRAMES_MAX * 3 / 4) as f64;
    let needed = (duration_secs / budget).ceil() as u64;
    needed.max(VIDEO_FRAME_GRID_SECS)
}

/// Merge the two legs' candidates under the §4.5 rules:
/// sorted by timestamp (scene wins ties), a candidate closer
/// than the grid floor to the last kept one collapses into
/// it, and the result caps at `VIDEO_FRAMES_MAX` earliest.
pub fn merge_candidates(scene: &[u64], grid: &[u64]) -> (Vec<(u64, &'static str)>, usize, bool) {
    let mut all: Vec<(u64, &'static str)> = scene
        .iter()
        .map(|ts| (*ts, "scene"))
        .chain(grid.iter().map(|ts| (*ts, "grid")))
        .collect();
    // Stable sort: scene entries were pushed first, so a
    // scene/grid tie keeps the scene entry ahead.
    all.sort_by_key(|(ts, _)| *ts);
    let floor_ms = VIDEO_FRAME_GRID_SECS * 1000;
    let mut kept: Vec<(u64, &'static str)> = Vec::new();
    for candidate in all {
        match kept.last() {
            Some((last_ts, _)) if candidate.0 < last_ts + floor_ms => {}
            _ => kept.push(candidate),
        }
    }
    let total = kept.len();
    let truncated = total > VIDEO_FRAMES_MAX;
    if truncated {
        kept.truncate(VIDEO_FRAMES_MAX);
    }
    (kept, total, truncated)
}

/// PNG dimensions from the IHDR chunk (bytes 16..24,
/// big-endian); `None` for anything that is not a PNG.
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || &bytes[0..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    Some((width, height))
}

/// Extract one frame as a PNG into the scratch dir.
fn extract_frame(
    config: &Config,
    media: &Path,
    timestamp_ms: u64,
    scratch: &Path,
) -> Result<PathBuf, String> {
    let out = scratch.join(format!("frame-{timestamp_ms}.png"));
    let secs = format!("{}.{:03}", timestamp_ms / 1000, timestamp_ms % 1000);
    let args: Vec<String> = vec![
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "error".to_string(),
        "-ss".to_string(),
        secs,
        "-i".to_string(),
        media.to_string_lossy().into_owned(),
        "-frames:v".to_string(),
        "1".to_string(),
        out.to_string_lossy().into_owned(),
    ];
    let outcome = process_run_with(
        config.video.sampler_program.as_os_str(),
        &args,
        scratch,
        Duration::from_secs(PROCESS_TIMEOUT_SECS),
        OUTPUT_BYTES_MAX,
    )
    .map_err(|error| format!("frame extraction could not start: {}", error.message))?;
    if outcome.timed_out || outcome.exit_code != Some(0) || !out.exists() {
        return Err(format!(
            "frame extraction at {timestamp_ms} ms failed: {}",
            String::from_utf8_lossy(&outcome.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(out)
}

/// Run both legs and retain the frames under `frames_dir`.
/// Partial failure is data: an unknown and whatever records
/// the legs did produce.
pub fn sample_frames(
    config: &Config,
    media: &Path,
    duration_secs: f64,
    scratch: &Path,
    frames_dir: &Path,
) -> FrameOutcome {
    let mut unknowns: Vec<(String, String)> = Vec::new();
    let (scene, scene_truncated) = match scene_times_ms(config, media, scratch) {
        Ok(pair) => pair,
        Err(reason) => {
            unknowns.push(("frames_scene_leg".to_string(), reason));
            (Vec::new(), false)
        }
    };
    if scene_truncated {
        unknowns.push((
            "frames_scene_leg".to_string(),
            "scene enumeration output hit the capture cap; the scene leg may be incomplete"
                .to_string(),
        ));
    }
    let interval = grid_interval_secs(duration_secs);
    let duration_ms = (duration_secs * 1000.0).round() as u64;
    let mut grid: Vec<u64> = Vec::new();
    let mut t = 0_u64;
    while t < duration_ms {
        grid.push(t);
        t += interval * 1000;
    }
    let (candidates, total, truncated) = merge_candidates(&scene, &grid);
    if let Err(error) = std::fs::create_dir_all(frames_dir) {
        unknowns.push((
            "frames".to_string(),
            format!("cannot create the frames store dir: {error}"),
        ));
        return FrameOutcome {
            records: Vec::new(),
            total,
            truncated,
            unknowns,
        };
    }
    let mut records: Vec<Value> = Vec::with_capacity(candidates.len());
    for (index, (timestamp_ms, source)) in candidates.iter().enumerate() {
        let frame_key = format!("f_{:04}", index + 1);
        match extract_frame(config, media, *timestamp_ms, scratch) {
            Ok(png_path) => {
                let bytes = match std::fs::read(&png_path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        unknowns.push((
                            "frames".to_string(),
                            format!("cannot read the extracted frame {frame_key}: {error}"),
                        ));
                        continue;
                    }
                };
                if bytes.len() > VIDEO_FRAME_BYTES_MAX {
                    unknowns.push((
                        "frames".to_string(),
                        format!(
                            "frame {frame_key} exceeds VIDEO_FRAME_BYTES_MAX and was not retained"
                        ),
                    ));
                    continue;
                }
                let Some((width, height)) = png_dimensions(&bytes) else {
                    unknowns.push((
                        "frames".to_string(),
                        format!("frame {frame_key} is not a PNG and was not retained"),
                    ));
                    continue;
                };
                let stored = frames_dir.join(format!("{frame_key}.png"));
                if let Err(error) = std::fs::write(&stored, &bytes) {
                    unknowns.push((
                        "frames".to_string(),
                        format!("cannot store frame {frame_key}: {error}"),
                    ));
                    continue;
                }
                records.push(json!({
                    "bytes": bytes.len(),
                    "frame_key": frame_key,
                    "height": height,
                    "sha256": sha256_hex(&bytes),
                    "source": source,
                    "timestamp_ms": timestamp_ms,
                    "width": width,
                }));
            }
            Err(reason) => {
                unknowns.push(("frames".to_string(), reason));
            }
        }
    }
    FrameOutcome {
        records,
        total,
        truncated,
        unknowns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_grid_interval_respects_floor_and_budget() {
        assert_eq!(grid_interval_secs(254.0), VIDEO_FRAME_GRID_SECS);
        // 3600 s / 384 budget → ceil 9.375 → 10 s.
        assert_eq!(grid_interval_secs(3600.0), 10);
    }

    #[test]
    fn validation_merge_collapses_below_the_floor_and_scene_wins_ties() {
        let scene = vec![0_u64, 5_000, 5_500];
        let grid = vec![0_u64, 2_000, 4_000, 6_000];
        let (kept, total, truncated) = merge_candidates(&scene, &grid);
        assert!(!truncated);
        assert_eq!(total, 4);
        assert_eq!(
            kept,
            vec![
                (0, "scene"),
                (2_000, "grid"),
                (4_000, "grid"),
                (6_000, "grid")
            ]
        );
    }

    #[test]
    fn adversarial_merge_caps_at_the_frame_bound() {
        let grid: Vec<u64> = (0..1_000).map(|i| i * 2_000).collect();
        let (kept, total, truncated) = merge_candidates(&[], &grid);
        assert_eq!(total, 1_000);
        assert!(truncated);
        assert_eq!(kept.len(), VIDEO_FRAMES_MAX);
    }

    #[test]
    fn validation_png_dimensions_read_the_ihdr() {
        let mut bytes = vec![0_u8; 24];
        bytes[0..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        bytes[16..20].copy_from_slice(&1920_u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&1080_u32.to_be_bytes());
        assert_eq!(png_dimensions(&bytes), Some((1920, 1080)));
        assert_eq!(png_dimensions(b"not a png at all........"), None);
    }
}
