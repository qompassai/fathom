//! The local-ASR leg (§4.4 path 3): a provider behind the
//! same owned-child discipline as the fetcher, consuming the
//! §5-verdict engine (whisper.cpp, via the operator's
//! wrapper) under a fixed argv contract:
//! `<program> <model> <wav> <out_json>`, where out_json is
//! `{"segments": [{"start_ms", "end_ms", "text"}]}`.
//!
//! The engine is configuration, never a call argument — the
//! SPEC's §8 pattern. When no engine is configured, the leg
//! is simply unavailable and an ingest with no caption track
//! proceeds partial with the unknown stated (§4.4), never an
//! error and never a fabricated transcript.

use std::path::{Path, PathBuf};

use serde_json::Value;

use fathom_core::config::Config;

use crate::captions::RawSpan;
use crate::fetch::process_run;

/// Whether the operator configured a local-ASR engine.
pub fn configured(config: &Config) -> bool {
    config.video.asr_program.is_some()
}

/// Extract the mono 16 kHz WAV the ASR contract consumes.
/// Failures are leg errors (`Err(String)`) — the caller
/// degrades the ingest, never the run.
pub fn extract_audio(config: &Config, media: &Path, scratch: &Path) -> Result<PathBuf, String> {
    let wav = scratch.join("audio.wav");
    let args: Vec<String> = vec![
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "error".to_string(),
        "-y".to_string(),
        "-i".to_string(),
        media.to_string_lossy().into_owned(),
        "-vn".to_string(),
        "-ac".to_string(),
        "1".to_string(),
        "-ar".to_string(),
        "16000".to_string(),
        wav.to_string_lossy().into_owned(),
    ];
    let outcome = process_run(config.video.sampler_program.as_os_str(), &args, scratch)
        .map_err(|error| format!("audio extraction could not start: {}", error.message))?;
    if outcome.timed_out || outcome.exit_code != Some(0) || !wav.exists() {
        return Err(format!(
            "audio extraction failed: {}",
            String::from_utf8_lossy(&outcome.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    Ok(wav)
}

/// Transcribe one WAV through the configured engine. Spans
/// come back unkeyed; document assembly assigns keys and the
/// `local_asr` track kind, and the caller states the §4.4
/// standing limitation (machine transcript; wording may err)
/// on the track record.
pub fn transcribe(config: &Config, wav: &Path, scratch: &Path) -> Result<Vec<RawSpan>, String> {
    let program = config
        .video
        .asr_program
        .as_ref()
        .ok_or("no local ASR engine is configured".to_string())?;
    let model = config
        .video
        .asr_model
        .as_ref()
        .ok_or("an ASR program is configured without an ASR model".to_string())?;
    let out_json = scratch.join("asr-out.json");
    let args: Vec<String> = vec![
        model.to_string_lossy().into_owned(),
        wav.to_string_lossy().into_owned(),
        out_json.to_string_lossy().into_owned(),
    ];
    // The ASR child runs under the fetch timeout, not the
    // 60 s process default: transcribing an hour of audio is
    // a minutes-scale job on the estate's hardware, and the
    // SPEC's fetch bound is the honest ceiling for it.
    let outcome = crate::fetch::process_run_with(
        program.as_os_str(),
        &args,
        scratch,
        std::time::Duration::from_secs(fathom_core::limits::VIDEO_FETCH_TIMEOUT_SECS),
        fathom_core::limits::OUTPUT_BYTES_MAX,
    )
    .map_err(|error| format!("the ASR engine could not start: {}", error.message))?;
    if outcome.timed_out {
        return Err("the ASR engine timed out".to_string());
    }
    if outcome.exit_code != Some(0) {
        return Err(format!(
            "the ASR engine failed: {}",
            String::from_utf8_lossy(&outcome.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    let bytes = std::fs::read(&out_json)
        .map_err(|error| format!("the ASR engine produced no output document: {error}"))?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("the ASR engine's output is not JSON: {error}"))?;
    let segments = document
        .get("segments")
        .and_then(Value::as_array)
        .ok_or("the ASR engine's output carries no segments array")?;
    let mut spans = Vec::with_capacity(segments.len());
    for segment in segments {
        let text = segment
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if text.is_empty() {
            continue;
        }
        spans.push(RawSpan {
            end_ms: segment.get("end_ms").and_then(Value::as_u64).unwrap_or(0),
            start_ms: segment.get("start_ms").and_then(Value::as_u64).unwrap_or(0),
            text,
        });
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::VideoConfig;
    use std::os::unix::fs::PermissionsExt;

    fn temp_scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-video-asr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with_stub(stub: &Path) -> Config {
        let mut config = Config::restrictive_default();
        config.video = VideoConfig {
            asr_model: Some(PathBuf::from("model.bin")),
            asr_program: Some(stub.to_path_buf()),
            ..VideoConfig::default()
        };
        config
    }

    #[test]
    fn validation_stub_engine_segments_become_local_asr_spans() {
        let scratch = temp_scratch("segments");
        let stub = scratch.join("stub-asr.sh");
        std::fs::write(
            &stub,
            "#!/bin/sh\nprintf '%s' '{\"segments\":[{\"start_ms\":0,\"end_ms\":900,\"text\":\" hello \"},{\"start_ms\":1000,\"end_ms\":2000,\"text\":\"world\"}]}' > \"$3\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let wav = scratch.join("audio.wav");
        std::fs::write(&wav, b"RIFF").unwrap();
        let config = config_with_stub(&stub);
        let spans = transcribe(&config, &wav, &scratch).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].text, "hello");
        assert_eq!(spans[1].end_ms, 2000);
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn adversarial_unconfigured_engine_is_an_honest_leg_error() {
        let scratch = temp_scratch("unconfigured");
        let config = Config::restrictive_default();
        assert!(!configured(&config));
        let err = transcribe(&config, Path::new("x.wav"), &scratch).unwrap_err();
        assert!(err.contains("no local ASR engine"));
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
