//! Cross-engine audio census (R7).
//!
//! Walks a game tree (or censuses a single file) and
//! reads audio headers only — codec, channels, sample
//! rate, and duration where the header honestly gives
//! them. Nothing is decoded and nothing is played; the
//! estate's audio-silence rule is structural here, not
//! a setting.
//!
//! Formats read from their headers: WAV (RIFF fmt),
//! Ogg (Vorbis identification header; OpusHead), MP3
//! (first frame header, Xing frame count when present,
//! else a bitrate estimate explicitly labelled as
//! such), M4A (mvhd timescale/duration + stsd codec and
//! channels), and FLAC (STREAMINFO). Voice / SFX /
//! music categorisation follows the game's own path
//! vocabulary (voice/vo/dialogue, bgm/music/ost,
//! se/sfx/sound) and is labelled as path-derived.
//!
//! Corpus reality for the containerised formats the
//! rung names — CRI ACB/AWB, FSB, Wwise .bnk/.wem, HCA:
//! none exist anywhere in the moved corpus or in any
//! extracted output this programme produced. They are
//! recorded as a named gap in the programme report
//! rather than parsed speculatively without ground
//! truth. Unity AudioClip payloads inside Serialized
//! Files are likewise out of this reader (payload
//! extraction is the Unity rung's scope).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, AUDIO_FILES_MAX, AUDIO_HEAD_BYTES_MAX, GAME_WALK_DEPTH_MAX,
    GAME_WALK_FILES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

const AUDIO_EXTENSIONS: [&str; 7] = ["flac", "m4a", "mp3", "oga", "ogg", "opus", "wav"];

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

/// Header facts for one audio file; every field the
/// format does not honestly give stays None.
#[derive(Default)]
struct AudioFacts {
    /// Duration in seconds (see `duration_basis`).
    duration_seconds: Option<f64>,
    /// How the duration was derived: "header",
    /// "xing_frames", "granule_position", or
    /// "cbr_estimate".
    duration_basis: Option<&'static str>,
    /// Channels where the header states them.
    channels: Option<u32>,
    /// Codec label ("vorbis", "opus", "mp3", "pcm",
    /// "flac", "mp4a", ...).
    codec: Option<String>,
    /// Sample rate in Hz where the header states it.
    sample_rate: Option<u32>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u32_be_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Read up to `count` bytes from the file's head.
fn read_head(file: &mut File, count: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| mismatch(format!("cannot seek audio file: {error}")))?;
    let mut buffer = vec![0u8; count as usize];
    let mut filled = 0usize;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => {
                return Err(mismatch(format!("cannot read audio file: {error}")));
            }
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Read `count` bytes from the file's tail.
fn read_tail(file: &mut File, file_len: u64, count: u64) -> Result<Vec<u8>> {
    let take = count.min(file_len);
    file.seek(SeekFrom::Start(file_len - take))
        .map_err(|error| mismatch(format!("cannot seek audio tail: {error}")))?;
    let mut buffer = vec![0u8; take as usize];
    file.read_exact(&mut buffer)
        .map_err(|error| mismatch(format!("cannot read audio tail: {error}")))?;
    Ok(buffer)
}

/// WAV facts from the RIFF chunk walk.
fn wav_facts(head: &[u8], file_len: u64) -> AudioFacts {
    let mut facts = AudioFacts::default();
    let mut pos = 12usize;
    let mut byte_rate: Option<u32> = None;
    let mut data_bytes: Option<u64> = None;
    while let (Some(kind), Some(size)) = (
        head.get(pos..pos + 4),
        u32_at(head, pos + 4).map(|value| value as usize),
    ) {
        match kind {
            b"fmt " => {
                let format = u16_at(head, pos + 8).unwrap_or(0);
                facts.codec = Some(match format {
                    1 => "pcm".to_string(),
                    3 => "ieee_float".to_string(),
                    6 => "a_law".to_string(),
                    7 => "mu_law".to_string(),
                    other => format!("riff_tag_{other}"),
                });
                facts.channels = u16_at(head, pos + 10).map(u32::from);
                facts.sample_rate = u32_at(head, pos + 12);
                byte_rate = u32_at(head, pos + 16);
            }
            b"data" => {
                data_bytes = Some(size as u64);
            }
            _ => {}
        }
        // Chunks are word-aligned.
        pos += 8 + size + (size & 1);
        if pos >= head.len() {
            break;
        }
    }
    let _ = file_len;
    if let (Some(data), Some(rate)) = (data_bytes, byte_rate)
        && rate > 0
    {
        facts.duration_seconds = Some(round3(data as f64 / rate as f64));
        facts.duration_basis = Some("header");
    }
    facts
}

/// The last Ogg page granule in `tail` (scanning from
/// the end), used for stream duration.
fn last_granule(tail: &[u8]) -> Option<u64> {
    let mut at = tail.len().checked_sub(4)?;
    loop {
        if &tail[at..at + 4] == b"OggS" {
            return u64_at(tail, at + 6);
        }
        if at == 0 {
            return None;
        }
        at -= 1;
    }
}

/// Ogg facts (Vorbis / Opus) from the first page plus
/// the tail granule for duration.
fn ogg_facts(head: &[u8], tail: &[u8]) -> AudioFacts {
    let mut facts = AudioFacts::default();
    let Some(segments) = head.get(26).copied() else {
        return facts;
    };
    let table_at = 27usize;
    let Some(table) = head.get(table_at..table_at + segments as usize) else {
        return facts;
    };
    let packet_len: usize = table.iter().map(|byte| *byte as usize).sum();
    let packet_at = table_at + segments as usize;
    let Some(packet) = head.get(packet_at..packet_at + packet_len.min(64)) else {
        return facts;
    };
    let granule = last_granule(tail);
    if packet.starts_with(b"\x01vorbis") {
        facts.codec = Some("vorbis".to_string());
        facts.channels = packet.get(11).map(|byte| u32::from(*byte));
        facts.sample_rate = u32_at(packet, 12);
        if let (Some(granule), Some(rate)) = (granule, facts.sample_rate)
            && rate > 0
        {
            facts.duration_seconds = Some(round3(granule as f64 / rate as f64));
            facts.duration_basis = Some("granule_position");
        }
    } else if packet.starts_with(b"OpusHead") {
        facts.codec = Some("opus".to_string());
        facts.channels = packet.get(9).map(|byte| u32::from(*byte));
        let pre_skip = u16_at(packet, 10).map(u32::from).unwrap_or(0);
        // Opus granules count at 48 kHz by definition.
        facts.sample_rate = Some(48_000);
        if let Some(granule) = granule {
            let playable = granule.saturating_sub(pre_skip as u64);
            facts.duration_seconds = Some(round3(playable as f64 / 48_000.0));
            facts.duration_basis = Some("granule_position");
        }
    }
    facts
}

/// MPEG audio frame facts: first header + Xing count
/// when present, else a labelled bitrate estimate.
fn mp3_facts(head: &[u8], file_len: u64) -> AudioFacts {
    let mut facts = AudioFacts::default();
    let mut at = 0usize;
    // Skip an ID3v2 tag (syncsafe size).
    if head.starts_with(b"ID3") && head.len() >= 10 {
        let size = head[6..10]
            .iter()
            .fold(0usize, |acc, byte| (acc << 7) | (*byte & 0x7F) as usize);
        at = 10 + size;
    }
    // Find the first frame sync within the head.
    let mut frame: Option<usize> = None;
    let mut scan = at;
    while scan + 4 <= head.len() {
        if head[scan] == 0xFF && head[scan + 1] & 0xE0 == 0xE0 {
            frame = Some(scan);
            break;
        }
        scan += 1;
    }
    let Some(frame) = frame else {
        return facts;
    };
    let b1 = head[frame + 1];
    let b2 = head[frame + 2];
    let version = match (b1 >> 3) & 0x03 {
        3 => 1,
        2 => 2,
        0 => 25,
        _ => return facts,
    };
    let layer = match (b1 >> 1) & 0x03 {
        3 => 1,
        2 => 2,
        1 => 3,
        _ => return facts,
    };
    let bitrate_index = (b2 >> 4) & 0x0F;
    let rate_index = (b2 >> 2) & 0x03;
    if bitrate_index == 0 || bitrate_index == 15 || rate_index == 3 {
        return facts;
    }
    let bitrate = mp3_bitrate_kbps(version, layer, bitrate_index);
    let rate_base: u32 = match rate_index {
        0 => 44_100,
        1 => 48_000,
        _ => 32_000,
    };
    let sample_rate = match version {
        1 => rate_base,
        2 => rate_base / 2,
        _ => rate_base / 4,
    };
    let channel_mode = (head[frame + 3] >> 6) & 0x03;
    facts.codec = Some("mp3".to_string());
    facts.channels = Some(if channel_mode == 3 { 1 } else { 2 });
    facts.sample_rate = Some(sample_rate);
    if let Some(bitrate) = bitrate {
        // Xing/Info sits after the side information:
        // v1 32 (stereo) / 17 (mono); v2 17 / 9.
        let side = match (version, channel_mode == 3) {
            (1, false) => 32,
            (1, true) => 17,
            (_, false) => 17,
            (_, true) => 9,
        };
        let xing_at = frame + 4 + side;
        let frames = if head
            .get(xing_at..xing_at + 4)
            .is_some_and(|magic| magic == b"Xing" || magic == b"Info")
        {
            let flags = u32_be_at(head, xing_at + 4).unwrap_or(0);
            if flags & 0x01 != 0 {
                u32_be_at(head, xing_at + 8)
            } else {
                None
            }
        } else {
            None
        };
        let samples_per_frame: u64 = match (layer, version) {
            (1, _) => 384,
            (2, _) => 1_152,
            (_, 1) => 1_152,
            _ => 576,
        };
        if let Some(frames) = frames {
            facts.duration_seconds = Some(round3(
                frames as f64 * samples_per_frame as f64 / sample_rate as f64,
            ));
            facts.duration_basis = Some("xing_frames");
        } else {
            let audio_bytes = file_len.saturating_sub(frame as u64);
            facts.duration_seconds = Some(round3(
                audio_bytes as f64 * 8.0 / (bitrate as f64 * 1_000.0),
            ));
            facts.duration_basis = Some("cbr_estimate");
        }
    }
    facts
}

/// Bitrate in kbps for a version/layer/index triple
/// (index 1..=14), per the MPEG tables.
fn mp3_bitrate_kbps(version: u8, layer: u8, index: u8) -> Option<u32> {
    const V1_L1: [u32; 14] = [
        32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
    ];
    const V1_L2: [u32; 14] = [
        32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
    ];
    const V1_L3: [u32; 14] = [
        32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ];
    const V2_L1: [u32; 14] = [
        32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
    ];
    const V2_LX: [u32; 14] = [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    let table = match (version, layer) {
        (1, 1) => &V1_L1,
        (1, 2) => &V1_L2,
        (1, 3) => &V1_L3,
        (_, 1) => &V2_L1,
        _ => &V2_LX,
    };
    table.get((index - 1) as usize).copied()
}

/// M4A facts: mvhd timescale/duration for duration;
/// stsd first entry for codec + channels.
fn m4a_facts(head: &[u8]) -> AudioFacts {
    let mut facts = AudioFacts::default();
    // mvhd: after "mvhd" + version byte: v0 carries
    // timescale at +12 and duration at +16 (from the
    // version field).
    if let Some(at) = find_subslice(head, b"mvhd") {
        let version = head.get(at + 4).copied().unwrap_or(0);
        if version == 0 {
            let timescale = u32_be_at(head, at + 16);
            let duration = u32_be_at(head, at + 20);
            if let (Some(scale), Some(units)) = (timescale, duration)
                && scale > 0
            {
                facts.duration_seconds = Some(round3(units as f64 / scale as f64));
                facts.duration_basis = Some("header");
            }
        }
    }
    if let Some(at) = find_subslice(head, b"stsd") {
        // stsd: version/flags (4), entry count (4), then
        // the first entry: size (4), format (4), reserved
        // (6), ref idx (2), version (2), revision (2),
        // vendor (4), channels (2).
        let entry = at + 4 + 8;
        if let Some(format) = head.get(entry + 4..entry + 8) {
            facts.codec = Some(
                std::str::from_utf8(format)
                    .unwrap_or("mp4")
                    .trim()
                    .to_string(),
            );
            facts.channels = u16_at(head, entry + 24).map(u32::from);
        }
    }
    if facts.codec.is_none() {
        facts.codec = Some("mp4".to_string());
    }
    facts
}

/// FLAC facts from STREAMINFO (34 bytes at offset 42
/// in the canonical layout; searched, not assumed).
fn flac_facts(head: &[u8]) -> AudioFacts {
    let mut facts = AudioFacts::default();
    facts.codec = Some("flac".to_string());
    // The first metadata block follows "fLaC": block
    // header (4) then STREAMINFO. Sample rate is 20
    // bits at STREAMINFO+10, channels 3 bits, total
    // samples the low 36 bits ending at +17..21.
    let base = 8usize;
    if let (Some(rate_hi), Some(packed)) = (head.get(base + 10..base + 13), head.get(base + 13)) {
        let rate =
            ((rate_hi[0] as u32) << 12) | ((rate_hi[1] as u32) << 4) | (rate_hi[2] as u32 >> 4);
        facts.sample_rate = Some(rate);
        facts.channels = Some(((*packed >> 4) & 0x07) as u32 + 1);
        let total = head.get(base + 14..base + 18).map(|slice| {
            let low = ((packed & 0x0F) as u64) << 32;
            low | u32_be_at(slice, 0).unwrap_or(0) as u64
        });
        if let (Some(total), Some(rate)) = (total, facts.sample_rate)
            && rate > 0
            && total > 0
        {
            facts.duration_seconds = Some(round3(total as f64 / rate as f64));
            facts.duration_basis = Some("header");
        }
    }
    facts
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Path-derived category: the game's own vocabulary.
fn category_for_path(relative: &Path) -> &'static str {
    let text = relative.to_string_lossy().to_lowercase();
    let segments: Vec<&str> = text.split('/').collect();
    let has = |words: &[&str]| {
        segments
            .iter()
            .any(|segment| words.iter().any(|word| segment == word))
    };
    if has(&["voice", "vo", "voices", "dialogue", "dlg"]) {
        "voice"
    } else if has(&["bgm", "me", "music", "ost", "musics"]) {
        "music"
    } else if has(&["se", "sfx", "sound", "sounds", "audio"]) {
        "sfx"
    } else {
        "unknown"
    }
}

/// Census one audio file into a manifest row.
fn census_file(path: &Path, relative: &Path) -> Result<Value> {
    let mut file =
        File::open(path).map_err(|error| mismatch(format!("cannot open audio file: {error}")))?;
    let file_len = file
        .metadata()
        .map_err(|error| mismatch(format!("cannot stat audio file: {error}")))?
        .len();
    let head = read_head(&mut file, AUDIO_HEAD_BYTES_MAX)?;
    let mut facts = if head.starts_with(b"RIFF") {
        wav_facts(&head, file_len)
    } else if head.starts_with(b"OggS") {
        let tail = read_tail(&mut file, file_len, 65_536)?;
        ogg_facts(&head, &tail)
    } else if head.starts_with(b"fLaC") {
        flac_facts(&head)
    } else if head.starts_with(b"\xFF") || head.starts_with(b"ID3") {
        mp3_facts(&head, file_len)
    } else if head.get(4..8).is_some_and(|kind| kind == b"ftyp") {
        m4a_facts(&head)
    } else {
        AudioFacts::default()
    };
    if facts.codec.is_none() && (head.starts_with(b"ID3") || head.first() == Some(&0xFF)) {
        facts = mp3_facts(&head, file_len);
    }
    Ok(json!({
        "bytes": file_len,
        "category": category_for_path(relative),
        "channels": facts.channels,
        "codec": facts.codec,
        "duration_basis": facts.duration_basis,
        "duration_seconds": facts.duration_seconds,
        "path": relative.display().to_string(),
        "sample_rate": facts.sample_rate,
    }))
}

pub fn census_audio_tree(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX).ok();
    let target_sha256 = subject.as_ref().map(|entry| entry.sha256.clone());
    let mut evidence = Evidence::new("census_audio_tree", "audio");
    if let Some(subject) = subject {
        evidence.subject = Some(subject);
    }
    // Collect candidate files: the target itself when it
    // is a file, else a bounded sorted walk.
    let mut files: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    if path.is_file() {
        files.push((path.clone(), path.file_name().unwrap_or_default().into()));
    } else {
        let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(path.clone(), 0)];
        let mut seen = 0usize;
        while let Some((dir, depth)) = stack.pop() {
            if depth > GAME_WALK_DEPTH_MAX {
                continue;
            }
            let mut entries: Vec<_> = std::fs::read_dir(&dir)
                .map_err(|error| mismatch(format!("cannot walk audio tree: {error}")))?
                .filter_map(|entry| entry.ok())
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let entry_path = entry.path();
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_dir() {
                    stack.push((entry_path, depth + 1));
                } else if kind.is_file() {
                    seen += 1;
                    if seen > GAME_WALK_FILES_MAX {
                        return Err(mismatch("audio tree exceeds the walk file bound".into()));
                    }
                    let extension = entry_path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if AUDIO_EXTENSIONS.contains(&extension.as_str()) {
                        let relative = entry_path
                            .strip_prefix(&path)
                            .unwrap_or(&entry_path)
                            .to_path_buf();
                        files.push((entry_path, relative));
                    }
                }
            }
        }
    }
    if files.len() > AUDIO_FILES_MAX {
        return Err(mismatch("audio census file count exceeds the bound".into()));
    }
    files.sort();
    let mut rows: Vec<Value> = Vec::new();
    let mut by_codec: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut by_category: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut duration_total = 0.0f64;
    for (file_path, relative) in &files {
        let mut row = census_file(file_path, relative)?;
        row["sha256"] = json!(stream_sha256(file_path)?);
        let codec = row["codec"].as_str().unwrap_or("unknown").to_string();
        *by_codec.entry(codec).or_insert(0) += 1;
        let category = row["category"].as_str().unwrap_or("unknown").to_string();
        *by_category.entry(category).or_insert(0) += 1;
        if let Some(duration) = row["duration_seconds"].as_f64() {
            duration_total += duration;
        }
        rows.push(row);
    }
    let document = json!({"entries": rows});
    let (digest, retention_note) = match &target_sha256 {
        Some(sha) => match proof::retain_export(config, sha, "audio_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        },
        None => (None, None),
    };
    evidence.add_finding(Finding::new(
        "audio_census",
        Confidence::Observed,
        json!({
            "by_category": by_category,
            "by_codec": by_codec,
            "export_digest": digest,
            "files": rows.len(),
            "format": "audio header census (headers only; nothing decoded or played)",
            "target_sha256": target_sha256,
            "total_duration_seconds": round3(duration_total),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows.len(), "total": rows.len()}),
    ));
    if target_sha256.is_none() {
        evidence.add_unknown(
            "retention",
            "directory targets carry no single subject hash; the census document is listed but not proof-retained",
        );
    }
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

fn stream_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file =
        File::open(path).map_err(|error| mismatch(format!("cannot open audio file: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| mismatch(format!("cannot read audio file: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wav_bytes(channels: u16, rate: u32, data_len: usize) -> Vec<u8> {
        let byte_rate = rate * channels as u32 * 2;
        let mut out = Vec::new();
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&channels.to_le_bytes());
        out.extend_from_slice(&rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&(channels * 2).to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&(data_len as u32).to_le_bytes());
        out.extend(vec![0u8; data_len]);
        out
    }

    #[test]
    fn validation_wav_header_facts() {
        let bytes = wav_bytes(2, 44_100, 88_200); // 0.5 s of stereo 16-bit
        let facts = wav_facts(&bytes, bytes.len() as u64);
        assert_eq!(facts.codec.as_deref(), Some("pcm"));
        assert_eq!(facts.channels, Some(2));
        assert_eq!(facts.sample_rate, Some(44_100));
        assert_eq!(facts.duration_seconds, Some(0.5));
        assert_eq!(facts.duration_basis, Some("header"));
    }

    #[test]
    fn validation_mp3_bitrate_tables() {
        assert_eq!(mp3_bitrate_kbps(1, 3, 9), Some(128));
        assert_eq!(mp3_bitrate_kbps(1, 1, 1), Some(32));
        assert_eq!(mp3_bitrate_kbps(2, 3, 8), Some(64));
        assert_eq!(mp3_bitrate_kbps(25, 2, 14), Some(160));
    }

    #[test]
    fn validation_category_vocabulary() {
        assert_eq!(category_for_path(Path::new("audio/bgm/title.ogg")), "music");
        assert_eq!(
            category_for_path(Path::new("game/voice/hero/01.ogg")),
            "voice"
        );
        assert_eq!(category_for_path(Path::new("audio/se/battle.wav")), "sfx");
        assert_eq!(category_for_path(Path::new("data/track.mp3")), "unknown");
    }

    #[test]
    fn adversarial_truncated_wav_yields_partial_facts() {
        let bytes = wav_bytes(1, 22_050, 100);
        let facts = wav_facts(&bytes[..20], 100);
        // fmt chunk starts at 12, needs 24 bytes: codec
        // cannot be read from 20 bytes of head.
        assert!(facts.codec.is_none() || facts.duration_seconds.is_none());
    }
}
