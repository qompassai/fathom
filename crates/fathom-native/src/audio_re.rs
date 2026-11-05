//! Containerised-audio reverse engineering (D-989):
//! FMOD FSB5 banks (standalone or embedded as Unity
//! `.resource` files, which are one or more FSB5 banks
//! concatenated back to back), CRI Atom ACB cue sheets
//! with their embedded AFS2 wave archive, RPG Maker MV
//! encrypted audio, and measured analysis of single
//! audio files.
//!
//! Every parser here was built against corpus ground
//! truth, not speculation (the standard the R7 audio
//! census set when it recorded these formats as a named
//! gap): the FSB5 layout follows the published format
//! as implemented by vgmstream's `fsb5.c` and was
//! verified bank-by-bank against Hypno Rhythm's
//! `sharedassets0.resource` (12 concatenated banks, all
//! version 1, codec 15 Custom Vorbis, 44100 Hz, no loop
//! points); the CRI @UTF/AFS2 readers were verified
//! against Yuremizu's BGM.acb (3 HCA streams) and
//! SE.acb (28 HCA streams), including the CueName and
//! Waveform tables. Wwise `.bnk`/`.wem` remains a named
//! gap: the corpus holds no specimen, so no parser is
//! offered for it.
//!
//! Nothing is decoded by this module itself and nothing
//! is played: extraction writes the stored streams
//! verbatim (PCM streams additionally get a synthesised
//! WAV header, which is a rewrap, not a decode). When
//! the operator allowlists `vgmstream-cli`, extraction
//! additionally offers each carved bank to that external
//! decoder and records the outcome per stream.
//!
//! Facts are labelled: header/table facts are Observed,
//! durations and every `analyze_audio_file` measurement
//! are Derived with the method stated.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, sha256_hex, subject_for_file_with_bound,
};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, AUDIO_ANALYZE_BYTES_MAX, AUDIO_ANALYZE_SEGMENTS_MAX,
    AUDIO_SILENCE_RUNS_MAX, CRI_ACB_BYTES_MAX, CRI_AFS2_ENTRIES_MAX, CRI_UTF_COLUMNS_MAX,
    CRI_UTF_ROWS_MAX, CRI_UTF_SCHEMA_BYTES_MAX, CRI_UTF_STRINGS_BYTES_MAX, FSB5_BANKS_MAX,
    FSB5_NAME_BYTES_MAX, FSB5_SUBSOUNDS_MAX, GAME_EXTRACT_BYTES_MAX, MV_FILE_BYTES_MAX,
    MV_FILES_MAX, PROCESS_OUTPUT_BYTES_MAX, VGMSTREAM_TIMEOUT_SECS,
};
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run as run_process};
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

fn mismatch(message: String) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message)
}

fn unsupported(message: String) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message)
}

fn u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn u16_be(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

fn u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_be(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at + 8)?;
    Some(u64::from_be_bytes(slice.try_into().ok()?))
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

/// Read `count` bytes at `offset` from a seekable file.
fn read_at(file: &mut File, offset: u64, count: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| mismatch(format!("cannot seek target: {error}")))?;
    let mut buffer = vec![0u8; count];
    file.read_exact(&mut buffer)
        .map_err(|error| mismatch(format!("cannot read target: {error}")))?;
    Ok(buffer)
}

/// Write `bytes` to `destination` atomically; returns
/// the payload SHA-256 (the GameMaker lane's pattern).
fn write_atomic(destination: &Path, bytes: &[u8]) -> Result<String> {
    let temp = destination.with_extension("partial");
    {
        let mut file = File::create(&temp)
            .map_err(|error| mismatch(format!("cannot create output file: {error}")))?;
        file.write_all(bytes)
            .map_err(|error| mismatch(format!("cannot write output file: {error}")))?;
    }
    std::fs::rename(&temp, destination)
        .map_err(|error| mismatch(format!("cannot finalise output file: {error}")))?;
    Ok(sha256_hex(bytes))
}

/// Stream-copy `count` bytes at `offset` to
/// `destination` atomically; returns the SHA-256.
fn copy_range_atomic(
    file: &mut File,
    offset: u64,
    count: u64,
    destination: &Path,
) -> Result<String> {
    let temp = destination.with_extension("partial");
    let digest = {
        let mut out = File::create(&temp)
            .map_err(|error| mismatch(format!("cannot create output file: {error}")))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| mismatch(format!("cannot seek target: {error}")))?;
        let mut remaining = count;
        let mut buffer = [0u8; 65_536];
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..take])
                .map_err(|error| mismatch(format!("cannot read target: {error}")))?;
            hasher.update(&buffer[..take]);
            out.write_all(&buffer[..take])
                .map_err(|error| mismatch(format!("cannot write output file: {error}")))?;
            remaining -= take as u64;
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    };
    std::fs::rename(&temp, destination)
        .map_err(|error| mismatch(format!("cannot finalise output file: {error}")))?;
    Ok(digest)
}

// ----------------------------------------------------------------
// FSB5 (FMOD Sound Bank 5)
// ----------------------------------------------------------------

/// FMOD sound-format name for a header codec id
/// (FMOD_SOUND_FORMAT order, as published and as
/// vgmstream's fsb5 reader enumerates it).
fn fsb5_codec_name(codec: u32) -> &'static str {
    match codec {
        0 => "none",
        1 => "pcm8",
        2 => "pcm16",
        3 => "pcm24",
        4 => "pcm32",
        5 => "pcmfloat",
        6 => "gcadpcm",
        7 => "imaadpcm",
        8 => "vag",
        9 => "hevag",
        10 => "xma",
        11 => "mpeg",
        12 => "celt",
        13 => "atrac9",
        14 => "xwma",
        15 => "vorbis",
        16 => "fadpcm",
        17 => "opus",
        _ => "unknown",
    }
}

/// Sample-rate table indexed by the sample header's
/// 4-bit frequency index (published FSB5 layout).
const FSB5_SAMPLE_RATES: [u32; 11] = [
    4_000, 8_000, 11_000, 11_025, 16_000, 22_050, 24_000, 32_000, 44_100, 48_000, 96_000,
];

/// One FSB5 subsound (sample) header, parsed.
#[derive(Default)]
struct Fsb5Subsound {
    channels: Option<u32>,
    /// Byte offset of the stream inside the bank's data
    /// section.
    data_offset: u64,
    /// Stream size in bytes (derived from the next
    /// subsound's offset or the data-section size).
    data_size: u64,
    index: usize,
    loop_end: Option<u32>,
    loop_start: Option<u32>,
    name: Option<String>,
    num_samples: u64,
    sample_rate: Option<u32>,
}

/// One FSB5 bank inside a (possibly concatenated) file.
struct Fsb5Bank {
    bank_index: usize,
    /// Absolute file offset of this bank.
    bank_offset: u64,
    /// Total bank length in bytes (header-declared).
    bank_size: u64,
    base_header_size: u64,
    codec: u32,
    data_size: u32,
    limitations: Vec<String>,
    name_table_size: u32,
    sample_headers_size: u32,
    subsounds: Vec<Fsb5Subsound>,
    version: u32,
}

/// Parse one bank's sample-header area. `area` is the
/// bank's declared sample-header bytes; inconsistencies
/// are recorded as limitations, never panics.
fn parse_fsb5_sample_headers(
    area: &[u8],
    count: usize,
    data_size: u32,
    limitations: &mut Vec<String>,
) -> Vec<Fsb5Subsound> {
    let mut subsounds: Vec<Fsb5Subsound> = Vec::new();
    let mut cursor = 0usize;
    for index in 0..count {
        let Some(mode) = u64_le(area, cursor) else {
            limitations.push(format!(
                "subsound {index}: sample header overruns the declared sample-header area"
            ));
            break;
        };
        let mut sub = Fsb5Subsound {
            index,
            ..Fsb5Subsound::default()
        };
        sub.num_samples = (mode >> 34) & 0x3FFF_FFFF;
        sub.data_offset = ((mode >> 7) & 0x07FF_FFFF) << 5;
        sub.channels = Some(match (mode >> 5) & 0x03 {
            0 => 1,
            1 => 2,
            2 => 6,
            _ => 8,
        });
        let rate_index = ((mode >> 1) & 0x0F) as usize;
        sub.sample_rate = FSB5_SAMPLE_RATES.get(rate_index).copied();
        if sub.sample_rate.is_none() {
            limitations.push(format!(
                "subsound {index}: frequency index {rate_index} is outside the published table; sample rate not established"
            ));
        }
        let mut consumed = 8usize;
        if mode & 0x01 != 0 {
            // Extra-flag chain: u32 header (type in bits
            // 25..31, payload size in bits 1..24,
            // continue flag in bit 0) + payload.
            let mut extra_at = cursor + 8;
            loop {
                let Some(extra) = u32_le(area, extra_at) else {
                    limitations.push(format!(
                        "subsound {index}: extra-flag chain overruns the sample-header area"
                    ));
                    break;
                };
                let kind = (extra >> 25) & 0x7F;
                let size = ((extra >> 1) & 0x00FF_FFFF) as usize;
                let payload_at = extra_at + 4;
                let payload = area.get(payload_at..payload_at + size);
                match (kind, payload) {
                    (1, Some(payload)) => {
                        if let Some(channels) = payload.first() {
                            sub.channels = Some(u32::from(*channels));
                        }
                    }
                    (2, Some(payload)) => {
                        if let Some(rate) = u32_le(payload, 0) {
                            sub.sample_rate = Some(rate);
                        }
                    }
                    (3, Some(payload)) => {
                        if let Some(start) = u32_le(payload, 0) {
                            sub.loop_start = Some(start);
                        }
                        if size > 4
                            && let Some(end) = u32_le(payload, 4)
                        {
                            // FMOD stores loop end one
                            // below the exclusive end.
                            sub.loop_end = Some(end.saturating_add(1));
                        }
                    }
                    (0x0E, Some(payload)) => {
                        if let (Some(channels), Some(layers)) = (sub.channels, u32_le(payload, 0)) {
                            sub.channels = Some(channels.saturating_mul(layers));
                        }
                    }
                    _ => {}
                }
                consumed += 4 + size;
                extra_at = payload_at + size;
                if extra & 0x01 == 0 {
                    break;
                }
                if extra_at >= area.len() {
                    limitations.push(format!(
                        "subsound {index}: extra-flag chain does not terminate inside the sample-header area"
                    ));
                    break;
                }
            }
        }
        subsounds.push(sub);
        cursor += consumed;
        if cursor > area.len() {
            limitations.push(format!(
                "subsound {index}: parsed header bytes overrun the declared sample-header area"
            ));
            break;
        }
    }
    // Stream sizes from consecutive data offsets; the
    // last subsound runs to the data-section end.
    for index in 0..subsounds.len() {
        let start = subsounds[index].data_offset;
        let end = subsounds
            .get(index + 1)
            .map(|next| next.data_offset)
            .unwrap_or(u64::from(data_size));
        if end < start || start > u64::from(data_size) {
            limitations.push(format!(
                "subsound {index}: data offset {start} is inconsistent with the data-section size {data_size}"
            ));
            subsounds[index].data_size = 0;
        } else {
            subsounds[index].data_size = end - start;
        }
    }
    subsounds
}

/// Parse every FSB5 bank in a file (a Unity `.resource`
/// is several banks concatenated; bank N+1 starts
/// exactly where bank N's declared size ends). Returns
/// the banks plus file-level limitations; a file whose
/// first bank does not parse is an error, a later
/// inconsistency is Partial evidence.
fn parse_fsb5_banks(file: &mut File, file_len: u64) -> Result<(Vec<Fsb5Bank>, Vec<String>)> {
    let mut banks: Vec<Fsb5Bank> = Vec::new();
    let mut file_limitations: Vec<String> = Vec::new();
    let mut offset = 0u64;
    while offset < file_len {
        if banks.len() >= FSB5_BANKS_MAX {
            file_limitations.push(format!(
                "bank count exceeds the census bound ({FSB5_BANKS_MAX}); remaining bytes not examined"
            ));
            break;
        }
        let head = read_at(file, offset, 64.min((file_len - offset) as usize))?;
        if !head.starts_with(b"FSB5") {
            if banks.is_empty() {
                return Err(unsupported(
                    "target does not start with the FSB5 magic".into(),
                ));
            }
            file_limitations.push(format!(
                "bytes at offset {offset} after {} bank(s) do not start another FSB5 bank; trailing bytes not examined",
                banks.len()
            ));
            break;
        }
        let version = u32_le(&head, 4).unwrap_or(0);
        let base_header_size: u64 = match version {
            0 => 0x40,
            1 => 0x3C,
            other => {
                if banks.is_empty() {
                    return Err(unsupported(format!(
                        "FSB5 version {other} is not a published version (0 or 1)"
                    )));
                }
                file_limitations.push(format!(
                    "bank at offset {offset} declares FSB5 version {other}; bank iteration stops"
                ));
                break;
            }
        };
        let declared_subsounds = u32_le(&head, 8).unwrap_or(0) as usize;
        let sample_headers_size = u32_le(&head, 12).unwrap_or(0);
        let name_table_size = u32_le(&head, 16).unwrap_or(0);
        let data_size = u32_le(&head, 20).unwrap_or(0);
        let codec = u32_le(&head, 24).unwrap_or(0);
        let bank_size = base_header_size
            + u64::from(sample_headers_size)
            + u64::from(name_table_size)
            + u64::from(data_size);
        let mut limitations: Vec<String> = Vec::new();
        if offset + bank_size > file_len {
            limitations.push(format!(
                "bank declares {bank_size} bytes but only {} remain in the file; bank not parsed further",
                file_len - offset
            ));
            banks.push(Fsb5Bank {
                bank_index: banks.len(),
                bank_offset: offset,
                bank_size,
                base_header_size,
                codec,
                data_size,
                limitations,
                name_table_size,
                sample_headers_size,
                subsounds: Vec::new(),
                version,
            });
            break;
        }
        if declared_subsounds > FSB5_SUBSOUNDS_MAX {
            limitations.push(format!(
                "bank declares {declared_subsounds} subsounds, over the census bound ({FSB5_SUBSOUNDS_MAX}); subsounds not parsed"
            ));
            banks.push(Fsb5Bank {
                bank_index: banks.len(),
                bank_offset: offset,
                bank_size,
                base_header_size,
                codec,
                data_size,
                limitations,
                name_table_size,
                sample_headers_size,
                subsounds: Vec::new(),
                version,
            });
            offset += bank_size;
            continue;
        }
        let area = read_at(
            file,
            offset + base_header_size,
            sample_headers_size as usize,
        )?;
        let mut subsounds =
            parse_fsb5_sample_headers(&area, declared_subsounds, data_size, &mut limitations);
        if name_table_size > 0 && !subsounds.is_empty() {
            let table = read_at(
                file,
                offset + base_header_size + u64::from(sample_headers_size),
                name_table_size as usize,
            )?;
            for sub in &mut subsounds {
                let Some(name_offset) = u32_le(&table, sub.index * 4) else {
                    continue;
                };
                let start = name_offset as usize;
                if start >= table.len() {
                    limitations.push(format!(
                        "subsound {}: name offset {start} is outside the name table",
                        sub.index
                    ));
                    continue;
                }
                let slice = &table[start..];
                let end = slice
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(slice.len());
                if end > FSB5_NAME_BYTES_MAX {
                    limitations.push(format!(
                        "subsound {}: name exceeds the name bound; name not reported",
                        sub.index
                    ));
                    continue;
                }
                sub.name = Some(String::from_utf8_lossy(&slice[..end]).into_owned());
            }
        }
        if subsounds.len() < declared_subsounds {
            limitations.push(format!(
                "bank declares {declared_subsounds} subsounds but {} headers parsed",
                subsounds.len()
            ));
        }
        banks.push(Fsb5Bank {
            bank_index: banks.len(),
            bank_offset: offset,
            bank_size,
            base_header_size,
            codec,
            data_size,
            limitations,
            name_table_size,
            sample_headers_size,
            subsounds,
            version,
        });
        offset += bank_size;
    }
    if offset < file_len && banks.iter().all(|bank| bank.limitations.is_empty()) {
        file_limitations.push(format!(
            "{} trailing bytes after the last complete bank were not examined",
            file_len - offset
        ));
    }
    Ok((banks, file_limitations))
}

/// One subsound as a census row (Observed header facts
/// plus the Derived duration).
fn fsb5_subsound_row(bank: &Fsb5Bank, sub: &Fsb5Subsound) -> Value {
    let duration = match (sub.sample_rate, sub.num_samples) {
        (Some(rate), samples) if rate > 0 => Some(round3(samples as f64 / f64::from(rate))),
        _ => None,
    };
    json!({
        "bank_index": bank.bank_index,
        "channels": sub.channels,
        "codec": fsb5_codec_name(bank.codec),
        "codec_id": bank.codec,
        "data_offset": bank.bank_offset + bank.base_header_size
            + u64::from(bank.sample_headers_size) + u64::from(bank.name_table_size)
            + sub.data_offset,
        "data_size": sub.data_size,
        "duration_seconds": duration,
        "index": sub.index,
        "loop_end": sub.loop_end,
        "loop_start": sub.loop_start,
        "name": sub.name,
        "num_samples": sub.num_samples,
        "sample_rate": sub.sample_rate,
    })
}

pub fn census_fsb5_container(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let file_len = subject.size_bytes;
    let sha256 = subject.sha256.clone();
    let mut evidence = Evidence::new("census_fsb5_container", "fmod");
    evidence.subject = Some(subject);
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open target: {error}")))?;
    let (banks, file_limitations) = parse_fsb5_banks(&mut file, file_len)?;
    let mut rows: Vec<Value> = Vec::new();
    let mut bank_rows: Vec<Value> = Vec::new();
    let mut total_subsounds = 0u64;
    for bank in &banks {
        for sub in &bank.subsounds {
            rows.push(fsb5_subsound_row(bank, sub));
        }
        total_subsounds += bank.subsounds.len() as u64;
        bank_rows.push(json!({
            "bank_index": bank.bank_index,
            "bank_offset": bank.bank_offset,
            "bank_size": bank.bank_size,
            "codec": fsb5_codec_name(bank.codec),
            "codec_id": bank.codec,
            "data_size": bank.data_size,
            "limitations": bank.limitations,
            "name_table_size": bank.name_table_size,
            "sample_headers_size": bank.sample_headers_size,
            "subsound_count": bank.subsounds.len(),
            "version": bank.version,
        }));
        for limitation in &bank.limitations {
            evidence.add_unknown(
                "fsb5 bank parse",
                format!("bank {}: {limitation}", bank.bank_index),
            );
        }
    }
    for limitation in &file_limitations {
        evidence.add_unknown("fsb5 bank iteration", limitation.clone());
    }
    let document = json!({"banks": bank_rows, "entries": rows});
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "fsb5_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.coverage.examined = total_subsounds;
    evidence.coverage.total = total_subsounds;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    evidence.add_finding(
        Finding::new(
            "fsb5_census",
            Confidence::Observed,
            json!({
                "bank_count": banks.len(),
                "banks": bank_rows,
                "export_digest": digest,
                "format": "FMOD FSB5 (one or more banks concatenated; a Unity .resource is this form)",
                "subsound_count": total_subsounds,
                "target_sha256": sha256,
            }),
        )
        .with_limitation(
            "loop points are reported only when the sample header's extra-flag chain carries a loop record (type 3); decoder-side loop metadata is not consulted",
        ),
    );
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows.len(), "total": rows.len()}),
    ));
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

/// Bits per sample and WAV format tag for the PCM
/// codecs this lane rewraps into WAV containers.
fn fsb5_pcm_format(codec: u32) -> Option<(u16, u16)> {
    // (format tag, bits per sample): 1 = integer PCM,
    // 3 = IEEE float.
    match codec {
        1 => Some((1, 8)),
        2 => Some((1, 16)),
        3 => Some((1, 24)),
        4 => Some((1, 32)),
        5 => Some((3, 32)),
        _ => None,
    }
}

/// Synthesise a WAV container around raw PCM bytes
/// (a rewrap: the samples are copied verbatim).
fn wrap_pcm_as_wav(
    pcm: &[u8],
    format_tag: u16,
    bits: u16,
    channels: u32,
    sample_rate: u32,
) -> Vec<u8> {
    let block_align = channels.max(1) * u32::from(bits / 8);
    let byte_rate = sample_rate * block_align;
    let data_size = pcm.len() as u32;
    let mut out = Vec::with_capacity(44 + pcm.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_size).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&format_tag.to_le_bytes());
    out.extend_from_slice(&(channels as u16).to_le_bytes());
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&(block_align as u16).to_le_bytes());
    out.extend_from_slice(&bits.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_size.to_le_bytes());
    out.extend_from_slice(pcm);
    out
}

/// The decoders root the provisioning lane installed
/// (primo): `~/.local/share/pax/audio-decoders/`.
fn decoders_root() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share/pax/audio-decoders"))
}

/// Locate an installed `vgmstream-cli` under the
/// decoders root: version directories are scanned in
/// sorted order and the first binary wins, so the
/// choice is deterministic for a fixed install tree.
fn locate_vgmstream_cli(root: &Path) -> Option<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    for dir in entries {
        let candidate = dir.join("vgmstream-cli");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Decode one carved bank's subsound with the external
/// decoder. Returns the decoded bytes on success.
fn vgmstream_decode(
    cli: &Path,
    bank_file: &Path,
    subsound_index: usize,
    decoded_path: &Path,
) -> std::result::Result<Vec<u8>, String> {
    let outcome = run_process(&ProcessSpec {
        args: vec![
            "-i".to_string(),
            "-s".to_string(),
            format!("{}", subsound_index + 1),
            "-o".to_string(),
            decoded_path.display().to_string(),
            bank_file.display().to_string(),
        ],
        cwd: None,
        env: Vec::new(),
        output_cap: PROCESS_OUTPUT_BYTES_MAX,
        program: cli.display().to_string(),
        timeout: Duration::from_secs(VGMSTREAM_TIMEOUT_SECS),
    })
    .map_err(|error| error.message.clone())?;
    if outcome.timed_out {
        return Err("vgmstream-cli timed out".to_string());
    }
    if outcome.exit_code != Some(0) {
        return Err(format!(
            "vgmstream-cli exited with code {:?}",
            outcome.exit_code
        ));
    }
    std::fs::read(decoded_path).map_err(|error| format!("decoded output unreadable: {error}"))
}

pub fn extract_fsb5_audio(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let output_arg = require_str(args, "output_dir")?;
    let output_dir = paths::validate_output_dir(config, Path::new(output_arg))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut evidence = Evidence::new("extract_fsb5_audio", "fmod");
    evidence.subject = Some(subject);
    let mut file =
        File::open(&path).map_err(|error| mismatch(format!("cannot open target: {error}")))?;
    let (banks, file_limitations) = parse_fsb5_banks(&mut file, file_len)?;
    // The external decode leg runs only when the
    // operator allowlisted the program AND it is
    // installed; both facts are reported, never assumed.
    let decode_allowed = config
        .allow_programs
        .iter()
        .any(|name| name == "vgmstream-cli");
    let cli = if decode_allowed {
        decoders_root().and_then(|root| locate_vgmstream_cli(&root))
    } else {
        None
    };
    let mut rows: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut spent: u64 = 0;
    let mut total_subsounds = 0u64;
    for bank in &banks {
        // Carve the bank once when decoding is possible:
        // vgmstream refuses concatenated containers, so
        // it is offered single-bank files.
        let carved: Option<PathBuf> = if cli.is_some() && !bank.subsounds.is_empty() {
            let carved_path = output_dir.join(format!(".bank{:02}.fsb", bank.bank_index));
            match copy_range_atomic(&mut file, bank.bank_offset, bank.bank_size, &carved_path) {
                Ok(_) => Some(carved_path),
                Err(_) => None,
            }
        } else {
            None
        };
        for sub in &bank.subsounds {
            total_subsounds += 1;
            let mut row = fsb5_subsound_row(bank, sub);
            let data_start = bank.bank_offset
                + bank.base_header_size
                + u64::from(bank.sample_headers_size)
                + u64::from(bank.name_table_size)
                + sub.data_offset;
            let status: &str;
            if sub.data_size == 0 {
                status = "failed";
                row["failure"] = json!("stream size is zero or its data offset is inconsistent");
            } else if spent + sub.data_size > GAME_EXTRACT_BYTES_MAX {
                status = "skipped_budget";
            } else if let Some((tag, bits)) = fsb5_pcm_format(bank.codec) {
                // PCM streams are rewrapped as WAV.
                match read_at(&mut file, data_start, sub.data_size as usize) {
                    Ok(pcm) => {
                        let wav = wrap_pcm_as_wav(
                            &pcm,
                            tag,
                            bits,
                            sub.channels.unwrap_or(1),
                            sub.sample_rate.unwrap_or(0),
                        );
                        let name = format!("bank{:02}_sub{:03}.wav", bank.bank_index, sub.index);
                        match write_atomic(&output_dir.join(&name), &wav) {
                            Ok(digest) => {
                                spent += sub.data_size;
                                row["artifact"] = json!({
                                    "bytes": wav.len(),
                                    "kind": "decoded-pcm",
                                    "path": name,
                                    "sha256": digest,
                                });
                                status = "decoded-pcm";
                            }
                            Err(_) => status = "failed",
                        }
                    }
                    Err(_) => status = "failed",
                }
            } else {
                let extension = "vgmstream-raw";
                let name = format!("bank{:02}_sub{:03}.{extension}", bank.bank_index, sub.index);
                match copy_range_atomic(
                    &mut file,
                    data_start,
                    sub.data_size,
                    &output_dir.join(&name),
                ) {
                    Ok(digest) => {
                        spent += sub.data_size;
                        row["artifact"] = json!({
                            "bytes": sub.data_size,
                            "kind": "raw-stream",
                            "path": name,
                            "sha256": digest,
                        });
                        status = "raw-stream";
                    }
                    Err(_) => status = "failed",
                }
            }
            // Optional external decode of the raw stream.
            let mut decode_status = "not_attempted";
            if status == "raw-stream" {
                match (&cli, &carved) {
                    (Some(cli), Some(carved_path)) => {
                        let decoded_name =
                            format!("bank{:02}_sub{:03}.decoded.wav", bank.bank_index, sub.index);
                        let decoded_path = output_dir.join(&decoded_name);
                        match vgmstream_decode(cli, carved_path, sub.index, &decoded_path) {
                            Ok(bytes) => {
                                row["decoded_artifact"] = json!({
                                    "bytes": bytes.len(),
                                    "kind": "vgmstream-decoded",
                                    "path": decoded_name,
                                    "sha256": sha256_hex(&bytes),
                                });
                                decode_status = "decoded";
                            }
                            Err(reason) => {
                                decode_status = "decode_failed";
                                row["decode_note"] = json!(reason);
                                let _ = std::fs::remove_file(&decoded_path);
                            }
                        }
                    }
                    (Some(_), None) => decode_status = "decode_unavailable",
                    _ => {}
                }
            }
            row["decode_status"] = json!(decode_status);
            row["status"] = json!(status);
            *counts.entry(status).or_insert(0) += 1;
            rows.push(row);
        }
        if let Some(carved_path) = &carved {
            let _ = std::fs::remove_file(carved_path);
        }
        for limitation in &bank.limitations {
            evidence.add_unknown(
                "fsb5 bank parse",
                format!("bank {}: {limitation}", bank.bank_index),
            );
        }
    }
    for limitation in &file_limitations {
        evidence.add_unknown("fsb5 bank iteration", limitation.clone());
    }
    if !decode_allowed {
        evidence.add_unknown(
            "external decode",
            "vgmstream-cli is not in allow_programs; raw streams were extracted without a decode attempt",
        );
    } else if cli.is_none() {
        evidence.add_unknown(
            "external decode",
            "vgmstream-cli is allowlisted but no installed binary was found under the decoders root; decode is pending provisioning",
        );
    }
    let manifest = json!({
        "entries": rows,
        "format": "FMOD FSB5 (one or more banks concatenated)",
        "notes": [
            "PCM streams are rewrapped into WAV containers verbatim (status decoded-pcm); all other codecs are written as raw streams (status raw-stream)",
            "FSB Vorbis uses setup-id codebooks, so a raw Vorbis stream is NOT a standalone Ogg file; decode requires vgmstream-cli or an FMOD runtime",
            "decoded artifacts, when present, were produced by the operator-allowlisted vgmstream-cli from the carved single-bank file",
        ],
        "source_sha256": sha256,
        "totals": {
            "banks": banks.len(),
            "entries": total_subsounds,
            "decoded_pcm": counts.get("decoded-pcm").copied().unwrap_or(0),
            "failed": counts.get("failed").copied().unwrap_or(0),
            "raw_stream": counts.get("raw-stream").copied().unwrap_or(0),
            "skipped_budget": counts.get("skipped_budget").copied().unwrap_or(0),
        },
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("cannot serialise manifest: {error}")))?;
    std::fs::write(output_dir.join("manifest.json"), &manifest_bytes)
        .map_err(|error| mismatch(format!("cannot write manifest: {error}")))?;
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "fsb5_extract", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.coverage.examined = total_subsounds;
    evidence.coverage.total = total_subsounds;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    evidence.add_finding(Finding::new(
        "fsb5_extract",
        Confidence::Observed,
        json!({
            "banks": banks.len(),
            "bytes_written": spent,
            "entries": total_subsounds,
            "export_digest": digest,
            "format": "FMOD FSB5",
            "output_dir": output_dir.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": manifest["entries"], "returned": total_subsounds, "total": total_subsounds}),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "manifest retention failed ({note}); the on-disk manifest stands, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

// ----------------------------------------------------------------
// CRI @UTF tables and AFS2 wave archives (ACB cue sheets)
// ----------------------------------------------------------------

/// One @UTF column: where its values live and their
/// type. Offsets are relative to the table base for
/// default (schema-held) values, or to the row start
/// for per-row values.
struct UtfColumn {
    flag: u8,
    kind: u8,
    name: Option<String>,
    offset: usize,
}

/// A parsed @UTF table header + schema. Section
/// offsets are absolute positions in the source buffer.
struct UtfTable {
    base: usize,
    columns: Vec<UtfColumn>,
    data_offset: usize,
    name: String,
    row_width: usize,
    rows: usize,
    rows_offset: usize,
    strings_offset: usize,
    strings_size: usize,
}

/// A @UTF cell value.
enum UtfValue {
    Data(usize, u32),
    Float(f64),
    Int(i64),
    Str(String),
    UInt(u64),
}

fn utf_value_size(kind: u8) -> Option<usize> {
    match kind {
        0 | 1 => Some(1),
        2 | 3 => Some(2),
        4 | 5 | 8 | 10 => Some(4),
        6 | 7 | 9 | 11 => Some(8),
        _ => None,
    }
}

/// Read a NUL-terminated string from the table's
/// string section at `offset` (bounded, lossy UTF-8 —
/// CRI names are UTF-8 in the corpus).
fn utf_string_at(bytes: &[u8], table: &UtfTable, offset: usize) -> Option<String> {
    if offset >= table.strings_size {
        return None;
    }
    let start = table.strings_offset + offset;
    let slice = bytes.get(start..table.strings_offset + table.strings_size)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Parse the @UTF table at `base` in `bytes`. All
/// multi-byte fields are big-endian. Errors are
/// strings: the caller decides whether a broken
/// subtable is fatal or a recorded limitation.
fn parse_utf(bytes: &[u8], base: usize) -> std::result::Result<UtfTable, String> {
    let head = bytes
        .get(base..base + 0x20)
        .ok_or_else(|| "table header overruns the file".to_string())?;
    if &head[0..4] != b"@UTF" {
        return Err("missing @UTF magic".to_string());
    }
    let table_size = u32_be(head, 4).map(|value| value as usize + 8).unwrap_or(0);
    let version = u16_be(head, 8).unwrap_or(0);
    if version > 1 {
        return Err(format!("@UTF version {version} is not a known version"));
    }
    let rows_offset = u16_be(head, 10)
        .map(|value| value as usize + 8)
        .unwrap_or(0);
    let strings_offset = u32_be(head, 12)
        .map(|value| value as usize + 8)
        .unwrap_or(0);
    let data_offset = u32_be(head, 16)
        .map(|value| value as usize + 8)
        .unwrap_or(0);
    let name_offset = u32_be(head, 20).map(|value| value as usize).unwrap_or(0);
    let columns = u16_be(head, 24).map(|value| value as usize).unwrap_or(0);
    let row_width = u16_be(head, 26).map(|value| value as usize).unwrap_or(0);
    let rows = u32_be(head, 28).map(|value| value as usize).unwrap_or(0);
    if columns == 0 || columns > CRI_UTF_COLUMNS_MAX {
        return Err(format!("@UTF column count {columns} is outside the bound"));
    }
    if rows > CRI_UTF_ROWS_MAX {
        return Err(format!("@UTF row count {rows} is outside the bound"));
    }
    if !(0x20 <= rows_offset
        && rows_offset <= strings_offset
        && strings_offset <= data_offset
        && data_offset <= table_size)
    {
        return Err("@UTF section offsets are not in schema/rows/strings/data order".to_string());
    }
    if base + table_size > bytes.len() {
        return Err("@UTF table size overruns the file".to_string());
    }
    let schema_size = rows_offset - 0x20;
    if schema_size > CRI_UTF_SCHEMA_BYTES_MAX {
        return Err("@UTF schema exceeds the bound".to_string());
    }
    let strings_size = data_offset - strings_offset;
    if strings_size == 0 || strings_size > CRI_UTF_STRINGS_BYTES_MAX {
        return Err("@UTF string section is empty or exceeds the bound".to_string());
    }
    let rows_size = strings_offset - rows_offset;
    if rows
        .checked_mul(row_width)
        .is_some_and(|need| need > rows_size)
    {
        return Err("@UTF rows overrun the rows section".to_string());
    }
    let mut table = UtfTable {
        base,
        columns: Vec::new(),
        data_offset: base + data_offset,
        name: String::new(),
        row_width,
        rows,
        rows_offset: base + rows_offset,
        strings_offset: base + strings_offset,
        strings_size,
    };
    table.name = utf_string_at(bytes, &table, name_offset)
        .ok_or_else(|| "@UTF table name is outside the string section".to_string())?;
    // Schema walk: each column is a 5-byte descriptor
    // (flag+type byte, name offset); default values are
    // stored inline after their descriptor.
    let mut schema_at = 0x20usize;
    let mut row_cursor = 0usize;
    for _ in 0..columns {
        let info = bytes
            .get(base + schema_at)
            .copied()
            .ok_or_else(|| "@UTF schema overruns the schema section".to_string())?;
        let col_name_offset = u32_be(bytes, base + schema_at + 1)
            .map(|value| value as usize)
            .ok_or_else(|| "@UTF schema overruns the schema section".to_string())?;
        schema_at += 5;
        let flag = info & 0xF0;
        let kind = info & 0x0F;
        if flag & 0x80 != 0 || flag & 0x10 == 0 || (flag & 0x20 == 0 && flag & 0x40 == 0) {
            return Err(format!(
                "@UTF column flag {flag:#04x} is not a known combination"
            ));
        }
        let value_size = utf_value_size(kind)
            .ok_or_else(|| format!("@UTF column type {kind} is not a known type"))?;
        let offset = if flag & 0x20 != 0 {
            let offset = schema_at;
            schema_at += value_size;
            if schema_at > rows_offset {
                return Err("@UTF default value overruns the schema section".to_string());
            }
            offset
        } else {
            let offset = row_cursor;
            row_cursor += value_size;
            offset
        };
        let name = if flag & 0x10 != 0 {
            Some(
                utf_string_at(bytes, &table, col_name_offset)
                    .ok_or_else(|| "@UTF column name is outside the string section".to_string())?,
            )
        } else {
            None
        };
        table.columns.push(UtfColumn {
            flag,
            kind,
            name,
            offset,
        });
    }
    Ok(table)
}

/// Read one cell. `row` must be within the table.
fn utf_value(bytes: &[u8], table: &UtfTable, row: usize, column: usize) -> Option<UtfValue> {
    let col = table.columns.get(column)?;
    let at = if col.flag & 0x20 != 0 {
        table.base + col.offset
    } else {
        table.rows_offset + row * table.row_width + col.offset
    };
    match col.kind {
        0 => bytes.get(at).map(|value| UtfValue::UInt(u64::from(*value))),
        1 => bytes
            .get(at)
            .map(|value| UtfValue::Int(i64::from(*value as i8))),
        2 => u16_be(bytes, at).map(|value| UtfValue::UInt(u64::from(value))),
        3 => u16_be(bytes, at).map(|value| UtfValue::Int(i64::from(value as i16))),
        4 => u32_be(bytes, at).map(|value| UtfValue::UInt(u64::from(value))),
        5 => u32_be(bytes, at).map(|value| UtfValue::Int(i64::from(value as i32))),
        6 => u64_be(bytes, at).map(UtfValue::UInt),
        7 => u64_be(bytes, at).map(|value| UtfValue::Int(value as i64)),
        8 => u32_be(bytes, at).map(|value| UtfValue::Float(f64::from(f32::from_bits(value)))),
        9 => u64_be(bytes, at).map(|value| UtfValue::Float(f64::from_bits(value))),
        10 => {
            let offset = u32_be(bytes, at).map(|value| value as usize)?;
            utf_string_at(bytes, table, offset).map(UtfValue::Str)
        }
        11 => {
            let offset = u32_be(bytes, at)?;
            let size = u32_be(bytes, at + 4)?;
            let absolute = table.data_offset + offset as usize;
            if absolute + size as usize > bytes.len() {
                return None;
            }
            Some(UtfValue::Data(absolute, size))
        }
        _ => None,
    }
}

fn utf_column_index(table: &UtfTable, name: &str) -> Option<usize> {
    table
        .columns
        .iter()
        .position(|col| col.name.as_deref() == Some(name))
}

fn utf_string(bytes: &[u8], table: &UtfTable, row: usize, name: &str) -> Option<String> {
    match utf_value(bytes, table, row, utf_column_index(table, name)?) {
        Some(UtfValue::Str(text)) => Some(text),
        _ => None,
    }
}

fn utf_data(bytes: &[u8], table: &UtfTable, row: usize, name: &str) -> Option<(usize, u32)> {
    match utf_value(bytes, table, row, utf_column_index(table, name)?) {
        Some(UtfValue::Data(offset, size)) => Some((offset, size)),
        _ => None,
    }
}

/// Dump one row's scalar cells as a JSON object
/// (data cells are reported as offset/size facts).
fn utf_row_json(bytes: &[u8], table: &UtfTable, row: usize) -> Value {
    let mut object = serde_json::Map::new();
    for (index, col) in table.columns.iter().enumerate() {
        let Some(name) = &col.name else { continue };
        let value = match utf_value(bytes, table, row, index) {
            Some(UtfValue::UInt(value)) => json!(value),
            Some(UtfValue::Int(value)) => json!(value),
            Some(UtfValue::Float(value)) => json!(value),
            Some(UtfValue::Str(text)) => json!(text),
            Some(UtfValue::Data(offset, size)) => json!({"data_offset": offset, "data_size": size}),
            None => Value::Null,
        };
        object.insert(name.clone(), value);
    }
    Value::Object(object)
}

/// One AFS2 entry: a stored wave stream.
struct Afs2Entry {
    id: u32,
    /// Absolute offset in the ACB file.
    offset: usize,
    size: usize,
}

/// Parse the AFS2 archive at `base`, spanning
/// `region_size` bytes. Entry offsets are relative to
/// `base` and are aligned up to the header's offset
/// alignment, as the published AWB/AFS2 reader does.
fn parse_afs2(
    bytes: &[u8],
    base: usize,
    region_size: usize,
) -> std::result::Result<(Vec<Afs2Entry>, u32), String> {
    let head = bytes
        .get(base..base + 16)
        .ok_or_else(|| "AFS2 header overruns the file".to_string())?;
    if &head[0..4] != b"AFS2" {
        return Err("missing AFS2 magic".to_string());
    }
    let offset_size = head[5] as usize;
    if offset_size != 2 && offset_size != 4 {
        return Err(format!("AFS2 offset size {offset_size} is not 2 or 4"));
    }
    let waveid_alignment = u16_le(head, 6).map(|value| value as usize).unwrap_or(0);
    if waveid_alignment != 2 && waveid_alignment != 4 {
        return Err(format!(
            "AFS2 wave-id alignment {waveid_alignment} is not 2 or 4"
        ));
    }
    let count = u32_le(head, 8).map(|value| value as usize).unwrap_or(0);
    if count == 0 || count > CRI_AFS2_ENTRIES_MAX {
        return Err(format!("AFS2 entry count {count} is outside the bound"));
    }
    let offset_alignment = u16_le(head, 12).map(u64::from).unwrap_or(0);
    if offset_alignment == 0 {
        return Err("AFS2 offset alignment is zero".to_string());
    }
    let read_entry_value = |at: usize, size: usize| -> Option<u32> {
        if size == 2 {
            u16_le(bytes, at).map(u32::from)
        } else {
            u32_le(bytes, at)
        }
    };
    let mut ids: Vec<u32> = Vec::with_capacity(count);
    for index in 0..count {
        let at = base + 16 + index * waveid_alignment;
        ids.push(
            read_entry_value(at, waveid_alignment)
                .ok_or_else(|| "AFS2 wave-id table overruns the file".to_string())?,
        );
    }
    let offsets_at = base + 16 + count * waveid_alignment;
    let mut raw_offsets: Vec<u64> = Vec::with_capacity(count + 1);
    for index in 0..count + 1 {
        let at = offsets_at + index * offset_size;
        raw_offsets
            .push(u64::from(read_entry_value(at, offset_size).ok_or_else(
                || "AFS2 offset table overruns the file".to_string(),
            )?));
    }
    let align_up = |value: u64| -> u64 {
        if value.is_multiple_of(offset_alignment) {
            value
        } else {
            value + (offset_alignment - value % offset_alignment)
        }
    };
    let mut entries: Vec<Afs2Entry> = Vec::with_capacity(count);
    for index in 0..count {
        let start = align_up(raw_offsets[index]);
        let next_raw = raw_offsets[index + 1];
        // The final offset names the archive end and is
        // not aligned up past it (the AWB reader's rule).
        let end = if !next_raw.is_multiple_of(offset_alignment) && (next_raw as usize) < region_size
        {
            align_up(next_raw)
        } else {
            next_raw
        };
        if end < start || end as usize > region_size {
            return Err(format!(
                "AFS2 entry {index} span {start}..{end} is outside the archive region"
            ));
        }
        entries.push(Afs2Entry {
            id: ids[index],
            offset: base + start as usize,
            size: (end - start) as usize,
        });
    }
    Ok((entries, offset_alignment as u32))
}

/// The stream kind an AFS2 entry's magic names.
fn afs2_entry_kind(bytes: &[u8], entry: &Afs2Entry) -> &'static str {
    let magic = bytes.get(entry.offset..entry.offset + 4);
    match magic {
        Some(magic) if magic == b"HCA\0" => "hca",
        Some(magic) if magic.len() >= 2 && magic[0] == 0x80 && magic[1] == 0x00 => "adx",
        _ => "bin",
    }
}

/// Everything the two CRI handlers share from one ACB
/// parse.
struct AcbParsed {
    acb_name: Option<String>,
    afs2_base: Option<usize>,
    afs2_size: Option<usize>,
    cue_names: Vec<Value>,
    entries: Vec<Afs2Entry>,
    limitations: Vec<String>,
    waveforms: Vec<Value>,
}

fn load_acb(bytes: &[u8]) -> std::result::Result<AcbParsed, String> {
    if !bytes.starts_with(b"@UTF") {
        return Err("target does not start with the CRI @UTF magic".to_string());
    }
    let top = parse_utf(bytes, 0)?;
    let mut parsed = AcbParsed {
        acb_name: utf_string(bytes, &top, 0, "Name"),
        afs2_base: None,
        afs2_size: None,
        cue_names: Vec::new(),
        entries: Vec::new(),
        limitations: Vec::new(),
        waveforms: Vec::new(),
    };
    // Cue names from the CueNameTable subtable: a real
    // table parse, labelled Observed by the callers.
    match utf_data(bytes, &top, 0, "CueNameTable") {
        Some((offset, _)) => match parse_utf(bytes, offset) {
            Ok(table) => {
                for row in 0..table.rows {
                    parsed.cue_names.push(json!({
                        "cue_index": match utf_value(bytes, &table, row, utf_column_index(&table, "CueIndex").unwrap_or(usize::MAX)) {
                            Some(UtfValue::UInt(value)) => json!(value),
                            _ => Value::Null,
                        },
                        "name": utf_string(bytes, &table, row, "CueName"),
                    }));
                }
            }
            Err(reason) => parsed
                .limitations
                .push(format!("CueNameTable did not parse: {reason}")),
        },
        None => parsed
            .limitations
            .push("the ACB carries no CueNameTable data column".to_string()),
    }
    // Waveform rows: per-stream CRI metadata (encode
    // type, channels, loop flag, sample rate, samples).
    match utf_data(bytes, &top, 0, "WaveformTable") {
        Some((offset, _)) => match parse_utf(bytes, offset) {
            Ok(table) => {
                for row in 0..table.rows {
                    parsed.waveforms.push(utf_row_json(bytes, &table, row));
                }
            }
            Err(reason) => parsed
                .limitations
                .push(format!("WaveformTable did not parse: {reason}")),
        },
        None => parsed
            .limitations
            .push("the ACB carries no WaveformTable data column".to_string()),
    }
    // The embedded wave archive: the AwbFile data
    // column names it exactly; a magic search is the
    // fallback.
    let (base, size) = match utf_data(bytes, &top, 0, "AwbFile") {
        Some((offset, size)) if size > 0 => (offset, size as usize),
        _ => {
            parsed.limitations.push(
                "no AwbFile data column; the AFS2 archive was located by magic search".to_string(),
            );
            let found = bytes
                .windows(4)
                .position(|window| window == b"AFS2")
                .ok_or_else(|| "no AFS2 archive found in the ACB".to_string())?;
            (found, bytes.len() - found)
        }
    };
    parsed.afs2_base = Some(base);
    parsed.afs2_size = Some(size);
    let (entries, _alignment) = parse_afs2(bytes, base, size)?;
    parsed.entries = entries;
    parsed.limitations.push(
        "cue-name-to-waveform pairing follows the cue/synth/track graph, which this lane does not traverse; cue names are reported in CueNameTable order and waveforms in WaveformTable order, unpaired"
            .to_string(),
    );
    Ok(parsed)
}

/// Pair an AFS2 entry with its WaveformTable row: the
/// row whose StreamAwbId (streaming) or MemoryAwbId
/// (in-memory) equals the entry's wave id.
fn waveform_for_entry<'a>(parsed: &'a AcbParsed, entry: &Afs2Entry) -> Option<&'a Value> {
    parsed.waveforms.iter().find(|row| {
        let stream_id = row.get("StreamAwbId").and_then(Value::as_u64);
        let memory_id = row.get("MemoryAwbId").and_then(Value::as_u64);
        stream_id == Some(u64::from(entry.id)) || memory_id == Some(u64::from(entry.id))
    })
}

fn cri_entry_row(bytes: &[u8], parsed: &AcbParsed, index: usize, entry: &Afs2Entry) -> Value {
    json!({
        "index": index,
        "kind": afs2_entry_kind(bytes, entry),
        "offset": entry.offset,
        "size": entry.size,
        "wave_id": entry.id,
        "waveform": waveform_for_entry(parsed, entry),
    })
}

/// Read an ACB target whole, enforcing the size bound.
fn read_acb_target(path: &Path) -> Result<(Vec<u8>, fathom_core::evidence::Subject)> {
    let subject = subject_for_file_with_bound(path, CRI_ACB_BYTES_MAX)?;
    let bytes =
        std::fs::read(path).map_err(|error| mismatch(format!("cannot read target: {error}")))?;
    Ok((bytes, subject))
}

pub fn census_cri_acb(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let (bytes, subject) = read_acb_target(&path)?;
    let sha256 = subject.sha256.clone();
    let mut evidence = Evidence::new("census_cri_acb", "cri");
    evidence.subject = Some(subject);
    let parsed = load_acb(&bytes).map_err(mismatch)?;
    let rows: Vec<Value> = parsed
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| cri_entry_row(&bytes, &parsed, index, entry))
        .collect();
    for limitation in &parsed.limitations {
        evidence.add_unknown("cri acb parse", limitation.clone());
    }
    let document = json!({
        "cue_names": parsed.cue_names,
        "entries": rows,
        "waveforms": parsed.waveforms,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "cri_acb_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.coverage.examined = rows.len() as u64;
    evidence.coverage.total = rows.len() as u64;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    evidence.add_finding(
        Finding::new(
            "cri_acb_census",
            Confidence::Observed,
            json!({
                "acb_name": parsed.acb_name,
                "afs2_offset": parsed.afs2_base,
                "afs2_size": parsed.afs2_size,
                "cue_name_count": parsed.cue_names.len(),
                "export_digest": digest,
                "format": "CRI Atom ACB (@UTF cue sheet with embedded AFS2 wave archive)",
                "stream_count": rows.len(),
                "target_sha256": sha256,
                "waveform_count": parsed.waveforms.len(),
            }),
        )
        .with_limitation(
            "entry sizes are AFS2 spans (aligned offset differences) and can include inter-stream padding at the tail",
        ),
    );
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows.len(), "total": rows.len()}),
    ));
    evidence.add_finding(Finding::new(
        "cue_names",
        Confidence::Observed,
        json!({"entries": parsed.cue_names, "returned": parsed.cue_names.len(), "total": parsed.cue_names.len()}),
    ));
    evidence.add_finding(Finding::new(
        "waveforms",
        Confidence::Observed,
        json!({"entries": parsed.waveforms, "returned": parsed.waveforms.len(), "total": parsed.waveforms.len()}),
    ));
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

pub fn extract_cri_acb(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let output_arg = require_str(args, "output_dir")?;
    let output_dir = paths::validate_output_dir(config, Path::new(output_arg))?;
    let (bytes, subject) = read_acb_target(&path)?;
    let sha256 = subject.sha256.clone();
    let mut evidence = Evidence::new("extract_cri_acb", "cri");
    evidence.subject = Some(subject);
    let parsed = load_acb(&bytes).map_err(mismatch)?;
    let mut rows: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut spent: u64 = 0;
    for (index, entry) in parsed.entries.iter().enumerate() {
        let mut row = cri_entry_row(&bytes, &parsed, index, entry);
        let kind = afs2_entry_kind(&bytes, entry);
        let mut status = "extracted";
        if spent + entry.size as u64 > GAME_EXTRACT_BYTES_MAX {
            status = "skipped_budget";
        } else {
            let name = format!("stream{:03}.{kind}", entry.id);
            let slice = &bytes[entry.offset..entry.offset + entry.size];
            match write_atomic(&output_dir.join(&name), slice) {
                Ok(digest) => {
                    spent += entry.size as u64;
                    row["artifact"] = json!({
                        "bytes": entry.size,
                        "kind": kind,
                        "path": name,
                        "sha256": digest,
                    });
                }
                Err(_) => status = "failed",
            }
        }
        row["status"] = json!(status);
        *counts.entry(status).or_insert(0) += 1;
        rows.push(row);
    }
    for limitation in &parsed.limitations {
        evidence.add_unknown("cri acb parse", limitation.clone());
    }
    let manifest = json!({
        "cue_names": parsed.cue_names,
        "entries": rows,
        "format": "CRI Atom ACB (AFS2 wave archive)",
        "notes": [
            "entries are the AFS2 stored streams verbatim (HCA/ADX are not decoded by this lane); entry spans can include inter-stream alignment padding at the tail",
            "cue names are the CueNameTable rows in table order; the cue/synth/track pairing graph is not traversed",
        ],
        "source_sha256": sha256,
        "totals": {
            "entries": parsed.entries.len(),
            "extracted": counts.get("extracted").copied().unwrap_or(0),
            "failed": counts.get("failed").copied().unwrap_or(0),
            "skipped_budget": counts.get("skipped_budget").copied().unwrap_or(0),
        },
        "waveforms": parsed.waveforms,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("cannot serialise manifest: {error}")))?;
    std::fs::write(output_dir.join("manifest.json"), &manifest_bytes)
        .map_err(|error| mismatch(format!("cannot write manifest: {error}")))?;
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "cri_acb_extract", &manifest) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.coverage.examined = rows.len() as u64;
    evidence.coverage.total = rows.len() as u64;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    evidence.add_finding(Finding::new(
        "cri_acb_extract",
        Confidence::Observed,
        json!({
            "bytes_written": spent,
            "entries": rows.len(),
            "export_digest": digest,
            "format": "CRI Atom ACB (AFS2)",
            "output_dir": output_dir.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": manifest["entries"], "returned": rows.len(), "total": rows.len()}),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "manifest retention failed ({note}); the on-disk manifest stands, but no proof can bind this run"
            ),
        );
    }
    Ok(evidence.to_value())
}

// ----------------------------------------------------------------
// RPG Maker MV/MZ encrypted audio
// ----------------------------------------------------------------

/// The 16-byte fake header every MV-encrypted file
/// carries (the literal "RPGMV" signature plus the
/// format's fixed version bytes).
const MV_FAKE_HEADER_LEN: usize = 16;

/// Decrypt one MV-encrypted payload: drop the fake
/// header, XOR the first 16 body bytes with the key,
/// copy the rest verbatim.
fn mv_decrypt(bytes: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    if bytes.len() < MV_FAKE_HEADER_LEN || &bytes[0..5] != b"RPGMV" {
        return None;
    }
    let mut out = bytes[MV_FAKE_HEADER_LEN..].to_vec();
    for (index, byte) in out.iter_mut().take(16).enumerate() {
        *byte ^= key[index];
    }
    Some(out)
}

/// Decode a 32-hex-character MV encryption key.
fn mv_key_from_hex(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    for (index, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}

pub fn extract_rpgmaker_mv_audio(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let output_arg = require_str(args, "output_dir")?;
    let output_dir = paths::validate_output_dir(config, Path::new(output_arg))?;
    let mut evidence = Evidence::new("extract_rpgmaker_mv_audio", "rpgmaker");
    // Locate the www root: the target itself or its
    // `www` child must carry data/System.json.
    let www_root = [path.clone(), path.join("www")]
        .into_iter()
        .find(|candidate| candidate.join("data/System.json").is_file())
        .ok_or_else(|| {
            unsupported("no data/System.json under the target or its www directory".into())
        })?;
    let system_path = www_root.join("data/System.json");
    let system_bytes = std::fs::read(&system_path)
        .map_err(|error| mismatch(format!("cannot read System.json: {error}")))?;
    let system: Value = serde_json::from_slice(&system_bytes)
        .map_err(|error| mismatch(format!("System.json is not valid JSON: {error}")))?;
    let key_text = system
        .get("encryptionKey")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("System.json carries no encryptionKey".into()))?;
    let key = mv_key_from_hex(key_text)
        .ok_or_else(|| unsupported("System.json encryptionKey is not 32 hex characters".into()))?;
    let has_encrypted_audio = system
        .get("hasEncryptedAudio")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Bounded sorted walk of the audio tree.
    let audio_root = www_root.join("audio");
    let mut files: Vec<PathBuf> = Vec::new();
    let mut image_files = 0u64;
    if audio_root.is_dir() {
        let mut stack: Vec<PathBuf> = vec![audio_root.clone()];
        while let Some(dir) = stack.pop() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
                .map_err(|error| mismatch(format!("cannot walk audio tree: {error}")))?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect();
            entries.sort();
            for entry in entries {
                if entry.is_dir() {
                    stack.push(entry);
                } else if entry.is_file() {
                    let extension = entry
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    match extension.as_str() {
                        "rpgmvo" | "rpgmvm" => files.push(entry),
                        "rpgmvp" => image_files += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    files.sort();
    if files.len() > MV_FILES_MAX {
        return Err(mismatch(format!(
            "encrypted audio file count {} exceeds the bound ({MV_FILES_MAX})",
            files.len()
        )));
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut spent: u64 = 0;
    for file_path in &files {
        let relative = file_path
            .strip_prefix(&www_root)
            .unwrap_or(file_path)
            .to_path_buf();
        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();
        let (out_extension, kind) = if extension == "rpgmvo" {
            ("ogg", "ogg")
        } else {
            ("m4a", "m4a")
        };
        let mut row = json!({
            "bytes": file_path.metadata().map(|meta| meta.len()).unwrap_or(0),
            "path": relative.display().to_string(),
        });
        let status: &str;
        let size = file_path.metadata().map(|meta| meta.len()).unwrap_or(0);
        if size > MV_FILE_BYTES_MAX || spent + size > GAME_EXTRACT_BYTES_MAX {
            status = "skipped_budget";
        } else {
            match std::fs::read(file_path) {
                Ok(bytes) => match mv_decrypt(&bytes, &key) {
                    Some(decrypted) => {
                        let verified = if kind == "ogg" {
                            decrypted.starts_with(b"OggS")
                        } else {
                            decrypted.get(4..8).is_some_and(|magic| magic == b"ftyp")
                        };
                        let out_relative = relative.with_extension(out_extension);
                        let destination = output_dir.join(&out_relative);
                        if let Some(parent) = destination.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        match write_atomic(&destination, &decrypted) {
                            Ok(digest) => {
                                spent += decrypted.len() as u64;
                                row["artifact"] = json!({
                                    "bytes": decrypted.len(),
                                    "kind": kind,
                                    "path": out_relative.display().to_string(),
                                    "sha256": digest,
                                });
                                status = if verified {
                                    "verified"
                                } else {
                                    "decrypted_unverified"
                                };
                            }
                            Err(_) => status = "failed",
                        }
                    }
                    None => status = "bad_header",
                },
                Err(_) => status = "failed",
            }
        }
        row["status"] = json!(status);
        *counts.entry(status).or_insert(0) += 1;
        rows.push(row);
    }
    if image_files > 0 {
        evidence.add_unknown(
            "encrypted images",
            format!(
                "{image_files} .rpgmvp image files use the same scheme but are out of this audio lane's scope and were not extracted"
            ),
        );
    }
    evidence.add_unknown(
        "retention",
        "directory targets carry no single subject hash; the manifest is written to the output directory but not proof-retained",
    );
    let manifest = json!({
        "entries": rows,
        "format": "RPG Maker MV encrypted audio (.rpgmvo/.rpgmvm)",
        "has_encrypted_audio": has_encrypted_audio,
        "notes": [
            "decryption drops the 16-byte fake header and XORs the first 16 body bytes with the System.json encryption key; the key itself is never recorded",
            "status verified means the decrypted payload carries the expected container magic (OggS for .rpgmvo, ftyp for .rpgmvm)",
        ],
        "source": www_root.display().to_string(),
        "totals": {
            "bad_header": counts.get("bad_header").copied().unwrap_or(0),
            "decrypted_unverified": counts.get("decrypted_unverified").copied().unwrap_or(0),
            "entries": files.len(),
            "failed": counts.get("failed").copied().unwrap_or(0),
            "skipped_budget": counts.get("skipped_budget").copied().unwrap_or(0),
            "verified": counts.get("verified").copied().unwrap_or(0),
        },
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| mismatch(format!("cannot serialise manifest: {error}")))?;
    std::fs::write(output_dir.join("manifest.json"), &manifest_bytes)
        .map_err(|error| mismatch(format!("cannot write manifest: {error}")))?;
    evidence.coverage.examined = rows.len() as u64;
    evidence.coverage.total = rows.len() as u64;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    evidence.add_finding(Finding::new(
        "rpgmaker_mv_audio_extract",
        Confidence::Observed,
        json!({
            "bytes_written": spent,
            "entries": files.len(),
            "format": "RPG Maker MV encrypted audio",
            "has_encrypted_audio": has_encrypted_audio,
            "output_dir": output_dir.display().to_string(),
            "www_root": www_root.display().to_string(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": manifest["entries"], "returned": rows.len(), "total": rows.len()}),
    ));
    Ok(evidence.to_value())
}

// ----------------------------------------------------------------
// Single-file analysis (header facts + WAV measurements)
// ----------------------------------------------------------------

/// A decoded WAV: format facts plus the sample data.
struct WavData {
    channels: u32,
    sample_rate: u32,
    /// Interleaved samples normalised to [-1, 1).
    samples: Vec<f64>,
}

/// Parse a WAV file's fmt/data chunks over the whole
/// file and decode integer/float PCM to f64 samples.
fn parse_wav(bytes: &[u8]) -> Option<WavData> {
    if !bytes.starts_with(b"RIFF") || bytes.get(8..12) != Some(b"WAVE") {
        return None;
    }
    let mut format_tag = 0u16;
    let mut channels = 0u32;
    let mut sample_rate = 0u32;
    let mut bits = 0u16;
    let mut data: Option<&[u8]> = None;
    let mut pos = 12usize;
    while pos + 8 <= bytes.len() {
        let kind = &bytes[pos..pos + 4];
        let size = u32_le(bytes, pos + 4)? as usize;
        let body_at = pos + 8;
        let body = bytes.get(body_at..body_at + size)?;
        match kind {
            b"fmt " => {
                format_tag = u16_le(body, 0)?;
                channels = u32::from(u16_le(body, 2)?);
                sample_rate = u32_le(body, 4)?;
                bits = u16_le(body, 14)?;
            }
            b"data" => data = Some(body),
            _ => {}
        }
        pos += 8 + size + (size & 1);
    }
    let data = data?;
    if channels == 0 || sample_rate == 0 {
        return None;
    }
    let bytes_per_sample = (bits / 8) as usize;
    if bytes_per_sample == 0 {
        return None;
    }
    let mut samples: Vec<f64> = Vec::with_capacity(data.len() / bytes_per_sample);
    match (format_tag, bits) {
        (1, 8) => {
            for byte in data {
                samples.push((f64::from(*byte) - 128.0) / 128.0);
            }
        }
        (1, 16) => {
            for chunk in data.as_chunks::<2>().0 {
                samples.push(f64::from(i16::from_le_bytes([chunk[0], chunk[1]])) / 32_768.0);
            }
        }
        (1, 24) => {
            for chunk in data.as_chunks::<3>().0 {
                let value =
                    i32::from(chunk[0]) | i32::from(chunk[1]) << 8 | i32::from(chunk[2]) << 16;
                let signed = if value & 0x0080_0000 != 0 {
                    value - 0x0100_0000
                } else {
                    value
                };
                samples.push(f64::from(signed) / 8_388_608.0);
            }
        }
        (1, 32) => {
            for chunk in data.as_chunks::<4>().0 {
                samples.push(
                    f64::from(i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                        / 2_147_483_648.0,
                );
            }
        }
        (3, 32) => {
            for chunk in data.as_chunks::<4>().0 {
                samples.push(f64::from(f32::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3],
                ])));
            }
        }
        (3, 64) => {
            for chunk in data.as_chunks::<8>().0 {
                samples.push(f64::from_le_bytes(*chunk));
            }
        }
        _ => return None,
    }
    let _ = (bits, format_tag);
    Some(WavData {
        channels,
        sample_rate,
        samples,
    })
}

/// Iterative radix-2 FFT (in place) over (re, im).
fn fft(re: &mut [f64], im: &mut [f64]) {
    let n = re.len();
    debug_assert!(n.is_power_of_two() && im.len() == n);
    // Bit-reversal permutation.
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let mut len = 2usize;
    while len <= n {
        let angle = -2.0 * std::f64::consts::PI / len as f64;
        let (w_re, w_im) = (angle.cos(), angle.sin());
        for start in (0..n).step_by(len) {
            let (mut cur_re, mut cur_im) = (1.0f64, 0.0f64);
            for k in 0..len / 2 {
                let (a, b) = (start + k, start + k + len / 2);
                let (t_re, t_im) = (
                    re[b] * cur_re - im[b] * cur_im,
                    re[b] * cur_im + im[b] * cur_re,
                );
                re[b] = re[a] - t_re;
                im[b] = im[a] - t_im;
                re[a] += t_re;
                im[a] += t_im;
                let next_re = cur_re * w_re - cur_im * w_im;
                cur_im = cur_re * w_im + cur_im * w_re;
                cur_re = next_re;
            }
        }
        len <<= 1;
    }
}

/// Derived measurements for one decoded WAV.
fn wav_measurements(wav: &WavData) -> Value {
    let channels = wav.channels.max(1) as usize;
    let frames = wav.samples.len() / channels;
    let mut peak = 0.0f64;
    let mut sum = 0.0f64;
    let mut sum_sq = 0.0f64;
    for sample in &wav.samples {
        peak = peak.max(sample.abs());
        sum += sample;
        sum_sq += sample * sample;
    }
    let count = wav.samples.len().max(1) as f64;
    let dc_offset = sum / count;
    let rms = (sum_sq / count).sqrt();
    let crest = if rms > 0.0 { peak / rms } else { 0.0 };
    // Silence map: frames whose every channel is below
    // -50 dBFS, runs of at least 50 ms, in frames.
    let threshold = 0.003_162_277_660_168_379; // 10^(-50/20)
    let min_run = (wav.sample_rate / 20).max(1) as usize;
    let mut silence: Vec<Value> = Vec::new();
    let mut run_start: Option<usize> = None;
    for frame in 0..frames {
        let silent =
            (0..channels).all(|channel| wav.samples[frame * channels + channel].abs() < threshold);
        match (silent, run_start) {
            (true, None) => run_start = Some(frame),
            (false, Some(start)) => {
                if frame - start >= min_run && silence.len() < AUDIO_SILENCE_RUNS_MAX {
                    silence.push(json!([start, frame]));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = run_start
        && frames - start >= min_run
        && silence.len() < AUDIO_SILENCE_RUNS_MAX
    {
        silence.push(json!([start, frames]));
    }
    // Zero-crossing rate on the first channel.
    let mut crossings = 0u64;
    for frame in 1..frames {
        let previous = wav.samples[(frame - 1) * channels];
        let current = wav.samples[frame * channels];
        if (previous < 0.0) != (current < 0.0) {
            crossings += 1;
        }
    }
    let duration = frames as f64 / f64::from(wav.sample_rate);
    let zcr_per_second = if duration > 0.0 {
        crossings as f64 / duration
    } else {
        0.0
    };
    // Spectral summary: Hann-windowed radix-2 FFT over
    // up to AUDIO_ANALYZE_SEGMENTS_MAX evenly spaced
    // segments of the first channel.
    let mut spectral = Value::Null;
    let window = if frames >= 256 {
        let mut size = 256usize;
        while size * 2 <= frames && size < 8192 {
            size *= 2;
        }
        size
    } else {
        0
    };
    if let Some(segment_pool) = frames.checked_div(window) {
        let segments = AUDIO_ANALYZE_SEGMENTS_MAX.min(segment_pool).max(1);
        let mut power = vec![0.0f64; window / 2];
        for segment in 0..segments {
            let start = if segments == 1 {
                0
            } else {
                segment * (frames - window) / (segments - 1)
            };
            let mut re = vec![0.0f64; window];
            let mut im = vec![0.0f64; window];
            for (index, slot) in re.iter_mut().enumerate() {
                let hann = 0.5
                    - 0.5 * (2.0 * std::f64::consts::PI * index as f64 / (window - 1) as f64).cos();
                *slot = wav.samples[(start + index) * channels] * hann;
            }
            fft(&mut re, &mut im);
            for bin in 0..window / 2 {
                power[bin] += (re[bin] * re[bin] + im[bin] * im[bin]) / segments as f64;
            }
        }
        let bin_hz = f64::from(wav.sample_rate) / window as f64;
        let mut weighted = 0.0f64;
        let mut magnitude_sum = 0.0f64;
        let bands: [(&str, f64, f64); 5] = [
            ("0-250", 0.0, 250.0),
            ("250-2000", 250.0, 2_000.0),
            ("2000-6000", 2_000.0, 6_000.0),
            ("6000-12000", 6_000.0, 12_000.0),
            ("12000+", 12_000.0, f64::INFINITY),
        ];
        let mut band_power = [0.0f64; 5];
        let mut total_power = 0.0f64;
        for (bin, value) in power.iter().enumerate() {
            let frequency = bin as f64 * bin_hz;
            let magnitude = value.sqrt();
            weighted += frequency * magnitude;
            magnitude_sum += magnitude;
            total_power += value;
            for (band_index, (_, low, high)) in bands.iter().enumerate() {
                if frequency >= *low && frequency < *high {
                    band_power[band_index] += value;
                }
            }
        }
        let centroid = if magnitude_sum > 0.0 {
            weighted / magnitude_sum
        } else {
            0.0
        };
        let mut band_json = serde_json::Map::new();
        for (band_index, (name, _, _)) in bands.iter().enumerate() {
            let share = if total_power > 0.0 {
                band_power[band_index] / total_power
            } else {
                0.0
            };
            band_json.insert((*name).to_string(), json!(round6(share)));
        }
        spectral = json!({
            "band_energy_shares": band_json,
            "fft_window": window,
            "segments": segments,
            "spectral_centroid_hz": round3(centroid),
        });
    }
    json!({
        "crest_factor": round6(crest),
        "crest_factor_db": round3(20.0 * crest.max(1e-12).log10()),
        "dc_offset": round6(dc_offset),
        "duration_seconds": round3(duration),
        "frames": frames,
        "peak": round6(peak),
        "rms": round6(rms),
        "silence_runs": silence,
        "spectral": spectral,
        "zero_crossing_rate_per_second": round3(zcr_per_second),
    })
}

pub fn analyze_audio_file(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, AUDIO_ANALYZE_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let size = subject.size_bytes;
    let mut evidence = Evidence::new("analyze_audio_file", "audio");
    evidence.subject = Some(subject);
    let bytes =
        std::fs::read(&path).map_err(|error| mismatch(format!("cannot read target: {error}")))?;
    // Container pointers: these magics belong to the
    // container census tools, not this single-file lane.
    if bytes.starts_with(b"FSB5") {
        evidence.add_finding(
            Finding::new(
                "audio_header",
                Confidence::Observed,
                json!({
                    "detected_format": "fsb5",
                    "format": "FMOD FSB5 container",
                    "sha256": sha256,
                    "size_bytes": size,
                }),
            )
            .with_limitation(
                "FSB5 is a container; use census_fsb5_container for its banks and subsounds",
            ),
        );
        return Ok(evidence.to_value());
    }
    if bytes.starts_with(b"HCA\0") {
        evidence.add_finding(
            Finding::new(
                "audio_header",
                Confidence::Observed,
                json!({
                    "detected_format": "hca",
                    "format": "CRI HCA stream",
                    "sha256": sha256,
                    "size_bytes": size,
                }),
            )
            .with_limitation("HCA streams are extracted by extract_cri_acb from their ACB/AFS2 container; this lane does not decode HCA"),
        );
        return Ok(evidence.to_value());
    }
    if bytes.starts_with(b"@UTF") {
        evidence.add_finding(
            Finding::new(
                "audio_header",
                Confidence::Observed,
                json!({
                    "detected_format": "cri_acb",
                    "format": "CRI Atom ACB cue sheet",
                    "sha256": sha256,
                    "size_bytes": size,
                }),
            )
            .with_limitation("an ACB is a container; use census_cri_acb for its streams"),
        );
        return Ok(evidence.to_value());
    }
    // Loose-file header facts reuse the R7 census
    // parsers (the same code census_audio_tree runs).
    let head_len = (bytes.len() as u64).min(fathom_core::limits::AUDIO_HEAD_BYTES_MAX) as usize;
    let head = &bytes[..head_len];
    let tail = &bytes[bytes.len().saturating_sub(65_536)..];
    let facts = if bytes.starts_with(b"RIFF") {
        crate::audio::wav_facts(head, size)
    } else if bytes.starts_with(b"OggS") {
        crate::audio::ogg_facts(head, tail)
    } else if bytes.starts_with(b"fLaC") {
        crate::audio::flac_facts(head)
    } else if bytes.starts_with(b"ID3") || bytes.first() == Some(&0xFF) {
        crate::audio::mp3_facts(head, size)
    } else if bytes.get(4..8).is_some_and(|magic| magic == b"ftyp") {
        crate::audio::m4a_facts(head)
    } else {
        crate::audio::AudioFacts::default()
    };
    evidence.add_finding(Finding::new(
        "audio_header",
        Confidence::Observed,
        json!({
            "channels": facts.channels,
            "codec": facts.codec,
            "duration_basis": facts.duration_basis,
            "duration_seconds": facts.duration_seconds,
            "sample_rate": facts.sample_rate,
            "sha256": sha256,
            "size_bytes": size,
        }),
    ));
    if bytes.starts_with(b"RIFF") {
        match parse_wav(&bytes) {
            Some(wav) => {
                let measurements = wav_measurements(&wav);
                evidence.add_finding(
                    Finding::new(
                        "audio_measurements",
                        Confidence::Derived,
                        measurements,
                    )
                    .with_limitation(
                        "method: samples decoded from integer/float PCM to f64 in [-1, 1); peak/RMS/DC over all channels' samples; silence = frames with every channel below -50 dBFS for at least 50 ms, ranges in frames; zero-crossing rate on the first channel; spectral summary = Hann-windowed radix-2 FFT over up to 8 evenly spaced segments of the first channel, centroid from the averaged magnitude spectrum, band shares from the averaged power spectrum",
                    ),
                );
            }
            None => evidence.add_unknown(
                "measurements",
                "the WAV is not integer/float PCM this lane decodes (or its chunks are inconsistent); header facts only",
            ),
        }
    } else {
        evidence.add_unknown(
            "measurements",
            "sample measurements are implemented for WAV PCM only; other formats are header-census only in this lane",
        );
    }
    Ok(evidence.to_value())
}

// ----------------------------------------------------------------
// Tests
// ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-audio-re-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with_root(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    // ---- FSB5 fixtures ----

    struct FixtureSub {
        channels_code: u64,
        data: Vec<u8>,
        extras: Vec<(u32, Vec<u8>)>,
        num_samples: u64,
        rate_index: u64,
    }

    fn fixture_sub(num_samples: u64, data_len: usize) -> FixtureSub {
        FixtureSub {
            channels_code: 1,
            data: vec![0x5A; data_len],
            extras: Vec::new(),
            num_samples,
            rate_index: 8,
        }
    }

    /// Build one FSB5 bank (version 1) from fixture
    /// subsounds; data offsets are 32-byte aligned.
    fn fsb5_bank_bytes(codec: u32, subs: &[FixtureSub], names: Option<&[&str]>) -> Vec<u8> {
        let mut headers: Vec<u8> = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        for sub in subs {
            let data_offset = data.len() as u64;
            let mut mode: u64 = 0;
            if !sub.extras.is_empty() {
                mode |= 1;
            }
            mode |= (sub.rate_index & 0x0F) << 1;
            mode |= (sub.channels_code & 0x03) << 5;
            mode |= ((data_offset >> 5) & 0x07FF_FFFF) << 7;
            mode |= (sub.num_samples & 0x3FFF_FFFF) << 34;
            headers.extend_from_slice(&mode.to_le_bytes());
            for (index, (kind, payload)) in sub.extras.iter().enumerate() {
                let continues = u32::from(index + 1 < sub.extras.len());
                let header = ((kind & 0x7F) << 25)
                    | (((payload.len() as u32) & 0x00FF_FFFF) << 1)
                    | continues;
                headers.extend_from_slice(&header.to_le_bytes());
                headers.extend_from_slice(payload);
            }
            data.extend_from_slice(&sub.data);
            while !data.len().is_multiple_of(32) {
                data.push(0);
            }
        }
        let mut name_table: Vec<u8> = Vec::new();
        if let Some(names) = names {
            let mut offsets: Vec<u32> = Vec::new();
            let mut strings: Vec<u8> = Vec::new();
            for name in names {
                offsets.push((names.len() * 4 + strings.len()) as u32);
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
            }
            for offset in offsets {
                name_table.extend_from_slice(&offset.to_le_bytes());
            }
            name_table.extend_from_slice(&strings);
        }
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"FSB5");
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(subs.len() as u32).to_le_bytes());
        out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_table.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&codec.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // 0x1c zero
        out.extend_from_slice(&0u32.to_le_bytes()); // 0x20 flags
        out.extend_from_slice(&[0u8; 16]); // name hash
        out.extend_from_slice(&[0u8; 8]); // sub-hash
        assert_eq!(out.len(), 60);
        out.extend_from_slice(&headers);
        out.extend_from_slice(&name_table);
        out.extend_from_slice(&data);
        out
    }

    fn parse_bytes(bytes: &[u8], tag: &str) -> (Vec<Fsb5Bank>, Vec<String>) {
        let dir = scratch(tag);
        let path = write_temp(&dir, "in.resource", bytes);
        let mut file = File::open(&path).unwrap();
        let len = bytes.len() as u64;
        let parsed = parse_fsb5_banks(&mut file, len).expect("parse");
        std::fs::remove_dir_all(&dir).ok();
        parsed
    }

    #[test]
    fn validation_fsb5_two_pcm_subsounds_and_loop_extra() {
        let mut first = fixture_sub(44_100, 128);
        first.channels_code = 1; // stereo
        let mut loop_payload = Vec::new();
        loop_payload.extend_from_slice(&100u32.to_le_bytes());
        loop_payload.extend_from_slice(&43_998u32.to_le_bytes()); // stored end-1
        first.extras.push((3, loop_payload));
        let mut second = fixture_sub(22_050, 64);
        second.channels_code = 0; // mono
        let bytes = fsb5_bank_bytes(2, &[first, second], None);
        let (banks, limitations) = parse_bytes(&bytes, "fsb-two");
        assert!(limitations.is_empty(), "{limitations:?}");
        assert_eq!(banks.len(), 1);
        let bank = &banks[0];
        assert_eq!(bank.codec, 2);
        assert_eq!(bank.subsounds.len(), 2);
        let sub0 = &bank.subsounds[0];
        assert_eq!(sub0.sample_rate, Some(44_100));
        assert_eq!(sub0.channels, Some(2));
        assert_eq!(sub0.num_samples, 44_100);
        assert_eq!(sub0.data_offset, 0);
        assert_eq!(sub0.data_size, 128);
        assert_eq!(sub0.loop_start, Some(100));
        assert_eq!(sub0.loop_end, Some(43_999));
        let sub1 = &bank.subsounds[1];
        assert_eq!(sub1.channels, Some(1));
        assert_eq!(sub1.data_offset, 128);
        assert_eq!(sub1.data_size, 64);
        assert_eq!(sub1.loop_start, None);
    }

    #[test]
    fn validation_fsb5_two_banks_concatenated() {
        let bank_a = fsb5_bank_bytes(15, &[fixture_sub(10_164, 96)], None);
        let bank_b = fsb5_bank_bytes(2, &[fixture_sub(2_338, 64)], None);
        let mut both = bank_a.clone();
        both.extend_from_slice(&bank_b);
        let (banks, limitations) = parse_bytes(&both, "fsb-concat");
        assert!(limitations.is_empty(), "{limitations:?}");
        assert_eq!(banks.len(), 2);
        assert_eq!(banks[0].bank_offset, 0);
        assert_eq!(banks[0].codec, 15);
        assert_eq!(banks[1].bank_offset, bank_a.len() as u64);
        assert_eq!(banks[1].codec, 2);
        assert_eq!(banks[1].subsounds[0].num_samples, 2_338);
    }

    #[test]
    fn validation_fsb5_name_table_and_channel_extra() {
        let mut sub = fixture_sub(4_800, 32);
        sub.channels_code = 1;
        sub.extras.push((1, vec![6u8])); // channels override: 6
        let bytes = fsb5_bank_bytes(15, &[sub], Some(&["theme_main"]));
        let (banks, _) = parse_bytes(&bytes, "fsb-names");
        let parsed = &banks[0].subsounds[0];
        assert_eq!(parsed.name.as_deref(), Some("theme_main"));
        assert_eq!(parsed.channels, Some(6));
    }

    #[test]
    fn adversarial_fsb5_bad_magic_is_refused() {
        let dir = scratch("fsb-badmagic");
        let path = write_temp(&dir, "in.bin", b"NOPE not a bank at all......");
        let mut file = File::open(&path).unwrap();
        assert!(parse_fsb5_banks(&mut file, 28).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_fsb5_declared_size_past_eof_is_partial_not_panic() {
        let mut bytes = fsb5_bank_bytes(2, &[fixture_sub(100, 64)], None);
        // Lie: data size far past EOF.
        bytes[20..24].copy_from_slice(&9_000_000u32.to_le_bytes());
        let (banks, _) = parse_bytes(&bytes, "fsb-lying");
        assert_eq!(banks.len(), 1);
        assert!(banks[0].subsounds.is_empty());
        assert!(!banks[0].limitations.is_empty());
    }

    #[test]
    fn adversarial_fsb5_lying_data_offset_yields_zero_size_and_limitation() {
        let mut sub = fixture_sub(100, 64);
        sub.data = vec![0x5A; 64];
        let mut bytes = fsb5_bank_bytes(2, &[sub], None);
        // Corrupt the sample header's data offset (bits
        // 7..33) to point past the data section.
        let mode_at = 60usize;
        let mut mode = u64_le(&bytes, mode_at).unwrap();
        mode |= 0xFFFFu64 << 7;
        bytes[mode_at..mode_at + 8].copy_from_slice(&mode.to_le_bytes());
        let (banks, _) = parse_bytes(&bytes, "fsb-badoffset");
        assert_eq!(banks[0].subsounds[0].data_size, 0);
        assert!(
            banks[0]
                .limitations
                .iter()
                .any(|text| text.contains("inconsistent"))
        );
    }

    #[test]
    fn validation_extract_fsb5_pcm_writes_wav_and_manifest() {
        let dir = scratch("fsb-extract");
        let root = dir.clone();
        let bytes = fsb5_bank_bytes(2, &[fixture_sub(1_000, 64)], None);
        let source = write_temp(&root, "bank.resource", &bytes);
        let registry = Registry::new();
        let config = config_with_root(&root);
        let out = root.join("out");
        let value = extract_fsb5_audio(
            &registry,
            &config,
            &json!({"target": source.display().to_string(), "output_dir": out.display().to_string()}),
        )
        .expect("extract");
        let findings = value["findings"].as_array().unwrap();
        let entries = &findings[1]["facts"]["entries"];
        assert_eq!(entries[0]["status"], "decoded-pcm");
        assert!(out.join("bank00_sub000.wav").is_file());
        assert!(out.join("manifest.json").is_file());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_extract_fsb5_output_dir_escape_is_refused() {
        let dir = scratch("fsb-escape");
        let outside = scratch("fsb-escape-outside");
        let bytes = fsb5_bank_bytes(2, &[fixture_sub(10, 32)], None);
        let source = write_temp(&dir, "bank.resource", &bytes);
        let registry = Registry::new();
        let config = config_with_root(&dir);
        let result = extract_fsb5_audio(
            &registry,
            &config,
            &json!({
                "target": source.display().to_string(),
                "output_dir": outside.join("loot").display().to_string(),
            }),
        );
        assert!(result.is_err());
        assert!(!outside.join("loot").exists());
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn validation_vgmstream_fake_decoder_is_located_and_run() {
        let dir = scratch("vgm-fake");
        let version_dir = dir.join("vgmstream-r0000");
        std::fs::create_dir_all(&version_dir).unwrap();
        let cli = version_dir.join("vgmstream-cli");
        let script = "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"-o\" ]; then out=\"$a\"; fi\n  prev=\"$a\"\ndone\nprintf 'FAKEWAV' > \"$out\"\nexit 0\n";
        std::fs::write(&cli, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let located = locate_vgmstream_cli(&dir).expect("locate");
        assert_eq!(located, cli);
        let bank = write_temp(&dir, "bank.fsb", b"FSB5 fake");
        let decoded_path = dir.join("out.wav");
        let bytes = vgmstream_decode(&located, &bank, 0, &decoded_path).expect("decode");
        assert_eq!(bytes, b"FAKEWAV");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- CRI fixtures ----

    /// A minimal @UTF table builder: all columns are
    /// per-row; strings and data blobs supplied by the
    /// caller.
    fn utf_table(
        name: &str,
        columns: &[(&str, u8)],
        rows: &[Vec<UtfFixtureCell>],
        data_blobs: &[&[u8]],
    ) -> Vec<u8> {
        // String section: \0 + table name + column names
        // + string cell values (collected in row order).
        let mut strings: Vec<u8> = vec![0];
        let mut string_offsets: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        let mut intern = |text: &str, strings: &mut Vec<u8>| -> u32 {
            if let Some(offset) = string_offsets.get(text) {
                return *offset;
            }
            let offset = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            string_offsets.insert(text.to_string(), offset);
            offset
        };
        let table_name_offset = intern(name, &mut strings);
        let mut column_name_offsets: Vec<u32> = Vec::new();
        for (column_name, _) in columns {
            column_name_offsets.push(intern(column_name, &mut strings));
        }
        // Data section layout first (offsets depend only
        // on blob sizes).
        let mut data_offsets: Vec<u32> = Vec::new();
        let mut data_section: Vec<u8> = Vec::new();
        for blob in data_blobs {
            data_offsets.push(data_section.len() as u32);
            data_section.extend_from_slice(blob);
        }
        // Row width + encoded rows (string cells need
        // their offsets interned before encoding).
        let sizes: Vec<usize> = columns
            .iter()
            .map(|(_, kind)| utf_value_size(*kind).unwrap())
            .collect();
        let row_width: usize = sizes.iter().sum();
        let mut encoded_rows: Vec<u8> = Vec::new();
        let mut blob_cursor = 0usize;
        for row in rows {
            assert_eq!(row.len(), columns.len());
            for (cell, kind) in row.iter().zip(columns.iter().map(|(_, kind)| kind)) {
                match (cell, kind) {
                    (UtfFixtureCell::UInt(value), 0) => encoded_rows.push(*value as u8),
                    (UtfFixtureCell::UInt(value), 2) => {
                        encoded_rows.extend_from_slice(&(*value as u16).to_be_bytes())
                    }
                    (UtfFixtureCell::UInt(value), 4) => {
                        encoded_rows.extend_from_slice(&(*value as u32).to_be_bytes())
                    }
                    (UtfFixtureCell::Str(text), 10) => {
                        let offset = intern(text, &mut strings);
                        encoded_rows.extend_from_slice(&offset.to_be_bytes());
                    }
                    (UtfFixtureCell::Blob(size), 11) => {
                        let offset = data_offsets[blob_cursor];
                        blob_cursor += 1;
                        encoded_rows.extend_from_slice(&offset.to_be_bytes());
                        encoded_rows.extend_from_slice(&(*size as u32).to_be_bytes());
                    }
                    _ => panic!("fixture cell/kind mismatch"),
                }
            }
        }
        let schema_size = columns.len() * 5;
        let rows_offset = 0x20 + schema_size;
        let strings_offset = rows_offset + encoded_rows.len();
        let data_offset = strings_offset + strings.len();
        let total = data_offset + data_section.len();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"@UTF");
        out.extend_from_slice(&((total - 8) as u32).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&((rows_offset - 8) as u16).to_be_bytes());
        out.extend_from_slice(&((strings_offset - 8) as u32).to_be_bytes());
        out.extend_from_slice(&((data_offset - 8) as u32).to_be_bytes());
        out.extend_from_slice(&table_name_offset.to_be_bytes());
        out.extend_from_slice(&(columns.len() as u16).to_be_bytes());
        out.extend_from_slice(&(row_width as u16).to_be_bytes());
        out.extend_from_slice(&(rows.len() as u32).to_be_bytes());
        assert_eq!(out.len(), 0x20);
        for ((_, kind), name_offset) in columns.iter().zip(column_name_offsets.iter()) {
            out.push(0x50 | kind); // NAME + ROW flags
            out.extend_from_slice(&name_offset.to_be_bytes());
        }
        out.extend_from_slice(&encoded_rows);
        out.extend_from_slice(&strings);
        out.extend_from_slice(&data_section);
        assert_eq!(out.len(), total);
        out
    }

    enum UtfFixtureCell {
        Blob(usize),
        Str(String),
        UInt(u64),
    }

    fn afs2_fixture(streams: &[&[u8]]) -> Vec<u8> {
        let count = streams.len();
        let ids_size = count * 2;
        let offsets_size = (count + 1) * 4;
        let first_offset = 16 + ids_size + offsets_size;
        let mut offsets: Vec<u32> = Vec::new();
        let mut cursor = first_offset;
        for stream in streams {
            offsets.push(cursor as u32);
            cursor += stream.len();
            while !cursor.is_multiple_of(32) {
                cursor += 1;
            }
        }
        offsets.push((cursor) as u32);
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"AFS2");
        out.push(0);
        out.push(4); // offset size
        out.extend_from_slice(&2u16.to_le_bytes()); // wave-id alignment
        out.extend_from_slice(&(count as u32).to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes()); // offset alignment
        out.extend_from_slice(&0u16.to_le_bytes()); // subkey
        for index in 0..count {
            out.extend_from_slice(&(index as u16).to_le_bytes());
        }
        for offset in &offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        for (index, stream) in streams.iter().enumerate() {
            while out.len() < offsets[index] as usize {
                out.push(0);
            }
            out.extend_from_slice(stream);
        }
        out
    }

    fn acb_fixture() -> Vec<u8> {
        let hca_a = {
            let mut bytes = b"HCA\0".to_vec();
            bytes.extend_from_slice(&[0u8; 60]);
            bytes
        };
        let hca_b = {
            let mut bytes = b"HCA\0".to_vec();
            bytes.extend_from_slice(&[1u8; 28]);
            bytes
        };
        let afs2 = afs2_fixture(&[&hca_a, &hca_b]);
        let cue_names = utf_table(
            "CueName",
            &[("CueName", 10), ("CueIndex", 2)],
            &[
                vec![
                    UtfFixtureCell::Str("bgm_one".into()),
                    UtfFixtureCell::UInt(0),
                ],
                vec![
                    UtfFixtureCell::Str("se_two".into()),
                    UtfFixtureCell::UInt(1),
                ],
            ],
            &[],
        );
        let waveforms = utf_table(
            "Waveform",
            &[
                ("MemoryAwbId", 2),
                ("EncodeType", 0),
                ("Streaming", 0),
                ("NumChannels", 0),
                ("LoopFlag", 0),
                ("SamplingRate", 4),
                ("NumSamples", 4),
                ("StreamAwbId", 2),
            ],
            &[
                vec![
                    UtfFixtureCell::UInt(0),
                    UtfFixtureCell::UInt(2),
                    UtfFixtureCell::UInt(0),
                    UtfFixtureCell::UInt(2),
                    UtfFixtureCell::UInt(0),
                    UtfFixtureCell::UInt(44_100),
                    UtfFixtureCell::UInt(22_050),
                    UtfFixtureCell::UInt(0),
                ],
                vec![
                    UtfFixtureCell::UInt(1),
                    UtfFixtureCell::UInt(2),
                    UtfFixtureCell::UInt(0),
                    UtfFixtureCell::UInt(1),
                    UtfFixtureCell::UInt(1),
                    UtfFixtureCell::UInt(48_000),
                    UtfFixtureCell::UInt(48_000),
                    UtfFixtureCell::UInt(1),
                ],
            ],
            &[],
        );
        utf_table(
            "Header",
            &[
                ("Name", 10),
                ("CueNameTable", 11),
                ("WaveformTable", 11),
                ("AwbFile", 11),
            ],
            &[vec![
                UtfFixtureCell::Str("TestAcb".into()),
                UtfFixtureCell::Blob(cue_names.len()),
                UtfFixtureCell::Blob(waveforms.len()),
                UtfFixtureCell::Blob(afs2.len()),
            ]],
            &[&cue_names, &waveforms, &afs2],
        )
    }

    #[test]
    fn validation_cri_acb_census_facts() {
        let bytes = acb_fixture();
        let parsed = load_acb(&bytes).expect("load acb");
        assert_eq!(parsed.acb_name.as_deref(), Some("TestAcb"));
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].id, 0);
        assert_eq!(afs2_entry_kind(&bytes, &parsed.entries[0]), "hca");
        assert_eq!(afs2_entry_kind(&bytes, &parsed.entries[1]), "hca");
        assert_eq!(parsed.cue_names.len(), 2);
        assert_eq!(parsed.cue_names[0]["name"], "bgm_one");
        assert_eq!(parsed.cue_names[1]["cue_index"], 1);
        assert_eq!(parsed.waveforms.len(), 2);
        assert_eq!(parsed.waveforms[1]["LoopFlag"], 1);
        assert_eq!(parsed.waveforms[0]["SamplingRate"], 44_100);
        let paired = waveform_for_entry(&parsed, &parsed.entries[1]).expect("pair");
        assert_eq!(paired["NumSamples"], 48_000);
    }

    #[test]
    fn adversarial_cri_bad_magic_is_refused() {
        assert!(load_acb(b"NOPE not an acb").is_err());
    }

    #[test]
    fn adversarial_cri_afs2_count_lies_past_eof() {
        let mut bytes = acb_fixture();
        // Find the AFS2 blob and inflate its entry count.
        let at = bytes
            .windows(4)
            .position(|window| window == b"AFS2")
            .unwrap();
        bytes[at + 8..at + 12].copy_from_slice(&99_999u32.to_le_bytes());
        assert!(load_acb(&bytes).is_err());
    }

    // ---- RPG Maker MV ----

    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff";

    fn mv_encrypt(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"RPGMV\0\0\0\0\x03\x01\x01\x01\x01\x01\x01");
        assert_eq!(out.len(), 16);
        let mut body = plain.to_vec();
        for (index, byte) in body.iter_mut().take(16).enumerate() {
            *byte ^= key[index];
        }
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn validation_mv_encrypt_decrypt_roundtrip() {
        let key = mv_key_from_hex(TEST_KEY_HEX).expect("key");
        let mut plain = b"OggS".to_vec();
        plain.extend_from_slice(&[7u8; 500]);
        let encrypted = mv_encrypt(&plain, &key);
        let decrypted = mv_decrypt(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn adversarial_mv_bad_header_and_bad_key() {
        let key = mv_key_from_hex(TEST_KEY_HEX).expect("key");
        assert!(mv_decrypt(b"OggS without the fake header........", &key).is_none());
        assert!(mv_key_from_hex("00112233").is_none());
        assert!(mv_key_from_hex("zz112233445566778899aabbccddeeff").is_none());
    }

    #[test]
    fn validation_mv_handler_extracts_verified_ogg() {
        let dir = scratch("mv-handler");
        let www = dir.join("www");
        std::fs::create_dir_all(www.join("data")).unwrap();
        std::fs::create_dir_all(www.join("audio/bgm")).unwrap();
        std::fs::write(
            www.join("data/System.json"),
            format!("{{\"encryptionKey\":\"{TEST_KEY_HEX}\",\"hasEncryptedAudio\":true}}"),
        )
        .unwrap();
        let key = mv_key_from_hex(TEST_KEY_HEX).unwrap();
        let mut plain = b"OggS".to_vec();
        plain.extend_from_slice(&[3u8; 200]);
        std::fs::write(www.join("audio/bgm/theme.rpgmvo"), mv_encrypt(&plain, &key)).unwrap();
        let registry = Registry::new();
        let config = config_with_root(&dir);
        let out = dir.join("out");
        let value = extract_rpgmaker_mv_audio(
            &registry,
            &config,
            &json!({"target": dir.display().to_string(), "output_dir": out.display().to_string()}),
        )
        .expect("extract");
        let findings = value["findings"].as_array().unwrap();
        let entries = &findings[1]["facts"]["entries"];
        assert_eq!(entries[0]["status"], "verified");
        let written = std::fs::read(out.join("audio/bgm/theme.ogg")).unwrap();
        assert_eq!(written, plain);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- analyze_audio_file ----

    fn sine_wav_bytes(rate: u32, seconds: f64, frequency: f64, amplitude: f64) -> Vec<u8> {
        let frames = (rate as f64 * seconds) as usize;
        let mut pcm: Vec<u8> = Vec::with_capacity(frames * 2);
        for index in 0..frames {
            let phase = 2.0 * std::f64::consts::PI * frequency * index as f64 / rate as f64;
            let sample = (phase.sin() * amplitude * 32_767.0) as i16;
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
        wrap_pcm_as_wav(&pcm, 1, 16, 1, rate)
    }

    #[test]
    fn validation_wav_measurements_match_known_sine() {
        let bytes = sine_wav_bytes(44_100, 1.0, 440.0, 0.5);
        let wav = parse_wav(&bytes).expect("wav");
        let measured = wav_measurements(&wav);
        let peak = measured["peak"].as_f64().unwrap();
        let rms = measured["rms"].as_f64().unwrap();
        assert!((peak - 0.5).abs() < 0.002, "peak {peak}");
        assert!((rms - 0.353_55).abs() < 0.002, "rms {rms}");
        let centroid = measured["spectral"]["spectral_centroid_hz"]
            .as_f64()
            .unwrap();
        assert!((centroid - 440.0).abs() < 15.0, "centroid {centroid}");
        assert_eq!(measured["silence_runs"].as_array().unwrap().len(), 0);
        assert!(measured["dc_offset"].as_f64().unwrap().abs() < 0.001);
    }

    #[test]
    fn validation_analyze_handler_reports_header_and_measurements() {
        let dir = scratch("analyze-handler");
        let path = write_temp(&dir, "tone.wav", &sine_wav_bytes(44_100, 0.5, 440.0, 0.5));
        let registry = Registry::new();
        let config = config_with_root(&dir);
        let value = analyze_audio_file(
            &registry,
            &config,
            &json!({"target": path.display().to_string()}),
        )
        .expect("analyze");
        let findings = value["findings"].as_array().unwrap();
        assert_eq!(findings[0]["facts"]["codec"], "pcm");
        assert_eq!(findings[1]["kind"], "audio_measurements");
        assert_eq!(findings[1]["confidence"], "derived");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_analyze_truncated_wav_yields_no_measurements() {
        let bytes = sine_wav_bytes(44_100, 0.25, 440.0, 0.5);
        let truncated = &bytes[..30];
        assert!(parse_wav(truncated).is_none());
        let dir = scratch("analyze-trunc");
        let path = write_temp(&dir, "broken.wav", truncated);
        let registry = Registry::new();
        let config = config_with_root(&dir);
        let value = analyze_audio_file(
            &registry,
            &config,
            &json!({"target": path.display().to_string()}),
        )
        .expect("analyze");
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "measurements")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_analyze_non_audio_has_no_codec() {
        let dir = scratch("analyze-non");
        let path = write_temp(&dir, "notes.txt", b"definitely not audio bytes at all");
        let registry = Registry::new();
        let config = config_with_root(&dir);
        let value = analyze_audio_file(
            &registry,
            &config,
            &json!({"target": path.display().to_string()}),
        )
        .expect("analyze");
        assert!(value["findings"][0]["facts"]["codec"].is_null());
        std::fs::remove_dir_all(&dir).ok();
    }
}
