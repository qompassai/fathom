//! Reads over a retained ingest (§4.6): a summary view that
//! carries no evidence payloads, paged inventory reads under
//! `PAGE_LIMIT_MAX`, and single-frame payload return bounded
//! by `VIDEO_FRAME_BYTES_MAX`. Every load runs the store's
//! integrity checks (document digest + media re-hash).

use std::path::Path;

use base64::Engine;
use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::limits::{PAGE_LIMIT_MAX, VIDEO_FRAME_BYTES_MAX};
use fathom_core::registry::{Registry, optional_str, require_str};

/// The inventory names a read may page, and the finding kind
/// each record surfaces as (§5.1).
const INVENTORIES: [(&str, &str); 6] = [
    ("chapters", "chapter"),
    ("coverage_gaps", "coverage_gap"),
    ("demonstration_events", "demonstration_event"),
    ("frames", "frame_sample"),
    ("transcript_disagreements", "transcript_disagreement"),
    ("transcript_spans", "transcript_span"),
];

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message)
}

fn page_bounds(args: &Value) -> Result<(usize, usize), FathomError> {
    let limit = match args.get("limit") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid("argument 'limit' must be a non-negative integer"))?
            as usize,
        None => PAGE_LIMIT_MAX,
    };
    if limit == 0 || limit > PAGE_LIMIT_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!("limit must be within 1..=PAGE_LIMIT_MAX ({PAGE_LIMIT_MAX})"),
        ));
    }
    let offset = match args.get("offset") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid("argument 'offset' must be a non-negative integer"))?
            as usize,
        None => 0,
    };
    Ok((limit, offset))
}

/// Read one retained ingest: summary by default, one paged
/// inventory when `inventory` names one, or one frame's
/// payload when `frame_key` is given.
pub fn read_video_ingest(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let ingest_id = require_str(args, "ingest_id")?;
    let loaded = crate::document::load_ingest(config, ingest_id)?;
    let document = &loaded.document;
    let mut evidence = Evidence::new("read_video_ingest", "video");
    evidence.subject = Some(fathom_core::evidence::Subject {
        path: document["subject"]["path"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        sha256: loaded.subject_sha256.clone(),
        size_bytes: document["subject"]["size_bytes"].as_u64().unwrap_or(0),
    });

    if let Some(frame_key) = optional_str(args, "frame_key") {
        let frame = document["inventories"]["frames"]
            .as_array()
            .and_then(|frames| {
                frames
                    .iter()
                    .find(|frame| frame.get("frame_key").and_then(Value::as_str) == Some(frame_key))
            })
            .ok_or_else(|| {
                invalid(format!(
                    "ingest '{ingest_id}' retains no frame '{frame_key}'"
                ))
            })?;
        let path: &Path = &loaded
            .payload_dir
            .join("frames")
            .join(format!("{frame_key}.png"));
        let bytes = std::fs::read(path).map_err(|error| {
            FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                format!("the retained frame payload is unreadable: {error}"),
            )
        })?;
        if bytes.len() > VIDEO_FRAME_BYTES_MAX {
            return Err(FathomError::new(
                ErrorCode::ResourceConstraint,
                format!(
                    "the retained frame exceeds VIDEO_FRAME_BYTES_MAX ({VIDEO_FRAME_BYTES_MAX})"
                ),
            ));
        }
        if sha256_hex(&bytes) != frame["sha256"].as_str().unwrap_or("") {
            return Err(FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                "the retained frame payload no longer hashes to its record",
            ));
        }
        evidence.coverage.examined = 1;
        evidence.coverage.total = 1;
        evidence.coverage.exhaustive = true;
        evidence.add_finding(Finding::new(
            "frame_payload",
            Confidence::Observed,
            json!({
                "bytes": bytes.len(),
                "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "frame_key": frame_key,
                "height": frame["height"],
                "sha256": frame["sha256"],
                "timestamp_ms": frame["timestamp_ms"],
                "width": frame["width"],
            }),
        ));
        return Ok(evidence.to_value());
    }

    match optional_str(args, "inventory") {
        None => {
            // Summary: counts and bindings only. No span
            // text, no frame bytes — the summary is safe to
            // quote anywhere (obligation 1's leak leg).
            let inventories = &document["inventories"];
            let count = |name: &str| inventories[name].as_array().map_or(0, Vec::len);
            evidence.coverage.examined = document["coverage"]["examined"].as_u64().unwrap_or(0);
            evidence.coverage.total = document["coverage"]["total"].as_u64().unwrap_or(0);
            evidence.coverage.exhaustive = document["coverage"]["exhaustive"]
                .as_bool()
                .unwrap_or(false);
            evidence.add_finding(Finding::new(
                "ingest_summary",
                Confidence::Observed,
                json!({
                    "coverage": document["coverage"],
                    "document_digest": document["document_digest"],
                    "ingest_id": ingest_id,
                    "inventories": {
                        "chapters": count("chapters"),
                        "coverage_gaps": count("coverage_gaps"),
                        "demonstration_events": count("demonstration_events"),
                        "frames": count("frames"),
                        "transcript_disagreements": count("transcript_disagreements"),
                        "transcript_spans": count("transcript_spans"),
                    },
                    "producer": document["producer"],
                    "provenance": document["provenance"],
                    "status": document["status"],
                    "subject": document["subject"],
                    "unknowns": document["unknowns"],
                }),
            ));
            Ok(evidence.to_value())
        }
        Some("metadata") => {
            let metadata = document["inventories"]["metadata"]
                .as_object()
                .ok_or_else(|| {
                    FathomError::new(
                        ErrorCode::EvidenceIntegrityMismatch,
                        "the ingest document carries no metadata inventory",
                    )
                })?;
            evidence.coverage.examined = metadata.len() as u64;
            evidence.coverage.total = metadata.len() as u64;
            evidence.coverage.exhaustive = true;
            for (field, value) in metadata {
                evidence.add_finding(Finding::new(
                    "metadata_fact",
                    Confidence::Observed,
                    json!({"field": field, "value": value}),
                ));
            }
            Ok(evidence.to_value())
        }
        Some(name) => {
            let kind = INVENTORIES
                .iter()
                .find(|(inventory, _)| *inventory == name)
                .map(|(_, kind)| *kind)
                .ok_or_else(|| {
                    invalid(format!(
                        "inventory '{name}' is not readable; the readable inventories are \
                         chapters, coverage_gaps, demonstration_events, frames, metadata, \
                         transcript_disagreements, transcript_spans"
                    ))
                })?;
            let (limit, offset) = page_bounds(args)?;
            let records = document["inventories"][name].as_array().ok_or_else(|| {
                FathomError::new(
                    ErrorCode::EvidenceIntegrityMismatch,
                    format!("the ingest document carries no '{name}' inventory"),
                )
            })?;
            let total = records.len();
            let page: Vec<&Value> = records.iter().skip(offset).take(limit).collect();
            evidence.coverage.examined = page.len() as u64;
            evidence.coverage.total = total as u64;
            evidence.coverage.exhaustive = offset + page.len() >= total;
            let confidence = if kind == "transcript_disagreement" || kind == "demonstration_event" {
                Confidence::Derived
            } else {
                Confidence::Observed
            };
            for record in page {
                evidence.add_finding(Finding::new(kind, confidence, record.clone()));
            }
            Ok(evidence.to_value())
        }
    }
}
