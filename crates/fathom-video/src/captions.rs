//! Caption-track parsing and the transcript derivations of
//! §4.4: json3 → spans, the platform-ASR rolling-duplicate
//! de-duplication, and the normalized wording comparison the
//! `transcript_disagreement` finding is computed from.
//!
//! Transcript text is data (SPEC §2, obligation 12): nothing
//! in this module — or anywhere in the crate — branches on
//! what a span *says*, beyond the deterministic text measures
//! the SPEC names (prefix extension, token overlap).

use std::collections::BTreeSet;

use serde_json::Value;

/// One timed text span, before keys are assigned at document
/// assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSpan {
    pub end_ms: u64,
    pub start_ms: u64,
    pub text: String,
}

/// A parsed caption track: spans in served order, plus the
/// pre-derivation span count the track record reports.
#[derive(Clone, Debug)]
pub struct ParsedTrack {
    pub deduplicated: bool,
    pub kind: String,
    pub language: String,
    pub raw_span_count: usize,
    pub spans: Vec<RawSpan>,
    pub track_id: String,
}

/// The store-safe track id: `<kind>-<language>` with the
/// language reduced to `[A-Za-z0-9-]`.
pub fn track_id(kind: &str, language: &str) -> String {
    let sanitized: String = language
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{kind}-{sanitized}")
}

/// Parse one json3 caption file into raw spans. Events with
/// no segment list are window dressing (they carry styling,
/// not text) and are skipped; segments concatenate verbatim,
/// newlines become spaces, and empty-after-trim spans drop.
/// A malformed document is a leg failure (the caller degrades
/// the ingest to partial), never a panic.
pub fn parse_json3(bytes: &[u8]) -> Result<Vec<RawSpan>, String> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("caption JSON: {error}"))?;
    let events = document
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| "caption JSON carries no events array".to_string())?;
    let mut spans = Vec::with_capacity(events.len());
    for event in events {
        let Some(segments) = event.get("segs").and_then(Value::as_array) else {
            continue;
        };
        let mut text = String::new();
        for segment in segments {
            if let Some(piece) = segment.get("utf8").and_then(Value::as_str) {
                text.push_str(piece);
            }
        }
        let text = text.replace('\n', " ");
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let start_ms = event.get("tStartMs").and_then(Value::as_u64).unwrap_or(0);
        let duration_ms = event
            .get("dDurationMs")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        spans.push(RawSpan {
            end_ms: start_ms.saturating_add(duration_ms),
            start_ms,
            text: text.to_string(),
        });
    }
    Ok(spans)
}

/// The §4.4 prefix-extension de-duplication for platform-ASR
/// tracks: the platform serves each line as growing prefixes
/// of the next, so when a span's text begins with the
/// previously retained span's text and their windows overlap,
/// the two are one utterance — merge into the longer text
/// with the union window. The derivation is recorded on the
/// track record; the raw track file is retained untouched.
pub fn dedup_asr(spans: Vec<RawSpan>) -> (Vec<RawSpan>, bool) {
    let mut kept: Vec<RawSpan> = Vec::with_capacity(spans.len());
    let mut merged = false;
    for span in spans {
        let extends_previous = match kept.last() {
            Some(previous) => {
                !previous.text.is_empty()
                    && span.text.starts_with(previous.text.as_str())
                    && span.start_ms <= previous.end_ms
            }
            None => false,
        };
        if extends_previous {
            let previous = kept.last_mut().expect("checked non-empty above");
            previous.end_ms = previous.end_ms.max(span.end_ms);
            previous.text = span.text;
            merged = true;
        } else {
            kept.push(span);
        }
    }
    (kept, merged)
}

/// The normalized token set the disagreement measure
/// compares: lowercase, punctuation stripped, whitespace
/// collapsed (§4.4's derived finding needs a stated rule;
/// this is it, and it lives in exactly one place).
pub fn normalized_tokens(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether two renderings of (nominally) the same speech
/// agree in wording: Jaccard similarity of normalized token
/// sets at or above 0.5. An empty side never disagrees —
/// absence is a coverage fact, not a contradiction.
pub fn wording_agrees(a: &str, b: &str) -> bool {
    let tokens_a = normalized_tokens(a);
    let tokens_b = normalized_tokens(b);
    if tokens_a.is_empty() || tokens_b.is_empty() {
        return true;
    }
    let shared = tokens_a.intersection(&tokens_b).count() as f64;
    let union = tokens_a.union(&tokens_b).count() as f64;
    union > 0.0 && shared / union >= 0.5
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start_ms: u64, end_ms: u64, text: &str) -> RawSpan {
        RawSpan {
            end_ms,
            start_ms,
            text: text.to_string(),
        }
    }

    #[test]
    fn validation_json3_events_become_spans() {
        let bytes = br#"{"events":[
            {"tStartMs":0,"dDurationMs":1200,"segs":[{"utf8":"Hello "},{"utf8":"world"}]},
            {"tStartMs":1200,"dDurationMs":800,"aAppend":1},
            {"tStartMs":2000,"dDurationMs":900,"segs":[{"utf8":"next\nline"}]},
            {"tStartMs":2900,"dDurationMs":100,"segs":[{"utf8":"  "}]}
        ]}"#;
        let spans = parse_json3(bytes).unwrap();
        assert_eq!(
            spans,
            vec![span(0, 1200, "Hello world"), span(2000, 2900, "next line")]
        );
    }

    #[test]
    fn validation_asr_rolling_duplicates_merge_by_prefix_extension() {
        let raw = vec![
            span(0, 1000, "the quick"),
            span(400, 1600, "the quick brown"),
            span(900, 2200, "the quick brown fox"),
            span(2300, 3000, "a new sentence"),
        ];
        let (kept, merged) = dedup_asr(raw);
        assert!(merged);
        assert_eq!(
            kept,
            vec![
                span(0, 2200, "the quick brown fox"),
                span(2300, 3000, "a new sentence")
            ]
        );
    }

    #[test]
    fn validation_wording_agreement_uses_normalized_tokens() {
        assert!(wording_agrees(
            "Click the Settings button, please!",
            "click the settings button please"
        ));
        assert!(!wording_agrees(
            "the mitochondria is the powerhouse",
            "completely unrelated words appear here"
        ));
        assert!(wording_agrees("", "anything at all"));
    }

    #[test]
    fn adversarial_malformed_caption_json_is_a_leg_error_not_a_panic() {
        assert!(parse_json3(b"not json").is_err());
        assert!(parse_json3(b"{}").is_err());
        assert!(parse_json3(b"{\"events\": 42}").is_err());
    }

    #[test]
    fn adversarial_prefix_without_overlap_does_not_merge() {
        // Same prefix, disjoint windows: two utterances that
        // happen to start alike are not one utterance.
        let raw = vec![span(0, 500, "yes"), span(5000, 6000, "yes indeed")];
        let (kept, merged) = dedup_asr(raw);
        assert!(!merged);
        assert_eq!(kept.len(), 2);
    }
}
