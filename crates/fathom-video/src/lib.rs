//! fathom-video: the YouTube reverse-engineering lane
//! (YouTube-RE SPEC, gate-passed D-159).
//!
//! Y1 ingest (`ingest_youtube_video`, `read_video_ingest`,
//! `delete_video_ingest`): metadata pre-flight refusal, an
//! owned-child fetch under a fixed template with no
//! credential slot, retained ingest documents whose digests
//! anchor `video-ingest` proofs in the §4.1 machinery.
//! Y1.5: local ASR as the third transcript rank, behind a
//! configured engine. Y2 (`build_video_guide`): caller-
//! authored and rule-derived procedure guides whose steps
//! verify as §6.3 claims. Y3/Y4 (research loop, clean room)
//! are later stages of the same SPEC and are not stubbed
//! here — unbuilt means absent, never faked.
#![forbid(unsafe_code)]

mod asr;
mod captions;
mod document;
mod fetch;
mod frames;
mod guide;
mod ingest;
mod read;
mod url;

use std::sync::Arc;

use serde_json::json;

use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor};

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "build_video_guide",
            ToolClass::Read,
            "video",
            "Compose, revise, or read a procedure guide over a retained video ingest: caller-authored steps with server-resolved locators, or rule-derived steps; gaps and conflicts are records",
            json!({
                "type": "object",
                "properties": {
                    "derive": {"type": "boolean",
                        "description": "Also derive steps by the span-cluster rule (§6.2)"},
                    "detail": {"type": "string", "enum": ["complete", "summary"],
                        "description": "Summary is the default; complete adds per-step findings"},
                    "gaps": {"type": "array", "items": {"type": "object"},
                        "description": "Caller-declared gap records: {step_id?, window, reason}"},
                    "guide_id": {"type": "string",
                        "description": "The guide to revise or read"},
                    "ingest_id": {"type": "string",
                        "description": "The retained ingest to compose over"},
                    "operation": {"type": "string", "enum": ["compose", "read", "revise"],
                        "description": "Default compose"},
                    "research_system": {"type": "string",
                        "description": "The research system the guide's loop consults (recorded, Y3)"},
                    "steps": {"type": "array", "items": {"type": "object"},
                        "description": "Caller-authored steps: {step_id, action, window, target, parameters?, evidence: [{inventory, key}], conflict_with?}"},
                },
                "additionalProperties": false,
            }),
        ),
        Arc::new(guide::build_video_guide),
    );
    registry.register(
        descriptor(
            "delete_video_ingest",
            ToolClass::Execute,
            "video",
            "Delete a retained video ingest by ingest_id, or every ingest of one subject by media target (operator verb)",
            json!({
                "type": "object",
                "properties": {
                    "ingest_id": {"type": "string"},
                    "target": {"type": "string", "description": "Media path under a configured target root"},
                },
                "additionalProperties": false,
            }),
        ),
        Arc::new(ingest::delete_video_ingest),
    );
    registry.register(
        descriptor(
            "ingest_youtube_video",
            ToolClass::Observe,
            "video",
            "Ingest one public YouTube video: metadata pre-flight, media fetch, caption/ASR transcripts, frame sampling, retained as a digest-bound ingest document",
            json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string",
                        "description": "A youtube.com /watch, /shorts, /live, or youtu.be URL"},
                },
                "required": ["url"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(ingest::ingest_youtube_video),
    );
    registry.register(
        descriptor(
            "read_video_ingest",
            ToolClass::Read,
            "video",
            "Read a retained video ingest: summary (no payloads), one paged inventory, or one frame payload by frame_key",
            json!({
                "type": "object",
                "properties": {
                    "frame_key": {"type": "string"},
                    "ingest_id": {"type": "string"},
                    "inventory": {"type": "string",
                        "enum": ["chapters", "coverage_gaps", "demonstration_events", "frames", "metadata", "transcript_disagreements", "transcript_spans"]},
                    "limit": {"type": "integer", "minimum": 1},
                    "offset": {"type": "integer", "minimum": 0},
                },
                "required": ["ingest_id"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(read::read_video_ingest),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::{Config, VideoConfig};
    use fathom_core::error::ErrorCode;
    use fathom_core::evidence::sha256_hex;
    use fathom_core::proof::{self, Aggregate, Outcome};
    use serde_json::{Value, json};
    use std::path::PathBuf;

    const VIDEO_ID: &str = "abcDEF12345";
    const VIDEO_URL: &str = "https://www.youtube.com/watch?v=abcDEF12345";

    const MANUAL_JSON3: &str = r#"{"events":[
        {"tStartMs":0,"dDurationMs":1500,"segs":[{"utf8":"Click the red button now"}]},
        {"tStartMs":1600,"dDurationMs":1400,"segs":[{"utf8":"Watch how the color changes"}]},
        {"tStartMs":3100,"dDurationMs":800,"segs":[{"utf8":"the summary wraps up here"}]}
    ]}"#;

    const ASR_JSON3: &str = r#"{"events":[
        {"tStartMs":0,"dDurationMs":700,"segs":[{"utf8":"click the"}]},
        {"tStartMs":500,"dDurationMs":1000,"segs":[{"utf8":"click the red button now"}]},
        {"tStartMs":1600,"dDurationMs":1400,"segs":[{"utf8":"watch how the color changes"}]},
        {"tStartMs":3100,"dDurationMs":800,"segs":[{"utf8":"a completely different closing thought appears"}]}
    ]}"#;

    fn info_json(duration: f64) -> String {
        format!(
            r#"{{"id":"{VIDEO_ID}","title":"Stub Lecture","channel":"Stub Channel",
            "channel_id":"UCstub","duration":{duration},"availability":"public",
            "live_status":"not_live","is_live":false,"language":"en",
            "upload_date":"20260101","view_count":42,"like_count":7,
            "webpage_url":"{VIDEO_URL}",
            "chapters":[{{"start_time":0,"end_time":{duration},"title":"Whole"}}],
            "formats":[
                {{"format_id":"18","height":360,"filesize":100000,"vcodec":"avc1","acodec":"mp4a"}},
                {{"format_id":"137","height":1080,"filesize":900000,"vcodec":"avc1","acodec":"none"}},
                {{"format_id":"140","filesize":50000,"vcodec":"none","acodec":"mp4a"}}
            ],
            "subtitles":{{"en":[{{"ext":"json3"}}]}},
            "automatic_captions":{{"en":[{{"ext":"json3"}}]}}}}"#
        )
    }

    /// A fixture: temp dirs, a lavfi-generated media file
    /// (red 2 s → blue 2 s, one hard scene cut), and a stub
    /// fetcher shell script with the fixture paths baked in
    /// (the child environment is scrubbed, so nothing can be
    /// passed through it).
    struct Fixture {
        config: Config,
        root: PathBuf,
        state_dir: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str, duration: f64) -> Fixture {
            let root =
                std::env::temp_dir().join(format!("fathom-video-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let state_dir = root.join("state");
            let target_root = root.join("targets");
            std::fs::create_dir_all(&state_dir).unwrap();
            std::fs::create_dir_all(&target_root).unwrap();
            let media = root.join("media.mp4");
            let status = std::process::Command::new("ffmpeg")
                .args([
                    "-y",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "lavfi",
                    "-i",
                    "color=c=red:s=320x240:r=10:d=2",
                    "-f",
                    "lavfi",
                    "-i",
                    "color=c=blue:s=320x240:r=10:d=2",
                    "-f",
                    "lavfi",
                    "-i",
                    "sine=frequency=440:d=4",
                    "-filter_complex",
                    "[0:v][1:v]concat=n=2:v=1:a=0[v]",
                    "-map",
                    "[v]",
                    "-map",
                    "2:a",
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    "-c:a",
                    "aac",
                ])
                .arg(&media)
                .status()
                .expect("ffmpeg is the lane's sampler and must exist");
            assert!(status.success(), "lavfi media generation failed");
            let info_path = root.join("info.json");
            std::fs::write(&info_path, info_json(duration)).unwrap();
            let manual_path = root.join("manual.json3");
            std::fs::write(&manual_path, MANUAL_JSON3).unwrap();
            let asr_path = root.join("asr.json3");
            std::fs::write(&asr_path, ASR_JSON3).unwrap();
            let stub = root.join("stub-yt-dlp.sh");
            let script = format!(
                "#!/bin/sh\n\
                 for a in \"$@\"; do if [ \"$a\" = \"--version\" ]; then echo 2099.01.01; exit 0; fi; done\n\
                 mode=\"\"; out=\"\"; prev=\"\"\n\
                 for a in \"$@\"; do\n\
                   if [ \"$prev\" = \"--output\" ]; then out=\"$a\"; fi\n\
                   case \"$a\" in\n\
                     --dump-single-json) mode=meta ;;\n\
                     --skip-download) mode=caps ;;\n\
                     --write-info-json) mode=media ;;\n\
                   esac\n\
                   prev=\"$a\"\n\
                 done\n\
                 case \"$mode\" in\n\
                   meta) cat \"{info}\" ;;\n\
                   media) cp \"{media}\" \"./{VIDEO_ID}.mkv\"; cp \"{info}\" \"./{VIDEO_ID}.info.json\" ;;\n\
                   caps)\n\
                     for a in \"$@\"; do\n\
                       if [ \"$a\" = \"--write-subs\" ]; then cp \"{manual}\" \"$out.en.json3\"; fi\n\
                       if [ \"$a\" = \"--write-auto-subs\" ]; then cp \"{asr}\" \"$out.en.json3\"; fi\n\
                     done ;;\n\
                 esac\n\
                 exit 0\n",
                info = info_path.display(),
                media = media.display(),
                manual = manual_path.display(),
                asr = asr_path.display(),
            );
            std::fs::write(&stub, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let config = Config {
                allow_programs: Vec::new(),
                allow_tools: [
                    "build_video_guide",
                    "delete_video_ingest",
                    "ingest_youtube_video",
                    "read_video_ingest",
                ]
                .iter()
                .map(ToString::to_string)
                .collect(),
                ghidra_headless: None,
                http_bind: "127.0.0.1:8731".parse().unwrap(),
                signing_key_file: None,
                state_dir: state_dir.clone(),
                target_roots: vec![target_root],
                video: VideoConfig::default(),
            };
            let mut config = config;
            config.video.fetcher_program = stub;
            Fixture {
                config,
                root,
                state_dir,
            }
        }

        fn registry(&self) -> Registry {
            let mut registry = Registry::new();
            register(&mut registry);
            registry
        }

        fn ingest(&self) -> Value {
            self.registry()
                .call(
                    &self.config,
                    "ingest_youtube_video",
                    &json!({"url": VIDEO_URL}),
                )
                .expect("stub ingest should succeed")
        }

        fn ingest_id_of(envelope: &Value) -> String {
            envelope["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|finding| finding["kind"] == "ingest")
                .and_then(|finding| finding["facts"]["ingest_id"].as_str().map(str::to_string))
                .expect("ingest finding carries the id")
        }

        fn document_of(&self, envelope: &Value) -> Value {
            let subject_sha = envelope["subject"]["sha256"].as_str().unwrap();
            proof::find_video_ingest_document(&self.config, subject_sha)
                .expect("the ingest document is retained")
        }

        fn cleanup(&self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn validation_stub_ingest_end_to_end() {
        let fixture = Fixture::new("e2e", 4.0);
        let envelope = fixture.ingest();
        let ingest_id = Fixture::ingest_id_of(&envelope);
        let document = fixture.document_of(&envelope);
        // Ranks: manual sp_0001..3, ASR deduped to 3 spans.
        let spans = document["inventories"]["transcript_spans"]
            .as_array()
            .unwrap();
        assert_eq!(spans.len(), 6);
        assert_eq!(spans[0]["track_kind"], "manual");
        assert_eq!(spans[3]["track_kind"], "asr");
        // The planted divergence yields exactly one
        // disagreement (obligation 3's count leg).
        let disagreements = document["inventories"]["transcript_disagreements"]
            .as_array()
            .unwrap();
        assert_eq!(disagreements.len(), 1);
        assert_eq!(disagreements[0]["span_key_a"], "sp_0003");
        // The ASR track record carries the dedup derivation.
        let asr_component = document["components"]["captions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|track| track["kind"] == "asr")
            .unwrap()
            .clone();
        assert_eq!(asr_component["deduplicated"], true);
        assert_eq!(asr_component["raw_span_count"], 4);
        // Summary reads carry no span text (obligation 1's
        // leak leg).
        let summary = fixture
            .registry()
            .call(
                &fixture.config,
                "read_video_ingest",
                &json!({"ingest_id": ingest_id}),
            )
            .unwrap();
        let summary_text = serde_json::to_string(&summary).unwrap();
        assert!(!summary_text.contains("Click the red button"));
        assert!(!summary_text.contains("content_base64"));
        // Paged span reads do carry the records.
        let page = fixture
            .registry()
            .call(
                &fixture.config,
                "read_video_ingest",
                &json!({"ingest_id": ingest_id, "inventory": "transcript_spans", "limit": 2}),
            )
            .unwrap();
        assert_eq!(page["coverage"]["examined"], 2);
        assert_eq!(page["coverage"]["total"], 6);
        fixture.cleanup();
    }

    #[test]
    fn validation_absent_chapters_are_an_unknown_not_a_partial() {
        // §4.6/§4.7: chapters the platform never published
        // are a recorded unknown; the ingest is complete
        // when every processing leg succeeded.
        let fixture = Fixture::new("nochapters", 4.0);
        let info = std::fs::read_to_string(fixture.root.join("info.json")).unwrap();
        let mut info_value: Value = serde_json::from_str(&info).unwrap();
        assert!(
            !info_value["chapters"].as_array().unwrap().is_empty(),
            "the fixture info must carry chapters"
        );
        info_value["chapters"] = json!([]);
        std::fs::write(
            fixture.root.join("info.json"),
            serde_json::to_string(&info_value).unwrap(),
        )
        .unwrap();
        let envelope = fixture.ingest();
        let document = fixture.document_of(&envelope);
        assert_eq!(document["status"], "complete");
        assert_eq!(document["coverage"]["exhaustive"], true);
        let unknowns = document["unknowns"].as_array().unwrap();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0]["aspect"], "chapters");
        fixture.cleanup();
    }

    #[test]
    fn validation_metadata_beyond_the_generic_cap_still_ingests() {
        // The D-184 corpus caught this live: caption-rich
        // videos carry --dump-single-json documents past
        // the generic 8 MiB capture cap (every caption
        // track in every language). The metadata run has
        // its own bound, VIDEO_METADATA_BYTES_MAX.
        let fixture = Fixture::new("bigmeta", 4.0);
        let info = std::fs::read_to_string(fixture.root.join("info.json")).unwrap();
        let mut info_value: Value = serde_json::from_str(&info).unwrap();
        info_value["description"] = json!("x".repeat(8_388_608 + 65_536));
        std::fs::write(
            fixture.root.join("info.json"),
            serde_json::to_string(&info_value).unwrap(),
        )
        .unwrap();
        let envelope = fixture.ingest();
        let document = fixture.document_of(&envelope);
        assert_eq!(document["status"], "complete");
        fixture.cleanup();
    }

    #[test]
    fn validation_frame_sampling_is_deterministic_across_ingests() {
        // Obligation 4: same media + parameters + sampler →
        // identical frame keys, timestamps, and hashes.
        let first = Fixture::new("det-a", 4.0);
        let second = Fixture::new("det-b", 4.0);
        let doc_a = first.document_of(&first.ingest());
        let doc_b = second.document_of(&second.ingest());
        let frames_a = doc_a["inventories"]["frames"].as_array().unwrap();
        let frames_b = doc_b["inventories"]["frames"].as_array().unwrap();
        assert!(!frames_a.is_empty(), "the sampler retained frames");
        assert_eq!(frames_a.len(), frames_b.len());
        for (a, b) in frames_a.iter().zip(frames_b) {
            assert_eq!(a["frame_key"], b["frame_key"]);
            assert_eq!(a["timestamp_ms"], b["timestamp_ms"]);
            assert_eq!(a["sha256"], b["sha256"]);
            assert_eq!(a["source"], b["source"]);
        }
        first.cleanup();
        second.cleanup();
    }

    #[test]
    fn validation_guide_compose_derive_and_caller_steps() {
        let fixture = Fixture::new("guide", 4.0);
        let envelope = fixture.ingest();
        let ingest_id = Fixture::ingest_id_of(&envelope);
        let document = fixture.document_of(&envelope);
        let event_key = document["inventories"]["demonstration_events"][0]["event_key"]
            .as_str()
            .expect("a demonstration event was derived")
            .to_string();
        let guide = fixture
            .registry()
            .call(
                &fixture.config,
                "build_video_guide",
                &json!({
                    "ingest_id": ingest_id,
                    "derive": true,
                    "steps": [{
                        "step_id": "press",
                        "action": "invoke",
                        "window": {"start_ms": 0, "end_ms": 1500},
                        "target": "the red button",
                        "evidence": [
                            {"inventory": "transcript_spans", "key": "sp_0001"},
                            {"inventory": "demonstration_events", "key": event_key},
                        ],
                    }],
                }),
            )
            .unwrap();
        let guide_finding = guide["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "guide")
            .unwrap()
            .clone();
        assert_eq!(guide_finding["facts"]["coverage"]["established"], 2);
        assert_eq!(guide_finding["facts"]["version"], 1);
        fixture.cleanup();
    }

    #[test]
    fn adversarial_guide_unresolvable_locator_is_refused_naming_the_step() {
        let fixture = Fixture::new("guide-bad", 4.0);
        let envelope = fixture.ingest();
        let ingest_id = Fixture::ingest_id_of(&envelope);
        let err = fixture
            .registry()
            .call(
                &fixture.config,
                "build_video_guide",
                &json!({
                    "ingest_id": ingest_id,
                    "steps": [{
                        "step_id": "ghost",
                        "action": "invoke",
                        "window": {"start_ms": 0, "end_ms": 1000},
                        "target": "nothing",
                        "evidence": [{"inventory": "frames", "key": "f_9999"}],
                    }],
                }),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(err.message.contains("ghost"), "{}", err.message);
        fixture.cleanup();
    }

    #[test]
    fn adversarial_over_duration_refuses_before_any_download() {
        // Obligation 13: the pre-flight refusal leaves zero
        // retained bytes and no subject store at all.
        let fixture = Fixture::new("toolong", 7200.0);
        let err = fixture
            .registry()
            .call(
                &fixture.config,
                "ingest_youtube_video",
                &json!({"url": VIDEO_URL}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ResourceConstraint);
        assert!(!fixture.state_dir.join("video-ingests").exists());
        fixture.cleanup();
    }

    #[test]
    fn adversarial_tampered_document_fails_integrity_at_read() {
        // Obligation 14's tamper leg.
        let fixture = Fixture::new("tamper", 4.0);
        let envelope = fixture.ingest();
        let ingest_id = Fixture::ingest_id_of(&envelope);
        let subject_sha = envelope["subject"]["sha256"].as_str().unwrap().to_string();
        let doc_path = fixture
            .state_dir
            .join("video-ingests")
            .join(&subject_sha[..32])
            .join(format!("{ingest_id}.json"));
        let text = std::fs::read_to_string(&doc_path).unwrap();
        let mutated = text.replace("Click the red button", "Click the blue button");
        assert_ne!(text, mutated);
        std::fs::write(&doc_path, mutated).unwrap();
        let err = fixture
            .registry()
            .call(
                &fixture.config,
                "read_video_ingest",
                &json!({"ingest_id": ingest_id}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::EvidenceIntegrityMismatch);
        fixture.cleanup();
    }

    #[test]
    fn adversarial_delete_of_missing_ingest_is_a_refusal() {
        let fixture = Fixture::new("delete", 4.0);
        let err = fixture
            .registry()
            .call(
                &fixture.config,
                "delete_video_ingest",
                &json!({"ingest_id": "vi_0000000000000000"}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        fixture.cleanup();
    }

    /// Build a shape-valid proof over a synthetic video
    /// document, binding refs the way the ledger does.
    fn proof_over(document: &Value, claims: Vec<Value>) -> proof::Proof {
        let mut bound_claims = Vec::new();
        for claim in claims {
            let mut refs = Vec::new();
            for reference in claim["evidence"].as_array().unwrap() {
                let (inventory, key) = (
                    reference["inventory"].as_str().unwrap(),
                    reference["key"].as_str().unwrap(),
                );
                let record = match proof::resolve_record_for_mode(
                    document,
                    "video-ingest",
                    inventory,
                    key,
                ) {
                    proof::Resolution::Record(record) => record,
                    _ => panic!("test ref {inventory}/{key} must resolve"),
                };
                refs.push(json!({
                    "inventory": inventory,
                    "key": key,
                    "record_digest": proof::value_digest(&record),
                }));
            }
            bound_claims.push(json!({
                "claim_id": claim["claim_id"],
                "class": claim["class"],
                "confidence": claim["confidence"],
                "evidence": refs,
                "statement": claim["statement"],
            }));
        }
        let registry = Registry::new();
        let mut value = json!({
            "claims": bound_claims,
            "export": {
                "digest": proof::video_ingest_digest(document),
                "mode": "video-ingest",
            },
            "producer": proof::producer_identity(&registry),
            "proof_version": proof::PROOF_VERSION,
            "subject": {
                "path": "media.bin",
                "sha256": sha256_hex(b"synthetic media"),
                "size_bytes": 15,
            },
        });
        let digest = proof::compute_proof_digest(&value);
        value["proof_digest"] = json!(digest.clone());
        value["proof_id"] = json!(digest[..32].to_string());
        proof::parse_proof(&value).expect("the built proof is shape-valid")
    }

    fn synthetic_doc(inventories: Value) -> Value {
        json!({
            "document_digest": "0".repeat(64),
            "ingest_id": "vi_test",
            "inventories": inventories,
            "subject": {"path": "media.bin", "sha256": sha256_hex(b"synthetic media"), "size_bytes": 15},
            "version": 1,
        })
    }

    #[test]
    fn validation_video_claims_verify_against_the_ingest_document() {
        let document = synthetic_doc(json!({
            "chapters": [],
            "coverage_gaps": [],
            "demonstration_events": [],
            "frames": [],
            "metadata": {"duration_secs": 4, "video_id": VIDEO_ID},
            "transcript_disagreements": [],
            "transcript_spans": [
                {"end_ms": 1500, "language": "en", "span_key": "sp_0001",
                 "start_ms": 0, "text": "Click the red button now",
                 "track_id": "manual-en", "track_kind": "manual"}
            ],
            "transcript_spans_total": 1,
            "transcript_spans_truncated": false,
        }));
        let proof = proof_over(
            &document,
            vec![
                json!({
                    "claim_id": "step-1",
                    "class": "stated_step",
                    "confidence": "observed",
                    "statement": {"end_ms": 1500, "start_ms": 0},
                    "evidence": [{"inventory": "transcript_spans", "key": "sp_0001"}],
                }),
                json!({
                    "claim_id": "cov-1",
                    "class": "guide_coverage",
                    "confidence": "observed",
                    "statement": {
                        "exhaustive": true, "inventory": "transcript_spans",
                        "retained": 1, "total": 1, "truncated": false,
                    },
                    "evidence": [{"inventory": "coverage", "key": "transcript_spans"}],
                }),
            ],
        );
        let outcomes = proof::verify_claims(&proof, Some(&document));
        assert!(
            outcomes.iter().all(|o| o.outcome == Outcome::Verified),
            "{outcomes:?}"
        );
        assert_eq!(proof::aggregate(&outcomes, false), Aggregate::Verified);
    }

    #[test]
    fn adversarial_id_array_claim_verifies_nothing() {
        // Obligation 7: bare identifiers in place of bound
        // refs parse as Unbound and fail at verify.
        let document = synthetic_doc(json!({
            "transcript_spans": [
                {"end_ms": 1500, "span_key": "sp_0001", "start_ms": 0, "text": "x"}
            ],
        }));
        let registry = Registry::new();
        let mut value = json!({
            "claims": [{
                "claim_id": "ids-only",
                "class": "stated_step",
                "confidence": "observed",
                "statement": {"start_ms": 0},
                "evidence": ["sp_0001"],
            }],
            "export": {"digest": proof::video_ingest_digest(&document), "mode": "video-ingest"},
            "producer": proof::producer_identity(&registry),
            "proof_version": proof::PROOF_VERSION,
            "subject": {"path": "media.bin", "sha256": sha256_hex(b"synthetic media"), "size_bytes": 15},
        });
        let digest = proof::compute_proof_digest(&value);
        value["proof_digest"] = json!(digest.clone());
        value["proof_id"] = json!(digest[..32].to_string());
        let parsed = proof::parse_proof(&value).unwrap();
        let outcomes = proof::verify_claims(&parsed, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Failed);
        assert!(outcomes[0].diagnostic.contains("unbound_evidence"));
    }

    #[test]
    fn adversarial_gap_spanning_claim_fails() {
        // Obligation 10's verify leg: continuity across a
        // recorded gap is a failed claim.
        let document = synthetic_doc(json!({
            "coverage_gaps": [
                {"end_ms": 3000, "gap_key": "gap_0001", "start_ms": 2000}
            ],
            "transcript_spans": [
                {"end_ms": 10000, "span_key": "sp_0001", "start_ms": 0, "text": "x"}
            ],
        }));
        let proof = proof_over(
            &document,
            vec![json!({
                "claim_id": "across-the-gap",
                "class": "stated_step",
                "confidence": "observed",
                "statement": {"end_ms": 10000, "start_ms": 0},
                "evidence": [{"inventory": "transcript_spans", "key": "sp_0001"}],
            })],
        );
        let outcomes = proof::verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Failed);
        assert!(outcomes[0].diagnostic.starts_with("gap_spanned:"));
    }

    #[test]
    fn adversarial_disputed_span_caps_the_aggregate_at_partial() {
        // Obligation 8's verify leg: the step verifies over
        // its bound evidence, and the dispute caps the proof.
        let document = synthetic_doc(json!({
            "transcript_disagreements": [
                {"aspect": "wording", "disagreement_key": "td_0001",
                 "span_key_a": "sp_0001", "span_key_b": "sp_0002"}
            ],
            "transcript_spans": [
                {"end_ms": 1000, "span_key": "sp_0001", "start_ms": 0, "text": "hello world"},
                {"end_ms": 1000, "span_key": "sp_0002", "start_ms": 0, "text": "goodbye world"}
            ],
        }));
        let proof = proof_over(
            &document,
            vec![json!({
                "claim_id": "disputed-step",
                "class": "stated_step",
                "confidence": "observed",
                "statement": {"end_ms": 1000, "start_ms": 0},
                "evidence": [{"inventory": "transcript_spans", "key": "sp_0001"}],
            })],
        );
        let outcomes = proof::verify_claims(&proof, Some(&document));
        assert_eq!(outcomes[0].outcome, Outcome::Verified);
        assert!(outcomes[0].diagnostic.starts_with("conflict_cap:"));
        assert_eq!(proof::aggregate(&outcomes, false), Aggregate::Partial);
    }
}
