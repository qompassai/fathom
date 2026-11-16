//! The A2A agent card, in the D-1607 fleet profile (D-1615).
//!
//! Fathom's interface is MCP over stdio; it exposes no A2A
//! endpoint. The card therefore declares exactly one interface
//! under the fleet's custom MCP binding URI, whose `url` carries
//! the stdio command under that binding's own semantics, and the
//! invocation facts (transport, command, args, protocol era) ride
//! in the matching `capabilities.extensions` entry. Fleet cards
//! are unsigned (the A2A v1.0 JWS route is recorded future
//! practice, not current practice), so the card carries no
//! signature block, no top-level `url`, and no
//! `stateTransitionHistory` (a field A2A v1.0 removed).
//!
//! The content of record is the committed static card at
//! `.well-known/agent-card.json`. This generator mirrors it
//! field-for-field from the same fleet constants, and
//! `tests/manifest_agreement.rs` pins the two equal, so the
//! served card and the committed card cannot drift apart
//! silently.

use serde_json::{Value, json};

/// The fleet's custom MCP-interface binding URI (D-1607). A
/// breaking change to this binding mints a new URI version.
pub const MCP_BINDING_URI: &str = "https://qompass.ai/extensions/mcp-interface/v1";

/// The MCP protocol era the fleet serves (modern era only).
pub const PROTOCOL_ERA: &str = "2026-07-28";

/// Card identity and invocation facts. The interface `url` and
/// the extension invocation `command` both come from `command`,
/// so the join invariant between them holds by construction.
#[derive(Clone, Debug)]
pub struct CardParams {
    pub command: String,
    pub command_args: Vec<String>,
    pub description: String,
    pub documentation_url: String,
    pub name: String,
    pub organization: String,
    pub provider_url: String,
    pub registry_name: String,
    pub version: String,
}

impl CardParams {
    /// The fleet card's own parameters: the values the committed
    /// static card at `.well-known/agent-card.json` carries.
    pub fn fleet() -> Self {
        Self {
            command: "~/.GH/Qompass/fathom/target/release/fathom".to_string(),
            command_args: vec![
                "serve".to_string(),
                "--profile".to_string(),
                "full".to_string(),
            ],
            description: "Clean-room reverse-engineering MCP server: artifact census and \
                          inspection across native, managed, JavaScript, and art/video \
                          providers, with evidence-carrying findings, a \
                          reconstruction-proof ledger, and a policy engine classifying \
                          every tool read, observe, or execute. This card is a discovery \
                          record and capability manifest for catalogues, registries, and \
                          client-config generators; the interface declared here is \
                          Fathom's MCP over stdio."
                .to_string(),
            documentation_url: "https://github.com/qompassai/fathom".to_string(),
            name: "Fathom".to_string(),
            organization: "Qompass AI".to_string(),
            provider_url: "https://qompass.ai".to_string(),
            registry_name: "ai.qompass/fathom".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

/// The card's skills: Fathom's tool groups, as the static card
/// groups them (one skill per group, never one per tool).
fn skills() -> Vec<Value> {
    vec![
        json!({
            "id": "artifact-census",
            "name": "Artifact census and inspection",
            "description": "Stateless per-call census and inspection of artifacts across \
                            providers: binaries, Android APKs, asar/Electron apps, managed \
                            assemblies, firmware, Godot packs, Python artifacts, source \
                            maps, and web captures (inspect_artifact, binary_overview, \
                            inspect_android_apk, inspect_asar, inspect_managed_assembly, \
                            inspect_firmware, inspect_godot_pck, inspect_python_artifact, \
                            inspect_source_map, inspect_web_capture).",
            "tags": ["mcp", "reverse-engineering", "census"],
        }),
        json!({
            "id": "binary-analysis",
            "name": "Binary analysis",
            "description": "Ghidra-provider analysis: function listing and deep analysis, \
                            names, strings, JavaScript application analysis, and artifact \
                            comparison (list_functions, analyze_function, list_names, \
                            list_strings, analyze_javascript_application, \
                            compare_artifacts).",
            "tags": ["mcp", "reverse-engineering", "ghidra"],
        }),
        json!({
            "id": "reconstruction-ledger",
            "name": "Reconstruction-proof ledger",
            "description": "Build the reconstruction obligation ledger from findings, \
                            manage its proof objects, and export evidence bundles \u{2014} \
                            the claim model a clean-room rebuild must discharge \
                            (build_reconstruction_obligation_ledger, \
                            delete_reconstruction_proof, export_evidence_bundle).",
            "tags": ["mcp", "reverse-engineering", "evidence"],
        }),
        json!({
            "id": "media-re",
            "name": "Art and video RE",
            "description": "Art-style analysis, palette remapping, style application via \
                            lumen, and the video-RE lane: ingest, read, guide-building, \
                            and ingest management (analyze_art_style, remap_palette, \
                            apply_style_via_lumen, ingest_youtube_video, \
                            read_video_ingest, build_video_guide, delete_video_ingest).",
            "tags": ["mcp", "reverse-engineering", "media"],
        }),
        json!({
            "id": "observation",
            "name": "Observation",
            "description": "Observe- and execute-class capture under the policy engine: \
                            headless-browser DOM inventory and process capture \
                            (observe_browser, capture_process).",
            "tags": ["mcp", "reverse-engineering", "observe"],
        }),
    ]
}

/// Build the card value in the D-1607 fleet profile.
pub fn build_card(params: &CardParams) -> Value {
    json!({
        "name": params.name,
        "description": params.description,
        "documentationUrl": params.documentation_url,
        "version": params.version,
        "provider": {
            "organization": params.organization,
            "url": params.provider_url,
        },
        "supportedInterfaces": [{
            "protocolBinding": MCP_BINDING_URI,
            "protocolVersion": "1.0",
            "url": params.command,
        }],
        "capabilities": {
            "pushNotifications": false,
            "streaming": false,
            "extensions": [{
                "uri": MCP_BINDING_URI,
                "description": "This agent's interface is MCP over stdio, not A2A. The \
                                card is a capability manifest and discovery record, not \
                                an A2A endpoint declaration; no A2A endpoint exists for \
                                this agent. The params carry the invocation facts a \
                                client config generator needs to wire this server from \
                                the card alone.",
                "required": false,
                "params": {
                    "implementation": "rmcp",
                    "interface": "mcp",
                    "invocation": {
                        "args": params.command_args,
                        "command": params.command,
                        "protocolEra": PROTOCOL_ERA,
                        "transport": "stdio",
                    },
                    "registryName": params.registry_name,
                },
            }],
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills(),
    })
}

/// An axum route serving the card at the A2A well-known path.
pub fn card_router(card: Value) -> axum::Router {
    axum::Router::new().route(
        "/.well-known/agent-card.json",
        axum::routing::get(move || {
            let card = card.clone();
            async move { axum::Json(card) }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_card_carries_no_removed_or_custom_fields() {
        let card = build_card(&CardParams::fleet());
        // A2A v1.0 removed these; the pre-profile card emitted the
        // first two. None may reappear.
        assert!(card.get("url").is_none(), "no top-level url");
        assert!(card.get("signature").is_none(), "no signature block");
        assert!(card.get("signatures").is_none(), "fleet cards are unsigned");
        assert!(
            card["capabilities"].get("stateTransitionHistory").is_none(),
            "stateTransitionHistory was removed in A2A v1.0"
        );
    }

    #[test]
    fn adversarial_command_change_moves_both_join_sides_together() {
        let mut params = CardParams::fleet();
        params.command = "/elsewhere/fathom".to_string();
        let card = build_card(&params);
        assert_eq!(card["supportedInterfaces"][0]["url"], "/elsewhere/fathom");
        assert_eq!(
            card["capabilities"]["extensions"][0]["params"]["invocation"]["command"],
            "/elsewhere/fathom"
        );
    }

    #[test]
    fn validation_card_declares_exactly_one_mcp_interface() {
        let card = build_card(&CardParams::fleet());
        let interfaces = card["supportedInterfaces"].as_array().unwrap();
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0]["protocolBinding"], MCP_BINDING_URI);
        assert_eq!(interfaces[0]["protocolVersion"], "1.0");
        assert_eq!(
            interfaces[0]["url"],
            "~/.GH/Qompass/fathom/target/release/fathom"
        );
        let extension = &card["capabilities"]["extensions"][0];
        assert_eq!(extension["uri"], MCP_BINDING_URI);
        assert_eq!(extension["required"], false);
        let invocation = &extension["params"]["invocation"];
        assert_eq!(invocation["transport"], "stdio");
        assert_eq!(invocation["args"], json!(["serve", "--profile", "full"]));
        assert_eq!(invocation["protocolEra"], PROTOCOL_ERA);
        assert_eq!(extension["params"]["registryName"], "ai.qompass/fathom");
    }

    #[test]
    fn validation_card_provider_and_skills_match_the_static_card() {
        let card = build_card(&CardParams::fleet());
        assert_eq!(card["provider"]["organization"], "Qompass AI");
        assert_eq!(card["provider"]["url"], "https://qompass.ai");
        let skills = card["skills"].as_array().unwrap();
        let ids: Vec<&str> = skills.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "artifact-census",
                "binary-analysis",
                "reconstruction-ledger",
                "media-re",
                "observation"
            ]
        );
    }
}
