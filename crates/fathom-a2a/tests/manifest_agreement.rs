//! Manifest agreement: the runtime-generated agent card, the
//! committed static card, and server.json are one provisioning
//! set (D-1605, D-1607, D-1615). Client configs for the estate's
//! agent runtimes are generated from card + server.json pairs, so
//! the join keys must agree exactly, and the card the server
//! serves at runtime must be the card committed at
//! `.well-known/agent-card.json` — the two cannot drift:
//!
//! - runtime card == committed static card, field for field
//! - card `name` == server.json `title`
//! - card `version` == server.json `version`
//! - the card's MCP-interface extension `registryName` ==
//!   server.json `name`
//!
//! The card must also stay honest AND spec-valid (D-1607): it
//! declares exactly one interface, bound with the qompass MCP
//! custom binding (a URI protocolBinding, per the A2A v1.0
//! custom-transport rule) whose url carries the stdio command
//! under that binding's own semantics; no core A2A binding is
//! claimed, no top-level `url` or signature block is emitted, and
//! `stateTransitionHistory` (removed in A2A v1.0) never appears.

use std::path::PathBuf;

fn read_json(rel: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn runtime_card() -> serde_json::Value {
    fathom_a2a::build_card(&fathom_a2a::CardParams::fleet())
}

#[test]
fn runtime_card_equals_committed_static_card() {
    assert_eq!(
        runtime_card(),
        read_json(".well-known/agent-card.json"),
        "the served card and the committed card must agree (D-1615)"
    );
}

#[test]
fn card_and_server_json_agree_on_the_join_keys() {
    let card = runtime_card();
    let server = read_json("server.json");
    assert_eq!(card["name"], server["title"], "card name / server title");
    assert_eq!(
        card["version"], server["version"],
        "card version / server version"
    );
    let extension = &card["capabilities"]["extensions"][0];
    assert_eq!(
        extension["params"]["registryName"], server["name"],
        "extension registryName / server name"
    );
}

#[test]
fn card_declares_no_a2a_endpoint_and_carries_invocation() {
    let card = runtime_card();
    // Spec-valid honesty (D-1607): supportedInterfaces is a
    // required, non-empty field in A2A v1.0, so the card
    // declares exactly one interface under the qompass MCP
    // custom binding (URI protocolBinding); its url carries
    // the stdio command under that binding's semantics. No
    // core A2A binding (JSONRPC / GRPC / HTTP+JSON) is claimed.
    let interfaces = card["supportedInterfaces"].as_array().expect("interfaces");
    assert_eq!(interfaces.len(), 1, "exactly one declared interface");
    assert_eq!(
        interfaces[0]["protocolBinding"],
        "https://qompass.ai/extensions/mcp-interface/v1"
    );
    assert_eq!(
        interfaces[0]["url"],
        "~/.GH/Qompass/fathom/target/release/fathom"
    );
    assert_eq!(interfaces[0]["protocolVersion"], "1.0");
    // Fields the pre-profile card emitted, and one A2A v1.0
    // removed, must never reappear.
    assert!(card.get("url").is_none(), "no top-level url");
    assert!(card.get("signature").is_none(), "no signature block");
    assert!(
        card["capabilities"].get("stateTransitionHistory").is_none(),
        "stateTransitionHistory was removed in A2A v1.0"
    );
    // Provider, if present, carries both organization and url.
    assert_eq!(card["provider"]["organization"], "Qompass AI");
    assert_eq!(card["provider"]["url"], "https://qompass.ai");
    let invocation = &card["capabilities"]["extensions"][0]["params"]["invocation"];
    assert_eq!(invocation["transport"], "stdio");
    assert_eq!(
        invocation["command"],
        "~/.GH/Qompass/fathom/target/release/fathom"
    );
    assert_eq!(invocation["args"], serde_json::json!(["serve"]));
    assert_eq!(invocation["protocolEra"], "2026-07-28");
    // The five tool groups are the card's skills.
    assert_eq!(card["skills"].as_array().map(Vec::len), Some(5));
}
