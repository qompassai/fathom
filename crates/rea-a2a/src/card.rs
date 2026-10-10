//! The signed A2A agent card (SPEC §10).
//!
//! Skills derive from the tool registry. The signature covers
//! the JCS canonicalization of the card without the `signature`
//! field. Without an operator key the card is served with an
//! explicit unsigned marker — a visible fact, not a silent
//! forgery.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use std::path::Path;

use rea_core::error::{ErrorCode, ReaError};
use rea_core::registry::ToolDescriptor;

use crate::jcs::canonicalize;

/// Operator-facing card identity.
#[derive(Clone, Debug)]
pub struct CardParams {
    pub description: String,
    pub name: String,
    pub organization: String,
    pub url: String,
    pub version: String,
}

/// Load an Ed25519 signing key from a file holding the base64 of
/// a 32-byte seed. The file is operator material; keep it 0600.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, ReaError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ReaError::new(
            ErrorCode::ConfigurationInvalid,
            format!("cannot read signing key {}: {e}", path.display()),
        )
    })?;
    let bytes = BASE64.decode(text.trim()).map_err(|e| {
        ReaError::new(
            ErrorCode::ConfigurationInvalid,
            format!("signing key is not base64: {e}"),
        )
    })?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        ReaError::new(
            ErrorCode::ConfigurationInvalid,
            "signing key seed must be exactly 32 bytes",
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Build the card value, signed when a key is supplied.
pub fn build_card(
    params: &CardParams,
    tools: &[ToolDescriptor],
    signing_key: Option<&SigningKey>,
) -> Result<Value, ReaError> {
    let mut skills: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "id": tool.name,
                "name": tool.name,
                "description": tool.description,
                "tags": [tool.tool_class.as_str(), tool.provider.as_str()],
            })
        })
        .collect();
    skills.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let mut card = json!({
        "name": params.name,
        "description": params.description,
        "url": params.url,
        "version": params.version,
        "provider": {"organization": params.organization},
        "capabilities": {"pushNotifications": false, "streaming": false},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
    });
    match signing_key {
        Some(key) => {
            let canonical = canonicalize(&card)?;
            let signature = key.sign(canonical.as_bytes());
            let verifying = key.verifying_key();
            card["signature"] = json!({
                "alg": "Ed25519",
                "kid": BASE64.encode(verifying.to_bytes()),
                "value": BASE64.encode(signature.to_bytes()),
            });
        }
        None => {
            card["signature"] = json!({
                "alg": "none",
                "status": "unsigned — no signing key configured",
            });
        }
    }
    Ok(card)
}

/// Verify a card's signature against a verifying key.
pub fn verify_card_signature(card: &Value, verifying_key: &VerifyingKey) -> Result<bool, ReaError> {
    let signature_block = card
        .get("signature")
        .ok_or_else(|| ReaError::new(ErrorCode::InvalidRequest, "card has no signature"))?;
    let value = signature_block
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ReaError::new(
                ErrorCode::InvalidRequest,
                "card signature is absent or unsigned",
            )
        })?;
    let signature_bytes = BASE64.decode(value).map_err(|e| {
        ReaError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("signature is not base64: {e}"),
        )
    })?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|e| {
        ReaError::new(
            ErrorCode::EvidenceIntegrityMismatch,
            format!("signature has the wrong shape: {e}"),
        )
    })?;
    let mut unsigned = card.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("signature");
    }
    let canonical = canonicalize(&unsigned)?;
    Ok(verifying_key
        .verify(canonical.as_bytes(), &signature)
        .is_ok())
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
    use rea_core::policy::ToolClass;
    use rea_core::registry::Availability;

    fn params() -> CardParams {
        CardParams {
            description: "test card".to_string(),
            name: "rea-rust".to_string(),
            organization: "Qompass AI".to_string(),
            url: "http://127.0.0.1:8731".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn tool(name: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: name.to_string(),
            tool_class: ToolClass::Read,
            provider: "core".to_string(),
            description: "a tool".to_string(),
            input_schema: json!({"type": "object"}),
            availability: Availability::Available,
        }
    }

    #[test]
    fn adversarial_tampered_card_fails_verification() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut card = build_card(&params(), &[tool("alpha")], Some(&key)).unwrap();
        card["description"] = json!("forged description");
        assert!(!verify_card_signature(&card, &key.verifying_key()).unwrap());
    }

    #[test]
    fn validation_signed_card_verifies() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let card = build_card(&params(), &[tool("alpha")], Some(&key)).unwrap();
        assert!(verify_card_signature(&card, &key.verifying_key()).unwrap());
    }

    #[test]
    fn validation_unsigned_card_says_so() {
        let card = build_card(&params(), &[], None).unwrap();
        assert_eq!(card["signature"]["alg"], "none");
    }

    #[test]
    fn validation_skills_derive_from_registry() {
        let card = build_card(&params(), &[tool("beta"), tool("alpha")], None).unwrap();
        let skills = card["skills"].as_array().unwrap();
        assert_eq!(skills.len(), 2);
        assert_eq!(skills[0]["id"], "alpha");
    }
}
