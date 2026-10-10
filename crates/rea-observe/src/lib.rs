//! rea-observe: runtime and capture providers (SPEC §9.4).
//!
//! `capture_process` (execute class, default-deny), HAR capture
//! reading, EVM selector extraction, and the scaffolded
//! browser / firmware / Android providers. Stage 1 registers the
//! catalog as scaffolds; stage 3 builds the handlers.
#![forbid(unsafe_code)]

use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, target_schema};
use serde_json::json;

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register_not_implemented(
        descriptor(
            "capture_process",
            ToolClass::Execute,
            "process",
            "Run an allowlisted command confined, capturing output, exit, timing, and hashes",
            json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": "argv; the program must be allowlisted by name in config",
                    },
                },
                "required": ["command"],
                "additionalProperties": false,
            }),
        ),
        "§9.4",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_android_apk",
            ToolClass::Read,
            "android",
            "Static APK analysis via a caller-supplied headless JADX engine",
            target_schema(),
        ),
        "§9.4",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_evm_bytecode",
            ToolClass::Read,
            "evm",
            "Offline EVM bytecode: dispatcher scan and inferred function selectors",
            json!({
                "type": "object",
                "properties": {
                    "bytecode": {"type": "string", "description": "Hex bytecode, optional 0x prefix"},
                    "target": {"type": "string", "description": "Or a file under a target root"},
                },
                "additionalProperties": false,
            }),
        ),
        "§9.4",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_firmware",
            ToolClass::Read,
            "firmware",
            "Firmware regions and extraction via caller-supplied Binwalk/Unblob engines",
            target_schema(),
        ),
        "§9.4",
    );
    registry.register_not_implemented(
        descriptor(
            "inspect_web_capture",
            ToolClass::Read,
            "web",
            "HAR capture reading: request/response inventory and payload exposure",
            target_schema(),
        ),
        "§9.4",
    );
    registry.register_not_implemented(
        descriptor(
            "observe_browser",
            ToolClass::Observe,
            "browser",
            "CDP website observation: structure, scripts, network, screenshots on request",
            json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": false,
            }),
        ),
        "§9.4",
    );
}
