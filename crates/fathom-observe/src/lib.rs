//! fathom-observe: runtime and capture providers (SPEC §9.4).
//!
//! `capture_process` (execute class, default-deny), HAR capture
//! reading, browser observation, firmware inspection, and EVM
//! selector extraction, and the Android APK provider are
//! built.
#![forbid(unsafe_code)]

mod android;
mod browser;
mod capture;
mod evm;
mod firmware;
mod har;

use std::sync::Arc;

use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, target_schema};
use serde_json::json;

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register(
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
        Arc::new(capture::capture_process),
    );
    registry.register(
        descriptor(
            "inspect_android_apk",
            ToolClass::Read,
            "android",
            "Static APK inventory: ZIP contents, contents classes, and the binary-XML manifest (package, permissions, components)",
            target_schema(),
        ),
        Arc::new(android::inspect_android_apk),
    );
    registry.register(
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
        Arc::new(evm::inspect_evm_bytecode),
    );
    registry.register(
        descriptor(
            "inspect_firmware",
            ToolClass::Read,
            "firmware",
            "Firmware inspection: header/format detection, embedded-filesystem signature scan, entropy profile (no extraction)",
            target_schema(),
        ),
        Arc::new(firmware::inspect_firmware),
    );
    registry.register(
        descriptor(
            "inspect_web_capture",
            ToolClass::Read,
            "web",
            "HAR capture reading: request/response inventory and payload exposure",
            target_schema(),
        ),
        Arc::new(har::inspect_web_capture),
    );
    registry.register(
        descriptor(
            "observe_browser",
            ToolClass::Observe,
            "browser",
            "Chromium-headless page observation: title, meta, script, link, and form inventory from the serialized DOM",
            json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(browser::observe_browser),
    );
}
