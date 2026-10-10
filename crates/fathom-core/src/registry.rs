//! The tool registry and dispatch (SPEC §4, §8).
//!
//! One registry holds every tool: its descriptor (name, class,
//! provider, schema, availability) and its handler. Dispatch is
//! policy-first: the policy engine decides before any handler
//! runs, and a scaffolded tool answers with an explicit
//! `not_implemented` error — never a fabricated success.

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{ErrorCode, FathomError};
use crate::evidence::sha256_hex;
use crate::policy::{self, PolicyDecision, ToolClass};

/// Whether a tool can run in this build right now.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Availability {
    Available,
    NotImplemented { spec: String },
    Unavailable { reason: String },
}

/// A tool's public contract.
#[derive(Clone, Debug, Serialize)]
pub struct ToolDescriptor {
    pub name: String,
    #[serde(rename = "class")]
    pub tool_class: ToolClass,
    pub provider: String,
    pub description: String,
    pub input_schema: Value,
    pub availability: Availability,
}

/// A tool handler: registry + config + JSON arguments → evidence
/// JSON. The registry is passed so discovery tools (`session_info`)
/// can describe the catalog they live in.
pub type ToolHandler =
    Arc<dyn Fn(&Registry, &Config, &Value) -> Result<Value, FathomError> + Send + Sync>;

struct RegisteredTool {
    descriptor: ToolDescriptor,
    handler: Option<ToolHandler>,
}

/// The complete tool inventory, alphabetical by construction.
#[derive(Default)]
pub struct Registry {
    tools: BTreeMap<String, RegisteredTool>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            tools: BTreeMap::new(),
        }
    }

    /// Register an implemented tool.
    pub fn register(&mut self, descriptor: ToolDescriptor, handler: ToolHandler) {
        let name = descriptor.name.clone();
        let previous = self.tools.insert(
            name.clone(),
            RegisteredTool {
                descriptor,
                handler: Some(handler),
            },
        );
        assert!(previous.is_none(), "duplicate tool registration: {name}");
    }

    /// Register a scaffolded tool: listed in the catalog, answers
    /// `not_implemented`, runs no handler.
    pub fn register_not_implemented(&mut self, mut descriptor: ToolDescriptor, spec: &str) {
        descriptor.availability = Availability::NotImplemented {
            spec: spec.to_string(),
        };
        let name = descriptor.name.clone();
        let previous = self.tools.insert(
            name.clone(),
            RegisteredTool {
                descriptor,
                handler: None,
            },
        );
        assert!(previous.is_none(), "duplicate tool registration: {name}");
    }

    /// Every descriptor, alphabetical by tool name.
    pub fn descriptors(&self) -> Vec<ToolDescriptor> {
        self.tools
            .values()
            .map(|tool| tool.descriptor.clone())
            .collect()
    }

    /// A digest of the catalog (identity for `session_info`).
    pub fn catalog_digest(&self) -> String {
        let serialized = serde_json::to_string(&self.descriptors()).unwrap_or_default();
        sha256_hex(serialized.as_bytes())
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Dispatch one call: policy first, availability second,
    /// handler last. Missing coverage is never fabricated.
    pub fn call(&self, config: &Config, name: &str, args: &Value) -> Result<Value, FathomError> {
        let tool = self.tools.get(name).ok_or_else(|| {
            FathomError::new(ErrorCode::InvalidRequest, format!("unknown tool: {name}"))
                .with_remediation("Call tools/list for the complete catalog.")
        })?;
        if let PolicyDecision::Deny { reason } =
            policy::decide(config, tool.descriptor.tool_class, name)
        {
            return Err(FathomError::new(ErrorCode::AccessDenied, reason).with_target(name));
        }
        match &tool.descriptor.availability {
            Availability::NotImplemented { spec } => Err(FathomError::not_implemented(name, spec)),
            Availability::Unavailable { reason } => Err(FathomError::new(
                ErrorCode::CapabilityUnavailable,
                format!("tool '{name}' is unavailable: {reason}"),
            )),
            Availability::Available => {
                let handler = tool
                    .handler
                    .as_ref()
                    .expect("available tools always carry a handler");
                handler(self, config, args)
            }
        }
    }
}

/// The `session_info` result: identity and discovery (SPEC §4).
pub fn session_info(config: &Config, registry: &Registry) -> Value {
    let descriptors = registry.descriptors();
    let available = descriptors
        .iter()
        .filter(|d| d.availability == Availability::Available)
        .count();
    json!({
        "product": crate::PRODUCT_NAME,
        "version": crate::VERSION,
        "catalog_digest": registry.catalog_digest(),
        "tools_total": descriptors.len(),
        "tools_available": available,
        "tools": descriptors,
        "target_roots": config.target_roots.len(),
        "allow_tools": config.allow_tools,
        "state_dir": config.state_dir.display().to_string(),
    })
}

/// A descriptor with `Available` availability; providers flip
/// scaffolded entries by registering a handler instead of a
/// scaffold (see [`Registry::register_not_implemented`]).
pub fn descriptor(
    name: &str,
    tool_class: ToolClass,
    provider: &str,
    description: &str,
    input_schema: Value,
) -> ToolDescriptor {
    ToolDescriptor {
        name: name.to_string(),
        tool_class,
        provider: provider.to_string(),
        description: description.to_string(),
        input_schema,
        availability: Availability::Available,
    }
}

/// The shared `{target}` input schema most read tools use.
pub fn target_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Path under a configured target root"},
        },
        "required": ["target"],
        "additionalProperties": false,
    })
}

/// The empty input schema (discovery tools).
pub fn empty_schema() -> Value {
    json!({"type": "object", "properties": {}, "additionalProperties": false})
}

/// Extract a required string argument from tool arguments.
pub fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, FathomError> {
    args.get(field).and_then(Value::as_str).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!("argument '{field}' is required and must be a string"),
        )
    })
}

/// Extract an optional string argument from tool arguments.
pub fn optional_str<'a>(args: &'a Value, field: &str) -> Option<&'a str> {
    args.get(field).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigFile;
    use serde_json::json;

    fn descriptor(name: &str, class: ToolClass) -> ToolDescriptor {
        ToolDescriptor {
            name: name.to_string(),
            tool_class: class,
            provider: "test".to_string(),
            description: "test tool".to_string(),
            input_schema: json!({"type": "object"}),
            availability: Availability::Available,
        }
    }

    fn config(allow: &[&str]) -> Config {
        Config::from_file_form(ConfigFile {
            allow_tools: Some(allow.iter().map(|s| s.to_string()).collect()),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    #[test]
    fn adversarial_unknown_tool_is_invalid_request() {
        let registry = Registry::new();
        let err = registry.call(&config(&[]), "nope", &json!({})).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_policy_denies_before_handler_runs() {
        let mut registry = Registry::new();
        registry.register(
            descriptor("capture_process", ToolClass::Execute),
            Arc::new(|_, _, _| panic!("handler must not run when policy denies")),
        );
        let err = registry
            .call(&config(&[]), "capture_process", &json!({}))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
    }

    #[test]
    fn adversarial_scaffold_answers_not_implemented_not_success() {
        let mut registry = Registry::new();
        registry
            .register_not_implemented(descriptor("observe_browser", ToolClass::Observe), "§9.4");
        let err = registry
            .call(&config(&["observe_browser"]), "observe_browser", &json!({}))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(err.details.unwrap()["status"], "not_implemented");
    }

    #[test]
    fn validation_registered_read_tool_runs() {
        let mut registry = Registry::new();
        registry.register(
            descriptor("session_info", ToolClass::Read),
            Arc::new(|_, _, _| Ok(json!({"ok": true}))),
        );
        let value = registry
            .call(&config(&[]), "session_info", &json!({}))
            .unwrap();
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn validation_descriptors_are_alphabetical() {
        let mut registry = Registry::new();
        for name in ["zebra_tool", "alpha_tool", "middle_tool"] {
            registry.register(
                descriptor(name, ToolClass::Read),
                Arc::new(|_, _, _| Ok(json!({}))),
            );
        }
        let names: Vec<String> = registry
            .descriptors()
            .iter()
            .map(|d| d.name.clone())
            .collect();
        assert_eq!(names, vec!["alpha_tool", "middle_tool", "zebra_tool"]);
    }
}
