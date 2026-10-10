//! The JSON-RPC core shared by both transports.

use serde_json::{Value, json};

use rea_core::config::Config;
use rea_core::registry::{Registry, ToolDescriptor};

/// Handle one JSON-RPC message. Notifications (no `id`) return
/// `None`: they never produce a response.
pub fn handle_message(registry: &Registry, config: &Config, message: &Value) -> Option<Value> {
    let id = message.get("id")?.clone();
    let response = match message.get("method").and_then(Value::as_str) {
        Some("initialize") => success_response(
            id,
            json!({
                "protocolVersion": crate::PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": rea_core::PRODUCT_NAME,
                    "version": rea_core::VERSION,
                },
            }),
        ),
        Some("ping") => success_response(id, json!({})),
        Some("tools/list") => success_response(
            id,
            json!({
                "tools": registry.descriptors().iter().map(tool_json).collect::<Vec<_>>(),
            }),
        ),
        Some("tools/call") => handle_tool_call(registry, config, message),
        Some(other) => error_response(id, -32601, &format!("method not found: {other}")),
        None => error_response(id, -32600, "invalid request: no method"),
    };
    Some(response)
}

fn handle_tool_call(registry: &Registry, config: &Config, message: &Value) -> Value {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str);
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let name = match name {
        Some(name) => name,
        None => return error_response(id, -32602, "invalid params: tools/call needs a name"),
    };
    match registry.call(config, name, &arguments) {
        Ok(value) => success_response(
            id,
            json!({
                "content": [{"type": "text", "text": value.to_string()}],
                "structuredContent": value,
                "isError": false,
            }),
        ),
        Err(error) => success_response(
            id,
            json!({
                "content": [{"type": "text", "text": error.to_envelope().to_string()}],
                "isError": true,
            }),
        ),
    }
}

/// The MCP form of one tool descriptor. The complete catalog is
/// always advertised, including unavailable tools (SPEC §4).
pub fn tool_json(tool: &ToolDescriptor) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": {
            "class": tool.tool_class.as_str(),
            "provider": tool.provider,
            "availability": tool.availability,
            "readOnlyHint": tool.tool_class == rea_core::policy::ToolClass::Read,
            "destructiveHint": false,
            "openWorldHint": false,
        },
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::config::Config;
    use rea_core::policy::ToolClass;
    use rea_core::registry::{Availability, ToolDescriptor};
    use std::sync::Arc;

    fn registry() -> Registry {
        let mut registry = Registry::new();
        registry.register(
            ToolDescriptor {
                name: "session_info".to_string(),
                tool_class: ToolClass::Read,
                provider: "core".to_string(),
                description: "identity".to_string(),
                input_schema: json!({"type": "object"}),
                availability: Availability::Available,
            },
            Arc::new(|_, _, _| Ok(json!({"product": "rea-rust"}))),
        );
        registry
    }

    #[test]
    fn adversarial_unknown_method_is_method_not_found() {
        let registry = registry();
        let config = Config::restrictive_default();
        let response = handle_message(
            &registry,
            &config,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "bogus/method"}),
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn adversarial_notification_gets_no_response() {
        let registry = registry();
        let config = Config::restrictive_default();
        let response = handle_message(
            &registry,
            &config,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        );
        assert!(response.is_none());
    }

    #[test]
    fn adversarial_tool_failure_is_is_error_with_envelope() {
        let registry = registry();
        let config = Config::restrictive_default();
        let response = handle_message(
            &registry,
            &config,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "missing_tool", "arguments": {}}
            }),
        )
        .unwrap();
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("invalid_request"), "text was: {text}");
        assert!(response["result"].get("structuredContent").is_none());
    }

    #[test]
    fn validation_initialize_reports_identity() {
        let registry = registry();
        let config = Config::restrictive_default();
        let response = handle_message(
            &registry,
            &config,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        )
        .unwrap();
        assert_eq!(response["result"]["serverInfo"]["name"], "rea-rust");
    }

    #[test]
    fn validation_tools_list_and_call() {
        let registry = registry();
        let config = Config::restrictive_default();
        let list = handle_message(
            &registry,
            &config,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .unwrap();
        assert_eq!(list["result"]["tools"][0]["name"], "session_info");
        let call = handle_message(
            &registry,
            &config,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "session_info", "arguments": {}}
            }),
        )
        .unwrap();
        assert_eq!(call["result"]["isError"], false);
        assert_eq!(call["result"]["structuredContent"]["product"], "rea-rust");
    }
}
