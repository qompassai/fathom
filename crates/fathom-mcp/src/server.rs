//! The rmcp server: tool surface and handler dispatch.
//!
//! Fathom rides the fleet's standardized pattern (D-113): rmcp
//! owns the envelope, the era guard (see `guard.rs`) owns the
//! stdio front door, and this handler owns the tools. All domain
//! work stays in the registry (`fathom_core::registry`), which is
//! transport-blind and unchanged by the migration: policy first,
//! availability second, handler last.
//!
//! Modern-only posture lives in two places: the era guard refuses
//! `initialize` before the SDK sees it, and
//! [`ServerHandler::supported_protocol_versions`] pins this
//! handler to 2026-07-28, so `server/discover` advertises exactly
//! one version and the SDK validates every request's `_meta`
//! against it.
//!
//! Result carriage matches the hand-rolled baseline byte-for-byte
//! in the parts clients depend on: success is one text block
//! carrying the compact value plus the value itself as
//! `structuredContent`; a domain failure is an `isError` result
//! whose text is the canonical error envelope, with no
//! `structuredContent`. (The SDK adds the era's `resultType`
//! field to success envelopes — the 2026-07-28 schema requires
//! it; recorded in the migration gate report.)
//!
//! Tool advertisement: the complete catalog is always listed,
//! including unavailable tools (SPEC §4). The baseline's
//! estate-specific annotation fields (`class`, `provider`,
//! `availability`) cannot ride rmcp's closed `ToolAnnotations`
//! type, so they move — same names, same values — into the
//! tool's `_meta` under the `fathom` key; the three standard
//! hints keep their baseline values in `annotations`. The same
//! facts also remain in-band via `session_info`.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeResult, ListToolsResult, MetaObject, PaginatedRequestParams, ProtocolVersion,
    ServerCapabilities, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, ToolDescriptor};

/// The MCP handler: one registry + config behind arcs; calls
/// dispatch through the registry on a blocking thread so a long
/// analysis cannot stall the runtime.
pub struct FathomServer {
    config: Arc<Config>,
    registry: Arc<Registry>,
}

impl FathomServer {
    pub fn new(registry: Arc<Registry>, config: Arc<Config>) -> Self {
        FathomServer { config, registry }
    }
}

/// The MCP form of one tool descriptor (see the module docs for
/// the annotations split).
fn descriptor_to_tool(descriptor: &ToolDescriptor) -> Tool {
    let schema = descriptor
        .input_schema
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut tool = Tool::new(
        descriptor.name.clone(),
        descriptor.description.clone(),
        schema,
    );
    tool.annotations = Some(ToolAnnotations::from_raw(
        None,
        Some(descriptor.tool_class == ToolClass::Read),
        Some(false),
        None,
        Some(false),
    ));
    let mut meta = serde_json::Map::new();
    meta.insert(
        "fathom".to_string(),
        json!({
            "availability": descriptor.availability,
            "class": descriptor.tool_class.as_str(),
            "provider": descriptor.provider,
        }),
    );
    tool.meta = Some(MetaObject(meta));
    tool
}

/// Run one registry call and shape the result exactly as the
/// baseline's core did. Synchronous: the handler runs it on a
/// blocking thread.
fn run_call(registry: &Registry, config: &Config, name: &str, arguments: &Value) -> CallToolResult {
    match registry.call(config, name, arguments) {
        Ok(value) => {
            let mut result = CallToolResult::success(vec![ContentBlock::text(value.to_string())]);
            result.structured_content = Some(value);
            result
        }
        Err(error) => {
            CallToolResult::error(vec![ContentBlock::text(error.to_envelope().to_string())])
        }
    }
}

impl ServerHandler for FathomServer {
    fn get_info(&self) -> InitializeResult {
        let mut server_info = Implementation::default();
        server_info.name = fathom_core::PRODUCT_NAME.to_string();
        server_info.version = fathom_core::VERSION.to_string();
        let mut info = InitializeResult::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = server_info;
        info
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: self
                .registry
                .descriptors()
                .iter()
                .map(descriptor_to_tool)
                .collect(),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let registry = Arc::clone(&self.registry);
        let config = Arc::clone(&self.config);
        let outcome =
            tokio::task::spawn_blocking(move || run_call(&registry, &config, &name, &arguments))
                .await;
        match outcome {
            Ok(result) => Ok(result.into()),
            Err(join) => Err(ErrorData::internal_error(
                format!("tool task failed: {join}"),
                None,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::error::{ErrorCode, FathomError};
    use fathom_core::registry::Availability;

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
            Arc::new(|_, _, _| Ok(json!({"product": "fathom"}))),
        );
        registry.register(
            ToolDescriptor {
                name: "capture_process".to_string(),
                tool_class: ToolClass::Execute,
                provider: "observe".to_string(),
                description: "capture".to_string(),
                input_schema: json!({"type": "object"}),
                availability: Availability::Available,
            },
            Arc::new(|_, _, _| Err(FathomError::new(ErrorCode::ExecutionFailure, "boom"))),
        );
        registry
    }

    fn server() -> FathomServer {
        FathomServer::new(
            Arc::new(registry()),
            Arc::new(Config::restrictive_default()),
        )
    }

    #[test]
    fn adversarial_tool_failure_is_is_error_with_envelope() {
        let server = server();
        // capture_process is execute-class: the restrictive
        // default config denies it before the handler runs, and
        // the denial is an isError envelope, not a protocol error.
        let result = run_call(
            &server.registry,
            &server.config,
            "capture_process",
            &json!({}),
        );
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
        let serialized = serde_json::to_value(&result).unwrap();
        let text = serialized["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("access_denied"), "text was: {text}");
    }

    #[test]
    fn adversarial_unknown_tool_is_is_error_not_protocol_error() {
        let server = server();
        let result = run_call(&server.registry, &server.config, "missing_tool", &json!({}));
        assert_eq!(result.is_error, Some(true));
        let serialized = serde_json::to_value(&result).unwrap();
        let text = serialized["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("invalid_request"), "text was: {text}");
        assert!(
            text.contains("unknown tool: missing_tool"),
            "text was: {text}"
        );
    }

    #[test]
    fn validation_call_success_carries_text_and_structured_content() {
        let server = server();
        let result = run_call(&server.registry, &server.config, "session_info", &json!({}));
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content,
            Some(json!({"product": "fathom"}))
        );
        let serialized = serde_json::to_value(&result).unwrap();
        assert_eq!(
            serialized["content"][0]["text"],
            json!("{\"product\":\"fathom\"}")
        );
        assert_eq!(
            serialized["structuredContent"],
            json!({"product": "fathom"})
        );
    }

    #[test]
    fn validation_descriptor_keeps_hints_and_relocates_estate_fields() {
        let descriptor = ToolDescriptor {
            name: "session_info".to_string(),
            tool_class: ToolClass::Read,
            provider: "core".to_string(),
            description: "identity".to_string(),
            input_schema: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            availability: Availability::Available,
        };
        let serialized = serde_json::to_value(descriptor_to_tool(&descriptor)).unwrap();
        assert_eq!(serialized["name"], json!("session_info"));
        assert_eq!(
            serialized["inputSchema"],
            json!({"type": "object", "properties": {"x": {"type": "string"}}})
        );
        // The standard hints keep their baseline values.
        assert_eq!(serialized["annotations"]["readOnlyHint"], json!(true));
        assert_eq!(serialized["annotations"]["destructiveHint"], json!(false));
        assert_eq!(serialized["annotations"]["openWorldHint"], json!(false));
        // The estate fields move to _meta under `fathom`, values
        // unchanged (availability keeps its serialized shape).
        assert_eq!(serialized["_meta"]["fathom"]["class"], json!("read"));
        assert_eq!(serialized["_meta"]["fathom"]["provider"], json!("core"));
        assert_eq!(
            serialized["_meta"]["fathom"]["availability"],
            json!({"status": "available"})
        );
    }

    #[test]
    fn validation_info_pins_the_modern_era() {
        let server = server();
        let info = server.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);
        assert_eq!(info.server_info.name, "fathom");
        assert_eq!(
            server.supported_protocol_versions().as_ref(),
            &[ProtocolVersion::V_2026_07_28]
        );
    }
}
