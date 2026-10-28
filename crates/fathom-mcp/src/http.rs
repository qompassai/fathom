//! MCP over streamable HTTP: `POST /mcp` served by rmcp's
//! streamable-HTTP service with the same handler as stdio.
//! Stateless per request, matching the stateless tool design
//! (SPEC §10).
//!
//! Modern-only posture (the D-118 app-embedding finding, applied
//! here): legacy session mode is off and stateless requests must
//! carry the modern protocol metadata, so a legacy `initialize`
//! is refused with the designed `-32022` instead of degrading —
//! `LocalSessionManager` is what produces that refusal; a
//! never-session manager answers HTTP 500 instead. Requests are
//! answered as plain JSON (no SSE stream), and the request body
//! is bounded at the fleet's 4 MiB line bound.

use std::sync::Arc;

use axum::routing::get;
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

use fathom_core::config::Config;
use fathom_core::registry::Registry;

use crate::server::FathomServer;

/// Maximum request-body bytes (the fleet bound; domain payload
/// limits live separately in `fathom_core::limits`).
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Shared transport state.
pub struct HttpState {
    pub config: Arc<Config>,
    pub registry: Arc<Registry>,
}

/// The rmcp server config for the modern-only posture.
fn modern_only_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_stateless_protocol_metadata_required(true)
        .with_json_response(true)
        .with_max_request_body_bytes(MAX_BODY_BYTES)
}

/// The HTTP router: `/mcp` plus a plain `/health` fact.
pub fn router(state: Arc<HttpState>) -> axum::Router {
    let registry = Arc::clone(&state.registry);
    let config = Arc::clone(&state.config);
    let service = StreamableHttpService::new(
        move || {
            Ok(FathomServer::new(
                Arc::clone(&registry),
                Arc::clone(&config),
            ))
        },
        LocalSessionManager::default().into(),
        modern_only_config(),
    );
    axum::Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest_service("/mcp", service)
}

/// Bind and serve until the process is stopped.
pub async fn serve(state: Arc<HttpState>) -> Result<(), fathom_core::error::FathomError> {
    let address = state.config.http_bind;
    let listener = tokio::net::TcpListener::bind(address).await.map_err(|e| {
        fathom_core::error::FathomError::new(
            fathom_core::error::ErrorCode::ExecutionFailure,
            format!("cannot bind {address}: {e}"),
        )
    })?;
    axum::serve(listener, router(state)).await.map_err(|e| {
        fathom_core::error::FathomError::new(
            fathom_core::error::ErrorCode::ExecutionFailure,
            format!("http server failed: {e}"),
        )
    })
}
