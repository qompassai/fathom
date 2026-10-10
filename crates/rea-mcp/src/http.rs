//! MCP over streamable HTTP: `POST /mcp` on the same JSON-RPC
//! core as stdio. Stateless per request, matching the stateless
//! tool design (SPEC §10).

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::Value;

use rea_core::config::Config;
use rea_core::registry::Registry;

use crate::protocol::handle_message;

/// Shared transport state.
pub struct HttpState {
    pub config: Arc<Config>,
    pub registry: Arc<Registry>,
}

/// The HTTP router: `/mcp` plus a plain `/health` fact.
pub fn router(state: Arc<HttpState>) -> axum::Router {
    axum::Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/mcp", post(handle_post))
        .with_state(state)
}

async fn handle_post(
    State(state): State<Arc<HttpState>>,
    axum::Json(message): axum::Json<Value>,
) -> impl IntoResponse {
    match handle_message(&state.registry, &state.config, &message) {
        Some(response) => axum::Json(response).into_response(),
        None => axum::http::StatusCode::ACCEPTED.into_response(),
    }
}

/// Bind and serve until the process is stopped.
pub async fn serve(state: Arc<HttpState>) -> Result<(), rea_core::error::ReaError> {
    let address = state.config.http_bind;
    let listener = tokio::net::TcpListener::bind(address).await.map_err(|e| {
        rea_core::error::ReaError::new(
            rea_core::error::ErrorCode::ExecutionFailure,
            format!("cannot bind {address}: {e}"),
        )
    })?;
    axum::serve(listener, router(state)).await.map_err(|e| {
        rea_core::error::ReaError::new(
            rea_core::error::ErrorCode::ExecutionFailure,
            format!("http server failed: {e}"),
        )
    })
}
