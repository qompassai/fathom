//! MCP over stdio: newline-delimited JSON-RPC on stdin/stdout,
//! with the era guard as the front door (see `guard.rs`).
//! Diagnostics go to stderr; stdout carries protocol only.
//!
//! Wiring: the guard owns stdio, the rmcp service sits behind an
//! in-process duplex, and a pump copies its responses back to
//! stdout through the same lock the guard writes its own frames
//! with — so guard frames and SDK responses can never interleave
//! mid-line, and the guard's ordering tracker keeps its frames
//! behind any earlier forwarded request's response.

use std::sync::Arc;

use rmcp::ServiceExt;
use rmcp::transport::async_rw::AsyncRwTransport;
use tokio::sync::Mutex;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::registry::Registry;

use crate::guard;
use crate::server::FathomServer;

/// Duplex buffer between the era guard and the SDK service.
/// Request lines can reach the 4 MiB line bound; the SDK consumes
/// incrementally, so this only needs to cover response bursts.
const DUPLEX_BUFFER_BYTES: usize = 1024 * 1024;

/// Serve until stdin closes.
pub fn run_stdio(registry: Registry, config: Config) -> Result<(), FathomError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot start async runtime: {e}"),
            )
        })?;
    runtime
        .block_on(serve(Arc::new(registry), Arc::new(config)))
        .map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("stdio serve failed: {e}"),
            )
        })
}

async fn serve(registry: Arc<Registry>, config: Arc<Config>) -> std::io::Result<()> {
    let (client_side, server_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (client_read, client_write) = tokio::io::split(client_side);
    let stdout: guard::SharedStdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let ordering = guard::Ordering::new();
    let handler = FathomServer::new(registry, config);
    let serve = tokio::spawn(async move {
        let transport = AsyncRwTransport::new_server(server_read, server_write);
        match handler.serve(transport).await {
            Ok(running) => running
                .waiting()
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string())),
            // The client closed the connection before selecting a
            // lifecycle (a probe, a spawn check, a client that only
            // ever wanted the refusal): bare EOF is a clean end of
            // session.
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => Ok(()),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    });
    let mut pump = tokio::spawn(guard::pump(
        client_read,
        Arc::clone(&stdout),
        Arc::clone(&ordering),
    ));

    // When stdin reaches EOF the guard shuts the duplex write
    // side down, which ends the SDK service; the pump ends when
    // the service's transport drops. The pump wait is bounded as
    // a backstop: a response still in flight when the service
    // ends gets its chance to drain, but a wedged pump cannot
    // hang exit.
    let guard_result = guard::run(tokio::io::stdin(), client_write, stdout, ordering).await;
    let serve_result = match serve.await {
        Ok(result) => result,
        Err(e) => Err(std::io::Error::other(e.to_string())),
    };
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut pump)
        .await
        .is_err()
    {
        pump.abort();
    }
    guard_result.and(serve_result)
}
