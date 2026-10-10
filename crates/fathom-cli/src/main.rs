//! fathom: clean-room Rust port of REA (SPEC.md).
//!
//! Surfaces: `serve` (MCP over stdio, or HTTP with the A2A card
//! when `--http` is given), `card`, `doctor`, and `tool` for
//! one-shot calls. Every failure prints the canonical error
//! envelope to stderr and exits non-zero.
#![forbid(unsafe_code)]

mod composition;
mod core_tools;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::registry::Registry;

#[derive(Parser)]
#[command(
    name = "fathom",
    version,
    about = "Reverse engineer anything — evidence-first MCP/A2A server (Rust port)"
)]
struct Cli {
    /// Config file (default: ./fathom.toml if present, else restrictive defaults)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the signed A2A agent card as JSON
    Card {
        /// Public URL the card advertises
        #[arg(long)]
        url: Option<String>,
    },
    /// Report host facts: engines, config, catalog (facts, not fixes)
    Doctor,
    /// Serve MCP (stdio by default; --http for streamable HTTP + agent card)
    Serve {
        /// Serve HTTP on the configured bind instead of stdio
        #[arg(long)]
        http: bool,
    },
    /// Call one tool once and print its evidence envelope
    Tool {
        /// Tool name (see the catalog via the session_info tool)
        name: String,
        /// JSON arguments object
        #[arg(default_value = "{}")]
        args: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.to_envelope());
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), FathomError> {
    let config = load_config(cli.config.as_deref())?;
    let registry = composition::build_registry();
    match cli.command {
        Command::Card { url } => {
            let card = build_card(&config, &registry, url.as_deref())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&card).unwrap_or_default()
            );
            Ok(())
        }
        Command::Doctor => {
            println!(
                "{}",
                serde_json::to_string_pretty(&doctor(&config, &registry)).unwrap_or_default()
            );
            Ok(())
        }
        Command::Serve { http } => {
            if http {
                serve_http(config, registry)
            } else {
                fathom_mcp::stdio::run_stdio(&registry, &config)
            }
        }
        Command::Tool { name, args } => {
            let args: Value = serde_json::from_str(&args).map_err(|e| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("tool arguments are not JSON: {e}"),
                )
            })?;
            let value = registry.call(&config, &name, &args)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            Ok(())
        }
    }
}

/// Config resolution: explicit `--config`, else `./fathom.toml` when
/// present, else restrictive defaults (SPEC §8).
fn load_config(explicit: Option<&std::path::Path>) -> Result<Config, FathomError> {
    if let Some(path) = explicit {
        return Config::load(path);
    }
    let local = PathBuf::from("fathom.toml");
    if local.exists() {
        return Config::load(&local);
    }
    Ok(Config::restrictive_default())
}

fn build_card(
    config: &Config,
    registry: &Registry,
    url: Option<&str>,
) -> Result<Value, FathomError> {
    let signing = match &config.signing_key_file {
        Some(path) => Some(fathom_a2a::load_signing_key(path)?),
        None => None,
    };
    let params = fathom_a2a::CardParams {
        description: "Evidence-first reverse-engineering tools: native binaries, JavaScript/Electron, .NET, web captures, EVM, process behavior".to_string(),
        name: fathom_core::PRODUCT_NAME.to_string(),
        organization: "Qompass AI".to_string(),
        url: url
            .map(str::to_string)
            .unwrap_or_else(|| format!("http://{}", config.http_bind)),
        version: fathom_core::VERSION.to_string(),
    };
    fathom_a2a::build_card(&params, &registry.descriptors(), signing.as_ref())
}

fn doctor(config: &Config, registry: &Registry) -> Value {
    let descriptors = registry.descriptors();
    let available = descriptors
        .iter()
        .filter(|d| d.availability == fathom_core::registry::Availability::Available)
        .count();
    let headless = fathom_native::locate_headless(config);
    json!({
        "product": fathom_core::PRODUCT_NAME,
        "version": fathom_core::VERSION,
        "catalog_digest": registry.catalog_digest(),
        "config": {
            "allow_tools": config.allow_tools,
            "http_bind": config.http_bind.to_string(),
            "http_bind_is_loopback": config.http_bind_is_loopback(),
            "signing_key_configured": config.signing_key_file.is_some(),
            "state_dir": config.state_dir.display().to_string(),
            "target_roots": config.target_roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        },
        "engines": {
            "ghidra_headless": headless.map(|p| p.display().to_string()),
        },
        "tools": {
            "total": descriptors.len(),
            "available": available,
            "not_implemented": descriptors.len() - available,
        },
    })
}

fn serve_http(config: Config, registry: Registry) -> Result<(), FathomError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot start async runtime: {e}"),
        )
    })?;
    runtime.block_on(async move {
        let card = build_card(&config, &registry, None)?;
        let state = Arc::new(fathom_mcp::http::HttpState {
            config: Arc::new(config),
            registry: Arc::new(registry),
        });
        let address = state.config.http_bind;
        let listener = tokio::net::TcpListener::bind(address).await.map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot bind {address}: {e}"),
            )
        })?;
        let app = fathom_mcp::http::router(state).merge(fathom_a2a::card::card_router(card));
        axum::serve(listener, app).await.map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("http server failed: {e}"),
            )
        })
    })
}
