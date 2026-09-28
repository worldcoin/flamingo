//! Axum server setup and lifecycle.

use std::net::SocketAddr;

use anyhow::Context;
use telemetry_batteries::tracing::middleware::TraceLayer;
use tokio::net::TcpListener;

use crate::{AppState, routes};

const DEFAULT_PORT: u16 = 8000;

/// Starts the API server.
///
/// # Errors
///
/// Returns an error when the configured port is invalid, the listener cannot bind, or the server
/// exits unexpectedly.
pub async fn start(state: AppState) -> anyhow::Result<()> {
    let port = std::env::var("PORT").map_or(Ok(DEFAULT_PORT), |value| value.parse())?;
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind API to {address}"))?;

    tracing::info!(%address, "API listening");

    axum::serve(
        listener,
        routes::handler()
            .with_state(state)
            .layer(TraceLayer::new_for_axum())
            .into_make_service(),
    )
    .await
    .context("API server failed")
}
