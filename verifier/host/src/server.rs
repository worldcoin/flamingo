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

    axum::serve(
        listener,
        routes::handler()
            .with_state(state)
            .layer(TraceLayer::new_for_axum())
            .into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("API server failed")
}

/// Resolves on the first shutdown signal. SIGTERM as well as Ctrl-C, since that is what an
/// orchestrator sends when it drains a pod.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    /// Compile-time level caps must not strip the default middleware's TRACE spans in release.
    #[test]
    fn default_http_span_is_enabled() {
        tracing::subscriber::with_default(tracing_subscriber::Registry::default(), || {
            let request = axum::http::Request::new(());
            let span = telemetry_batteries::tracing::middleware::make_span_from_request(&request);
            assert!(!span.is_disabled());
        });
    }
}
