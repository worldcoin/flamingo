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
            .layer(TraceLayer::new().with_make_span(|request| {
                // Do not copy raw URLs, query strings, user-agent values or headers to traces.
                let method = match *request.method() {
                    axum::http::Method::GET => "GET",
                    axum::http::Method::POST => "POST",
                    _ => "OTHER",
                };
                let route = match request.uri().path() {
                    "/health" => "/health",
                    "/ready" => "/ready",
                    "/v1/enclave-assignment" => "/v1/enclave-assignment",
                    "/v1/matches" => "/v1/matches",
                    _ => "unmatched",
                };
                tracing::info_span!(
                    "http.request",
                    http.request.method = method,
                    http.route = route,
                    http.response.status_code = tracing::field::Empty,
                    http.status_code = tracing::field::Empty,
                    otel.name = route,
                    otel.kind = "server",
                    otel.status_code = tracing::field::Empty,
                )
            }))
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
