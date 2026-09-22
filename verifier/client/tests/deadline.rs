//! The client must give up when the host never answers, at the configured deadline.

#![cfg(not(target_arch = "wasm32"))]

use std::net::{Ipv4Addr, SocketAddr};

use axum::Router;
use axum::routing::post;
use flamingo_verifier_client::{Config, Error, FlamingoVerifierClient};

/// Serves `router` on an ephemeral port and returns its base URL.
async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");

    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("stub should run");
    });

    format!("http://{address}")
}

#[tokio::test]
async fn a_host_that_never_answers_fails_at_the_deadline() {
    // Exercises the native request timeout; the browser's AbortSignal deadline is
    // compile-checked in CI only.
    let base_url = serve(Router::new().route(
        "/v1/enclave-assignment",
        post(|| async { std::future::pending::<()>().await }),
    ))
    .await;
    let config = Config::from_json(
        &serde_json::json!({
            "host_url": base_url,
            "allowed_pcr_configs": [[{"index": 0, "value": "01".repeat(48)}]],
            "request_timeout_millis": 20
        })
        .to_string(),
    )
    .expect("config should be valid");

    let error = FlamingoVerifierClient::new(config)
        .expect("client should build")
        .request_assignment()
        .await
        .expect_err("a host that hangs must not block past the deadline");

    assert!(
        matches!(error, Error::Request(ref error) if error.is_timeout()),
        "unexpected error: {error}"
    );
}
