use std::sync::Arc;

use axum::{body::Body, http::Request};
use flamingo_verifier_host::{AppState, HostConfig, enclave::PontifexEnclaveClient, routes};
use tower::ServiceExt;

/// Liveness, not readiness: it answers with no enclave reachable at all.
#[tokio::test]
async fn health_returns_ok() {
    let state = AppState::new(
        HostConfig::default(),
        Arc::new(PontifexEnclaveClient::new(0, 0)),
    );
    let response = routes::handler()
        .with_state(state)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("health request should be valid"),
        )
        .await
        .expect("health request should succeed");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
