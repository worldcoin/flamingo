use std::sync::Arc;

use axum::{body::Body, http::Request};
mod common;

use common::{FakeEscrowReader, payment_config};
use flamingo_verifier_host::payments::{InMemoryStore, PaymentLedger};
use flamingo_verifier_host::{
    AppState, Environment, PaymentGate, enclave::PontifexEnclaveClient, routes,
};
use tower::ServiceExt;

/// Liveness, not readiness: it answers with no enclave reachable at all.
#[tokio::test]
async fn health_returns_ok() {
    let state = AppState::new(
        Environment::Development,
        Arc::new(PontifexEnclaveClient::new(0, 0)),
        Some(PaymentGate::new(
            Arc::new(PaymentLedger::new(
                payment_config(),
                Arc::new(InMemoryStore::new()),
                Arc::new(FakeEscrowReader::new()),
            )),
            false,
        )),
    );
    let response = routes::handler(true)
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
