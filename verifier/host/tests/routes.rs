//! Route tests driven through the real router.
//!
//! Requests go through `routes::handler()`, so the path and method each route is registered
//! under are covered alongside its behaviour.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{StubEnclaveClient, state_with};
use flamingo_verifier_host::AppState;
use flamingo_verifier_host::enclave;
use flamingo_verifier_host::routes;
use tower::ServiceExt as _;

/// Sends `request` through the router and returns the status.
async fn status(state: AppState, request: Request<Body>) -> StatusCode {
    routes::handler()
        .with_state(state)
        .oneshot(request)
        .await
        .expect("the router should answer")
        .status()
}

fn request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request should be valid")
}

/// The versioned HTTP transport is gone: the assignment and the sealed match exchange now run over
/// the unversioned `/matches` WebSocket, so the old routes must not answer.
#[tokio::test]
async fn versioned_http_routes_are_gone() {
    for (method, uri) in [
        (Method::POST, "/v1/enclave-assignment"),
        (Method::POST, "/v1/matches"),
        (Method::GET, "/v2/matches"),
    ] {
        let response = status(
            state_with(StubEnclaveClient::default()),
            request(method, uri),
        )
        .await;

        assert_eq!(response, StatusCode::NOT_FOUND, "{uri} should not exist");
    }
}

/// Readiness is not liveness: with the registry gone the enclave is the only dependency left,
/// so readiness must follow it in both directions.
#[tokio::test]
async fn readiness_follows_the_enclave() {
    let ready = status(
        state_with(StubEnclaveClient::default()),
        request(Method::GET, "/ready"),
    )
    .await;
    assert_eq!(ready, StatusCode::OK);

    let unreachable = status(
        state_with(StubEnclaveClient {
            health: Some(Err(enclave::Error::Timeout)),
            ..StubEnclaveClient::default()
        }),
        request(Method::GET, "/ready"),
    )
    .await;
    assert_eq!(unreachable, StatusCode::SERVICE_UNAVAILABLE);
}
