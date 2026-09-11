//! Route tests driven through the real router.
//!
//! Requests go through `routes::handler()`, so the path and method each route is registered
//! under are covered alongside its behaviour.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{StubEnclaveClient, state_with};
use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_host::AppState;
use flamingo_verifier_host::enclave;
use flamingo_verifier_host::routes;
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

/// Sends `request` through the router and returns the status and decoded JSON body.
async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = routes::handler()
        .with_state(state)
        .oneshot(request)
        .await
        .expect("the router should answer");

    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body should be readable")
        .to_bytes();

    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("responses should be JSON")
    };

    (status, body)
}

fn assignment_request() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/enclave-assignment")
        .body(Body::empty())
        .expect("request should be valid")
}

/// Builds a match request carrying `ciphertext` and nothing else.
fn match_request(ciphertext: &str) -> Request<Body> {
    let body = format!(r#"{{"ciphertext":"{ciphertext}"}}"#);

    Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request should be valid")
}

/// Serves only the encryption key. The stub panics on anything else, so this doubles as an
/// assertion that the assignment route asks for one key and not the other.
fn encryption_key(attestation: Vec<u8>) -> StubEnclaveClient {
    StubEnclaveClient {
        encryption_key: Some(Ok(enclave_types::KeyAttestation {
            document: attestation,
            public_key: vec![0xab; 1216],
        })),
        ..StubEnclaveClient::default()
    }
}

#[tokio::test]
async fn assignment_returns_the_document_and_full_key_in_base64() {
    let state = state_with(encryption_key(vec![1, 2, 3]));

    let (status, body) = send(state, assignment_request()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["attestation"], "AQID");
    assert_eq!(body["public_key"], STANDARD.encode(vec![0xab; 1216]));
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(2),
        "the assignment must expose the attestation and full public key"
    );
}

#[tokio::test]
async fn assignment_is_not_reachable_by_get() {
    let state = state_with(encryption_key(vec![1, 2, 3]));

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/enclave-assignment")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(state, request).await;

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

/// Enclave keys are not exposed as their own route: the encryption key is served only as part
/// of an assignment, and the signing key's attestation only inside the sealed match response.
#[tokio::test]
async fn enclave_keys_are_not_served_as_a_route() {
    let state = state_with(encryption_key(vec![1, 2, 3]));

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/enclave/keys")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(state, request).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn assignment_surfaces_enclave_failures_as_structured_errors() {
    let cases = [
        (
            enclave::Error::Timeout,
            StatusCode::GATEWAY_TIMEOUT,
            "enclave_timeout",
            true,
        ),
        (
            enclave::Error::Transport("boom".to_string()),
            StatusCode::SERVICE_UNAVAILABLE,
            "enclave_unreachable",
            true,
        ),
        (
            enclave::Error::Operation(enclave_types::Error::NotReady),
            StatusCode::SERVICE_UNAVAILABLE,
            "enclave_not_ready",
            true,
        ),
        (
            enclave::Error::Operation(enclave_types::Error::RequestNotOpened),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            false,
        ),
    ];

    for (error, expected_status, expected_code, retryable) in cases {
        let state = state_with(StubEnclaveClient {
            encryption_key: Some(Err(error)),
            ..StubEnclaveClient::default()
        });

        let (status, body) = send(state, assignment_request()).await;

        assert_eq!(status, expected_status, "for {expected_code}");
        assert_eq!(body["error"]["code"], expected_code);
        assert_eq!(body["allowRetry"], retryable, "for {expected_code}");
    }
}

/// No key is configured, and the stub panics if asked: the match route makes no key call.
#[tokio::test]
async fn matches_relays_the_sealed_request_verbatim() {
    let state = state_with(StubEnclaveClient {
        match_result: Some(Ok(flamingo_verifier_enclave_types::MatchResponse {
            ciphertext: vec![9u8; 48],
        })),
        expected_body: Some(b"sealed".to_vec()),
        ..StubEnclaveClient::default()
    });

    let (status, body) = send(state, match_request(&STANDARD.encode("sealed"))).await;

    assert_eq!(status, StatusCode::OK);
    // Relayed opaquely: the host encodes, it does not interpret.
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
    // The attestation travels sealed inside the ciphertext, so nothing else is exposed.
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the host must not add cleartext fields beside the sealed outcome"
    );
}

#[tokio::test]
async fn matches_rejects_a_non_base64_ciphertext() {
    let state = state_with(StubEnclaveClient::default());

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"ciphertext":"not base64!"}"#))
        .expect("request should be valid");

    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn matches_rejects_a_body_over_the_limit_with_an_envelope() {
    let state = state_with(StubEnclaveClient::default());

    // One byte of ciphertext past the ceiling, so the limit rejects it before any parsing.
    let oversized = "A".repeat(routes::MAX_MATCH_BODY_BYTES + 1);

    let (status, body) = send(state, match_request(&oversized)).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "request_too_large");
    // Not retryable: the same body would be refused again.
    assert_eq!(body["allowRetry"], false);
}

#[tokio::test]
async fn matches_maps_an_unopenable_request_to_conflict() {
    // Re-assign and re-seal: the client cannot tell this from a corrupt ciphertext, which is why
    // the retry has to be bounded client-side.
    let state = state_with(StubEnclaveClient {
        match_result: Some(Err(enclave::Error::Operation(
            enclave_types::Error::RequestNotOpened,
        ))),
        ..StubEnclaveClient::default()
    });

    let (status, body) = send(state, match_request(&STANDARD.encode("sealed"))).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "reassign_required");
}

#[tokio::test]
async fn matches_answers_200_whatever_the_sealed_result_says() {
    // A quality failure, a below-threshold match and a malformed payload are all sealed now, so
    // the host cannot distinguish them from a statement -- and must not try.
    let state = state_with(StubEnclaveClient {
        match_result: Some(Ok(flamingo_verifier_enclave_types::MatchResponse {
            ciphertext: vec![9u8; 48],
        })),
        ..StubEnclaveClient::default()
    });

    let (status, body) = send(state, match_request(&STANDARD.encode("sealed"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the relay exposes the ciphertext and nothing else"
    );
}

/// Readiness is not liveness: with the registry gone the enclave is the only dependency left,
/// so readiness must follow it in both directions.
#[tokio::test]
async fn readiness_follows_the_enclave() {
    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri("/ready")
            .body(Body::empty())
            .expect("request should be valid")
    };

    let (healthy, _) = send(state_with(StubEnclaveClient::default()), request()).await;
    assert_eq!(healthy, StatusCode::OK);

    let (unreachable, _) = send(
        state_with(StubEnclaveClient {
            health: Some(Err(enclave::Error::Timeout)),
            ..StubEnclaveClient::default()
        }),
        request(),
    )
    .await;
    assert_eq!(unreachable, StatusCode::SERVICE_UNAVAILABLE);
}
