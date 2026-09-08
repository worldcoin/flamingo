//! End-to-end tests for the assignment client, over real HTTP.

use std::net::{Ipv4Addr, SocketAddr};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use flamingo_verifier_client as client;
use flamingo_verifier_client::PcrMeasurement;
use flamingo_verifier_client::{Config, FlamingoVerifierClient};
use hex_literal::hex;

fn config(base_url: &str) -> Config {
    let pcrs = vec![PcrMeasurement::new(
        0,
        hex!(
            "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
        ),
    )];

    Config::new(base_url, vec![pcrs]).expect("config should be valid")
}

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

/// A stub host answering assignments as the real one does.
async fn serve_assignment(attestation: &str, public_key: &str) -> String {
    let body = serde_json::json!({ "attestation": attestation, "public_key": public_key });

    serve(Router::new().route(
        "/v1/enclave-assignment",
        post(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    ))
    .await
}

#[tokio::test]
async fn rejects_an_assignment_whose_attestation_does_not_verify() {
    // A syntactically fine response carrying a document signed by nobody.
    let base_url = serve_assignment("hEBAQEA=", "a2V5").await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_assignment()
        .await
        .expect_err("an unverifiable document must not be accepted");

    assert!(
        matches!(error, client::Error::Channel(_)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn rejects_malformed_base64_in_either_assignment_field() {
    for (document, key) in [("!", "a2V5"), ("hEBAQEA=", "!")] {
        let base_url = serve_assignment(document, key).await;
        let error = FlamingoVerifierClient::new(config(&base_url))
            .unwrap()
            .request_assignment()
            .await
            .unwrap_err();
        assert!(matches!(error, client::Error::MalformedAssignment));
    }
}

#[tokio::test]
async fn surfaces_a_host_error_status_rather_than_retrying() {
    let base_url = serve(Router::new().route(
        "/v1/enclave-assignment",
        post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
    ))
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_assignment()
        .await
        .expect_err("a 503 should surface to the caller");

    assert!(
        matches!(error, client::Error::Status(503)),
        "unexpected error: {error}"
    );
}
