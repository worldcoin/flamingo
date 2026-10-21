//! Discovery uses the configured public document even when the enclave cannot serve matches.
mod common;

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{StubEnclaveClient, state_with_config};
use flamingo_verifier_host::{ENGINE_METADATA_PATH, HostConfig, enclave, routes};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

const METADATA: &str = include_str!("fixtures/engine-provider.json");

#[tokio::test]
async fn serves_exact_public_document_without_authentication_or_enclave_access() {
    let state = state_with_config(
        HostConfig {
            engine_provider_metadata: Some(Arc::new(METADATA.parse().unwrap())),
            ..HostConfig::default()
        },
        StubEnclaveClient {
            health: Some(Err(enclave::Error::Timeout)),
            ..StubEnclaveClient::default()
        },
    );
    for method in [Method::GET, Method::HEAD] {
        let response = routes::handler()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(ENGINE_METADATA_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        if method == Method::HEAD {
            assert!(bytes.is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::from_str::<serde_json::Value>(METADATA).unwrap()
            );
        }
    }
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let response = routes::handler()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(ENGINE_METADATA_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

#[tokio::test]
async fn unconfigured_discovery_is_not_found_and_never_cached() {
    let response = routes::handler()
        .with_state(state_with_config(
            HostConfig::default(),
            StubEnclaveClient::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(ENGINE_METADATA_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}
