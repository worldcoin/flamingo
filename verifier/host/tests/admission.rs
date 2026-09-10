//! Match admission happens before body allocation and never blocks control routes.

use std::{
    future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Method, Request, StatusCode},
};
use flamingo_verifier_enclave_types::{KeyAttestation, MatchRequest, MatchResponse};
use flamingo_verifier_host::{
    AppState, Environment,
    enclave::{self, EnclaveClient},
    routes,
};
use http_body_util::{BodyExt as _, Full};
use tokio::sync::Notify;
use tower::ServiceExt as _;

/// Enclave double with an optionally blocked first comparison.
#[derive(Default)]
struct ControlledEnclave {
    /// Whether the first comparison must wait for the test's release signal.
    hold_first: AtomicBool,
    /// Counts forwarded requests, including a subsequently canceled call.
    matches: AtomicUsize,
    /// Signals that the handler has passed admission and reached the enclave.
    entered: Notify,
    /// Allows a blocked comparison to finish.
    release: Notify,
}

#[async_trait]
impl EnclaveClient for ControlledEnclave {
    /// Control requests remain independent of the blocked comparison.
    async fn health(&self) -> Result<(), enclave::Error> {
        Ok(())
    }

    /// Supplies the assignment fixture without waiting for a comparison.
    async fn encryption_key_attestation(&self) -> Result<KeyAttestation, enclave::Error> {
        Ok(KeyAttestation {
            document: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
        })
    }

    /// Waits only on the first call when explicitly requested by a test.
    async fn run_match(&self, _request: MatchRequest) -> Result<MatchResponse, enclave::Error> {
        self.matches.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();

        if self.hold_first.swap(false, Ordering::SeqCst) {
            self.release.notified().await;
        }

        Ok(MatchResponse {
            ciphertext: vec![4, 5, 6],
        })
    }
}

/// Shares one admission slot across cloned routers.
fn router(client: &Arc<ControlledEnclave>) -> Router {
    routes::handler().with_state(AppState::new(Environment::Development, client.clone()))
}

/// Builds a match request whose body is controlled by a test.
fn request(body: Body) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

/// Builds a valid, small sealed request for the enclave double.
fn valid_request() -> Request<Body> {
    request(Body::from(r#"{"ciphertext":"AQID"}"#))
}

/// Supplies an incomplete body and signals when the extractor starts waiting.
fn stalled_body(entered: Arc<Notify>) -> Body {
    Body::new(
        Full::new(Bytes::from_static(b"{")).with_trailers(async move {
            entered.notify_one();
            future::pending().await
        }),
    )
}

/// Checks both the status and the stable, retryable busy envelope.
async fn assert_busy(app: &Router) {
    let polled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&polled);
    let body = Body::new(
        Full::new(Bytes::from_static(br#"{"ciphertext":"AQID"}"#)).map_frame(move |frame| {
            observed.store(true, Ordering::SeqCst);
            frame
        }),
    );
    let response = app.clone().oneshot(request(body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!polled.load(Ordering::SeqCst));

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "enclave_not_ready");
    assert_eq!(body["allowRetry"], true);
}

#[tokio::test]
/// Upload admission does not queue bodies or consume the control paths' capacity.
async fn stalled_upload_sheds_unread_bodies_and_leaves_controls_responsive() {
    let client = Arc::new(ControlledEnclave::default());
    let app = router(&client);
    let entered = Arc::new(Notify::new());
    let upload = tokio::spawn(
        app.clone()
            .oneshot(request(stalled_body(Arc::clone(&entered)))),
    );
    entered.notified().await;

    assert_busy(&app).await;

    for (method, path) in [
        (Method::GET, "/health"),
        (Method::GET, "/ready"),
        (Method::POST, "/v1/enclave-assignment"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    assert_eq!(client.matches.load(Ordering::SeqCst), 0);

    upload.abort();
    assert!(upload.await.unwrap_err().is_cancelled());

    let response = app.oneshot(valid_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(client.matches.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
/// An incomplete upload has a fixed deadline and never reaches the enclave.
async fn stalled_upload_times_out_and_releases_admission() {
    let client = Arc::new(ControlledEnclave::default());
    let app = router(&client);
    let entered = Arc::new(Notify::new());
    let upload = tokio::spawn(
        app.clone()
            .oneshot(request(stalled_body(Arc::clone(&entered)))),
    );
    entered.notified().await;

    tokio::time::advance(Duration::from_secs(6)).await;
    let response = upload.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "request_timeout");
    assert_eq!(body["allowRetry"], false);
    assert_eq!(client.matches.load(Ordering::SeqCst), 0);

    assert_eq!(
        app.oneshot(valid_request()).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
/// The host slot spans the entire enclave call, not just body extraction.
async fn admission_remains_held_while_the_enclave_is_busy() {
    let client = Arc::new(ControlledEnclave::default());
    client.hold_first.store(true, Ordering::SeqCst);
    let app = router(&client);
    let comparison = tokio::spawn(app.clone().oneshot(valid_request()));
    client.entered.notified().await;

    assert_busy(&app).await;
    assert_eq!(client.matches.load(Ordering::SeqCst), 1);

    client.release.notify_one();
    assert_eq!(comparison.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(
        app.oneshot(valid_request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(client.matches.load(Ordering::SeqCst), 2);
}

#[tokio::test]
/// Canceling host forwarding frees its slot; the broker owns worker admission separately.
async fn canceled_forwarding_releases_the_host_slot() {
    let client = Arc::new(ControlledEnclave::default());
    client.hold_first.store(true, Ordering::SeqCst);
    let app = router(&client);
    let comparison = tokio::spawn(app.clone().oneshot(valid_request()));
    client.entered.notified().await;

    comparison.abort();
    assert!(comparison.await.unwrap_err().is_cancelled());
    assert_eq!(
        app.oneshot(valid_request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(client.matches.load(Ordering::SeqCst), 2);
}

#[tokio::test]
/// Early validation failures cannot strand the host admission permit.
async fn rejected_bodies_release_admission() {
    let client = Arc::new(ControlledEnclave::default());
    let app = router(&client);

    for body in ["not JSON", r#"{"ciphertext":"not-base64"}"#] {
        assert_eq!(
            app.clone()
                .oneshot(request(Body::from(body)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(client.matches.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.oneshot(valid_request()).await.unwrap().status(),
        StatusCode::OK
    );
}
