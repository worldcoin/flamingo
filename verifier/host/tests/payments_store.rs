//! What the payment routes do when the store misbehaves.
//!
//! The fakes here wrap [`InMemoryStore`], so the rules still run: only the storage primitives
//! fail, which is the boundary the trait exists to draw.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::{Address, B256, FixedBytes, b256};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{
    COLLECTOR, FakeEscrowReader, StubEnclaveClient, ledger_over, payment_config,
    state_with_payments,
};
use flamingo_verifier_api_types::ChannelNonce;
use flamingo_verifier_host::AppState;
use flamingo_verifier_host::payments::escrow::ChannelSettings;
use flamingo_verifier_host::payments::{
    EpochLedger, InMemoryStore, PaymentStore, StoreError, eip712,
};
use flamingo_verifier_host::routes;
use http_body_util::BodyExt as _;
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const CHANNEL: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
const FIRST_REQUEST: B256 =
    b256!("0x0101010101010101010101010101010101010101010101010101010101010101");
const EPOCH_LENGTH: u64 = 3_600;

/// A store that loses the race a fixed number of times before it starts accepting writes.
#[derive(Debug)]
struct ConflictingStore {
    inner: InMemoryStore,
    remaining_conflicts: AtomicUsize,
}

impl ConflictingStore {
    fn new(conflicts: usize) -> Self {
        Self {
            inner: InMemoryStore::new(),
            remaining_conflicts: AtomicUsize::new(conflicts),
        }
    }

    /// How many conflicts are still owed, so a test can assert the retry actually happened.
    fn remaining(&self) -> usize {
        self.remaining_conflicts.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PaymentStore for ConflictingStore {
    async fn ready(&self) -> bool {
        true
    }

    async fn load_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
    ) -> Result<(EpochLedger, u64), StoreError> {
        self.inner.load_epoch(channel_id, epoch).await
    }

    async fn store_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
        ledger: &EpochLedger,
        expected: u64,
    ) -> Result<(), StoreError> {
        let owed = self.remaining_conflicts.load(Ordering::SeqCst);

        if owed > 0 {
            self.remaining_conflicts.store(owed - 1, Ordering::SeqCst);

            return Err(StoreError::Conflict);
        }

        self.inner
            .store_epoch(channel_id, epoch, ledger, expected)
            .await
    }
}

/// A store that is down, in both directions.
#[derive(Debug, Default)]
struct UnavailableStore;

impl UnavailableStore {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PaymentStore for UnavailableStore {
    async fn ready(&self) -> bool {
        false
    }

    async fn load_epoch(
        &self,
        _channel_id: B256,
        _epoch: u64,
    ) -> Result<(EpochLedger, u64), StoreError> {
        Err(StoreError::Unavailable("table is throttled".to_owned()))
    }

    async fn store_epoch(
        &self,
        _channel_id: B256,
        _epoch: u64,
        _ledger: &EpochLedger,
        _expected: u64,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unavailable("table is throttled".to_owned()))
    }
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = routes::handler()
        .with_state(state.clone())
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

fn json_request(method: Method, uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request should be valid")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock should be after the unix epoch")
        .as_secs()
}

fn epoch_zero() -> u64 {
    now() - 7 * EPOCH_LENGTH - EPOCH_LENGTH / 2
}

fn current_epoch() -> u64 {
    (now() - epoch_zero()) / EPOCH_LENGTH
}

fn signing_key() -> SigningKey {
    let scalar = b256!("0x0000000000000000000000000000000000000000000000000000000000000009");

    SigningKey::from_slice(scalar.as_slice()).expect("scalar should be a valid key")
}

fn authorize(epoch: u64, lane: u32, counter: u64) -> FixedBytes<65> {
    let prehash = eip712::digest(
        &eip712::domain(4801, Address::ZERO),
        CHANNEL,
        epoch,
        ChannelNonce::new(lane, counter),
    );

    let (signature, recovery_id) = signing_key()
        .sign_prehash_recoverable(prehash.as_slice())
        .expect("signing should succeed");

    let mut encoded = [0u8; 65];
    encoded[..64].copy_from_slice(&signature.to_bytes());
    encoded[64] = recovery_id.to_byte() + 27;

    FixedBytes(encoded)
}

/// An escrow that knows the test channel and funds it generously.
fn escrow() -> FakeEscrowReader {
    FakeEscrowReader::new()
        .with_channel(
            CHANNEL,
            ChannelSettings {
                spend_key: spend_key(),
                collector: COLLECTOR,
                epoch_zero: epoch_zero(),
                epoch_length: EPOCH_LENGTH,
            },
        )
        .with_capacity(CHANNEL, current_epoch(), 100)
}

fn spend_key() -> Address {
    eip712::recover_signer(
        &eip712::domain(4801, Address::ZERO),
        CHANNEL,
        0,
        ChannelNonce::new(0, 1),
        &authorize(0, 0, 1),
    )
    .expect("the test signature should recover")
}

async fn reserve(state: &AppState) -> (StatusCode, Value) {
    let body = json!({ "epoch": current_epoch() });
    let uri = format!("/v1/channels/{CHANNEL}/nonces");

    send(state, json_request(Method::POST, &uri, &body)).await
}

/// A lost race is not the caller's problem: the ledger reads again and rewrites.
#[tokio::test]
async fn a_conflicting_write_is_retried_and_succeeds() {
    let store = Arc::new(ConflictingStore::new(1));
    let state = state_with_payments(
        StubEnclaveClient::default(),
        ledger_over(
            payment_config(),
            Arc::clone(&store) as Arc<dyn PaymentStore>,
            Arc::new(escrow()),
        ),
    );

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["lane"], 0);
    assert_eq!(body["counter"], 1);
    assert_eq!(store.remaining(), 0, "the conflict should have been spent");
}

/// Five attempts is the ceiling. Past it the caller is told to come back rather than left with a
/// write that silently did not land.
#[tokio::test]
async fn sustained_conflicts_give_up_as_unavailable() {
    let store = Arc::new(ConflictingStore::new(99));
    let state = state_with_payments(
        StubEnclaveClient::default(),
        ledger_over(
            payment_config(),
            Arc::clone(&store) as Arc<dyn PaymentStore>,
            Arc::new(escrow()),
        ),
    );

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "payments_store_unavailable");
    assert_eq!(body["allowRetry"], true);
    assert_eq!(
        store.remaining(),
        99 - 5,
        "the retry must be bounded at five attempts"
    );
}

/// A store outage is a dependency failure, not a bad request, and nothing is recorded.
#[tokio::test]
async fn an_unavailable_store_is_a_retryable_503_that_records_nothing() {
    let state = state_with_payments(
        StubEnclaveClient::default(),
        ledger_over(
            payment_config(),
            Arc::new(UnavailableStore::new()),
            Arc::new(escrow()),
        ),
    );

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "payments_store_unavailable");
    assert_eq!(body["allowRetry"], true);
}

/// Readiness, not liveness: a host whose store is down must stop taking traffic, and the enclave
/// is never consulted, so the stub would panic if it were.
#[tokio::test]
async fn a_broken_store_fails_readiness() {
    let state = state_with_payments(
        StubEnclaveClient::default(),
        ledger_over(
            payment_config(),
            Arc::new(UnavailableStore::new()),
            Arc::new(escrow()),
        ),
    );

    let request = Request::builder()
        .method(Method::GET)
        .uri("/ready")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(&state, request).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// Liveness is unaffected: the process is fine, its dependency is not.
#[tokio::test]
async fn a_broken_store_still_reports_healthy() {
    let state = state_with_payments(
        StubEnclaveClient::default(),
        ledger_over(
            payment_config(),
            Arc::new(UnavailableStore::new()),
            Arc::new(escrow()),
        ),
    );

    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(&state, request).await;

    assert_eq!(status, StatusCode::OK);
}
