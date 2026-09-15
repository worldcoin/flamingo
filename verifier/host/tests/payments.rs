//! The payment routes driven through the real router.
//!
//! Signatures are produced with `k256`, not fixtures, so the route, the ledger and the EIP-712
//! digest are exercised as one path. Channels come from a fake escrow, as they do from the chain.

mod common;

use alloy_primitives::{Address, B256, FixedBytes, U256, b256};
use alloy_sol_types::Eip712Domain;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{
    COLLECTOR, FEE_TOKEN, FakeEscrowReader, MIN_PRICE_PER_UNIT, StubEnclaveClient,
    state_requiring_payment, state_with, state_with_escrow,
};
use flamingo_verifier_api_types::ChannelNonce;
use flamingo_verifier_host::AppState;
use flamingo_verifier_host::payments::eip712;
use flamingo_verifier_host::payments::escrow::ChannelSettings;
use flamingo_verifier_host::routes;
use http_body_util::BodyExt as _;
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const CHANNEL: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
const OTHER_CHANNEL: B256 =
    b256!("0x2222222222222222222222222222222222222222222222222222222222222222");
const OTHER_COLLECTOR: Address =
    alloy_primitives::address!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");

const EPOCH_LENGTH: u64 = 3_600;

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = routes::handler(state.payments().is_some())
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

/// Seven and a half epochs back, so the current epoch is well above zero and a test never
/// straddles a boundary while it runs.
fn epoch_zero() -> u64 {
    now() - 7 * EPOCH_LENGTH - EPOCH_LENGTH / 2
}

fn current_epoch() -> u64 {
    (now() - epoch_zero()) / EPOCH_LENGTH
}

fn domain() -> Eip712Domain {
    eip712::domain(4801, Address::ZERO)
}

fn signing_key() -> SigningKey {
    let scalar = b256!("0x0000000000000000000000000000000000000000000000000000000000000009");

    SigningKey::from_slice(scalar.as_slice()).expect("scalar should be a valid key")
}

/// Signs `prehash` and returns `r || s || v`, the encoding the escrow expects.
fn sign(prehash: &B256) -> FixedBytes<65> {
    let (signature, recovery_id) = signing_key()
        .sign_prehash_recoverable(prehash.as_slice())
        .expect("signing should succeed");

    let mut encoded = [0u8; 65];
    encoded[..64].copy_from_slice(&signature.to_bytes());
    encoded[64] = recovery_id.to_byte() + 27;

    FixedBytes(encoded)
}

fn authorize(channel_id: B256, epoch: u64, lane: u32, counter: u64) -> FixedBytes<65> {
    sign(&eip712::digest(
        &domain(),
        channel_id,
        epoch,
        ChannelNonce::new(lane, counter),
    ))
}

/// The signing key's address, taken through recovery so the test shares the host's derivation.
fn spend_key() -> Address {
    eip712::recover_signer(
        &domain(),
        CHANNEL,
        0,
        ChannelNonce::new(0, 1),
        &authorize(CHANNEL, 0, 0, 1),
    )
    .expect("the test signature should recover")
}

fn settings(spend_key: Address, collector: Address) -> ChannelSettings {
    ChannelSettings {
        spend_key,
        collector,
        token: FEE_TOKEN,
        price_per_unit: U256::from(MIN_PRICE_PER_UNIT),
        epoch_zero: epoch_zero(),
        epoch_length: EPOCH_LENGTH,
    }
}

/// The same channel on terms this host does not sell at.
fn settings_with_terms(token: Address, price_per_unit: u64) -> ChannelSettings {
    ChannelSettings {
        token,
        price_per_unit: U256::from(price_per_unit),
        ..settings(spend_key(), COLLECTOR)
    }
}

/// An escrow that knows the test channel and funds it for `capacity` units this epoch.
fn escrow_with(capacity: u64) -> FakeEscrowReader {
    FakeEscrowReader::new()
        .with_channel(CHANNEL, settings(spend_key(), COLLECTOR))
        .with_capacity(CHANNEL, current_epoch(), capacity)
        .with_capacity(CHANNEL, current_epoch() + 1, capacity)
}

fn payment(epoch: u64, lane: u32, counter: u64) -> Value {
    json!({
        "channel_id": CHANNEL,
        "epoch": epoch,
        "channel_nonce": ChannelNonce::new(lane, counter),
        "signature": authorize(CHANNEL, epoch, lane, counter),
    })
}

/// Signs a reservation for `epoch` as the channel's spend key would.
fn reservation_signature(epoch: u64, issued_at: u64) -> FixedBytes<65> {
    sign(&eip712::reservation_digest(
        &domain(),
        CHANNEL,
        epoch,
        issued_at,
    ))
}

async fn reserve_body(state: &AppState, body: &Value) -> (StatusCode, Value) {
    let uri = format!("/v1/channels/{CHANNEL}/nonces");

    send(state, json_request(Method::POST, &uri, body)).await
}

async fn reserve_for(state: &AppState, epoch: u64) -> (StatusCode, Value) {
    let issued_at = now();
    let body = json!({
        "epoch": epoch,
        "issued_at": issued_at,
        "signature": reservation_signature(epoch, issued_at),
    });

    reserve_body(state, &body).await
}

async fn reserve(state: &AppState) -> (StatusCode, Value) {
    reserve_for(state, current_epoch()).await
}

/// A stub enclave that answers every match with the same sealed bytes.
fn answering_enclave() -> StubEnclaveClient {
    StubEnclaveClient {
        match_result: Some(Ok(flamingo_verifier_enclave_types::MatchResponse {
            ciphertext: vec![9u8; 48],
        })),
        ..StubEnclaveClient::default()
    }
}

async fn run_match(state: &AppState, payment: Option<Value>) -> (StatusCode, Value) {
    let body = match payment {
        Some(payment) => json!({ "ciphertext": STANDARD.encode("sealed"), "payment": payment }),
        None => json!({ "ciphertext": STANDARD.encode("sealed") }),
    };

    send(state, json_request(Method::POST, "/v1/matches", &body)).await
}

/// The whole path: reserve a nonce, pay with it, and see the next reservation carry what was
/// signed for the one before.
#[tokio::test]
async fn a_paid_nonce_becomes_the_next_reservations_previous() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    let epoch = current_epoch();

    let (status, body) = reserve(&state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["lane"], 0);
    assert_eq!(body["counter"], 1);
    assert_eq!(body["previous"], Value::Null);

    let (status, _) = run_match(&state, Some(payment(epoch, 0, 1))).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = reserve(&state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["lane"], 0, "an admitted lane is free again");
    assert_eq!(body["counter"], 2);
    assert_eq!(body["previous"]["channel_nonce"], "0x1");
    assert_eq!(
        body["previous"]["signature"],
        authorize(CHANNEL, epoch, 0, 1).to_string()
    );
}

/// A second caller arriving while the first is still out cannot share its lane.
#[tokio::test]
async fn a_concurrent_reservation_opens_a_new_lane() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(10));

    let (_, first) = reserve(&state).await;
    let (_, second) = reserve(&state).await;

    assert_eq!(
        (first["lane"].as_u64(), first["counter"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(
        (second["lane"].as_u64(), second["counter"].as_u64()),
        (Some(1), Some(1))
    );
}

#[tokio::test]
async fn an_unknown_channel_is_not_found() {
    let state = state_with(StubEnclaveClient::default());

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "unknown_channel");
}

/// The first admission check: a channel funded for another verifier is not this one's to spend.
#[tokio::test]
async fn a_channel_settling_to_another_collector_is_refused() {
    let escrow = FakeEscrowReader::new()
        .with_channel(CHANNEL, settings(spend_key(), OTHER_COLLECTOR))
        .with_capacity(CHANNEL, current_epoch(), 10);
    let state = state_with_escrow(answering_enclave(), escrow);

    let (status, body) = reserve(&state).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "wrong_collector");

    let (status, body) = run_match(&state, Some(payment(current_epoch(), 0, 1))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "wrong_collector");
}

/// A node this host cannot reach means it cannot tell whether the spend is allowed, so it does
/// not allow it, and nothing is reserved.
#[tokio::test]
async fn an_unavailable_escrow_refuses_and_reserves_nothing() {
    let state = state_with_escrow(answering_enclave(), FakeEscrowReader::unavailable());

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "escrow_unavailable");
    assert_eq!(body["allowRetry"], true);

    // The escrow comes back with the channel absent, which is what a stored reservation would
    // have to survive. Nothing was written, so the retry starts from counter 1.
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    let (status, body) = reserve(&state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["counter"], 1);
}

#[tokio::test]
async fn an_epoch_that_is_not_current_or_next_is_refused() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(10));
    let current = current_epoch();

    let (status, _) = reserve_for(&state, current + 1).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the next epoch is open at a boundary"
    );

    for epoch in [current.saturating_sub(1), current + 2] {
        let (status, body) = reserve_for(&state, epoch).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "for epoch {epoch}");
        assert_eq!(body["error"]["code"], "invalid_epoch");
    }
}

/// `B256::from_str` treats the `0x` prefix as optional. The route does not, so one channel has
/// one spelling in a URL and in a log.
#[tokio::test]
async fn a_channel_id_that_is_not_32_bytes_of_prefixed_hex_is_rejected() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(10));

    for channel_id in ["0x11", &"11".repeat(32), "0xzz"] {
        let issued_at = now();
        let body = json!({
            "epoch": current_epoch(),
            "issued_at": issued_at,
            "signature": reservation_signature(current_epoch(), issued_at),
        });
        let uri = format!("/v1/channels/{channel_id}/nonces");

        let (status, body) = send(&state, json_request(Method::POST, &uri, &body)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "for {channel_id}");
        assert_eq!(body["error"]["code"], "invalid_request");
    }
}

/// The refusal carries its own proof, so a relying party can check the arithmetic without
/// another endpoint to ask.
#[tokio::test]
async fn a_capacity_refusal_shows_the_authorizations_behind_it() {
    let state = state_with_escrow(answering_enclave(), escrow_with(1));
    let epoch = current_epoch();

    let (status, _) = reserve(&state).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = run_match(&state, Some(payment(epoch, 0, 1))).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "capacity_exhausted");
    assert_eq!(body["allowRetry"], false);

    let details = &body["error"]["details"];
    assert_eq!(details["epoch"], epoch);
    assert_eq!(details["admitted_units"], 1);
    assert_eq!(details["capacity"], 1);

    let authorizations = details["authorizations"]
        .as_array()
        .expect("the refusal should carry authorizations");
    assert_eq!(authorizations.len(), 1);
    assert_eq!(authorizations[0]["lane"], 0);
    assert_eq!(authorizations[0]["channel_nonce"], "0x1");
    assert_eq!(
        authorizations[0]["signature"],
        authorize(CHANNEL, epoch, 0, 1).to_string()
    );
}

#[tokio::test]
async fn a_body_over_the_payment_limit_is_rejected_with_an_envelope() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(10));

    let padding = "a".repeat(routes::MAX_PAYMENT_BODY_BYTES + 1);
    let issued_at = now();
    let body = json!({
        "epoch": current_epoch(),
        "issued_at": issued_at,
        "signature": reservation_signature(current_epoch(), issued_at),
        "padding": padding,
    });

    let (status, body) = reserve_body(&state, &body).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "request_too_large");
}

#[tokio::test]
async fn a_match_with_a_valid_payment_is_admitted_and_relayed() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    reserve(&state).await;

    let (status, body) = run_match(&state, Some(payment(current_epoch(), 0, 1))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
}

/// The payment is a bearer token for one verification. Replaying it must not buy a second, and
/// the earlier result is deliberately not returned in its place.
#[tokio::test]
async fn the_same_payment_cannot_buy_a_second_match() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    reserve(&state).await;

    let (status, _) = run_match(&state, Some(payment(current_epoch(), 0, 1))).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = run_match(&state, Some(payment(current_epoch(), 0, 1))).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "already_admitted");
}

/// A signature that recovers some other address is not this channel's, whoever signed it. Signed
/// here over the next counter, so it is valid bytes for a nonce this payment does not name.
#[tokio::test]
async fn a_match_paid_for_with_another_key_is_refused() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    let epoch = current_epoch();

    reserve(&state).await;

    let stray = json!({
        "channel_id": CHANNEL,
        "epoch": epoch,
        "channel_nonce": ChannelNonce::new(0, 1),
        "signature": authorize(CHANNEL, epoch, 0, 2),
    });
    let (status, body) = run_match(&state, Some(stray)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "invalid_signature");
}

/// Naming this host as collector does not set the terms: the channel's own token and price are
/// checked too, at both routes.
#[tokio::test]
async fn a_channel_on_terms_this_host_rejects_is_refused() {
    let wrong_token = alloy_primitives::address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let epoch = current_epoch();

    for terms in [
        settings_with_terms(wrong_token, MIN_PRICE_PER_UNIT),
        settings_with_terms(FEE_TOKEN, 1),
    ] {
        let escrow = FakeEscrowReader::new()
            .with_channel(CHANNEL, terms)
            .with_capacity(CHANNEL, epoch, 10);
        let state = state_with_escrow(answering_enclave(), escrow);

        let (status, body) = reserve(&state).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "channel_terms_rejected");

        let (status, body) = run_match(&state, Some(payment(epoch, 0, 1))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "channel_terms_rejected");
    }
}

/// A reservation holds capacity, so an unsigned one would let anyone starve a channel.
#[tokio::test]
async fn an_unsigned_or_stale_reservation_is_refused() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(10));
    let epoch = current_epoch();
    let issued_at = now();

    let unsigned = json!({
        "epoch": epoch,
        "issued_at": issued_at,
        "signature": FixedBytes::<65>::repeat_byte(0x11),
    });
    let (status, body) = reserve_body(&state, &unsigned).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "invalid_signature");

    // Valid bytes, but issued far enough back that a captured one is not a reusable ticket.
    let stale_at = issued_at - 3_600;
    let stale = json!({
        "epoch": epoch,
        "issued_at": stale_at,
        "signature": reservation_signature(epoch, stale_at),
    });
    let (status, body) = reserve_body(&state, &stale).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "stale_reservation");
}

/// The relying party's own burst holds its capacity without spending it, so it is told to come
/// back rather than that its epoch is gone.
#[tokio::test]
async fn reservations_holding_capacity_are_refused_as_retryable() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(2));

    for _ in 0..2 {
        let (status, _) = reserve(&state).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "capacity_reserved");
    assert_eq!(body["allowRetry"], true);
    assert_eq!(body["error"]["details"]["admitted_units"], 0);
    assert!(
        body["error"]["details"]["retry_after"].as_u64().is_some(),
        "the caller should be told when a lane comes back"
    );
}

#[tokio::test]
async fn a_payment_for_a_nonce_that_was_never_reserved_is_refused() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    reserve(&state).await;

    for (lane, counter) in [(4, 1), (0, 9)] {
        let (status, body) = run_match(&state, Some(payment(current_epoch(), lane, counter))).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "for lane {lane}");
        assert_eq!(body["error"]["code"], "unknown_reservation");
    }
}

#[tokio::test]
async fn a_payment_on_an_unknown_channel_is_not_found() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));

    let payment = json!({
        "channel_id": OTHER_CHANNEL,
        "epoch": current_epoch(),
        "channel_nonce": ChannelNonce::new(0, 1),
        "signature": authorize(OTHER_CHANNEL, current_epoch(), 0, 1),
    });

    let (status, body) = run_match(&state, Some(payment)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "unknown_channel");
}

/// Metering is off by default, so an existing caller keeps working until it is switched on.
#[tokio::test]
async fn an_unpaid_match_is_relayed_when_payment_is_not_required() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));

    let (status, body) = run_match(&state, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
}

/// With the kill switch on, the enclave is never reached: the stub would panic if it were.
#[tokio::test]
async fn an_unpaid_match_is_refused_when_payment_is_required() {
    let state = state_requiring_payment(StubEnclaveClient::default(), escrow_with(10));

    let (status, body) = run_match(&state, None).await;

    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body["error"]["code"], "payment_required");
    assert_eq!(body["allowRetry"], false);
}

/// The deleted routes stay deleted: the spec has one nonce route and one gated match.
#[tokio::test]
async fn the_removed_payment_routes_are_gone() {
    let state = state_with_escrow(StubEnclaveClient::default(), escrow_with(10));

    let gone = [
        (Method::POST, "/v1/channels".to_owned()),
        (Method::PUT, format!("/v1/channels/{CHANNEL}/nonces/0/1")),
        (
            Method::GET,
            format!("/v1/channels/{CHANNEL}/epochs/{}", current_epoch()),
        ),
    ];

    for (method, uri) in gone {
        let request = Request::builder()
            .method(method.clone())
            .uri(&uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request should be valid");

        let (status, _) = send(&state, request).await;

        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri} should be gone, got {status}"
        );
    }
}

/// The restart-replay finding: a host that comes back with an empty store must not serve the
/// epoch again against funding the chain has already seen spent.
///
/// Four units settled on lane 0, capacity six. Exactly two remain, on a lane this host can chain
/// onto: lane 0 is held because it has no authorization for counter 4 to put in `previous`.
#[tokio::test]
async fn a_restarted_host_serves_only_what_the_chain_has_not_settled() {
    let epoch = current_epoch();
    let escrow = FakeEscrowReader::new()
        .with_channel(CHANNEL, settings(spend_key(), COLLECTOR))
        .with_capacity(CHANNEL, epoch, 6)
        .with_settled(CHANNEL, epoch, &[4]);
    let state = state_with_escrow(answering_enclave(), escrow);

    let (status, body) = reserve(&state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["lane"], 1,
        "lane 0 is the chain's, not this host's to reissue"
    );
    assert_eq!(body["counter"], 1);
    assert_eq!(
        body["previous"],
        Value::Null,
        "a fresh lane has nothing before it"
    );

    // Two units of headroom, and no more.
    for counter in 1..=2u64 {
        let (status, _) = run_match(&state, Some(payment(epoch, 1, counter))).await;
        assert_eq!(status, StatusCode::OK, "unit {counter} is still funded");

        if counter == 1 {
            let (status, _) = reserve(&state).await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    let (status, body) = reserve(&state).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "capacity_exhausted");
    assert_eq!(
        body["error"]["details"]["admitted_units"], 6,
        "four settled on chain plus two served here"
    );

    // The proof lists only what this host can vouch for. The chain's own lanes are not its to
    // show: it never saw those signatures.
    let authorizations = body["error"]["details"]["authorizations"]
        .as_array()
        .expect("the refusal should carry authorizations");
    assert_eq!(authorizations.len(), 1);
    assert_eq!(authorizations[0]["lane"], 1);
    assert_eq!(authorizations[0]["channel_nonce"], "0x10000000000000002");
}

/// A store that still remembers the epoch keeps its lanes, so an ordinary restart-free run is
/// unaffected by the probe.
#[tokio::test]
async fn a_store_that_already_knows_a_lane_keeps_using_it() {
    let epoch = current_epoch();
    let state = state_with_escrow(answering_enclave(), escrow_with(10));

    let (status, first) = reserve(&state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["lane"], 0);

    let (status, _) = run_match(&state, Some(payment(epoch, 0, 1))).await;
    assert_eq!(status, StatusCode::OK);

    let (status, second) = reserve(&state).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["lane"], 0, "the lane this host opened stays its own");
    assert_eq!(second["counter"], 2);
    assert_eq!(second["previous"]["channel_nonce"], "0x1");
}

/// Switched off, a payment is not read, not verified and not spent. A body carrying one that
/// would be refused in any other mode still relays, because nothing looks at it.
#[tokio::test]
async fn payments_off_ignores_a_payment_entirely() {
    let state = common::state_without_payments(answering_enclave());

    let unusable = json!({
        "channel_id": OTHER_CHANNEL,
        "epoch": 0,
        "channel_nonce": ChannelNonce::new(0, 1),
        "signature": FixedBytes::<65>::repeat_byte(0x11),
    });

    for payment in [None, Some(unusable)] {
        let (status, body) = run_match(&state, payment).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
    }
}

/// The nonce route is not mounted when payments are off, so the path is absent rather than
/// answering from a handler.
#[tokio::test]
async fn payments_off_does_not_mount_the_nonce_route() {
    let state = common::state_without_payments(StubEnclaveClient::default());

    let issued_at = now();
    let body = json!({
        "epoch": current_epoch(),
        "issued_at": issued_at,
        "signature": reservation_signature(current_epoch(), issued_at),
    });

    let (status, _) = reserve_body(&state, &body).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A GET would answer 405 if the path were routed at all, so this pins absence rather than
    // a handler that happens to refuse.
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/channels/{CHANNEL}/nonces"))
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(&state, request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Readiness follows the enclave alone when payments are off, so a broken escrow cannot take a
/// rolled-back host out of rotation.
#[tokio::test]
async fn payments_off_keeps_readiness_independent_of_the_escrow() {
    let state = common::state_without_payments(StubEnclaveClient::default());

    let request = Request::builder()
        .method(Method::GET)
        .uri("/ready")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(&state, request).await;

    assert_eq!(status, StatusCode::OK);
}

/// Optional is the middle setting: a payment that is present is spent, and one that is absent is
/// still served.
#[tokio::test]
async fn payments_optional_meters_a_payment_and_serves_without_one() {
    let state = state_with_escrow(answering_enclave(), escrow_with(10));
    let epoch = current_epoch();

    let (status, _) = run_match(&state, None).await;
    assert_eq!(status, StatusCode::OK, "an unpaid match is still served");

    reserve(&state).await;
    let (status, _) = run_match(&state, Some(payment(epoch, 0, 1))).await;
    assert_eq!(status, StatusCode::OK);

    // Spent once, so the same payment does not buy a second even in the permissive mode.
    let (status, body) = run_match(&state, Some(payment(epoch, 0, 1))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "already_admitted");
}
