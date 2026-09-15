//! How the escrow reader classifies what a node says back.
//!
//! Driven through a real local HTTP server, so the reqwest path, the JSON-RPC envelope and the
//! ABI decoding are all exercised. The distinction under test is the one that matters: a node
//! that will not answer must never read as a channel that does not exist.

use std::net::SocketAddr;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256, address, b256};
use alloy_sol_types::{SolValue, sol};
use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use flamingo_verifier_host::payments::escrow::rpc::{EscrowConfig, RpcEscrowReader};
use flamingo_verifier_host::payments::escrow::{EscrowError, EscrowReader};
use serde_json::{Value, json};

const CHANNEL: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
const ESCROW: Address = address!("0x0000000000000000000000000000000000FeE5c0");
const CHAIN_ID: u64 = 4801;

sol! {
    /// The contract's own layout, so the fixtures are encoded the way a node would return them.
    struct SolChannelSettings {
        uint64 rpId;
        address spendKey;
        address collector;
        address token;
        uint256 pricePerUnit;
        uint64 epochLength;
        uint64 epochZero;
        bytes32 salt;
    }
}

/// Serves one canned answer to every JSON-RPC call except `eth_chainId`.
async fn serve(answer: Value, status: StatusCode) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let chain_id = format!("{CHAIN_ID:#x}");

    let app = Router::new().route(
        "/",
        post(move |body: axum::Json<Value>| {
            let answer = answer.clone();
            let chain_id = chain_id.clone();

            async move {
                if body.0.get("method").and_then(Value::as_str) == Some("eth_chainId") {
                    return (
                        StatusCode::OK,
                        axum::Json(json!({ "jsonrpc": "2.0", "id": 1, "result": chain_id })),
                    );
                }

                (status, axum::Json(answer))
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a local port should be available");
    let address = listener.local_addr().expect("the listener should be bound");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (address, handle)
}

fn reader(address: SocketAddr) -> RpcEscrowReader {
    RpcEscrowReader::new(EscrowConfig {
        rpc_url: format!("http://{address}/"),
        address: ESCROW,
        chain_id: CHAIN_ID,
        timeout: Duration::from_millis(500),
        capacity_ttl: Duration::from_millis(50),
    })
    .expect("the client should build")
}

/// A revert answer carrying `ChannelNotFound(bytes32)`, as a node reports one.
fn channel_not_found() -> Value {
    let mut data = vec![0xf3, 0x83, 0xb1, 0x3e];
    data.extend_from_slice(CHANNEL.as_slice());

    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": 3,
            "message": "execution reverted",
            "data": format!("0x{}", alloy_primitives::hex::encode(data)),
        },
    })
}

fn settings_answer(spend_key: Address) -> Value {
    let settings = SolChannelSettings {
        rpId: 46,
        spendKey: spend_key,
        collector: ESCROW,
        token: Address::ZERO,
        pricePerUnit: U256::from(1_000u64),
        epochLength: 3_600,
        epochZero: 1_700_000_000,
        salt: CHANNEL,
    };

    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": format!("0x{}", alloy_primitives::hex::encode(settings.abi_encode())),
    })
}

/// The finding this test exists for: a throttled node must not read as an absent channel, or a
/// rate limit would quietly open the gate to every unfunded caller.
#[tokio::test]
async fn a_rate_limited_node_is_unavailable_and_not_an_absent_channel() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32005, "message": "daily request count exceeded" },
    });
    let (address, server) = serve(body, StatusCode::TOO_MANY_REQUESTS).await;

    let answer = reader(address).channel(CHANNEL).await;

    assert!(
        matches!(answer, Err(EscrowError::Unavailable(_))),
        "a 429 must refuse, got {answer:?}"
    );
    server.abort();
}

/// The same when the node answers 200 with a JSON-RPC error that is not a revert.
#[tokio::test]
async fn a_json_rpc_error_without_revert_data_is_unavailable() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32603, "message": "internal error" },
    });
    let (address, server) = serve(body, StatusCode::OK).await;

    let answer = reader(address).channel(CHANNEL).await;

    assert!(
        matches!(answer, Err(EscrowError::Unavailable(_))),
        "an internal node error must refuse, got {answer:?}"
    );
    server.abort();
}

/// A revert this host recognises is the contract answering, and the only absent-channel answer.
#[tokio::test]
async fn a_channel_not_found_revert_is_an_absent_channel() {
    let (address, server) = serve(channel_not_found(), StatusCode::OK).await;

    assert_eq!(reader(address).channel(CHANNEL).await, Ok(None));
    server.abort();
}

/// A revert this host does not recognise is not an answer either.
#[tokio::test]
async fn an_unrecognised_revert_is_unavailable() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": 3, "message": "execution reverted", "data": "0xdeadbeef" },
    });
    let (address, server) = serve(body, StatusCode::OK).await;

    let answer = reader(address).channel(CHANNEL).await;

    assert!(
        matches!(answer, Err(EscrowError::Unavailable(_))),
        "an unknown revert must refuse, got {answer:?}"
    );
    server.abort();
}

/// A record the contract returns with a zero spend key is the other way it says "no channel".
#[tokio::test]
async fn a_zero_spend_key_is_an_absent_channel() {
    let (address, server) = serve(settings_answer(Address::ZERO), StatusCode::OK).await;

    assert_eq!(reader(address).channel(CHANNEL).await, Ok(None));
    server.abort();
}

#[tokio::test]
async fn a_real_channel_decodes_its_terms() {
    let spend_key = address!("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF");
    let (address, server) = serve(settings_answer(spend_key), StatusCode::OK).await;

    let settings = reader(address)
        .channel(CHANNEL)
        .await
        .expect("the node answered")
        .expect("the channel exists");

    assert_eq!(settings.spend_key, spend_key);
    assert_eq!(settings.collector, ESCROW);
    assert_eq!(settings.price_per_unit, U256::from(1_000u64));
    assert_eq!(settings.epoch_length, 3_600);
    server.abort();
}

/// Readiness is a real read: the escrow must answer `ChannelNotFound` for the zero channel id.
#[tokio::test]
async fn readiness_needs_the_contract_to_answer() {
    let (address, server) = serve(channel_not_found(), StatusCode::OK).await;
    assert_eq!(reader(address).ready().await, Ok(()));
    server.abort();

    let body = json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32603, "message": "down" } });
    let (address, server) = serve(body, StatusCode::INTERNAL_SERVER_ERROR).await;
    assert!(
        matches!(
            reader(address).ready().await,
            Err(EscrowError::Unavailable(_))
        ),
        "a node that will not answer is not ready"
    );
    server.abort();
}

/// A node that is not listening at all is a transport failure, not a missing channel.
#[tokio::test]
async fn an_unreachable_node_fails_readiness() {
    // Port 1 on loopback refuses immediately, so this does not wait for the timeout.
    let reader = RpcEscrowReader::new(EscrowConfig {
        rpc_url: "http://127.0.0.1:1/".to_owned(),
        address: ESCROW,
        chain_id: CHAIN_ID,
        timeout: Duration::from_millis(500),
        capacity_ttl: Duration::from_millis(50),
    })
    .expect("the client should build");

    assert!(matches!(
        reader.ready().await,
        Err(EscrowError::Unavailable(_) | EscrowError::Timeout)
    ));
    assert!(matches!(
        reader.channel(CHANNEL).await,
        Err(EscrowError::Unavailable(_) | EscrowError::Timeout)
    ));
}
