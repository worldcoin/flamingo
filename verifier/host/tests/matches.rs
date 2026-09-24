//! Real-socket tests for the `/matches` WebSocket session.
//!
//! These drive a bound TCP listener rather than the router's `oneshot`, because the upgrade and the
//! session that follows it only exist on a real connection.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{StubEnclaveClient, state_with, state_with_config};
use flamingo_verifier_api_types::{HostMessage, MAX_MATCH_BODY_BYTES};
use flamingo_verifier_enclave_types::{KeyAttestation, MatchResponse};
use flamingo_verifier_host::{AppState, HostConfig, enclave, routes};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Client = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const WAIT: Duration = Duration::from_secs(5);
const ASSIGNMENT_REQUEST: &str = r#"{"type":"assignment_request"}"#;

/// Serves `state` on an ephemeral local port and returns the bound address.
async fn serve(state: AppState) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("should bind a local port");
    let address = listener.local_addr().expect("should have a local address");

    tokio::spawn(async move {
        axum::serve(
            listener,
            routes::handler().with_state(state).into_make_service(),
        )
        .await
        .expect("server should run");
    });

    address
}

async fn connect(address: SocketAddr) -> Client {
    let (socket, _) = connect_async(format!("ws://{address}/matches"))
        .await
        .expect("the upgrade should succeed");
    socket
}

async fn send_text(socket: &mut Client, body: &str) {
    socket
        .send(Message::Text(body.to_owned().into()))
        .await
        .expect("text frame should send");
}

async fn send_binary(socket: &mut Client, body: Vec<u8>) {
    socket
        .send(Message::Binary(body.into()))
        .await
        .expect("binary frame should send");
}

/// Receives the next frame, failing the test rather than hanging.
async fn recv(socket: &mut Client) -> Message {
    timeout(WAIT, socket.next())
        .await
        .expect("a frame should arrive within the deadline")
        .expect("the stream should stay open")
        .expect("the frame should decode")
}

/// Reads an error envelope from the next text frame.
async fn recv_error(socket: &mut Client) -> Value {
    match recv(socket).await {
        Message::Text(text) => serde_json::from_str(text.as_str()).expect("an error envelope"),
        other => panic!("expected an error text frame, got {other:?}"),
    }
}

fn full_stub() -> StubEnclaveClient {
    StubEnclaveClient {
        encryption_key: Some(Ok(KeyAttestation {
            document: vec![1, 2, 3],
            public_key: vec![0xab; 1216],
        })),
        match_result: Some(Ok(MatchResponse {
            ciphertext: vec![9u8; 48],
        })),
        expected_body: Some(b"sealed".to_vec()),
        ..StubEnclaveClient::default()
    }
}

fn config_with_idle(idle_secs: u64) -> HostConfig {
    HostConfig {
        ws_idle_timeout: idle_secs.try_into().expect("nonzero idle timeout"),
        ..HostConfig::default()
    }
}

/// The happy path: assignment text, sealed match binary, sealed result binary, then close.
#[tokio::test]
async fn assignment_then_binary_relay() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, ASSIGNMENT_REQUEST).await;
    let Message::Text(text) = recv(&mut socket).await else {
        panic!("expected an assignment text frame");
    };
    let HostMessage::Assignment(assignment) =
        serde_json::from_str(text.as_str()).expect("an assignment message");
    assert_eq!(assignment.attestation, "AQID");
    assert_eq!(assignment.public_key, STANDARD.encode(vec![0xab; 1216]));

    send_binary(&mut socket, b"sealed".to_vec()).await;
    match recv(&mut socket).await {
        Message::Binary(body) => assert_eq!(body.as_ref(), &[9u8; 48]),
        other => panic!("expected a sealed result binary frame, got {other:?}"),
    }

    assert!(
        matches!(recv(&mut socket).await, Message::Close(_)),
        "the host should close after one match"
    );
}

#[tokio::test]
async fn binary_before_assignment_is_rejected() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_binary(&mut socket, b"sealed".to_vec()).await;

    let error = recv_error(&mut socket).await;
    assert_eq!(error["error"]["code"], "protocol_error");
    assert_eq!(error["allowRetry"], false);
}

#[tokio::test]
async fn unknown_message_type_is_rejected() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, r#"{"type":"nope"}"#).await;

    assert_eq!(
        recv_error(&mut socket).await["error"]["code"],
        "invalid_message"
    );
}

#[tokio::test]
async fn malformed_json_is_rejected() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, "not json").await;

    assert_eq!(
        recv_error(&mut socket).await["error"]["code"],
        "invalid_message"
    );
}

#[tokio::test]
async fn empty_match_frame_is_rejected() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, ASSIGNMENT_REQUEST).await;
    let _ = recv(&mut socket).await;
    send_binary(&mut socket, Vec::new()).await;

    assert_eq!(
        recv_error(&mut socket).await["error"]["code"],
        "invalid_request"
    );
}

#[tokio::test]
async fn oversize_match_frame_is_rejected() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, ASSIGNMENT_REQUEST).await;
    let _ = recv(&mut socket).await;
    send_binary(&mut socket, vec![0u8; MAX_MATCH_BODY_BYTES + 1]).await;

    let error = recv_error(&mut socket).await;
    assert_eq!(error["error"]["code"], "request_too_large");
    assert_eq!(error["allowRetry"], false);
}

/// A frame past the socket layer's cap is answered like one merely over the body limit, rather than
/// with a bare close.
#[tokio::test]
async fn frame_beyond_the_socket_limit_is_rejected() {
    let address = serve(state_with(full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, ASSIGNMENT_REQUEST).await;
    let _ = recv(&mut socket).await;

    // Feed queues the frame without awaiting the flush, so the host can answer while the peer has
    // not drained the frame it sent.
    socket
        .feed(Message::Binary(
            vec![0u8; routes::MAX_WS_MESSAGE_BYTES + 1].into(),
        ))
        .await
        .expect("the frame should queue");

    let error = recv_error(&mut socket).await;
    assert_eq!(error["error"]["code"], "request_too_large");
    assert_eq!(error["allowRetry"], false);
}

#[tokio::test]
async fn assignment_enclave_failure_is_reported() {
    let address = serve(state_with(StubEnclaveClient {
        encryption_key: Some(Err(enclave::Error::Timeout)),
        ..StubEnclaveClient::default()
    }))
    .await;
    let mut socket = connect(address).await;

    send_text(&mut socket, ASSIGNMENT_REQUEST).await;

    let error = recv_error(&mut socket).await;
    assert_eq!(error["error"]["code"], "enclave_timeout");
    assert_eq!(error["allowRetry"], true);
}

#[tokio::test]
async fn idle_before_assignment_is_reported() {
    let address = serve(state_with_config(config_with_idle(1), full_stub())).await;
    let mut socket = connect(address).await;

    assert_eq!(
        recv_error(&mut socket).await["error"]["code"],
        "idle_timeout"
    );
}

#[tokio::test]
async fn idle_after_assignment_is_reported() {
    let address = serve(state_with_config(config_with_idle(1), full_stub())).await;
    let mut socket = connect(address).await;

    send_text(&mut socket, ASSIGNMENT_REQUEST).await;
    let _ = recv(&mut socket).await;

    assert_eq!(
        recv_error(&mut socket).await["error"]["code"],
        "idle_timeout"
    );
}

/// One session holds the only slot and stays open; the next upgrade is refused with a `503`, and
/// the slot is released once the first session ends.
#[tokio::test]
async fn capacity_refuses_with_503_and_releases_on_close() {
    let config = HostConfig {
        ws_max_connections: NonZeroUsize::new(1).expect("one is nonzero"),
        ..HostConfig::default()
    };
    let address = serve(state_with_config(config, full_stub())).await;

    // Keep the first session open in its pre-assignment phase, holding the permit.
    let first = connect(address).await;

    let error = connect_async(format!("ws://{address}/matches"))
        .await
        .expect_err("the second upgrade should be refused");
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status(), 503);
        }
        other => panic!("expected an HTTP 503, got {other:?}"),
    }

    drop(first);

    // The permit is released when the session task drops it; retry until the slot frees up.
    for attempt in 0..100 {
        if connect_async(format!("ws://{address}/matches"))
            .await
            .is_ok()
        {
            return;
        }
        assert!(
            attempt < 99,
            "the slot should be released after the session closes"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A peer that stops reading cannot pin its connection slot: the host's bounded writes give up and
/// release the permit.
#[tokio::test]
async fn stalled_peer_releases_its_slot() {
    let config = HostConfig {
        ws_max_connections: NonZeroUsize::new(1).expect("one is nonzero"),
        ..config_with_idle(1)
    };
    // Larger than the peer's socket buffers, so the host's assignment write is left pending.
    let address = serve(state_with_config(
        config,
        StubEnclaveClient {
            encryption_key: Some(Ok(KeyAttestation {
                document: vec![0u8; 8 * 1024 * 1024],
                public_key: vec![0xab; 1216],
            })),
            ..StubEnclaveClient::default()
        },
    ))
    .await;

    let mut stalled = connect(address).await;
    send_text(&mut stalled, ASSIGNMENT_REQUEST).await;

    // The slot is held while the host waits out the bounded write, and must free within a few idle
    // timeouts rather than never.
    for attempt in 0..100 {
        if connect_async(format!("ws://{address}/matches"))
            .await
            .is_ok()
        {
            return;
        }
        assert!(
            attempt < 99,
            "a stalled peer should release its connection slot"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
