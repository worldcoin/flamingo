//! End-to-end tests for the WebSocket client against a stub host.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flamingo_verifier_api_types::MAX_MATCH_BODY_BYTES;
use flamingo_verifier_client as client;
use flamingo_verifier_client::{Config, FlamingoVerifierClient, PcrMeasurement};
use futures_util::{SinkExt, StreamExt};
use hex_literal::hex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::Request;
use tokio_tungstenite::{WebSocketStream, accept_async, accept_hdr_async};

fn config(base_url: &str) -> Config {
    let pcrs = vec![PcrMeasurement::new(
        0,
        hex!(
            "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
        ),
    )];

    Config::new(base_url, vec![pcrs]).expect("config should be valid")
}

fn assignment(attestation: &str, public_key: &str) -> String {
    serde_json::json!({
        "type": "assignment",
        "attestation": attestation,
        "public_key": public_key,
    })
    .to_string()
}

/// Serves one WebSocket connection and returns the host's base URL.
async fn serve<F, Fut>(handler: F) -> String
where
    F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("should accept");
        let socket = accept_async(stream).await.expect("should upgrade");
        handler(socket).await;
    });

    format!("http://{address}")
}

/// Asserts the client's first frame is the assignment request.
async fn expect_assignment_request(socket: &mut WebSocketStream<TcpStream>) {
    let request = socket
        .next()
        .await
        .expect("a frame")
        .expect("a valid frame");
    assert_eq!(
        request,
        Message::Text(r#"{"type":"assignment_request"}"#.into())
    );
}

#[tokio::test]
async fn rejects_an_assignment_whose_attestation_does_not_verify() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        let body = assignment("hEBAQEA=", "a2V5");
        let _ = socket.send(Message::Text(body.into())).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .connect()
        .await
        .expect_err("an unverifiable document must not be accepted");

    assert!(matches!(error, client::Error::Channel(_)), "got {error:?}");
}

#[tokio::test]
async fn rejects_malformed_base64_in_either_assignment_field() {
    for (document, key) in [("!", "a2V5"), ("hEBAQEA=", "!")] {
        let base_url = serve(move |mut socket| async move {
            expect_assignment_request(&mut socket).await;
            let body = assignment(document, key);
            let _ = socket.send(Message::Text(body.into())).await;
        })
        .await;

        let error = FlamingoVerifierClient::new(config(&base_url))
            .expect("client should build")
            .connect()
            .await
            .expect_err("malformed base64 must be rejected");

        assert!(
            matches!(error, client::Error::MalformedAssignment),
            "got {error:?}"
        );
    }
}

#[tokio::test]
async fn surfaces_a_host_error_envelope_frame() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        let body = r#"{"allowRetry":false,"error":{"code":"request_too_large","message":"stub"}}"#;
        let _ = socket.send(Message::Text(body.into())).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .connect()
        .await
        .expect_err("an envelope is an error");

    match error {
        client::Error::ApiFrame { code, allow_retry } => {
            assert_eq!(code, "request_too_large");
            assert!(!allow_retry);
        }
        other => panic!("expected an envelope, got {other:?}"),
    }
}

#[tokio::test]
async fn a_reassign_envelope_is_distinguishable() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        let body = r#"{"allowRetry":true,"error":{"code":"reassign_required","message":"stub"}}"#;
        let _ = socket.send(Message::Text(body.into())).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .connect()
        .await
        .expect_err("reassign_required is an error");

    assert!(
        matches!(error, client::Error::ReassignRequired),
        "got {error:?}"
    );
}

#[tokio::test]
async fn rejects_a_binary_frame_before_the_assignment() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        let _ = socket.send(Message::Binary(b"early".to_vec().into())).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .connect()
        .await
        .expect_err("binary before the assignment is a protocol error");

    assert!(
        matches!(error, client::Error::MalformedMessage),
        "got {error:?}"
    );
}

#[tokio::test]
async fn rejects_malformed_assignment_text() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        let _ = socket.send(Message::Text("not json".into())).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .connect()
        .await
        .expect_err("malformed text must be rejected");

    assert!(
        matches!(error, client::Error::MalformedMessage),
        "got {error:?}"
    );
}

#[tokio::test]
async fn rejects_a_frame_over_the_negotiated_limit() {
    // One byte over the cap the client imposes during the handshake.
    let oversized = MAX_MATCH_BODY_BYTES + 1;

    for text in [true, false] {
        let base_url = serve(move |mut socket| async move {
            expect_assignment_request(&mut socket).await;
            let message = if text {
                Message::Text("x".repeat(oversized).into())
            } else {
                Message::Binary(vec![0u8; oversized].into())
            };
            let _ = socket.send(message).await;
        })
        .await;

        let error = FlamingoVerifierClient::new(config(&base_url))
            .expect("client should build")
            .connect()
            .await
            .expect_err("a frame over the negotiated limit must be refused by the transport");

        assert!(
            matches!(error, client::Error::WebSocket(_)),
            "text={text}: got {error:?}"
        );
    }
}

#[tokio::test]
async fn times_out_when_the_assignment_never_arrives() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(
        config(&base_url).with_request_timeout(Duration::from_millis(100)),
    )
    .expect("client should build")
    .connect()
    .await
    .expect_err("an idle socket must eventually time out");

    assert!(matches!(error, client::Error::Timeout), "got {error:?}");
}

#[tokio::test]
async fn surfaces_a_rejected_upgrade() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("should accept");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer).await;
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n")
            .await
            .expect("should write");
    });

    let error = FlamingoVerifierClient::new(config(&format!("http://{address}")))
        .expect("client should build")
        .connect()
        .await
        .expect_err("a rejected upgrade must surface");

    assert!(
        matches!(error, client::Error::WebSocket(_)),
        "got {error:?}"
    );
}

#[tokio::test]
async fn classifies_an_upgrade_rejected_at_capacity() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("should accept");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer).await;
        let body = r#"{"allowRetry":true,"error":{"code":"at_capacity","message":"The host is at its WebSocket connection limit"}}"#;
        let response = format!(
            "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("should write");
    });

    let error = FlamingoVerifierClient::new(config(&format!("http://{address}")))
        .expect("client should build")
        .connect()
        .await
        .expect_err("a capacity rejection must surface");

    assert!(
        matches!(
            error,
            client::Error::ApiFrame {
                ref code,
                allow_retry: true
            } if code == "at_capacity"
        ),
        "got {error:?}"
    );
}

#[tokio::test]
async fn rejects_a_host_that_closes_before_the_assignment() {
    let base_url = serve(|mut socket| async move {
        expect_assignment_request(&mut socket).await;
        let _ = socket.close(None).await;
    })
    .await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .connect()
        .await
        .expect_err("a closed socket must surface");

    assert!(
        matches!(error, client::Error::ConnectionClosed),
        "got {error:?}"
    );
}

// `accept_hdr_async`'s callback returns tokio-tungstenite's large `ErrorResponse` type.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn connect_upgrades_the_unversioned_matches_endpoint() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    let seen = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&seen);

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("should accept");
        // Dropped as soon as the upgrade completes, so the client stops waiting for an
        // assignment instead of running to the request timeout.
        let _ = accept_hdr_async(stream, move |request: &Request, response| {
            *captured.lock().expect("lock should not be poisoned") =
                Some(request.uri().path().to_owned());
            Ok(response)
        })
        .await;
    });

    let _ = FlamingoVerifierClient::new(config(&format!("http://{address}")))
        .expect("client should build")
        .connect()
        .await;

    let path = seen.lock().expect("lock should not be poisoned").clone();
    assert_eq!(path.as_deref(), Some("/matches"));
}
