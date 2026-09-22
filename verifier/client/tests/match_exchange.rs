//! Wire contract of a sealed match exchange, over real HTTP.
//!
//! The request must be raw sealed ciphertext and the response must be a sealed match
//! result of the declared type and size; anything else fails closed.

#![cfg(not(target_arch = "wasm32"))]

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::routing::post;
use flamingo_verifier_api_types::{MATCH_CONTENT_TYPE, MAX_MATCH_RESPONSE_BYTES};
use flamingo_verifier_client::{
    Config, Error, FlamingoVerifierClient, PcrMeasurement, VerifiedMatchResult,
};
use flamingo_verifier_sealed_types::{
    ComparisonRole, FailureReason, MATCH_CHANNEL_DOMAIN, MatchResult,
};
use futures_util::stream;
use hex_literal::hex;
use pontifex::{ChannelConsumer, ChannelDomain, ChannelEnclave};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The plaintext a sealed request must never leak.
const PRIVATE_IMAGE_MARKER: &[u8] = b"private-image-marker";

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

/// Seals [`PRIVATE_IMAGE_MARKER`] to a fresh enclave and prepares the sealed `answer` for
/// the same exchange, exactly as the enclave would after opening the request.
/// `foreign_reply` seals the answer on a second, unrelated exchange instead.
fn exchange(
    answer: &MatchResult,
    foreign_reply: bool,
) -> (Vec<u8>, Vec<u8>, pontifex::ResponseOpener) {
    let enclave = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN)).unwrap();
    let consumer = ChannelConsumer::from_unverified_public_key(
        ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
        &enclave.public_key(),
    )
    .unwrap();
    let (request_ciphertext, opener) = consumer.seal_to_enclave(PRIVATE_IMAGE_MARKER).unwrap();
    let (plaintext, sealer) = enclave.open(&request_ciphertext).unwrap();
    assert_eq!(&*plaintext, PRIVATE_IMAGE_MARKER);
    let sealer = if foreign_reply {
        let (other, _) = consumer.seal_to_enclave(b"another request").unwrap();
        enclave.open(&other).unwrap().1
    } else {
        sealer
    };
    let response = sealer.seal(&answer.to_padded_cbor().unwrap()).unwrap();
    (request_ciphertext, response, opener)
}

/// A `/v1/matches` request carrying `ciphertext` raw, with the headers
/// `FlamingoVerifierClient::build_match_request` puts on the wire.
fn match_request(base_url: &str, ciphertext: Vec<u8>) -> reqwest::RequestBuilder {
    reqwest::Client::new()
        .post(format!("{base_url}/v1/matches"))
        .header(reqwest::header::CONTENT_TYPE, MATCH_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, MATCH_CONTENT_TYPE)
        .body(ciphertext)
}

/// The headers and body of the request the stub served.
type SeenRequest = Arc<Mutex<Option<(HeaderMap, Vec<u8>)>>>;

#[derive(Clone)]
struct Answer {
    body: Vec<u8>,
    content_type: &'static str,
    seen: SeenRequest,
}

/// Serves `body` as a `/v1/matches` answer with the given content type, recording the
/// headers and body of the request it receives.
async fn serve_answer(body: Vec<u8>, content_type: &'static str) -> (String, SeenRequest) {
    let seen: SeenRequest = Arc::new(Mutex::new(None));
    let state = Answer {
        body,
        content_type,
        seen: Arc::clone(&seen),
    };

    let router = Router::new()
        .route(
            "/v1/matches",
            post(
                |State(state): State<Answer>, headers: HeaderMap, body: Bytes| async move {
                    *state.seen.lock().expect("lock should not be poisoned") =
                        Some((headers, body.to_vec()));
                    ([(header::CONTENT_TYPE, state.content_type)], state.body)
                },
            ),
        )
        .with_state(state);

    (serve(router).await, seen)
}

#[tokio::test]
async fn a_sealed_exchange_round_trips_over_raw_ciphertext() {
    let reason = FailureReason::MatchBelowThreshold(ComparisonRole::SelfieChallenge);
    let (request_ciphertext, answer, opener) = exchange(&MatchResult::Failed(reason), false);
    let (base_url, seen) = serve_answer(answer, MATCH_CONTENT_TYPE).await;

    let result = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_match_with(match_request(&base_url, request_ciphertext.clone()), opener)
        .await
        .expect("a sealed rejection is a normal return");

    assert_eq!(result, VerifiedMatchResult::Failed(reason));

    let (headers, body) = seen
        .lock()
        .expect("lock should not be poisoned")
        .clone()
        .expect("the stub should have seen the request");
    assert_eq!(headers[header::CONTENT_TYPE], MATCH_CONTENT_TYPE);
    assert_eq!(headers[header::ACCEPT], MATCH_CONTENT_TYPE);
    assert_eq!(
        body, request_ciphertext,
        "the body is raw ciphertext, not a JSON/base64 envelope"
    );
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).is_err(),
        "the body must not be JSON"
    );
    assert!(
        !body
            .windows(PRIVATE_IMAGE_MARKER.len())
            .any(|window| window == PRIVATE_IMAGE_MARKER),
        "the sealed plaintext must not appear in the body"
    );
}

#[tokio::test]
async fn a_response_of_the_wrong_type_is_rejected() {
    let (request_ciphertext, answer, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
    let (base_url, _) = serve_answer(answer, "application/json").await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_match_with(match_request(&base_url, request_ciphertext), opener)
        .await
        .expect_err("only the declared content type can hold a match result");

    assert!(matches!(error, Error::MalformedResult), "got {error:?}");
}

#[tokio::test]
async fn an_oversized_streamed_response_is_rejected_before_it_is_buffered() {
    let (request_ciphertext, _, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);

    // Chunked encoding, so no Content-Length bounds the response up front.
    let chunks = std::iter::repeat_with(|| Ok::<_, Infallible>(Bytes::from_static(&[0; 4096])))
        .take(MAX_MATCH_RESPONSE_BYTES / 4096 + 2);
    let router = Router::new().route(
        "/v1/matches",
        post(move || {
            let chunks = chunks.clone();
            async move {
                (
                    [(header::CONTENT_TYPE, MATCH_CONTENT_TYPE)],
                    Body::from_stream(stream::iter(chunks)),
                )
            }
        }),
    );
    let base_url = serve(router).await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_match_with(match_request(&base_url, request_ciphertext), opener)
        .await
        .expect_err("a body past the response limit is not a match result");

    assert!(matches!(error, Error::MalformedResult), "got {error:?}");
}

#[tokio::test]
async fn an_oversized_declared_length_is_rejected_before_it_is_buffered() {
    let (request_ciphertext, _, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
    let base_url = serve_lying_length(u64::try_from(MAX_MATCH_RESPONSE_BYTES + 1).unwrap()).await;

    let error = FlamingoVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_match_with(match_request(&base_url, request_ciphertext), opener)
        .await
        .expect_err("a declared length past the response limit is not a match result");

    assert!(matches!(error, Error::MalformedResult), "got {error:?}");
}

/// Answers one `/v1/matches` request with a hand-written `Content-Length` and no body.
///
/// Hyper's server derives the length from the body it is given, so a length that lies
/// about a response's size can only be put on the wire by hand.
async fn serve_lying_length(declared_length: u64) -> String {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("stub should accept");
        read_request(&mut stream).await;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: {MATCH_CONTENT_TYPE}\r\ncontent-length: {declared_length}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("stub should write");
        stream.shutdown().await.expect("stub should close cleanly");
    });

    format!("http://{address}")
}

/// Drains one HTTP/1.1 request so the stub's close is a clean shutdown instead of a
/// reset that could discard the response.
async fn read_request(stream: &mut tokio::net::TcpStream) {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_length = loop {
        let read = stream.read(&mut chunk).await.expect("stub should read");
        assert!(read > 0, "the client should send a request");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let body_length: usize = String::from_utf8_lossy(&request[..head_length])
        .to_ascii_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .expect("the client should declare a body length");
    while request.len() < head_length + body_length {
        let read = stream.read(&mut chunk).await.expect("stub should read");
        assert!(read > 0, "the client should send the whole body");
        request.extend_from_slice(&chunk[..read]);
    }
}
