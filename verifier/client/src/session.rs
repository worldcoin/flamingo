//! The v2 WebSocket session for the Flamingo Verifier host.
//!
//! A session performs exactly one exchange: the assignment request is answered with the
//! enclave's attested key, and then the match request is sealed to that key and sent as a
//! single binary frame. The socket and the verified assignment are held together, so a match
//! cannot be sent over a connection whose assignment was never verified.

use std::time::Duration;

use flamingo_verifier_api_types::{
    ClientMessage, EnclaveAssignmentResponse, ErrorEnvelope, HostMessage, MAX_MATCH_BODY_BYTES,
    MAX_MATCH_RESPONSE_BYTES,
};
use flamingo_verifier_sealed_types::MatchInputs;
use futures_util::{SinkExt, StreamExt};
use pontifex::attestation::Verifier;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};
use url::Url;

use crate::client::{
    VerifiedAssignment, VerifiedMatchResult, classify_envelope, ensure_claims_match,
    open_verified_match, verify_assignment,
};
use crate::config::Config;
use crate::error::Error;

/// The WebSocket the session owns, over plain TCP or TLS.
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One verified v2 exchange: a WebSocket bound to the enclave assignment delivered on it.
///
/// Created by [`crate::FlamingoVerifierClient::connect_v2`].
#[derive(Debug)]
pub struct FlamingoVerifierSession {
    socket: Socket,
    assignment: VerifiedAssignment,
    verifier: Verifier,
    request_timeout: Duration,
}

impl FlamingoVerifierSession {
    /// The verified assignment delivered on this session's socket.
    #[must_use]
    pub const fn assignment(&self) -> &VerifiedAssignment {
        &self.assignment
    }

    /// Seals `inputs` to this session's verified enclave key, sends them as the one binary match
    /// frame, and returns the verified result or the sealed rejection.
    ///
    /// Consumes the session: one socket carries exactly one match, and it is closed after the
    /// exchange, including on failure.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if sealing or transport fails, the host answers with an error envelope,
    /// the response is oversized, or the result or its claims do not verify.
    pub async fn request_match(
        mut self,
        inputs: &MatchInputs,
    ) -> Result<VerifiedMatchResult, Error> {
        let result = exchange_match(
            &mut self.socket,
            self.assignment.consumer(),
            inputs,
            &self.verifier,
            self.request_timeout,
        )
        .await;

        let _ = tokio::time::timeout(self.request_timeout, self.socket.close(None)).await;

        result
    }
}

/// Opens the v2 WebSocket and verifies the assignment the host delivers on it.
pub async fn connect(
    config: &Config,
    verifier: Verifier,
) -> Result<FlamingoVerifierSession, Error> {
    let url = websocket_url(config.host_url())?;
    let socket_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MATCH_BODY_BYTES))
        .max_frame_size(Some(MAX_MATCH_BODY_BYTES));
    let (mut socket, _response) = tokio::time::timeout(
        config.connect_timeout(),
        connect_async_with_config(url.as_str(), Some(socket_config), false),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(Error::WebSocket)?;

    let assignment = request_assignment(&mut socket, &verifier, config.request_timeout()).await?;

    Ok(FlamingoVerifierSession {
        socket,
        assignment,
        verifier,
        request_timeout: config.request_timeout(),
    })
}

/// Maps the configured HTTP base URL onto its WebSocket endpoint.
fn websocket_url(host: &Url) -> Result<Url, Error> {
    let mut url = host.clone();
    let mapped = match host.scheme() {
        "http" => url.set_scheme("ws"),
        "https" => url.set_scheme("wss"),
        _ => {
            return Err(Error::InvalidConfig {
                attribute: "host_url".to_owned(),
                reason: "the base URL scheme must be http or https to map to a WebSocket"
                    .to_owned(),
            });
        }
    };
    mapped.map_err(|()| Error::InvalidConfig {
        attribute: "host_url".to_owned(),
        reason: "the base URL scheme could not be mapped to a WebSocket".to_owned(),
    })?;
    url.set_path("/v2/matches");

    Ok(url)
}

/// Sends the assignment request and returns the verified assignment.
async fn request_assignment(
    socket: &mut Socket,
    verifier: &Verifier,
    request_timeout: Duration,
) -> Result<VerifiedAssignment, Error> {
    // One absolute deadline bounds the whole phase: ignored pings and the send do not extend it.
    let deadline = Instant::now() + request_timeout;
    let request = serde_json::to_string(&ClientMessage::AssignmentRequest)
        .map_err(|_| Error::MalformedMessage)?;
    send_message(socket, Message::Text(request.into()), deadline).await?;

    loop {
        match read_message(socket, deadline).await? {
            Message::Text(text) => {
                let response = decode_assignment(text.as_str())?;
                return verify_assignment(verifier, &response);
            }
            Message::Binary(_) => return Err(Error::MalformedMessage),
            Message::Close(_) => return Err(Error::ConnectionClosed),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
}

/// Seals the inputs, sends the one binary frame, and verifies the one binary response.
async fn exchange_match(
    socket: &mut Socket,
    consumer: &pontifex::ChannelConsumer,
    inputs: &MatchInputs,
    verifier: &Verifier,
    request_timeout: Duration,
) -> Result<VerifiedMatchResult, Error> {
    let plaintext = inputs.to_cbor().map_err(|_| Error::MalformedResult)?;
    let (sealed, opener) = consumer
        .seal_to_enclave(&plaintext)
        .map_err(Error::Channel)?;
    if sealed.len() > MAX_MATCH_BODY_BYTES {
        return Err(Error::MalformedResult);
    }

    // One absolute deadline bounds the whole phase: ignored pings and the send do not extend it.
    let deadline = Instant::now() + request_timeout;
    send_message(socket, Message::Binary(sealed.into()), deadline).await?;

    loop {
        match read_message(socket, deadline).await? {
            Message::Binary(ciphertext) => {
                if ciphertext.len() > MAX_MATCH_RESPONSE_BYTES {
                    return Err(Error::MalformedResult);
                }
                let result = open_verified_match(verifier, &ciphertext, opener)?;
                ensure_claims_match(inputs, &result)?;
                return Ok(result);
            }
            Message::Text(text) => return Err(error_from_text(text.as_str())),
            Message::Close(_) => return Err(Error::ConnectionClosed),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
}

/// Parses the host's assignment text frame, or returns the error envelope it carries.
fn decode_assignment(text: &str) -> Result<EnclaveAssignmentResponse, Error> {
    if let Ok(HostMessage::Assignment(response)) = serde_json::from_str::<HostMessage>(text) {
        return Ok(response);
    }

    Err(error_from_text(text))
}

/// Reads a host text frame as an error envelope, falling back to a malformed-message error.
fn error_from_text(text: &str) -> Error {
    serde_json::from_str::<ErrorEnvelope>(text).map_or(Error::MalformedMessage, |envelope| {
        classify_envelope(&envelope)
    })
}

/// Reads the next frame, bounded by the phase's absolute deadline.
async fn read_message(socket: &mut Socket, deadline: Instant) -> Result<Message, Error> {
    match tokio::time::timeout_at(deadline, socket.next()).await {
        Err(_) => Err(Error::Timeout),
        Ok(None) => Err(Error::ConnectionClosed),
        Ok(Some(Err(error))) => Err(Error::WebSocket(error)),
        Ok(Some(Ok(message))) => Ok(message),
    }
}

/// Sends a frame, bounded by the phase's absolute deadline.
async fn send_message(
    socket: &mut Socket,
    message: Message,
    deadline: Instant,
) -> Result<(), Error> {
    match tokio::time::timeout_at(deadline, socket.send(message)).await {
        Err(_) => Err(Error::Timeout),
        Ok(Err(error)) => Err(Error::WebSocket(error)),
        Ok(Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use flamingo_verifier_api_types::MAX_MATCH_RESPONSE_BYTES;
    use flamingo_verifier_protocol::match_token::MatchToken;
    use flamingo_verifier_sealed_types::{
        AttestedStatement, FailureReason, MATCH_CHANNEL_DOMAIN, MatchInputs, MatchResult,
    };
    use futures_util::{SinkExt, StreamExt};
    use pontifex::attestation::PcrConfig;
    use pontifex::{ChannelConsumer, ChannelDomain, ChannelEnclave};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{WebSocketStream, accept_async, connect_async};

    use super::{Socket, exchange_match, websocket_url};
    use crate::VerifiedMatchResult;
    use crate::error::Error;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn verifier() -> super::Verifier {
        super::Verifier::new(vec![PcrConfig::new([0xab; 48])], Duration::from_mins(1))
    }

    fn inputs() -> MatchInputs {
        MatchInputs::GrayBadge(flamingo_verifier_sealed_types::GrayBadgeInputs {
            live: flamingo_verifier_sealed_types::LiveCapture::Vanilla(b"live".to_vec().into()),
            rtms_challenge: b"challenge".to_vec().into(),
            match_threshold: 0.5,
        })
    }

    fn consumer_for(enclave: &ChannelEnclave) -> ChannelConsumer {
        ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &enclave.public_key(),
        )
        .expect("valid key")
    }

    /// Answers the client's binary frame with whatever `handler` sends back.
    async fn connect_to_stub<F, Fut>(handler: F) -> Socket
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
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

        let (client, _) = connect_async(format!("ws://{address}"))
            .await
            .expect("client should upgrade");
        client
    }

    /// Reads one binary request frame and returns the responder sealed to the enclave.
    async fn open_request(socket: &mut WebSocketStream<TcpStream>) -> Arc<ChannelEnclave> {
        let request = socket
            .next()
            .await
            .expect("a frame")
            .expect("a valid frame");
        let Message::Binary(_) = request else {
            panic!("expected a binary match frame");
        };
        Arc::new(
            ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN))
                .expect("channel key"),
        )
    }

    fn responder() -> Arc<ChannelEnclave> {
        Arc::new(
            ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN))
                .expect("channel key"),
        )
    }

    async fn rejection_round_trip(foreign_reply: bool) -> Result<VerifiedMatchResult, Error> {
        let responder = responder();
        let answer = MatchResult::Failed(FailureReason::MalformedInputs);
        let server = Arc::clone(&responder);

        let mut socket = connect_to_stub(move |mut socket| async move {
            let request = socket
                .next()
                .await
                .expect("a frame")
                .expect("a valid frame");
            let Message::Binary(ciphertext) = request else {
                panic!("expected a binary match frame");
            };
            let (_, own_sealer) = server.open(&ciphertext).expect("opens its own request");
            let sealer = if foreign_reply {
                let stranger = consumer_for(&server);
                let (other, _) = stranger.seal_to_enclave(b"unrelated").expect("seal");
                server.open(&other).expect("opens its own").1
            } else {
                own_sealer
            };
            let encoded = answer.to_padded_cbor().expect("fits the envelope");
            socket
                .send(Message::Binary(sealer.seal(&encoded).unwrap().into()))
                .await
                .expect("should send");
        })
        .await;

        exchange_match(
            &mut socket,
            &consumer_for(&responder),
            &inputs(),
            &verifier(),
            TIMEOUT,
        )
        .await
    }

    #[tokio::test]
    async fn a_sealed_rejection_round_trips_over_the_socket() {
        let result = rejection_round_trip(false)
            .await
            .expect("a rejection is a normal return");

        assert!(matches!(
            result,
            VerifiedMatchResult::Failed(FailureReason::MalformedInputs)
        ));
    }

    #[tokio::test]
    async fn a_reply_from_another_exchange_cannot_be_opened() {
        let error = rejection_round_trip(true)
            .await
            .expect_err("a reply sealed on another exchange must not open");

        assert!(matches!(error, Error::Channel(_)), "got {error:?}");
    }

    #[tokio::test]
    async fn a_ping_storm_does_not_extend_the_phase_deadline() {
        let mut socket = connect_to_stub(|mut socket| async move {
            let _ = open_request(&mut socket).await;
            let ping = Message::Ping(Vec::new().into());
            // Keeps pinging well past the client's deadline: a per-read timeout would be reset
            // by each frame and never elapse.
            for _ in 0..500 {
                if socket.send(ping.clone()).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        let started = std::time::Instant::now();
        let error = exchange_match(
            &mut socket,
            &consumer_for(&responder()),
            &inputs(),
            &verifier(),
            Duration::from_millis(100),
        )
        .await
        .expect_err("a stream of pings must not keep the phase alive");

        assert!(matches!(error, Error::Timeout), "got {error:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the deadline was restarted by pings"
        );
    }

    #[tokio::test]
    async fn an_oversized_binary_response_is_rejected() {
        let mut socket = connect_to_stub(|mut socket| async move {
            let _ = open_request(&mut socket).await;
            let oversized = vec![0u8; MAX_MATCH_RESPONSE_BYTES + 1];
            socket
                .send(Message::Binary(oversized.into()))
                .await
                .expect("should send");
        })
        .await;

        let error = exchange_match(
            &mut socket,
            &consumer_for(&responder()),
            &inputs(),
            &verifier(),
            TIMEOUT,
        )
        .await
        .expect_err("an oversized response must be rejected");

        assert!(matches!(error, Error::MalformedResult), "got {error:?}");
    }

    #[tokio::test]
    async fn an_empty_binary_response_is_rejected() {
        let mut socket = connect_to_stub(|mut socket| async move {
            let _ = open_request(&mut socket).await;
            socket
                .send(Message::Binary(Vec::new().into()))
                .await
                .expect("should send");
        })
        .await;

        let error = exchange_match(
            &mut socket,
            &consumer_for(&responder()),
            &inputs(),
            &verifier(),
            TIMEOUT,
        )
        .await
        .expect_err("an empty response must be rejected");

        assert!(matches!(error, Error::Channel(_)), "got {error:?}");
    }

    #[tokio::test]
    async fn an_error_envelope_before_the_result_surfaces() {
        let mut socket = connect_to_stub(|mut socket| async move {
            let _ = open_request(&mut socket).await;
            let envelope =
                r#"{"allowRetry":true,"error":{"code":"reassign_required","message":"stale"}}"#;
            socket
                .send(Message::Text(envelope.into()))
                .await
                .expect("should send");
        })
        .await;

        let error = exchange_match(
            &mut socket,
            &consumer_for(&responder()),
            &inputs(),
            &verifier(),
            TIMEOUT,
        )
        .await
        .expect_err("an envelope is an error");

        assert!(matches!(error, Error::ReassignRequired), "got {error:?}");
    }

    #[tokio::test]
    async fn unexpected_text_before_the_result_is_rejected() {
        let mut socket = connect_to_stub(|mut socket| async move {
            let _ = open_request(&mut socket).await;
            socket
                .send(Message::Text("not json".into()))
                .await
                .expect("should send");
        })
        .await;

        let error = exchange_match(
            &mut socket,
            &consumer_for(&responder()),
            &inputs(),
            &verifier(),
            TIMEOUT,
        )
        .await
        .expect_err("stray text must be rejected");

        assert!(matches!(error, Error::MalformedMessage), "got {error:?}");
    }

    #[tokio::test]
    async fn a_statement_whose_attestation_does_not_verify_is_rejected_over_the_socket() {
        let responder = responder();
        let answer = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
            signing_key_attestation: b"not a COSE attestation document".to_vec(),
        });
        let server = Arc::clone(&responder);

        let mut socket = connect_to_stub(move |mut socket| async move {
            let request = socket
                .next()
                .await
                .expect("a frame")
                .expect("a valid frame");
            let Message::Binary(ciphertext) = request else {
                panic!("expected a binary match frame");
            };
            let (_, sealer) = server.open(&ciphertext).expect("opens its own request");
            let encoded = answer.to_padded_cbor().expect("fits the envelope");
            socket
                .send(Message::Binary(sealer.seal(&encoded).unwrap().into()))
                .await
                .expect("should send");
        })
        .await;

        let error = exchange_match(
            &mut socket,
            &consumer_for(&responder),
            &inputs(),
            &verifier(),
            TIMEOUT,
        )
        .await
        .expect_err("an unverifiable attestation must not yield a statement");

        assert!(matches!(error, Error::Attestation(_)), "got {error:?}");
    }

    #[test]
    fn base_urls_map_onto_the_v2_endpoint() {
        let secure = websocket_url(&url::Url::parse("https://verifier.example.com").unwrap())
            .expect("https should map");
        assert_eq!(secure.as_str(), "wss://verifier.example.com/v2/matches");

        let plain = websocket_url(&url::Url::parse("http://127.0.0.1:8080").unwrap())
            .expect("http should map");
        assert_eq!(plain.as_str(), "ws://127.0.0.1:8080/v2/matches");
    }

    #[test]
    fn a_non_http_base_url_scheme_is_rejected() {
        let error = websocket_url(&url::Url::parse("ftp://verifier.example.com").unwrap())
            .expect_err("a non-http scheme has no WebSocket mapping");

        assert!(
            matches!(error, Error::InvalidConfig { .. }),
            "got {error:?}"
        );
    }
}
