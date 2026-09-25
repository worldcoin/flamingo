//! Browser WebSocket transport for one attested assignment and one sealed match.

use std::future::Future;
use std::time::Duration;

use flamingo_verifier_api_types::{
    ClientMessage, EnclaveAssignmentResponse, ErrorEnvelope, HostMessage, MAX_MATCH_BODY_BYTES,
    MAX_MATCH_RESPONSE_BYTES,
};
use flamingo_verifier_sealed_types::MatchInputs;
use futures_util::future::{Either, select};
use futures_util::{SinkExt, StreamExt, pin_mut};
use gloo_timers::future::TimeoutFuture;
use pontifex::attestation::Verifier;
use url::Url;
use web_time::Instant;
use ws_stream_wasm::{WsMessage, WsMeta, WsStream};

use crate::client::{
    VerifiedAssignment, VerifiedMatchResult, classify_envelope, ensure_claims_match,
    open_verified_match, verify_assignment,
};
use crate::config::Config;
use crate::error::Error;

/// One verified exchange, bound to the WebSocket that delivered its assignment.
#[derive(Debug)]
pub struct FlamingoVerifierSession {
    _meta: WsMeta,
    socket: WsStream,
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

    /// Sends one sealed binary match frame and verifies its response.
    ///
    /// Consumes and closes the session, including when the exchange fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] on sealing, transport, timeout, protocol, or verification failure.
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
        drop(self.socket);
        result
    }
}

/// Opens a browser WebSocket and verifies the assignment delivered on it.
///
/// Browser WebSocket connections cannot set custom handshake headers; `build_request` and `connect_with`
/// are available only on native targets.
///
/// # Errors
///
/// Returns [`Error`] if connecting, receiving, or verifying the assignment fails or times out.
pub async fn connect(
    config: &Config,
    verifier: Verifier,
) -> Result<FlamingoVerifierSession, Error> {
    let url = websocket_url(config.host_url())?;
    let (meta, mut socket) = before_deadline(
        WsMeta::connect(url.as_str(), None),
        Instant::now() + config.connect_timeout(),
    )
    .await?
    .map_err(Error::BrowserWebSocket)?;

    let assignment = request_assignment(&mut socket, &verifier, config.request_timeout()).await;
    let assignment = match assignment {
        Ok(assignment) => assignment,
        Err(error) => {
            drop(socket);
            return Err(error);
        }
    };

    Ok(FlamingoVerifierSession {
        _meta: meta,
        socket,
        assignment,
        verifier,
        request_timeout: config.request_timeout(),
    })
}

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
    url.set_path(&format!("{}/v1/matches", host.path().trim_end_matches('/')));
    Ok(url)
}

async fn request_assignment(
    socket: &mut WsStream,
    verifier: &Verifier,
    request_timeout: Duration,
) -> Result<VerifiedAssignment, Error> {
    let deadline = Instant::now() + request_timeout;
    let request = serde_json::to_string(&ClientMessage::AssignmentRequest)
        .map_err(|_| Error::MalformedMessage)?;
    send_message(socket, WsMessage::Text(request), deadline).await?;

    match read_message(socket, deadline).await? {
        WsMessage::Text(text) => verify_assignment(verifier, &decode_assignment(&text)?),
        WsMessage::Binary(_) => Err(Error::MalformedMessage),
    }
}

async fn exchange_match(
    socket: &mut WsStream,
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

    let deadline = Instant::now() + request_timeout;
    send_message(socket, WsMessage::Binary(sealed), deadline).await?;
    match read_message(socket, deadline).await? {
        WsMessage::Binary(ciphertext) => {
            if ciphertext.len() > MAX_MATCH_RESPONSE_BYTES {
                return Err(Error::MalformedResult);
            }
            let result = open_verified_match(verifier, &ciphertext, opener)?;
            ensure_claims_match(inputs, &result)?;
            Ok(result)
        }
        WsMessage::Text(text) => Err(error_from_text(&text)),
    }
}

fn decode_assignment(text: &str) -> Result<EnclaveAssignmentResponse, Error> {
    if let Ok(HostMessage::Assignment(response)) = serde_json::from_str::<HostMessage>(text) {
        return Ok(response);
    }
    Err(error_from_text(text))
}

fn error_from_text(text: &str) -> Error {
    serde_json::from_str::<ErrorEnvelope>(text).map_or(Error::MalformedMessage, |envelope| {
        classify_envelope(&envelope)
    })
}

async fn read_message(socket: &mut WsStream, deadline: Instant) -> Result<WsMessage, Error> {
    before_deadline(socket.next(), deadline)
        .await?
        .ok_or(Error::ConnectionClosed)
}

async fn send_message(
    socket: &mut WsStream,
    message: WsMessage,
    deadline: Instant,
) -> Result<(), Error> {
    before_deadline(socket.send(message), deadline)
        .await?
        .map_err(Error::BrowserWebSocket)
}

async fn before_deadline<F: Future>(future: F, deadline: Instant) -> Result<F::Output, Error> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }
    let millis =
        remaining.as_millis() + u128::from(!remaining.subsec_nanos().is_multiple_of(1_000_000));
    let timer = TimeoutFuture::new(u32::try_from(millis).unwrap_or(u32::MAX));
    pin_mut!(future, timer);
    match select(future, timer).await {
        Either::Left((result, _)) => Ok(result),
        Either::Right(((), _)) => Err(Error::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_url_keeps_base_path() {
        let url = Url::parse("https://example.com/proxy/v2/?ignored=yes").unwrap();
        assert_eq!(
            websocket_url(&url).unwrap().as_str(),
            "wss://example.com/proxy/v2/v1/matches?ignored=yes"
        );
    }

    #[test]
    fn unexpected_assignment_is_rejected() {
        assert!(matches!(
            decode_assignment("not json"),
            Err(Error::MalformedMessage)
        ));
        assert!(matches!(
            decode_assignment("{}"),
            Err(Error::MalformedMessage)
        ));
    }
}
