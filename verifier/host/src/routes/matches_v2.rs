//! `GET /v2/matches`: a WebSocket session carrying one assignment and one match.
//!
//! The upgrade is refused with an HTTP `503` envelope once the host is at its connection limit. A
//! session then runs in phases: one assignment-request text frame, the assignment text frame, one
//! sealed match binary frame, and the sealed result binary frame, after which the host closes.
//! Anything out of order or malformed, including a frame past the socket layer's size limit, is
//! answered with an `ErrorEnvelope` text frame when the transport still accepts a write, then close.

use std::error::Error as _;

use axum::{
    body::Bytes,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flamingo_verifier_api_types::{
    ClientMessage, EnclaveAssignmentResponse, HostMessage, MAX_MATCH_BODY_BYTES,
    MAX_MATCH_RESPONSE_BYTES,
};
use flamingo_verifier_enclave_types as enclave_types;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, timeout_at};
use tungstenite::{Error as WsError, error::CapacityError};

use crate::{AppState, error::ApiError};

/// Headroom above the match byte limit, so a frame merely over the limit still reaches the handler.
///
/// Frames beyond this are cut off by the WebSocket layer before they are buffered.
pub const MAX_WS_MESSAGE_BYTES: usize = MAX_MATCH_BODY_BYTES + 8 * 1024;

/// Upgrades the request to a WebSocket session, or refuses it at capacity.
///
/// # Errors
///
/// Returns an HTTP `503` envelope when the host is already at `WS_MAX_CONNECTIONS`.
pub async fn handler(
    State(state): State<AppState>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Taken before the upgrade: the permit is held for the whole session and released on drop,
    // including on disconnect, error, timeout and cancellation.
    let permit = state.try_acquire_ws().ok_or_else(ApiError::at_capacity)?;

    Ok(upgrade
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| session(socket, state, permit))
        .into_response())
}

async fn session(mut socket: WebSocket, state: AppState, _permit: OwnedSemaphorePermit) {
    let failure = serve(&mut socket, &state).await.err();

    // One deadline for the whole teardown, so a peer that stopped reading cannot keep the
    // connection permit busy across a separate wait per frame.
    let deadline = Instant::now() + state.ws_idle_timeout();
    if let Some(error) = failure {
        error.log();
        if let Ok(body) = serde_json::to_string(&error.envelope()) {
            let _ = send_bounded(&mut socket, Message::Text(body.into()), deadline).await;
        }
    }
    let _ = send_bounded(&mut socket, Message::Close(None), deadline).await;
}

async fn serve(socket: &mut WebSocket, state: &AppState) -> Result<(), ApiError> {
    match next_client_message(socket, Instant::now() + state.ws_idle_timeout()).await? {
        Some(ClientMessage::AssignmentRequest) => {}
        None => return Ok(()),
    }

    let attestation = state
        .enclave_client()
        .encryption_key_attestation()
        .await
        .map_err(|error| ApiError::enclave_assignment(&error))?;
    let assignment = HostMessage::Assignment(EnclaveAssignmentResponse {
        attestation: STANDARD.encode(attestation.document),
        public_key: STANDARD.encode(attestation.public_key),
    });
    let body = serde_json::to_string(&assignment)
        .map_err(|_| ApiError::internal_error("assignment message failed to serialize"))?;
    send_bounded(
        socket,
        Message::Text(body.into()),
        Instant::now() + state.ws_idle_timeout(),
    )
    .await?;

    // The idle deadline restarts here and ends when the sealed frame arrives.
    let Some(sealed) = next_match_frame(socket, Instant::now() + state.ws_idle_timeout()).await?
    else {
        return Ok(());
    };

    let response = state
        .enclave_client()
        .run_match(enclave_types::MatchRequest { body: sealed })
        .await
        .map_err(|error| ApiError::enclave_match(&error))?;
    if response.ciphertext.len() > MAX_MATCH_RESPONSE_BYTES {
        return Err(ApiError::internal_error(
            "sealed match response exceeded the response limit",
        ));
    }

    send_bounded(
        socket,
        Message::Binary(response.ciphertext.into()),
        Instant::now() + state.ws_idle_timeout(),
    )
    .await
}

/// Sends one frame, giving up at `deadline`.
///
/// A peer that stops reading would otherwise leave the write pending forever, pinning the session
/// task and its connection permit.
async fn send_bounded(
    socket: &mut WebSocket,
    message: Message,
    deadline: Instant,
) -> Result<(), ApiError> {
    timeout_at(deadline, socket.send(message))
        .await
        .map_err(|_| ApiError::client_disconnected())?
        .map_err(|_| ApiError::client_disconnected())
}

/// Whether the socket layer rejected an inbound frame for exceeding [`MAX_WS_MESSAGE_BYTES`].
///
/// The layer cuts the frame off before it is buffered, so the handler never sees it and must
/// translate the read error into the same envelope as an oversized but buffered frame.
fn is_message_too_long(error: &axum::Error) -> bool {
    error
        .source()
        .and_then(|source| source.downcast_ref::<WsError>())
        .is_some_and(|error| {
            matches!(
                error,
                WsError::Capacity(CapacityError::MessageTooLong { .. })
            )
        })
}

/// Waits for the assignment request, ignoring pings and pongs without extending `deadline`.
///
/// `Ok(None)` means the peer closed or the transport failed before a request arrived.
async fn next_client_message(
    socket: &mut WebSocket,
    deadline: Instant,
) -> Result<Option<ClientMessage>, ApiError> {
    loop {
        match timeout_at(deadline, socket.recv()).await {
            Err(_elapsed) => return Err(ApiError::idle_timeout()),
            Ok(Some(Err(error))) if is_message_too_long(&error) => {
                return Err(ApiError::request_too_large());
            }
            Ok(None | Some(Ok(Message::Close(_)) | Err(_))) => return Ok(None),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Text(text)))) => {
                let message =
                    serde_json::from_str(text.as_str()).map_err(|_| ApiError::invalid_message())?;
                return Ok(Some(message));
            }
            Ok(Some(Ok(Message::Binary(_)))) => return Err(ApiError::unexpected_frame()),
        }
    }
}

/// Waits for the sealed match frame, ignoring pings and pongs without extending `deadline`.
///
/// `Ok(None)` means the peer closed or the transport failed before a frame arrived.
async fn next_match_frame(
    socket: &mut WebSocket,
    deadline: Instant,
) -> Result<Option<Bytes>, ApiError> {
    loop {
        match timeout_at(deadline, socket.recv()).await {
            Err(_elapsed) => return Err(ApiError::idle_timeout()),
            Ok(Some(Err(error))) if is_message_too_long(&error) => {
                return Err(ApiError::request_too_large());
            }
            Ok(None | Some(Ok(Message::Close(_)) | Err(_))) => return Ok(None),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Text(_)))) => return Err(ApiError::unexpected_frame()),
            Ok(Some(Ok(Message::Binary(frame)))) => {
                if frame.is_empty() {
                    return Err(ApiError::empty_request());
                }
                if frame.len() > MAX_MATCH_BODY_BYTES {
                    return Err(ApiError::request_too_large());
                }
                return Ok(Some(frame));
            }
        }
    }
}
