use axum::{Json, extract::State, extract::rejection::JsonRejection, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flamingo_verifier_api_types::{MatchRequestBody, MatchResponseBody};
use flamingo_verifier_enclave_types as enclave;

use crate::AppState;
use crate::error::AppError;

/// Largest match body this route accepts, including the base64 JSON envelope.
pub const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

/// Relays a sealed match request to the enclave.
///
/// # Errors
///
/// Returns [`AppError`] if the body is rejected or the enclave rejects the request.
pub async fn handler(
    State(state): State<AppState>,
    body: Result<Json<MatchRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<MatchResponseBody>), AppError> {
    let Json(body) = body.map_err(|rejection| rejected_body(&rejection))?;

    let ciphertext = STANDARD.decode(body.ciphertext.trim()).map_err(|_| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The sealed match request was not valid base64",
            false,
        )
    })?;

    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest { body: ciphertext })
        .await
        .map_err(|error| AppError::enclave_match(&error))?;

    // Always 200 when the enclave answered. Whether the match results (failure or success) must not be leaked to host.
    Ok((
        StatusCode::OK,
        Json(MatchResponseBody {
            response_ciphertext: STANDARD.encode(response.ciphertext),
        }),
    ))
}

/// Maps a body the extractor refused.
///
/// Axum answers its own rejections with a bare status and a plaintext line, which is the one way
/// out of this service that carries no `code` for a client to branch on. Routing them through
/// [`AppError`] keeps that envelope universal. The size is only ever logged: it describes the
/// request, and a caller that sent it already knows.
fn rejected_body(rejection: &JsonRejection) -> AppError {
    let (status, code, message) = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "The match request was larger than this route accepts",
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The match request body was not the expected JSON",
        )
    };

    // Serde diagnostics can echo attacker-provided values, including ciphertext.
    AppError::new(status, code, message, false).with_detail(format!("limit={MAX_BODY_BYTES}"))
}
