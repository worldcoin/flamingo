use crate::{AppState, error::ApiError};
use axum::{
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use flamingo_verifier_api_types::MATCH_CONTENT_TYPE;
use flamingo_verifier_enclave_types as enclave;

/// Maximum sealed binary body, independent of HTTP transfer encoding.
pub const MAX_BODY_BYTES: usize = flamingo_verifier_api_types::MAX_MATCH_BODY_BYTES;

/// Relay ciphertext without a JSON/base64 buffer or a copy into a Vec.
pub async fn handler(
    State(state): State<AppState>,
    _permit: UploadPermit,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        != Some(MATCH_CONTENT_TYPE)
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Expected application/octet-stream",
            false,
        ));
    }
    let body = body.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "The sealed request exceeded the body limit",
                false,
            )
        } else {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Could not read the sealed request",
                false,
            )
        }
    })?;
    if body.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The sealed request was empty",
            false,
        ));
    }
    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest { body })
        .await
        .map_err(|error| ApiError::enclave_match(&error))?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, MATCH_CONTENT_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        response.ciphertext,
    )
        .into_response())
}

/// Admission guard acquired before the body extractor and retained through the relay.
pub struct UploadPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl axum::extract::FromRequestParts<AppState> for UploadPermit {
    type Rejection = ApiError;

    fn from_request_parts(
        _: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = if state.is_draining() {
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_ready",
                "The verifier is not ready",
                true,
            ))
        } else {
            std::sync::Arc::clone(&state.uploads)
                .try_acquire_owned()
                .map(|permit| Self { _permit: permit })
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "not_ready",
                        "The verifier is at capacity or draining",
                        true,
                    )
                })
        };
        std::future::ready(result)
    }
}
