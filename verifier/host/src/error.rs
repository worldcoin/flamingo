//! Universal error handling for the API.
//!
//! Every route returns [`AppError`], so status codes, response bodies and logging are decided
//! in one place. Enclave failures map differently per route, since the same enclave error
//! means different things depending on what was asked, so each route gets its own constructor
//! rather than a blanket `From` impl.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use flamingo_verifier_api_types::{ApiErrorResponse, ErrorBody};
use flamingo_verifier_enclave_types as enclave_types;

use crate::enclave;

/// An API failure, with the status and body to return for it.
#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    allow_retry: bool,
    /// Extra context for logs. Never serialized, since it may name internals.
    detail: Option<String>,
}

impl AppError {
    /// Creates an error with the given status and body.
    #[must_use]
    pub const fn new(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        allow_retry: bool,
    ) -> Self {
        Self {
            status,
            code,
            message,
            allow_retry,
            detail: None,
        }
    }

    /// Attaches context that is logged but not returned to the client.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The status this error will return. Exposed for tests and callers that branch on it.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The machine-readable code this error will return.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Maps an enclave failure on the assignment route.
    ///
    /// Match-path errors cannot arise from an attestation request, so reaching one means the
    /// enclave answered a request it was not asked. That is a host bug, not retryable
    /// unavailability.
    #[must_use]
    pub fn enclave_assignment(error: &enclave::Error) -> Self {
        match error {
            enclave::Error::Timeout | enclave::Error::Transport(_) => {
                Self::enclave_unreachable(error)
            }
            enclave::Error::Operation(operation) => match operation {
                enclave_types::Error::NotReady
                | enclave_types::Error::SecureModuleNotInitialized
                | enclave_types::Error::AttestationFailed => Self::enclave_not_ready(*operation),
                enclave_types::Error::RequestNotOpened | enclave_types::Error::Internal => {
                    Self::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "Internal server error",
                        false,
                    )
                    .with_detail(format!(
                        "unexpected enclave error on assignment: {operation:?}"
                    ))
                }
            },
        }
    }

    /// Maps an enclave failure on the match route.
    #[must_use]
    pub fn enclave_match(error: &enclave::Error) -> Self {
        match error {
            enclave::Error::Timeout | enclave::Error::Transport(_) => {
                Self::enclave_unreachable(error)
            }
            enclave::Error::Operation(operation) => match operation {
                // The request did not open. Indistinguishable from a corrupt ciphertext here, so
                // the client is told to re-assign and re-seal -- once. See the spec's §6 note on
                // bounding this retry: an unbounded one would loop on a genuine sealing bug.
                enclave_types::Error::RequestNotOpened => Self::new(
                    StatusCode::CONFLICT,
                    "reassign_required",
                    "The request was not sealed to this enclave's current encryption key",
                    true,
                )
                .with_detail(format!("{operation:?}")),
                enclave_types::Error::Internal => Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error",
                    true,
                )
                .with_detail(format!("{operation:?}")),
                enclave_types::Error::NotReady
                | enclave_types::Error::SecureModuleNotInitialized
                | enclave_types::Error::AttestationFailed => Self::enclave_not_ready(*operation),
            },
        }
    }

    /// The request never reached a working enclave.
    fn enclave_unreachable(error: &enclave::Error) -> Self {
        match error {
            enclave::Error::Timeout => Self::new(
                StatusCode::GATEWAY_TIMEOUT,
                "enclave_timeout",
                "The enclave did not answer in time",
                true,
            ),
            enclave::Error::Transport(detail) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "enclave_unreachable",
                "The enclave is unreachable",
                true,
            )
            .with_detail(detail.clone()),
            enclave::Error::Operation(_) => unreachable!("caller matched a transport failure"),
        }
    }

    /// The enclave answered but cannot serve requests yet.
    fn enclave_not_ready(operation: enclave_types::Error) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "enclave_not_ready",
            "The enclave is not ready",
            true,
        )
        .with_detail(format!("{operation:?}"))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                code = self.code,
                status = %self.status,
                detail = self.detail.as_deref().unwrap_or_default(),
                dependency = "enclave",
                "request failed"
            );
        } else {
            tracing::warn!(
                code = self.code,
                status = %self.status,
                detail = self.detail.as_deref().unwrap_or_default(),
                "request rejected"
            );
        }

        // The envelope owns its strings, so the `&'static str`s are copied here.
        let body = ApiErrorResponse {
            allow_retry: self.allow_retry,
            error: ErrorBody {
                code: self.code.to_owned(),
                message: self.message.to_owned(),
            },
        };

        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use flamingo_verifier_enclave_types as enclave_types;

    use super::AppError;
    use crate::enclave;

    #[test]
    fn assignment_maps_transport_failures_to_retryable_statuses() {
        for (error, status, code) in [
            (
                enclave::Error::Timeout,
                StatusCode::GATEWAY_TIMEOUT,
                "enclave_timeout",
            ),
            (
                enclave::Error::Transport("boom".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
                "enclave_unreachable",
            ),
        ] {
            let mapped = AppError::enclave_assignment(&error);
            assert_eq!(mapped.status(), status);
            assert_eq!(mapped.code(), code);
            assert!(mapped.allow_retry, "{code} should be retryable");
        }
    }

    #[test]
    fn both_routes_agree_that_a_not_ready_enclave_is_retryable() {
        for operation in [
            enclave_types::Error::NotReady,
            enclave_types::Error::SecureModuleNotInitialized,
            enclave_types::Error::AttestationFailed,
        ] {
            let error = enclave::Error::Operation(operation);

            for mapped in [
                AppError::enclave_assignment(&error),
                AppError::enclave_match(&error),
            ] {
                assert_eq!(mapped.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(mapped.code(), "enclave_not_ready");
                assert!(mapped.allow_retry);
            }
        }
    }

    /// The same enclave error means different things depending on what was asked, which is
    /// why the mapping is per route rather than a blanket `From` impl.
    #[test]
    fn an_unopenable_request_is_retryable_on_matches_and_a_host_bug_on_assignment() {
        let error = enclave::Error::Operation(enclave_types::Error::RequestNotOpened);

        // On the match path the client should re-assign and re-seal.
        let mapped = AppError::enclave_match(&error);
        assert_eq!(mapped.status(), StatusCode::CONFLICT);
        assert!(mapped.allow_retry);

        // Reaching it from an attestation request means the enclave answered something it was
        // never asked, which is a host bug and not retryable.
        let mapped = AppError::enclave_assignment(&error);
        assert_eq!(mapped.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!mapped.allow_retry);
    }

    /// Pins the whole per-route matrix in one place. The two paths deliberately disagree on
    /// `RequestNotOpened` -- impossible on assignment, so a host bug; expected on the match path,
    /// so a retryable `409`. Nothing else fails if one side is changed alone, hence this test.
    #[test]
    fn each_enclave_error_maps_per_route() {
        let cases = [
            (
                enclave_types::Error::NotReady,
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                enclave_types::Error::SecureModuleNotInitialized,
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                enclave_types::Error::AttestationFailed,
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                enclave_types::Error::RequestNotOpened,
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::CONFLICT,
            ),
            (
                enclave_types::Error::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (error, on_assignment, on_match) in cases {
            let wrapped = enclave::Error::Operation(error);

            assert_eq!(
                AppError::enclave_assignment(&wrapped).status(),
                on_assignment,
                "assignment path for {error:?}"
            );
            assert_eq!(
                AppError::enclave_match(&wrapped).status(),
                on_match,
                "match path for {error:?}"
            );
        }
    }
}
