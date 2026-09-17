use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flamingo_verifier_api_types::EnclaveAssignmentResponse;

use crate::AppState;
use crate::error::AppError;

/// Assigns this host's enclave by returning its encryption key and attestation.
///
/// # Errors
///
/// Returns [`AppError`] if the enclave is unreachable or cannot attest.
pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<EnclaveAssignmentResponse>, AppError> {
    // Cached and refreshed ahead of use in the enclave, so this is a vsock round trip rather than
    // an NSM attestation. Caching it here would need a boot identifier and invalidation.
    let attestation = state
        .enclave_client()
        .encryption_key_attestation()
        .await
        .map_err(|error| AppError::enclave_assignment(&error))?;

    Ok(Json(EnclaveAssignmentResponse {
        attestation: STANDARD.encode(attestation.document),
        public_key: STANDARD.encode(attestation.public_key),
    }))
}
