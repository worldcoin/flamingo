use axum::{extract::State, http::StatusCode};

use crate::AppState;

/// Readiness, not liveness: this host takes traffic only once every dependency it cannot serve a
/// match without will answer. The enclave runs the match; the store and the fee escrow decide
/// whether the caller may have one.
pub async fn handler(State(state): State<AppState>) -> StatusCode {
    // Switched off, so neither the escrow nor the store can keep this host out of rotation.
    if let Some(gate) = state.payments()
        && let Err(error) = gate.ledger().ready().await
    {
        tracing::warn!(%error, "payments readiness check failed");

        return StatusCode::SERVICE_UNAVAILABLE;
    }

    match state.enclave_client().health().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(
                ?error,
                dependency = "enclave",
                "enclave readiness check failed"
            );
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
