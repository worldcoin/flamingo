use axum::{extract::State, http::StatusCode};

use crate::AppState;

/// Readiness, not liveness: this host takes traffic only once its enclave answers, which is the
/// one dependency it cannot serve a match without.
pub async fn handler(State(state): State<AppState>) -> StatusCode {
    match state.enclave_client().health().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(?error, "enclave readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
