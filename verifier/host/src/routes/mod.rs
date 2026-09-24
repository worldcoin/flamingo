//! HTTP route definitions.

mod enclave_assignment;
mod health;
mod matches;
mod matches_v2;
mod readiness;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::AppState;

pub use matches::MAX_BODY_BYTES as MAX_MATCH_BODY_BYTES;
pub use matches_v2::MAX_WS_MESSAGE_BYTES;

/// Builds the router with all API routes.
///
/// The body limit hangs off the match route alone, not the router. Assignment sends no body and
/// the health routes are `GET`s, so allowing multi-megabyte requests there would widen the
/// service's ingress for nothing.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave-assignment", post(enclave_assignment::handler))
        .route(
            "/v1/matches",
            post(matches::handler).layer(DefaultBodyLimit::max(matches::MAX_BODY_BYTES)),
        )
        .route("/v2/matches", get(matches_v2::handler))
}
