//! HTTP route definitions.

mod health;
mod matches;
mod readiness;

use axum::{Router, routing::get};

use crate::AppState;

pub use matches::MAX_WS_MESSAGE_BYTES;

/// Builds the router with all API routes.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/matches", get(matches::handler))
}
