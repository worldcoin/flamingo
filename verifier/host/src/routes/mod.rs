//! HTTP route definitions.

mod engine_provider;
mod health;
mod matches;
mod readiness;

use axum::{Router, routing::get};

use crate::AppState;

pub use matches::MAX_WS_MESSAGE_BYTES;

/// Builds the router with all API routes.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route(
            flamingo_verifier_api_types::ENGINE_METADATA_PATH,
            get(engine_provider::handler),
        )
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/matches", get(matches::handler))
}
