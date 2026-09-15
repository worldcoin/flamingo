//! HTTP route definitions.

mod enclave_assignment;
mod health;
mod matches;
mod payments;
mod readiness;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::AppState;

pub use matches::MAX_BODY_BYTES as MAX_MATCH_BODY_BYTES;
pub use payments::MAX_BODY_BYTES as MAX_PAYMENT_BODY_BYTES;

/// Builds the router with all API routes.
///
/// `payments_enabled` mounts the nonce route. Off, the path is not routed at all rather than
/// answering from a handler, so it reads as absent to anything probing the surface.
///
/// The body limits hang off the routes that take bodies, not the router. Assignment sends no
/// body and the health routes are `GET`s, so allowing multi-megabyte requests there would widen
/// the service's ingress for nothing. The payment routes carry fixed-width hex fields, so they
/// take a far smaller limit than a match.
pub fn handler(payments_enabled: bool) -> Router<AppState> {
    let nonces = payments_enabled.then(|| {
        Router::new()
            .route("/v1/channels/{channel_id}/nonces", post(payments::reserve))
            .layer(DefaultBodyLimit::max(payments::MAX_BODY_BYTES))
    });

    let router = Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave-assignment", post(enclave_assignment::handler))
        .route(
            "/v1/matches",
            post(matches::handler).layer(DefaultBodyLimit::max(matches::MAX_BODY_BYTES)),
        );

    match nonces {
        Some(nonces) => router.merge(nonces),
        None => router,
    }
}
