use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::AppState;

/// Serves public discovery without consulting enclave readiness or match admission.
pub async fn handler(State(state): State<AppState>) -> Response {
    let mut response = state
        .config()
        .engine_provider_metadata
        .as_ref()
        .map_or_else(
            || StatusCode::NOT_FOUND.into_response(),
            |metadata| Json(metadata.as_ref()).into_response(),
        );
    // Clients must refresh provider policy; an intermediary must not retain a revoked key.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}
