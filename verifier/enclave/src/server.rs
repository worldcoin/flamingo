//! Pontifex server setup and lifecycle.

use std::sync::Arc;

use anyhow::Context;

use crate::{routes, state::EnclaveState};

/// Starts the enclave's Pontifex server on the provided vsock port.
///
/// # Errors
///
/// Returns an error when Pontifex cannot listen for or serve requests.
pub async fn start(state: Arc<EnclaveState>, port: u32) -> anyhow::Result<()> {
    routes::router(state)
        .serve(port)
        .await
        .context("failed to serve Pontifex")
}
