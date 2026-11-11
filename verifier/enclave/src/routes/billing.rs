use std::sync::Arc;

use flamingo_verifier_enclave_types::{self as enclave_types, BillingStatus, BillingUpdateRequest};

use crate::state::EnclaveState;

/// Applies the host's next billing state update at the Verifier's time (WIP-107 §4.8).
#[allow(clippy::unused_async, reason = "uniform async route interface")]
pub async fn handler(
    state: Arc<EnclaveState>,
    request: BillingUpdateRequest,
) -> Result<BillingStatus, enclave_types::Error> {
    state.billing().apply(&request, state.now())
}
