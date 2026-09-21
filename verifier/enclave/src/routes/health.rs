use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::HealthRequest;

use crate::state::EnclaveState;

/// Reports broker availability and liveness of the initialized worker.
#[allow(clippy::unused_async, reason = "uniform async route interface")]
pub async fn handler(
    state: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_types::Error> {
    state.check_worker_health();
    Ok(())
}
