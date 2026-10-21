use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::HealthRequest;

use crate::state::EnclaveState;

/// Reports broker availability and liveness of the initialized worker, and whether the enclave
/// can run a request: it needs a loaded release manifest and room in its replay set.
#[allow(clippy::unused_async, reason = "uniform async route interface")]
pub async fn handler(
    state: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_types::Error> {
    state.check_worker_health();
    if state.release().is_none() || state.replay().is_full() {
        return Err(enclave_types::Error::NotReady);
    }
    Ok(())
}
