use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::HealthRequest;

use crate::state::EnclaveState;

/// Reports broker availability, not proof that lazy model initialization has completed.
#[allow(clippy::unused_async, reason = "uniform async route interface")]
pub async fn handler(
    state: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_types::Error> {
    state.face_engine().check_health();
    Ok(())
}
