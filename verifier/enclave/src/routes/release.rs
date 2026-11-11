use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::LoadReleaseRequest;

use crate::state::EnclaveState;

/// Loads the release manifest of this boot's Engine bundle. Loading attests the channel key, a
/// blocking NSM call, so it runs off the async workers.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: LoadReleaseRequest,
) -> Result<(), enclave_types::Error> {
    crate::blocking(move || state.load_release(&request.manifest)).await?
}
