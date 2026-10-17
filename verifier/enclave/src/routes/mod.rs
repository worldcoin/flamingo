//! Pontifex operation routing.

use std::sync::Arc;

use flamingo_verifier_enclave_types::{
    GetEncryptionKeyRequest, HealthRequest, LoadReleaseRequest, MatchRequest,
};
use pontifex::Router;

mod encryption_key;
mod health;
mod matches;
mod release;

use crate::state::EnclaveState;

/// Builds the router with all enclave operations.
pub(crate) fn router(state: Arc<EnclaveState>) -> Router<Arc<EnclaveState>> {
    Router::with_state(state)
        .route::<HealthRequest, _, _>(health::handler)
        .route::<GetEncryptionKeyRequest, _, _>(encryption_key::handler)
        .route::<MatchRequest, _, _>(matches::handler)
        .route::<LoadReleaseRequest, _, _>(release::handler)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::router;
    use crate::test_support::{EchoAttestor, state_with};

    #[test]
    fn router_registers_enclave_operations() {
        let _router = router(state_with(Arc::new(EchoAttestor)));
    }
}
