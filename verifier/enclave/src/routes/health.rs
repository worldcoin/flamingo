use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::HealthRequest;

use crate::state::EnclaveState;

/// Reports broker availability and liveness of the initialized worker, and whether the enclave
/// can run a request: it needs a loaded release manifest, room in its replay set, an Engine
/// that has not overrun a response slot and, if it bills, a caught-up billing state that is not
/// full (WIP-107 §4.8).
#[allow(clippy::unused_async, reason = "uniform async route interface")]
pub async fn handler(
    state: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_types::Error> {
    state.check_worker_health();
    if state.release().is_none()
        || state.replay().is_full()
        || state.engine_overran()
        || !state.billing().is_ready()
    {
        return Err(enclave_types::Error::NotReady);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use flamingo_verifier_enclave_types::{
        self as enclave_types, BillingUpdateRequest, HealthRequest,
    };

    use super::handler;
    use crate::{
        billing::BillingTarget,
        test_support::{UnusedBiometricEngine, loaded_billing_state, loaded_state},
    };

    const TARGET: BillingTarget = BillingTarget {
        chain_id: 480,
        contract: [0x11; 20],
        max_registrations: 1,
    };

    fn update(backfill_done: bool) -> BillingUpdateRequest {
        BillingUpdateRequest {
            chain_id: TARGET.chain_id,
            contract: TARGET.contract,
            seq: 0,
            ops: Vec::new(),
            backfill_done,
        }
    }

    #[tokio::test]
    async fn a_billing_enclave_is_ready_once_its_state_has_caught_up() {
        let state = loaded_billing_state(TARGET);
        assert_eq!(
            handler(Arc::clone(&state), HealthRequest).await,
            Err(enclave_types::Error::NotReady)
        );
        state.billing().apply(&update(false), state.now()).unwrap();
        assert_eq!(
            handler(Arc::clone(&state), HealthRequest).await,
            Err(enclave_types::Error::NotReady)
        );
        state.billing().apply(&update(true), state.now()).unwrap();
        assert_eq!(handler(state, HealthRequest).await, Ok(()));
    }

    #[tokio::test]
    async fn an_enclave_without_billing_needs_no_billing_state() {
        assert_eq!(
            handler(loaded_state(UnusedBiometricEngine), HealthRequest).await,
            Ok(())
        );
    }
}
