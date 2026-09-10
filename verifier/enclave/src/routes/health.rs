use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::HealthRequest;

use crate::state::EnclaveState;

/// Reports broker availability, not proof that lazy model initialization has completed.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_types::Error> {
    state.face_engine().check_health();
    if state.attestations_are_fresh().await {
        Ok(())
    } else {
        Err(enclave_types::Error::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use flamingo_verifier_enclave_types::HealthRequest;
    use flamingo_verifier_sealed_types::FailureReason;

    use super::handler;
    use crate::{
        face_engine::{ComparisonScores, FaceComparator},
        state::EnclaveState,
        test_support::EchoAttestor,
    };

    /// Records health probes independently of comparison admission.
    struct ProbedComparator {
        /// Number of delegated health checks.
        probes: AtomicUsize,
    }

    impl FaceComparator for ProbedComparator {
        /// A health probe must never send a comparison or load a model.
        fn compare_reference_to_probes(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<ComparisonScores, FailureReason> {
            panic!("health must not compare images")
        }

        /// Records that the process probe was reached.
        fn check_health(&self) {
            self.probes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Saturation rejects extra matches without flapping readiness or bypassing liveness checks.
    #[tokio::test]
    async fn health_probes_worker_while_match_slot_is_busy() {
        let comparator = Arc::new(ProbedComparator {
            probes: AtomicUsize::new(0),
        });
        let state =
            Arc::new(EnclaveState::generate(Arc::new(EchoAttestor), comparator.clone()).unwrap());
        let _permit = state.match_slot.try_acquire().unwrap();

        assert_eq!(handler(Arc::clone(&state), HealthRequest).await, Ok(()));
        assert_eq!(comparator.probes.load(Ordering::Relaxed), 1);
    }

    /// A stuck refresh cannot make expired attestation documents look ready.
    #[tokio::test(start_paused = true)]
    async fn expired_attestations_are_not_ready() {
        let state = crate::test_support::state_with(Arc::new(EchoAttestor));
        assert_eq!(handler(Arc::clone(&state), HealthRequest).await, Ok(()));

        tokio::time::advance(crate::attestation::MAX_SERVABLE_AGE).await;
        assert_eq!(
            handler(state, HealthRequest).await,
            Err(flamingo_verifier_enclave_types::Error::NotReady)
        );
    }
}
