//! Replay reservations live as long as the boot's channel key and are never evicted.

use std::{collections::HashSet, sync::Mutex};

use flamingo_verifier_sealed_types::FailureReason;

type RequestId = ([u8; 32], [u8; 32]);

/// Bound replay state independently of the number of requests an untrusted host sends.
const MAX_PROCESSED_REQUESTS: usize = 65_536;

#[derive(Default)]
pub struct ReplayGuard {
    processed: Mutex<HashSet<RequestId>>,
}

impl ReplayGuard {
    pub(crate) fn reserve(&self, aud: [u8; 32], nonce: [u8; 32]) -> Result<(), FailureReason> {
        self.reserve_with_limit((aud, nonce), MAX_PROCESSED_REQUESTS)
    }

    fn reserve_with_limit(&self, id: RequestId, limit: usize) -> Result<(), FailureReason> {
        let mut processed = self.processed.lock().map_err(|_| FailureReason::Internal)?;
        if processed.contains(&id) {
            return Err(FailureReason::MalformedInputs);
        }
        // A full set fails closed until the enclave reboots with a new channel key.
        if processed.len() >= limit {
            return Err(FailureReason::Internal);
        }
        processed.insert(id);
        drop(processed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_guard_never_evicts_a_processed_request() {
        let guard = ReplayGuard::default();
        let first = ([1; 32], [2; 32]);
        assert_eq!(guard.reserve_with_limit(first, 1), Ok(()));
        assert_eq!(
            guard.reserve_with_limit(([1; 32], [3; 32]), 1),
            Err(FailureReason::Internal)
        );
        assert_eq!(
            guard.reserve_with_limit(first, 1),
            Err(FailureReason::MalformedInputs)
        );
    }
}
