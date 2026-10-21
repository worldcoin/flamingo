//! WIP-201 §3.8 replay rejection: one request per (`aud`, `nonce`) under this boot's channel key.
//!
//! The set lives as long as the channel key and is never evicted, since evicting would let a
//! request run twice. Reservations refused before inference may be released. It is bounded so an untrusted host cannot exhaust memory; once full, the
//! enclave refuses every request and reports not ready until it reboots with a new channel key.

use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use flamingo_verifier_sealed_types::FailureReason;
use world_id_primitives::FieldElement;

/// Requests one boot answers, about 20 MiB of state.
pub const MAX_PROCESSED_REQUESTS: usize = 262_144;

/// Processed (`aud`, `nonce`) pairs of this boot.
pub struct ReplayGuard {
    processed: Mutex<HashSet<(FieldElement, FieldElement)>>,
    limit: usize,
    full: AtomicBool,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_limit(MAX_PROCESSED_REQUESTS)
    }
}

impl ReplayGuard {
    fn with_limit(limit: usize) -> Self {
        Self {
            processed: Mutex::new(HashSet::new()),
            limit,
            full: AtomicBool::new(false),
        }
    }

    /// Records the pair, or rejects it if this boot already processed it.
    ///
    /// # Errors
    /// [`FailureReason::Replayed`] for a processed pair, [`FailureReason::Internal`] once full.
    pub fn reserve(&self, aud: FieldElement, nonce: FieldElement) -> Result<(), FailureReason> {
        let mut processed = self
            .processed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if processed.contains(&(aud, nonce)) {
            return Err(FailureReason::Replayed);
        }
        if processed.len() >= self.limit {
            if !self.full.swap(true, Ordering::Relaxed) {
                tracing::error!(
                    limit = self.limit,
                    "replay set full; refusing requests until the enclave reboots"
                );
            }
            return Err(FailureReason::Internal);
        }
        processed.insert((aud, nonce));
        if processed.len() >= self.limit && !self.full.swap(true, Ordering::Relaxed) {
            tracing::error!(
                limit = self.limit,
                "replay set full; refusing requests until the enclave reboots"
            );
        }
        drop(processed);
        Ok(())
    }

    /// Releases only the reservation owned by the request that acquired this pair,
    /// and only when the Engine refused to start inference.
    pub(crate) fn release(&self, aud: FieldElement, nonce: FieldElement) {
        let mut processed = self
            .processed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        processed.remove(&(aud, nonce));
        self.full
            .store(processed.len() >= self.limit, Ordering::Relaxed);
    }

    /// Whether the set has no capacity; only an unstarted request can release a slot.
    pub fn is_full(&self) -> bool {
        self.full.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releasing_an_unstarted_request_restores_capacity() {
        let guard = ReplayGuard::with_limit(1);
        let aud = FieldElement::from(1u64);
        let nonce = FieldElement::from(2u64);
        guard.reserve(aud, nonce).unwrap();
        assert!(guard.is_full());
        guard.release(aud, nonce);
        assert!(!guard.is_full());
        assert_eq!(guard.reserve(aud, nonce), Ok(()));
    }

    #[test]
    fn rejects_a_processed_pair_and_fails_closed_once_full() {
        let guard = ReplayGuard::with_limit(2);
        let pair = |aud: u64, nonce: u64| (aud.into(), nonce.into());
        let (aud, nonce) = pair(1, 1);
        assert_eq!(guard.reserve(aud, nonce), Ok(()));
        assert!(!guard.is_full());
        assert_eq!(guard.reserve(aud, nonce), Err(FailureReason::Replayed));
        let (other_aud, _) = pair(2, 1);
        assert_eq!(guard.reserve(other_aud, nonce), Ok(()));
        assert!(guard.is_full());

        let (aud, nonce) = pair(3, 3);
        assert_eq!(guard.reserve(aud, nonce), Err(FailureReason::Internal));
        assert!(guard.is_full());
        // A full set still never forgets a processed pair.
        assert_eq!(
            guard.reserve(1u64.into(), 1u64.into()),
            Err(FailureReason::Replayed)
        );
    }
}
