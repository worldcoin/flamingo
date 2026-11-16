//! WIP-201 §3.8 replay rejection: one request per (`aud`, `nonce`) under this boot's channel key.
//!
//! The set lives as long as the channel key and is never evicted, since evicting would let a
//! request run twice. Reservations refused before inference may be released, and a request rejected
//! as unregistered is counted instead of recorded, so it can be resent up to
//! [`MAX_BILLING_ATTEMPTS`] times (WIP-201 §4.4.4). It is bounded so an untrusted host cannot
//! exhaust memory; once full, the enclave refuses every request and reports not ready until it
//! reboots with a new channel key.

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use flamingo_verifier_sealed_types::FailureReason;
use world_id_primitives::FieldElement;

/// Requests one boot answers, about 20 MiB of state.
pub const MAX_PROCESSED_REQUESTS: usize = 262_144;

/// Attempts per (`aud`, `nonce`) rejected as unregistered before the pair is recorded (WIP-201
/// §4.2).
pub const MAX_BILLING_ATTEMPTS: u8 = 3;

/// The (`aud`, `nonce`) pairs of this boot: processed, or rejected as unregistered so far.
pub struct ReplayGuard {
    pairs: Mutex<HashMap<(FieldElement, FieldElement), Pair>>,
    limit: usize,
    full: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pair {
    Processed,
    Unregistered(u8),
}

impl Pair {
    const fn after_attempts(attempts: u8) -> Self {
        if attempts >= MAX_BILLING_ATTEMPTS {
            Self::Processed
        } else {
            Self::Unregistered(attempts)
        }
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_limit(MAX_PROCESSED_REQUESTS)
    }
}

impl ReplayGuard {
    fn with_limit(limit: usize) -> Self {
        Self {
            pairs: Mutex::new(HashMap::new()),
            limit,
            full: AtomicBool::new(false),
        }
    }

    /// Records the pair, or rejects it if this boot already processed it.
    ///
    /// # Errors
    /// [`FailureReason::Replayed`] for a processed pair, [`FailureReason::Internal`] once full.
    pub fn reserve(&self, aud: FieldElement, nonce: FieldElement) -> Result<(), FailureReason> {
        let mut pairs = self.lock();
        self.admit(&pairs, aud, nonce)?;
        pairs.insert((aud, nonce), Pair::Processed);
        self.update_full(&pairs);
        drop(pairs);
        Ok(())
    }

    /// Rejects the pair as [`Self::reserve`] would, without recording it.
    ///
    /// # Errors
    /// As [`Self::reserve`].
    pub fn check(&self, aud: FieldElement, nonce: FieldElement) -> Result<(), FailureReason> {
        self.admit(&self.lock(), aud, nonce)
    }

    /// Counts a rejection as unregistered, recording the pair at the [`MAX_BILLING_ATTEMPTS`]-th.
    pub fn reject_unregistered(&self, aud: FieldElement, nonce: FieldElement) {
        let mut pairs = self.lock();
        let at_limit = pairs.len() >= self.limit;
        match pairs.entry((aud, nonce)) {
            Entry::Occupied(mut entry) => {
                if let Pair::Unregistered(attempts) = *entry.get() {
                    entry.insert(Pair::after_attempts(attempts.saturating_add(1)));
                }
            }
            // A full set refuses every request, so the pair cannot run again.
            Entry::Vacant(_) if at_limit => {}
            Entry::Vacant(entry) => {
                entry.insert(Pair::after_attempts(1));
            }
        }
        self.update_full(&pairs);
        drop(pairs);
    }

    /// Releases only the reservation owned by the request that acquired this pair,
    /// and only when the Engine refused to start inference.
    pub(crate) fn release(&self, aud: FieldElement, nonce: FieldElement) {
        let mut pairs = self.lock();
        pairs.remove(&(aud, nonce));
        self.full
            .store(pairs.len() >= self.limit, Ordering::Relaxed);
    }

    /// Whether the set has no capacity; only an unstarted request can release a slot.
    pub fn is_full(&self) -> bool {
        self.full.load(Ordering::Relaxed)
    }

    fn admit(
        &self,
        pairs: &HashMap<(FieldElement, FieldElement), Pair>,
        aud: FieldElement,
        nonce: FieldElement,
    ) -> Result<(), FailureReason> {
        match pairs.get(&(aud, nonce)) {
            Some(Pair::Processed) => Err(FailureReason::Replayed),
            None if pairs.len() >= self.limit => {
                self.update_full(pairs);
                Err(FailureReason::Internal)
            }
            Some(Pair::Unregistered(_)) | None => Ok(()),
        }
    }

    fn update_full(&self, pairs: &HashMap<(FieldElement, FieldElement), Pair>) {
        if pairs.len() >= self.limit && !self.full.swap(true, Ordering::Relaxed) {
            tracing::error!(
                limit = self.limit,
                "replay set full; refusing requests until the enclave reboots"
            );
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(FieldElement, FieldElement), Pair>> {
        self.pairs.lock().unwrap_or_else(PoisonError::into_inner)
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
        assert_eq!(guard.check(aud, nonce), Err(FailureReason::Internal));
        assert!(guard.is_full());
        // A full set still never forgets a processed pair.
        assert_eq!(
            guard.reserve(1u64.into(), 1u64.into()),
            Err(FailureReason::Replayed)
        );
    }

    #[test]
    fn records_a_pair_at_its_last_unregistered_attempt() {
        let guard = ReplayGuard::with_limit(4);
        let (aud, nonce) = (FieldElement::from(1u64), FieldElement::from(2u64));
        for _ in 1..MAX_BILLING_ATTEMPTS {
            guard.reject_unregistered(aud, nonce);
            assert_eq!(guard.check(aud, nonce), Ok(()));
        }
        guard.reject_unregistered(aud, nonce);
        assert_eq!(guard.check(aud, nonce), Err(FailureReason::Replayed));
    }

    #[test]
    fn an_unregistered_pair_can_still_be_reserved_once() {
        let guard = ReplayGuard::with_limit(4);
        let (aud, nonce) = (FieldElement::from(1u64), FieldElement::from(2u64));
        guard.reject_unregistered(aud, nonce);
        assert_eq!(guard.reserve(aud, nonce), Ok(()));
        assert_eq!(guard.reserve(aud, nonce), Err(FailureReason::Replayed));
        // Counting a processed pair leaves it processed.
        guard.reject_unregistered(aud, nonce);
        assert_eq!(guard.check(aud, nonce), Err(FailureReason::Replayed));
    }
}
