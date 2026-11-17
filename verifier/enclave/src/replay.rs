//! WIP-201 §4.4.4 replay rejection: one request per (`aud`, `nonce`) under this boot's channel key.
//!
//! A pair is kept until its request's `expires_at` has passed by the Verifier's time, which never
//! moves backward, so expiry rejects the request once its pair is dropped. Reservations refused
//! before inference may be released. The set is bounded so an untrusted host cannot exhaust
//! memory; while full, the enclave refuses new pairs and reports not ready until entries expire.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use flamingo_verifier_sealed_types::FailureReason;
use world_id_primitives::FieldElement;

/// Unexpired requests one boot holds, a few tens of MiB of state.
pub const MAX_PROCESSED_REQUESTS: usize = 262_144;

type Pair = (FieldElement, FieldElement);

/// The unexpired (`aud`, `nonce`) pairs of this boot.
pub struct ReplayGuard {
    pairs: Mutex<Pairs>,
    limit: usize,
    full: AtomicBool,
}

/// Each pair's `expires_at`, and the pairs by `expires_at` for eviction.
#[derive(Default)]
struct Pairs {
    expiries: HashMap<Pair, u64>,
    by_expiry: BTreeMap<u64, Vec<Pair>>,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_limit(MAX_PROCESSED_REQUESTS)
    }
}

impl ReplayGuard {
    fn with_limit(limit: usize) -> Self {
        Self {
            pairs: Mutex::default(),
            limit,
            full: AtomicBool::new(false),
        }
    }

    /// Records the pair until `expires_at`, or rejects it if this boot holds it, after dropping the
    /// pairs expired at the Verifier's time `now`.
    ///
    /// # Errors
    /// [`FailureReason::Replayed`] for a held pair, [`FailureReason::Internal`] while full.
    pub fn reserve(
        &self,
        aud: FieldElement,
        nonce: FieldElement,
        expires_at: u64,
        now: u64,
    ) -> Result<(), FailureReason> {
        let mut pairs = self.lock();
        pairs.evict(now);
        if pairs.expiries.contains_key(&(aud, nonce)) {
            return Err(FailureReason::Replayed);
        }
        if pairs.expiries.len() >= self.limit {
            self.update_full(&pairs);
            return Err(FailureReason::Internal);
        }
        pairs.expiries.insert((aud, nonce), expires_at);
        pairs
            .by_expiry
            .entry(expires_at)
            .or_default()
            .push((aud, nonce));
        self.update_full(&pairs);
        drop(pairs);
        Ok(())
    }

    /// Releases only the reservation owned by the request that acquired this pair,
    /// and only when the Engine refused to start inference.
    pub(crate) fn release(&self, aud: FieldElement, nonce: FieldElement) {
        let mut pairs = self.lock();
        if let Some(expires_at) = pairs.expiries.remove(&(aud, nonce))
            && let Some(bucket) = pairs.by_expiry.get_mut(&expires_at)
        {
            bucket.retain(|pair| *pair != (aud, nonce));
            if bucket.is_empty() {
                pairs.by_expiry.remove(&expires_at);
            }
        }
        self.update_full(&pairs);
        drop(pairs);
    }

    /// Whether the set has no capacity at the Verifier's time `now`, after dropping expired pairs.
    pub fn is_full(&self, now: u64) -> bool {
        let mut pairs = self.lock();
        pairs.evict(now);
        self.update_full(&pairs);
        drop(pairs);
        self.full.load(Ordering::Relaxed)
    }

    fn update_full(&self, pairs: &Pairs) {
        let full = pairs.expiries.len() >= self.limit;
        if full && !self.full.swap(true, Ordering::Relaxed) {
            tracing::error!(
                limit = self.limit,
                "replay set full; refusing requests until entries expire"
            );
        } else if !full {
            self.full.store(false, Ordering::Relaxed);
        }
    }

    fn lock(&self) -> MutexGuard<'_, Pairs> {
        self.pairs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Pairs {
    /// Drops every pair whose `expires_at` is before `now`; expiry rejects its request from then on.
    fn evict(&mut self, now: u64) {
        let live = self.by_expiry.split_off(&now);
        for pair in std::mem::replace(&mut self.by_expiry, live)
            .into_values()
            .flatten()
        {
            self.expiries.remove(&pair);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    fn pair(aud: u64, nonce: u64) -> Pair {
        (aud.into(), nonce.into())
    }

    #[test]
    fn releasing_an_unstarted_request_restores_capacity() {
        let guard = ReplayGuard::with_limit(1);
        let (aud, nonce) = pair(1, 2);
        guard.reserve(aud, nonce, NOW + 60, NOW).unwrap();
        assert!(guard.is_full(NOW));
        guard.release(aud, nonce);
        assert!(!guard.is_full(NOW));
        assert_eq!(guard.reserve(aud, nonce, NOW + 60, NOW), Ok(()));
    }

    #[test]
    fn rejects_a_held_pair_and_fails_closed_while_full() {
        let guard = ReplayGuard::with_limit(2);
        let (aud, nonce) = pair(1, 1);
        assert_eq!(guard.reserve(aud, nonce, NOW + 60, NOW), Ok(()));
        assert!(!guard.is_full(NOW));
        assert_eq!(
            guard.reserve(aud, nonce, NOW + 60, NOW),
            Err(FailureReason::Replayed)
        );
        let (other_aud, _) = pair(2, 1);
        assert_eq!(guard.reserve(other_aud, nonce, NOW + 60, NOW), Ok(()));
        assert!(guard.is_full(NOW));

        let (aud, nonce) = pair(3, 3);
        assert_eq!(
            guard.reserve(aud, nonce, NOW + 60, NOW),
            Err(FailureReason::Internal)
        );
        assert!(guard.is_full(NOW));
        // A full set still never forgets an unexpired pair.
        assert_eq!(
            guard.reserve(1u64.into(), 1u64.into(), NOW + 60, NOW),
            Err(FailureReason::Replayed)
        );
    }

    #[test]
    fn keeps_a_pair_through_its_expiry_and_drops_it_after() {
        let guard = ReplayGuard::with_limit(1);
        let (aud, nonce) = pair(1, 1);
        guard.reserve(aud, nonce, NOW, NOW - 60).unwrap();
        // The request is still accepted at `expires_at`, so its pair must still be held.
        assert_eq!(
            guard.reserve(aud, nonce, NOW, NOW),
            Err(FailureReason::Replayed)
        );
        assert!(guard.is_full(NOW));
        assert!(!guard.is_full(NOW + 1));
        assert_eq!(guard.reserve(aud, nonce, NOW + 61, NOW + 1), Ok(()));
    }

    #[test]
    fn evicts_only_the_expired_pairs() {
        let guard = ReplayGuard::with_limit(3);
        guard
            .reserve(1u64.into(), 1u64.into(), NOW + 10, NOW)
            .unwrap();
        guard
            .reserve(1u64.into(), 2u64.into(), NOW + 20, NOW)
            .unwrap();
        guard
            .reserve(1u64.into(), 3u64.into(), NOW + 10, NOW)
            .unwrap();
        assert!(guard.is_full(NOW + 10));
        assert!(!guard.is_full(NOW + 11));
        assert_eq!(
            guard.reserve(1u64.into(), 2u64.into(), NOW + 20, NOW + 11),
            Err(FailureReason::Replayed)
        );
        assert_eq!(
            guard.reserve(1u64.into(), 1u64.into(), NOW + 30, NOW + 11),
            Ok(())
        );
    }
}
