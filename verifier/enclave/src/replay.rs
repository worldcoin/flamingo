//! WIP-201 §4.4.4 expiry and replay rejection: one request per (`aud`, `nonce`) under this boot's
//! channel key.
//!
//! [`ReplayGuard::admit`] checks a request's expiry and records its pair under one lock, at a
//! Verifier time it reads under that lock. [`ReplayGuard::sweep`] drops pairs whose `expires_at`
//! has passed, under the same lock. The Verifier's time never moves backward, so a dropped pair's
//! request is rejected as expired from then on. The set is bounded so an untrusted host cannot
//! exhaust memory; while full, the enclave refuses every request and reports not ready.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use flamingo_verifier_sealed_types::{FailureReason, Request};
use world_id_primitives::FieldElement;

/// Unexpired requests one boot holds.
pub const MAX_PROCESSED_REQUESTS: usize = 262_144;

type Pair = (FieldElement, FieldElement);

/// The unexpired (`aud`, `nonce`) pairs of this boot.
pub struct ReplayGuard {
    pairs: Mutex<Pairs>,
    limit: usize,
    full: AtomicBool,
}

/// Each pair's `expires_at`, and the pairs by `expires_at` for the sweep.
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

    /// Rejects an expired or replayed request and records its pair until `expires_at`, returning
    /// the Verifier time it checked the expiry at.
    ///
    /// `now` reads the Verifier's time; it runs under the lock the sweep takes, so no pair this
    /// accepts can have been swept already.
    ///
    /// # Errors
    /// [`FailureReason::Expired`] for an expired request, [`FailureReason::Replayed`] for a held
    /// pair, [`FailureReason::Internal`] while full.
    pub fn admit(
        &self,
        request: &Request,
        now: impl FnOnce() -> u64,
    ) -> Result<u64, FailureReason> {
        let pair = (request.aud, request.nonce);
        let mut pairs = self.lock();
        let now = now();
        request.check_expiry(now)?;
        if pairs.expiries.contains_key(&pair) {
            return Err(FailureReason::Replayed);
        }
        if pairs.expiries.len() >= self.limit {
            self.update_full(&pairs);
            return Err(FailureReason::Internal);
        }
        pairs.expiries.insert(pair, request.expires_at);
        pairs
            .by_expiry
            .entry(request.expires_at)
            .or_default()
            .push(pair);
        self.update_full(&pairs);
        drop(pairs);
        Ok(now)
    }

    /// Releases only the pair admitted for a request whose Engine call never started.
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

    /// Drops every pair whose `expires_at` is before the Verifier's time `now`.
    pub fn sweep(&self, now: u64) {
        let mut pairs = self.lock();
        let live = pairs.by_expiry.split_off(&now);
        for pair in std::mem::replace(&mut pairs.by_expiry, live)
            .into_values()
            .flatten()
        {
            pairs.expiries.remove(&pair);
        }
        self.update_full(&pairs);
        drop(pairs);
    }

    /// Whether the set has no capacity until the next sweep.
    pub fn is_full(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use flamingo_verifier_sealed_types::{Entry, Payload};

    use super::*;

    const NOW: u64 = 1_000;

    fn request(aud: u64, nonce: u64, expires_at: u64) -> Request {
        let payload = Payload {
            pipeline_id: 1,
            match_strictness: 2,
            hints: Vec::new(),
            entries: [b"orb".as_slice(), b"live", b"challenge"]
                .map(|data| Entry {
                    data: data.to_vec(),
                    meta: Vec::new(),
                })
                .into(),
            pipeline_inputs: vec![1],
            compare: vec![0, 1, 2],
        };
        Request::new(
            aud.into(),
            nonce.into(),
            expires_at,
            FieldElement::ZERO,
            &payload,
            None,
        )
        .unwrap()
    }

    #[test]
    fn releasing_an_unstarted_request_restores_capacity() {
        let guard = ReplayGuard::with_limit(1);
        let request = request(1, 2, NOW + 60);
        guard.admit(&request, || NOW).unwrap();
        assert!(guard.is_full());
        guard.release(request.aud, request.nonce);
        assert!(!guard.is_full());
        assert_eq!(guard.admit(&request, || NOW), Ok(NOW));
    }

    #[test]
    fn rejects_a_held_pair_and_fails_closed_while_full() {
        let guard = ReplayGuard::with_limit(2);
        let first = request(1, 1, NOW + 60);
        assert_eq!(guard.admit(&first, || NOW), Ok(NOW));
        assert!(!guard.is_full());
        assert_eq!(guard.admit(&first, || NOW), Err(FailureReason::Replayed));
        assert_eq!(guard.admit(&request(2, 1, NOW + 60), || NOW), Ok(NOW));
        assert!(guard.is_full());
        assert_eq!(
            guard.admit(&request(3, 3, NOW + 60), || NOW),
            Err(FailureReason::Internal)
        );
        // A full set still never forgets an unexpired pair.
        assert_eq!(guard.admit(&first, || NOW), Err(FailureReason::Replayed));
    }

    #[test]
    fn rejects_an_expired_request_before_looking_it_up() {
        let guard = ReplayGuard::with_limit(1);
        assert_eq!(
            guard.admit(&request(1, 1, NOW), || NOW + 1),
            Err(FailureReason::Expired)
        );
        assert!(!guard.is_full(), "an expired request records nothing");
    }

    #[test]
    fn a_swept_pair_stays_rejected_as_expired() {
        let guard = ReplayGuard::with_limit(1);
        let request = request(1, 1, NOW);
        guard.admit(&request, || NOW - 60).unwrap();
        // Still accepted at `expires_at`, so the sweep keeps its pair.
        guard.sweep(NOW);
        assert_eq!(guard.admit(&request, || NOW), Err(FailureReason::Replayed));
        guard.sweep(NOW + 1);
        assert!(!guard.is_full());
        // The copy reads the time under the lock, after the sweep, so it cannot slip back in.
        assert_eq!(
            guard.admit(&request, || NOW + 1),
            Err(FailureReason::Expired)
        );
    }

    #[test]
    fn sweeps_only_the_expired_pairs() {
        let guard = ReplayGuard::with_limit(3);
        let late = request(1, 2, NOW + 20);
        guard.admit(&request(1, 1, NOW + 10), || NOW).unwrap();
        guard.admit(&late, || NOW).unwrap();
        guard.admit(&request(1, 3, NOW + 10), || NOW).unwrap();
        assert!(guard.is_full());
        guard.sweep(NOW + 11);
        assert!(!guard.is_full());
        assert_eq!(
            guard.admit(&late, || NOW + 11),
            Err(FailureReason::Replayed)
        );
        assert_eq!(
            guard.admit(&request(1, 1, NOW + 30), || NOW + 11),
            Ok(NOW + 11)
        );
    }
}
