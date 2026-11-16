//! WIP-201 §3.8 replay rejection: one request per (`aud`, `nonce`) under this boot's channel key.
//!
//! The set lives as long as the channel key and is never evicted, since evicting would let a
//! request run twice. Reservations refused before inference may be released. A pending request,
//! whose registration had not arrived before inference, holds its pair in flight instead, and one
//! rejected as unregistered is counted instead of recorded, so it can be resent up to
//! [`MAX_BILLING_ATTEMPTS`] times (WIP-201 §4.4.4). It is bounded so an untrusted host cannot
//! exhaust memory; once full, the enclave refuses every request and reports not ready until it
//! reboots with a new channel key.

use std::{
    collections::HashMap,
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

type Pairs = HashMap<(FieldElement, FieldElement), Pair>;

/// The (`aud`, `nonce`) pairs of this boot.
pub struct ReplayGuard {
    pairs: Mutex<Pairs>,
    limit: usize,
    full: AtomicBool,
}

/// A pair's state, with the attempts rejected as unregistered so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pair {
    Processed,
    Unregistered(u8),
    /// A pending request runs with this pair; no copy of it runs meanwhile.
    InFlight(u8),
}

/// How a pending request that held its pair in flight ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOutcome {
    /// Any outcome but the two below: the pair is processed.
    Done,
    /// Rejected as unregistered: counted, and processed at the [`MAX_BILLING_ATTEMPTS`]-th.
    Unregistered,
    /// The Engine never started: the attempt does not count.
    Unstarted,
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

    /// Records the pair, or rejects it if this boot already processed it or runs it.
    ///
    /// # Errors
    /// [`FailureReason::Replayed`] for a processed or in-flight pair, [`FailureReason::Internal`]
    /// once full.
    pub fn reserve(&self, aud: FieldElement, nonce: FieldElement) -> Result<(), FailureReason> {
        self.admit(aud, nonce, |_| Pair::Processed)
    }

    /// Holds the pair of a pending request in flight until [`Self::finish_pending`], rejecting it
    /// as [`Self::reserve`] would.
    ///
    /// # Errors
    /// As [`Self::reserve`].
    pub fn begin_pending(
        &self,
        aud: FieldElement,
        nonce: FieldElement,
    ) -> Result<(), FailureReason> {
        self.admit(aud, nonce, |previous| match previous {
            Some(Pair::Unregistered(attempts)) => Pair::InFlight(attempts),
            _ => Pair::InFlight(0),
        })
    }

    /// Ends the pending request [`Self::begin_pending`] admitted with this pair.
    pub fn finish_pending(&self, aud: FieldElement, nonce: FieldElement, outcome: PendingOutcome) {
        let mut pairs = self.lock();
        let Some(pair) = pairs.get_mut(&(aud, nonce)) else {
            return;
        };
        let Pair::InFlight(attempts) = *pair else {
            return;
        };
        match outcome {
            PendingOutcome::Done => *pair = Pair::Processed,
            PendingOutcome::Unregistered if attempts.saturating_add(1) >= MAX_BILLING_ATTEMPTS => {
                *pair = Pair::Processed;
            }
            PendingOutcome::Unregistered => *pair = Pair::Unregistered(attempts + 1),
            PendingOutcome::Unstarted if attempts == 0 => {
                pairs.remove(&(aud, nonce));
            }
            PendingOutcome::Unstarted => *pair = Pair::Unregistered(attempts),
        }
        self.full
            .store(pairs.len() >= self.limit, Ordering::Relaxed);
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

    /// Sets the pair to `next` of its previous state in one critical section, unless it is
    /// processed or in flight.
    fn admit(
        &self,
        aud: FieldElement,
        nonce: FieldElement,
        next: impl FnOnce(Option<Pair>) -> Pair,
    ) -> Result<(), FailureReason> {
        let mut pairs = self.lock();
        let previous = pairs.get(&(aud, nonce)).copied();
        match previous {
            Some(Pair::Processed | Pair::InFlight(_)) => return Err(FailureReason::Replayed),
            None if pairs.len() >= self.limit => {
                self.update_full(&pairs);
                return Err(FailureReason::Internal);
            }
            Some(Pair::Unregistered(_)) | None => {}
        }
        pairs.insert((aud, nonce), next(previous));
        self.update_full(&pairs);
        drop(pairs);
        Ok(())
    }

    fn update_full(&self, pairs: &Pairs) {
        if pairs.len() >= self.limit && !self.full.swap(true, Ordering::Relaxed) {
            tracing::error!(
                limit = self.limit,
                "replay set full; refusing requests until the enclave reboots"
            );
        }
    }

    fn lock(&self) -> MutexGuard<'_, Pairs> {
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
        assert_eq!(
            guard.begin_pending(aud, nonce),
            Err(FailureReason::Internal)
        );
        assert!(guard.is_full());
        // A full set still never forgets a processed pair.
        assert_eq!(
            guard.reserve(1u64.into(), 1u64.into()),
            Err(FailureReason::Replayed)
        );
    }

    #[test]
    fn records_a_pending_pair_at_its_last_unregistered_attempt() {
        let guard = ReplayGuard::with_limit(4);
        let (aud, nonce) = (FieldElement::from(1u64), FieldElement::from(2u64));
        for _ in 1..MAX_BILLING_ATTEMPTS {
            assert_eq!(guard.begin_pending(aud, nonce), Ok(()));
            guard.finish_pending(aud, nonce, PendingOutcome::Unregistered);
        }
        assert_eq!(guard.begin_pending(aud, nonce), Ok(()));
        guard.finish_pending(aud, nonce, PendingOutcome::Unregistered);
        assert_eq!(
            guard.begin_pending(aud, nonce),
            Err(FailureReason::Replayed)
        );
    }

    #[test]
    fn admits_no_copy_of_an_in_flight_pair() {
        let guard = ReplayGuard::with_limit(4);
        let (aud, nonce) = (FieldElement::from(1u64), FieldElement::from(2u64));
        assert_eq!(guard.begin_pending(aud, nonce), Ok(()));
        assert_eq!(
            guard.begin_pending(aud, nonce),
            Err(FailureReason::Replayed)
        );
        assert_eq!(guard.reserve(aud, nonce), Err(FailureReason::Replayed));
        guard.finish_pending(aud, nonce, PendingOutcome::Done);
        assert_eq!(
            guard.begin_pending(aud, nonce),
            Err(FailureReason::Replayed)
        );
    }

    #[test]
    fn an_unstarted_pending_request_keeps_its_attempts() {
        let guard = ReplayGuard::with_limit(1);
        let (aud, nonce) = (FieldElement::from(1u64), FieldElement::from(2u64));
        guard.begin_pending(aud, nonce).unwrap();
        guard.finish_pending(aud, nonce, PendingOutcome::Unstarted);
        assert!(!guard.is_full());
        guard.begin_pending(aud, nonce).unwrap();
        guard.finish_pending(aud, nonce, PendingOutcome::Unregistered);
        guard.begin_pending(aud, nonce).unwrap();
        guard.finish_pending(aud, nonce, PendingOutcome::Unstarted);
        // The unregistered attempt still counts, and a registered resend can still sign once.
        assert_eq!(guard.reserve(aud, nonce), Ok(()));
        assert_eq!(guard.reserve(aud, nonce), Err(FailureReason::Replayed));
    }
}
