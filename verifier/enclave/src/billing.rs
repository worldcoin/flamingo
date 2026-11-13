//! The WIP-107 billing state the host supplies (WIP-107 §4.8).
//!
//! The host follows the Billing Contract and pushes its state as a numbered update stream. A new
//! stream replaces the state, which serves requests once an update of it carries `backfill_done`.
//! A rejected update ends its stream and stops serving until a new stream catches up, so a host
//! that keeps pushing updates the enclave cannot apply never leaves a stale state in service.
//!
//! Registrations are kept as 64-bit SipHash-2-4 digests of the nullifier and RP, under a key
//! drawn at boot from the hardware-seeded RNG. Nobody outside the enclave knows the key or sees a
//! digest, so collisions cannot be searched for; a blind one has a chance of about `n / 2^64`.

use std::{
    collections::{BTreeMap, HashSet},
    env,
    hash::{BuildHasherDefault, Hasher},
    sync::{Mutex, PoisonError},
};

use flamingo_verifier_billing_state::{BillingOp, BillingStateError, Registration};
use flamingo_verifier_enclave_types::{
    self as enclave_types, BillingStatus, BillingUpdateRequest, MAX_BILLING_OPS,
};
use rand::{RngCore as _, rngs::OsRng};
use siphasher::sip::SipHasher24;
use world_id_primitives::{FieldElement, billing::billing_period, rp::RpId};

/// Bound on the registrations the enclave holds, from the EIF's environment, so it is measured.
/// Billing is on with this bound if it is set, and off otherwise. Reaching the bound fails closed.
const MAX_REGISTRATIONS_VAR: &str = "FLAMINGO_BILLING_MAX_REGISTRATIONS";

/// The enclave's copy of the billing state.
pub struct BillingStore {
    config: Option<BillingConfig>,
    inner: Mutex<Inner>,
}

struct Inner {
    state: State,
    /// The last applied `seq`, or `None` before the first stream and after a rejection.
    last_seq: Option<u64>,
    /// Whether an update of the current stream carried `backfill_done`, and none was rejected
    /// since.
    caught_up: bool,
    next_expiry: u64,
}

impl BillingStore {
    /// A store billing with `config`, or a store that bills nothing if `config` is `None`.
    #[must_use]
    pub fn new(config: Option<BillingConfig>) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner {
                state: State::new(
                    config.map_or(0, |config| config.max_registrations),
                    boot_key(),
                ),
                last_seq: None,
                caught_up: false,
                next_expiry: 0,
            }),
        }
    }

    /// Whether requests can be served: billing is off, or the state has caught up and no update
    /// was rejected since.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.config.is_none() || self.lock().caught_up
    }

    /// Applies one update at the Verifier's time `now`, in Unix seconds.
    ///
    /// # Errors
    /// [`enclave_types::Error::BillingRejected`] for too many ops, an op the state rejects or a
    /// store that bills nothing, and [`enclave_types::Error::BillingOutOfOrder`]
    /// for a `seq` that neither follows nor repeats the last one. Neither changes the state. A
    /// rejection ends the stream and stops serving until a new stream catches up.
    pub fn apply(
        &self,
        update: &BillingUpdateRequest,
        now: u64,
    ) -> Result<BillingStatus, enclave_types::Error> {
        let Some(config) = self.config else {
            tracing::warn!("billing update for an enclave that does not bill");
            return Err(enclave_types::Error::BillingRejected);
        };
        let mut inner = self.lock();
        let result = inner.apply(config, update, now);
        if result == Err(enclave_types::Error::BillingRejected) {
            // The rejected update's changes are missing, so its stream cannot go on.
            inner.last_seq = None;
            inner.caught_up = false;
        }
        let status = result.map(|()| status(&inner, config.max_registrations));
        drop(inner);
        status
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Inner {
    fn apply(
        &mut self,
        config: BillingConfig,
        update: &BillingUpdateRequest,
        now: u64,
    ) -> Result<(), enclave_types::Error> {
        if update.ops.len() > MAX_BILLING_OPS {
            return Err(enclave_types::Error::BillingRejected);
        }
        // Ended periods go first, so they never count against the bound at a rollover.
        if now >= self.next_expiry {
            self.state.expire(now);
            self.next_expiry = billing_period(now).map_or(u64::MAX, |(_, end)| end);
        }
        if update.seq == 0 {
            let mut state = State::new(config.max_registrations, self.state.digest_key);
            apply_all(&mut state, &update.ops, now).map_err(rejected)?;
            self.state = state;
            self.caught_up = false;
        } else if self.last_seq == Some(update.seq) {
            // A retry of an update whose answer the host lost.
            return Ok(());
        } else if self.last_seq.map(|seq| seq + 1) == Some(update.seq) {
            apply_all(&mut self.state, &update.ops, now).map_err(rejected)?;
        } else {
            return Err(enclave_types::Error::BillingOutOfOrder);
        }
        self.last_seq = Some(update.seq);
        self.caught_up |= update.backfill_done;
        Ok(())
    }
}

/// A `SipHash` key drawn from the kernel RNG, which boot checks is the Nitro hardware RNG.
fn boot_key() -> (u64, u64) {
    (OsRng.next_u64(), OsRng.next_u64())
}

/// Applies `ops` in order at `now`, or none of them.
fn apply_all(state: &mut State, ops: &[BillingOp], now: u64) -> Result<(), BillingStateError> {
    let mut inverses = Vec::with_capacity(ops.len());
    for op in ops {
        match state.apply(*op, now) {
            Ok(inverse) => inverses.extend(inverse),
            Err(error) => {
                for inverse in inverses.into_iter().rev() {
                    // An inverse undoes an op just applied, so it cannot fail.
                    let _ = state.apply(inverse, now);
                }
                return Err(error);
            }
        }
    }
    Ok(())
}

fn rejected(error: BillingStateError) -> enclave_types::Error {
    tracing::error!(%error, "billing update rejected");
    enclave_types::Error::BillingRejected
}

fn status(inner: &Inner, max_registrations: usize) -> BillingStatus {
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    BillingStatus {
        registrations: count(inner.state.registrations),
        max_registrations: count(max_registrations),
        ready: inner.caught_up,
    }
}

/// The billed RPs and the registrations, as the enclave keeps them.
struct State {
    billed_rps: HashSet<RpId>,
    /// Registration digests by period, so expiry drops whole periods.
    periods: BTreeMap<u64, Digests>,
    registrations: usize,
    max_registrations: usize,
    digest_key: (u64, u64),
}

/// Digests are keyed `SipHash` outputs nobody outside the enclave can choose, so the set needs no
/// second hash of its own.
type Digests = HashSet<u64, BuildHasherDefault<DigestHasher>>;

impl State {
    fn new(max_registrations: usize, digest_key: (u64, u64)) -> Self {
        Self {
            billed_rps: HashSet::new(),
            periods: BTreeMap::new(),
            registrations: 0,
            max_registrations,
            digest_key,
        }
    }

    /// Applies `op` at `now` and returns the op that undoes it, or `None` if it changed nothing.
    ///
    /// A registration of a period that ended by `now` is dropped, as expiry would drop it.
    fn apply(&mut self, op: BillingOp, now: u64) -> Result<Option<BillingOp>, BillingStateError> {
        match op {
            BillingOp::SetBilledRp { rp_id, billed } => {
                let was_billed = if billed {
                    !self.billed_rps.insert(rp_id)
                } else {
                    self.billed_rps.remove(&rp_id)
                };
                Ok((was_billed != billed).then_some(BillingOp::SetBilledRp {
                    rp_id,
                    billed: was_billed,
                }))
            }
            BillingOp::AddRegistration {
                nullifier,
                registration,
            } => {
                let digest = self.digest(nullifier, registration.rp_id);
                if has_ended(registration.period_start, now) || self.holds(digest, registration) {
                    return Ok(None);
                }
                if self.registrations >= self.max_registrations {
                    return Err(BillingStateError::Full(self.max_registrations));
                }
                self.periods
                    .entry(registration.period_start)
                    .or_default()
                    .insert(digest);
                self.registrations += 1;
                Ok(Some(BillingOp::RemoveRegistration {
                    nullifier,
                    registration,
                }))
            }
            // A removal naming another registration than the held one finds nothing here. The
            // host's full `BillingState` rejects it as a conflict before it is ever pushed.
            BillingOp::RemoveRegistration {
                nullifier,
                registration,
            } => {
                let digest = self.digest(nullifier, registration.rp_id);
                let removed = self
                    .periods
                    .get_mut(&registration.period_start)
                    .is_some_and(|digests| digests.remove(&digest));
                if !removed {
                    return Ok(None);
                }
                self.registrations -= 1;
                Ok(Some(BillingOp::AddRegistration {
                    nullifier,
                    registration,
                }))
            }
        }
    }

    fn digest(&self, nullifier: FieldElement, rp_id: RpId) -> u64 {
        let mut hasher = SipHasher24::new_with_keys(self.digest_key.0, self.digest_key.1);
        hasher.write(&nullifier.to_be_bytes());
        hasher.write_u64(rp_id.into_inner());
        hasher.finish()
    }

    fn holds(&self, digest: u64, registration: Registration) -> bool {
        self.periods
            .get(&registration.period_start)
            .is_some_and(|digests| digests.contains(&digest))
    }

    /// Drops the periods that ended by `now`.
    fn expire(&mut self, now: u64) {
        let registrations = &mut self.registrations;
        self.periods.retain(|&period_start, digests| {
            let ended = has_ended(period_start, now);
            if ended {
                *registrations -= digests.len();
            }
            !ended
        });
    }
}

/// Whether the period starting at `period_start` ended by `now`. A period not started yet only
/// holds registrations made during its overlap, so it is kept.
fn has_ended(period_start: u64, now: u64) -> bool {
    billing_period(period_start).map_or(true, |(_, end)| now >= end)
}

/// Passes a digest through as its own hash.
#[derive(Default)]
struct DigestHasher(u64);

impl Hasher for DigestHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

/// How the enclave bills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingConfig {
    /// Bound on the registrations the enclave holds.
    pub max_registrations: usize,
}

impl BillingConfig {
    /// The config set in the EIF's environment, or `None` if billing is off.
    ///
    /// # Errors
    /// If the bound is malformed: a broken image must not boot.
    pub fn from_env() -> Result<Option<Self>, String> {
        env::var(MAX_REGISTRATIONS_VAR)
            .ok()
            .map(|value| Self::parse(&value))
            .transpose()
    }

    fn parse(max_registrations: &str) -> Result<Self, String> {
        max_registrations
            .parse()
            .ok()
            .filter(|&bound| bound > 0)
            .map(|max_registrations| Self { max_registrations })
            .ok_or_else(|| format!("{MAX_REGISTRATIONS_VAR} is not a positive count"))
    }
}

#[cfg(test)]
mod tests {
    use flamingo_verifier_billing_state::Registration;
    use world_id_primitives::{FieldElement, billing::PERIOD_OVERLAP, rp::RpId};

    use super::*;

    // 1 Nov and 1 Dec 2026, 00:00:00 AoE.
    const NOV_2026: u64 = 1_793_534_400;
    const DEC_2026: u64 = 1_796_126_400;
    const NOW: u64 = NOV_2026 + 86_400;
    const CONFIG: BillingConfig = BillingConfig {
        max_registrations: 1 << 22,
    };

    fn add(nullifier: u64, period_start: u64) -> BillingOp {
        BillingOp::AddRegistration {
            nullifier: FieldElement::from(nullifier),
            registration: Registration {
                rp_id: RpId::new(7),
                period_start,
            },
        }
    }

    const fn bill(billed: bool) -> BillingOp {
        BillingOp::SetBilledRp {
            rp_id: RpId::new(7),
            billed,
        }
    }

    fn update(seq: u64, ops: Vec<BillingOp>, backfill_done: bool) -> BillingUpdateRequest {
        BillingUpdateRequest {
            seq,
            ops,
            backfill_done,
        }
    }

    /// Whether `nullifier` is registered for RP 7 in any period the store holds.
    fn registered(store: &BillingStore, nullifier: u64) -> bool {
        let inner = store.lock();
        let digest = inner
            .state
            .digest(FieldElement::from(nullifier), RpId::new(7));
        inner
            .state
            .periods
            .values()
            .any(|digests| digests.contains(&digest))
    }

    #[test]
    fn a_stream_serves_once_it_has_caught_up() {
        let store = BillingStore::new(Some(CONFIG));
        assert!(!store.is_ready());
        store
            .apply(&update(0, vec![bill(true), add(1, NOV_2026)], false), NOW)
            .unwrap();
        assert!(!store.is_ready());
        let status = store
            .apply(&update(1, vec![add(2, NOV_2026)], true), NOW)
            .unwrap();
        assert_eq!(
            status,
            BillingStatus {
                registrations: 2,
                max_registrations: 1 << 22,
                ready: true
            }
        );
        assert!(store.is_ready());
    }

    #[test]
    fn a_new_stream_replaces_the_state() {
        let store = BillingStore::new(Some(CONFIG));
        store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        store
            .apply(&update(0, vec![add(2, NOV_2026)], false), NOW)
            .unwrap();
        assert!(!store.is_ready());
        assert!(!registered(&store, 1));
        assert!(registered(&store, 2));
        store.apply(&update(1, Vec::new(), true), NOW).unwrap();
        assert!(store.is_ready());
    }

    #[test]
    fn updates_must_follow_their_stream_and_may_repeat_the_last() {
        let store = BillingStore::new(Some(CONFIG));
        assert_eq!(
            store.apply(&update(1, Vec::new(), true), NOW),
            Err(enclave_types::Error::BillingOutOfOrder)
        );
        store.apply(&update(0, Vec::new(), true), NOW).unwrap();
        assert_eq!(
            store.apply(&update(2, Vec::new(), true), NOW),
            Err(enclave_types::Error::BillingOutOfOrder)
        );
        store
            .apply(&update(1, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        // The retried update changes nothing, even with other ops.
        store
            .apply(&update(1, vec![add(2, NOV_2026)], true), NOW)
            .unwrap();
        assert!(registered(&store, 1));
        assert!(!registered(&store, 2));
    }

    #[test]
    fn a_rejected_update_changes_nothing() {
        let store = BillingStore::new(Some(BillingConfig {
            max_registrations: 2,
        }));
        store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        // The second op exceeds the bound, so the first must not stay either.
        assert_eq!(
            store.apply(
                &update(1, vec![add(2, NOV_2026), add(3, NOV_2026)], true),
                NOW
            ),
            Err(enclave_types::Error::BillingRejected)
        );
        assert!(!registered(&store, 2));
        assert_eq!(
            store.apply(&update(1, Vec::new(), true), NOW),
            Err(enclave_types::Error::BillingOutOfOrder)
        );
        assert!(!store.is_ready());
        assert!(registered(&store, 1));
    }

    #[test]
    fn too_many_ops_are_rejected() {
        let store = BillingStore::new(Some(CONFIG));
        assert_eq!(
            store.apply(&update(0, vec![bill(true); MAX_BILLING_OPS + 1], true), NOW),
            Err(enclave_types::Error::BillingRejected)
        );
        assert!(!store.is_ready());
    }

    #[test]
    fn an_enclave_without_a_config_bills_nothing() {
        let store = BillingStore::new(None);
        assert!(store.is_ready());
        assert_eq!(
            store.apply(&update(0, Vec::new(), true), NOW),
            Err(enclave_types::Error::BillingRejected)
        );
    }

    #[test]
    fn a_rejection_stops_serving_until_a_new_stream_catches_up() {
        let store = BillingStore::new(Some(BillingConfig {
            max_registrations: 1,
        }));
        let status = store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        assert!(status.ready, "a store at its bound still serves");
        assert_eq!(
            store.apply(&update(1, vec![add(2, NOV_2026)], true), NOW),
            Err(enclave_types::Error::BillingRejected)
        );
        assert!(!store.is_ready());
        // A new stream the store rejects too keeps the old state out of service.
        assert_eq!(
            store.apply(
                &update(0, vec![add(2, NOV_2026), add(3, NOV_2026)], true),
                NOW
            ),
            Err(enclave_types::Error::BillingRejected)
        );
        assert!(!store.is_ready());
        assert!(registered(&store, 1));
        store
            .apply(&update(0, vec![add(2, NOV_2026)], true), NOW)
            .unwrap();
        assert!(store.is_ready());
    }

    #[test]
    fn ended_periods_do_not_count_against_the_bound_at_a_rollover() {
        let store = BillingStore::new(Some(BillingConfig {
            max_registrations: 1,
        }));
        store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        let status = store
            .apply(&update(1, vec![add(2, DEC_2026)], true), DEC_2026)
            .unwrap();
        assert_eq!(status.registrations, 1);
        assert!(registered(&store, 2));
        // A snapshot may still carry the ended period.
        let status = store
            .apply(
                &update(0, vec![add(1, NOV_2026), add(2, DEC_2026)], true),
                DEC_2026,
            )
            .unwrap();
        assert_eq!(status.registrations, 1);
        assert!(status.ready);
    }

    #[test]
    fn registrations_expire_with_the_verifier_clock() {
        let store = BillingStore::new(Some(CONFIG));
        store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        // December's registrations start during its overlap with November.
        store
            .apply(
                &update(1, vec![add(2, DEC_2026)], true),
                DEC_2026 - PERIOD_OVERLAP,
            )
            .unwrap();
        assert!(registered(&store, 1));
        store.apply(&update(2, Vec::new(), true), DEC_2026).unwrap();
        assert!(!registered(&store, 1));
        assert!(registered(&store, 2));
    }

    #[test]
    fn a_registration_is_bound_to_its_rp_and_removed_by_its_own_op() {
        let store = BillingStore::new(Some(CONFIG));
        let for_rp = |rp_id: u64| BillingOp::AddRegistration {
            nullifier: FieldElement::from(1u64),
            registration: Registration {
                rp_id: RpId::new(rp_id),
                period_start: NOV_2026,
            },
        };
        store.apply(&update(0, vec![for_rp(8)], true), NOW).unwrap();
        assert!(!registered(&store, 1), "registered for RP 8, not RP 7");
        store.apply(&update(1, vec![for_rp(7)], true), NOW).unwrap();
        assert!(registered(&store, 1));

        let remove_for_rp_8 = BillingOp::RemoveRegistration {
            nullifier: FieldElement::from(1u64),
            registration: Registration {
                rp_id: RpId::new(8),
                period_start: NOV_2026,
            },
        };
        let status = store
            .apply(&update(2, vec![remove_for_rp_8], true), NOW)
            .unwrap();
        assert_eq!(status.registrations, 1);
        assert!(registered(&store, 1));
    }

    #[test]
    fn every_store_draws_its_own_key() {
        let one = BillingStore::new(Some(CONFIG));
        let other = BillingStore::new(Some(CONFIG));
        let digest = |store: &BillingStore| {
            store
                .lock()
                .state
                .digest(FieldElement::from(1u64), RpId::new(7))
        };
        assert_ne!(digest(&one), digest(&other));
    }

    #[test]
    fn the_bound_must_be_a_positive_count() {
        assert_eq!(
            BillingConfig::parse("5"),
            Ok(BillingConfig {
                max_registrations: 5
            })
        );
        for bound in ["0", "-1", "many"] {
            assert!(BillingConfig::parse(bound).is_err());
        }
    }
}
