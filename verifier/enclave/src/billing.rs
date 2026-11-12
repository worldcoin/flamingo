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

/// Default bound on the registrations the enclave holds. Reaching the bound fails closed.
pub const DEFAULT_MAX_REGISTRATIONS: usize = 1 << 22;

/// The chain this measurement bills on, from the EIF's environment, so the host cannot change it.
const CHAIN_ID_VAR: &str = "FLAMINGO_BILLING_CHAIN_ID";
const CONTRACT_VAR: &str = "FLAMINGO_BILLING_CONTRACT";
const MAX_REGISTRATIONS_VAR: &str = "FLAMINGO_BILLING_MAX_REGISTRATIONS";

/// The enclave's copy of the billing state.
pub struct BillingStore {
    target: Option<BillingTarget>,
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
    /// A store for `target`, or a store that bills nothing if `target` is `None`.
    #[must_use]
    pub fn new(target: Option<BillingTarget>) -> Self {
        Self {
            target,
            inner: Mutex::new(Inner {
                state: State::new(max_registrations(target), boot_key()),
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
        self.target.is_none() || self.lock().caught_up
    }

    /// Applies one update at the Verifier's time `now`, in Unix seconds.
    ///
    /// # Errors
    /// [`enclave_types::Error::BillingRejected`] for another target, too many ops, an op the
    /// state rejects or a store that bills nothing, and [`enclave_types::Error::BillingOutOfOrder`]
    /// for a `seq` that neither follows nor repeats the last one. Neither changes the state. A
    /// rejection ends the stream and stops serving until a new stream catches up.
    pub fn apply(
        &self,
        update: &BillingUpdateRequest,
        now: u64,
    ) -> Result<BillingStatus, enclave_types::Error> {
        let Some(target) = self.target else {
            tracing::warn!("billing update for an enclave that does not bill");
            return Err(enclave_types::Error::BillingRejected);
        };
        let mut inner = self.lock();
        let result = inner.apply(target, update, now);
        if result == Err(enclave_types::Error::BillingRejected) {
            // The rejected update's changes are missing, so its stream cannot go on.
            inner.last_seq = None;
            inner.caught_up = false;
        }
        let status = result.map(|()| status(&inner, target.max_registrations));
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
        target: BillingTarget,
        update: &BillingUpdateRequest,
        now: u64,
    ) -> Result<(), enclave_types::Error> {
        if update.chain_id != target.chain_id || update.contract != target.contract {
            tracing::error!(
                chain_id = update.chain_id,
                "billing update for another chain or contract than the image's"
            );
            return Err(enclave_types::Error::BillingRejected);
        }
        if update.ops.len() > MAX_BILLING_OPS {
            return Err(enclave_types::Error::BillingRejected);
        }
        // Ended periods go first, so they never count against the bound at a rollover.
        if now >= self.next_expiry {
            self.state.expire(now);
            self.next_expiry = billing_period(now).map_or(u64::MAX, |(_, end)| end);
        }
        if update.seq == 0 {
            let mut state = State::new(target.max_registrations, self.state.key);
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

/// A store that bills nothing holds no registrations.
fn max_registrations(target: Option<BillingTarget>) -> usize {
    target.map_or(0, |target| target.max_registrations)
}

fn status(inner: &Inner, max_registrations: usize) -> BillingStatus {
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    BillingStatus {
        registrations: count(inner.state.len),
        max_registrations: count(max_registrations),
        ready: inner.caught_up,
    }
}

/// The billed RPs and the registrations, as the enclave keeps them.
struct State {
    billed_rps: HashSet<RpId>,
    /// Registration digests by period, so expiry drops whole periods.
    periods: BTreeMap<u64, Digests>,
    len: usize,
    max: usize,
    key: (u64, u64),
}

/// Digests are keyed `SipHash` outputs nobody outside the enclave can choose, so the set needs no
/// second hash of its own.
type Digests = HashSet<u64, BuildHasherDefault<DigestHasher>>;

impl State {
    fn new(max: usize, key: (u64, u64)) -> Self {
        Self {
            billed_rps: HashSet::new(),
            periods: BTreeMap::new(),
            len: 0,
            max,
            key,
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
                if self.len >= self.max {
                    return Err(BillingStateError::Full(self.max));
                }
                self.periods
                    .entry(registration.period_start)
                    .or_default()
                    .insert(digest);
                self.len += 1;
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
                self.len -= 1;
                Ok(Some(BillingOp::AddRegistration {
                    nullifier,
                    registration,
                }))
            }
        }
    }

    fn digest(&self, nullifier: FieldElement, rp_id: RpId) -> u64 {
        let mut hasher = SipHasher24::new_with_keys(self.key.0, self.key.1);
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
        let len = &mut self.len;
        self.periods.retain(|&period_start, digests| {
            let ended = has_ended(period_start, now);
            if ended {
                *len -= digests.len();
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

/// The Billing Contract this enclave accepts state of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingTarget {
    /// The chain hosting the Billing Contract.
    pub chain_id: u64,
    /// The Billing Contract's address.
    pub contract: [u8; 20],
    /// Bound on the registrations the enclave holds.
    pub max_registrations: usize,
}

impl BillingTarget {
    /// The target set in the EIF's environment, or `None` if billing is off.
    ///
    /// # Errors
    /// If only one of chain and contract is set, or a variable is malformed: a broken image must
    /// not boot. The bound defaults to [`DEFAULT_MAX_REGISTRATIONS`].
    pub fn from_env() -> Result<Option<Self>, String> {
        let chain_id = env::var(CHAIN_ID_VAR).ok();
        let contract = env::var(CONTRACT_VAR).ok();
        let max_registrations = env::var(MAX_REGISTRATIONS_VAR).ok();
        match (chain_id, contract) {
            (None, None) => Ok(None),
            (Some(chain_id), Some(contract)) => {
                Self::parse(&chain_id, &contract, max_registrations.as_deref()).map(Some)
            }
            _ => Err(format!(
                "set both {CHAIN_ID_VAR} and {CONTRACT_VAR}, or neither"
            )),
        }
    }

    fn parse(
        chain_id: &str,
        contract: &str,
        max_registrations: Option<&str>,
    ) -> Result<Self, String> {
        let chain_id = chain_id
            .parse()
            .map_err(|_| format!("{CHAIN_ID_VAR} is not a chain ID"))?;
        let contract = hex::decode(contract.strip_prefix("0x").unwrap_or(contract))
            .ok()
            .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
            .ok_or_else(|| format!("{CONTRACT_VAR} is not a 20-byte hex address"))?;
        let max_registrations =
            max_registrations.map_or(Ok(DEFAULT_MAX_REGISTRATIONS), |value| {
                value
                    .parse()
                    .ok()
                    .filter(|&bound| bound > 0)
                    .ok_or_else(|| format!("{MAX_REGISTRATIONS_VAR} is not a positive count"))
            })?;
        Ok(Self {
            chain_id,
            contract,
            max_registrations,
        })
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
    const TARGET: BillingTarget = BillingTarget {
        chain_id: 480,
        contract: [0x11; 20],
        max_registrations: DEFAULT_MAX_REGISTRATIONS,
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
            chain_id: TARGET.chain_id,
            contract: TARGET.contract,
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
        let store = BillingStore::new(Some(TARGET));
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
        let store = BillingStore::new(Some(TARGET));
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
        let store = BillingStore::new(Some(TARGET));
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
        let store = BillingStore::new(Some(BillingTarget {
            max_registrations: 2,
            ..TARGET
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
    fn another_target_or_too_many_ops_is_rejected() {
        let store = BillingStore::new(Some(TARGET));
        let mut other_chain = update(0, Vec::new(), true);
        other_chain.chain_id += 1;
        let mut other_contract = update(0, Vec::new(), true);
        other_contract.contract = [0x22; 20];
        let too_many = update(0, vec![bill(true); MAX_BILLING_OPS + 1], true);
        for update in [other_chain, other_contract, too_many] {
            assert_eq!(
                store.apply(&update, NOW),
                Err(enclave_types::Error::BillingRejected)
            );
        }
        assert!(!store.is_ready());
    }

    #[test]
    fn an_enclave_without_a_target_bills_nothing() {
        let store = BillingStore::new(None);
        assert!(store.is_ready());
        assert_eq!(
            store.apply(&update(0, Vec::new(), true), NOW),
            Err(enclave_types::Error::BillingRejected)
        );
    }

    #[test]
    fn a_rejection_stops_serving_until_a_new_stream_catches_up() {
        let store = BillingStore::new(Some(BillingTarget {
            max_registrations: 1,
            ..TARGET
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
        let store = BillingStore::new(Some(BillingTarget {
            max_registrations: 1,
            ..TARGET
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
        let store = BillingStore::new(Some(TARGET));
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
        let store = BillingStore::new(Some(TARGET));
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
        let one = BillingStore::new(Some(TARGET));
        let other = BillingStore::new(Some(TARGET));
        let digest = |store: &BillingStore| {
            store
                .lock()
                .state
                .digest(FieldElement::from(1u64), RpId::new(7))
        };
        assert_ne!(digest(&one), digest(&other));
    }

    #[test]
    fn the_target_needs_valid_values_and_defaults_its_bound() {
        const CONTRACT: &str = "0x1111111111111111111111111111111111111111";
        assert_eq!(BillingTarget::parse("480", CONTRACT, None), Ok(TARGET));
        assert_eq!(
            BillingTarget::parse("480", &CONTRACT[2..], Some("5")),
            Ok(BillingTarget {
                max_registrations: 5,
                ..TARGET
            })
        );
        assert!(BillingTarget::parse("world", CONTRACT, None).is_err());
        assert!(BillingTarget::parse("480", "0x11", None).is_err());
        for bound in ["0", "-1", "many"] {
            assert!(BillingTarget::parse("480", CONTRACT, Some(bound)).is_err());
        }
    }
}
