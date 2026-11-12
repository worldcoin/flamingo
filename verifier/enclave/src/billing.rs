//! The WIP-107 billing state the host supplies (WIP-107 §4.8).
//!
//! The host follows the Billing Contract and pushes its state as a numbered update stream. A new
//! stream replaces the state, which serves requests once an update of it carries `backfill_done`.

use std::{
    env,
    sync::{Mutex, PoisonError},
};

use flamingo_verifier_billing_state::{BillingOp, BillingState, BillingStateError};
use flamingo_verifier_enclave_types::{
    self as enclave_types, BillingStatus, BillingUpdateRequest, MAX_BILLING_OPS,
};
use world_id_primitives::billing::billing_period;

/// Default bound on the registrations the enclave holds. Reaching the bound fails closed.
pub const DEFAULT_MAX_REGISTRATIONS: usize = 1 << 22;

/// The chain this measurement bills on, from the EIF's environment, so the host cannot change it.
const CHAIN_ID_VAR: &str = "FLAMINGO_BILLING_CHAIN_ID";
const CONTRACT_VAR: &str = "FLAMINGO_BILLING_CONTRACT";
const MAX_REGISTRATIONS_VAR: &str = "FLAMINGO_BILLING_MAX_REGISTRATIONS";

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

struct Inner {
    state: BillingState,
    /// The last applied `seq`, or `None` before the first stream.
    last_seq: Option<u64>,
    /// Whether an update of the current stream carried `backfill_done`.
    caught_up: bool,
    next_expiry: u64,
}

/// The enclave's copy of the billing state.
pub struct BillingStore {
    target: Option<BillingTarget>,
    inner: Mutex<Inner>,
}

impl BillingStore {
    /// A store for `target`, or a store that bills nothing if `target` is `None`.
    #[must_use]
    pub fn new(target: Option<BillingTarget>) -> Self {
        Self {
            target,
            inner: Mutex::new(Inner {
                state: BillingState::with_limit(max_registrations(target)),
                last_seq: None,
                caught_up: false,
                next_expiry: 0,
            }),
        }
    }

    /// Whether requests can be served: billing is off, or the state has caught up and is not full.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.target.is_none() || ready(&self.lock())
    }

    /// Applies one update at the Verifier's time `now`, in Unix seconds.
    ///
    /// # Errors
    /// [`enclave_types::Error::BillingRejected`] for another target, too many ops, an op the
    /// state rejects or a store that bills nothing, and [`enclave_types::Error::BillingOutOfOrder`]
    /// for a `seq` that neither follows nor repeats the last one. Either leaves the store unchanged.
    pub fn apply(
        &self,
        update: &BillingUpdateRequest,
        now: u64,
    ) -> Result<BillingStatus, enclave_types::Error> {
        let Some(target) = self.target else {
            tracing::warn!("billing update for an enclave that does not bill");
            return Err(enclave_types::Error::BillingRejected);
        };
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

        let mut inner = self.lock();
        if update.seq == 0 {
            let mut state = BillingState::with_limit(target.max_registrations);
            apply_all(&mut state, &update.ops).map_err(rejected)?;
            inner.state = state;
            inner.caught_up = false;
        } else if inner.last_seq == Some(update.seq) {
            // A retry of an update whose answer the host lost.
            return Ok(status(&inner, target.max_registrations));
        } else if inner.last_seq.map(|seq| seq + 1) == Some(update.seq) {
            apply_all(&mut inner.state, &update.ops).map_err(rejected)?;
        } else {
            return Err(enclave_types::Error::BillingOutOfOrder);
        }
        inner.last_seq = Some(update.seq);
        inner.caught_up |= update.backfill_done;
        if now >= inner.next_expiry {
            inner.state.expire(now);
            inner.next_expiry = billing_period(now).map_or(u64::MAX, |(_, end)| end);
        }
        let status = status(&inner, target.max_registrations);
        drop(inner);
        Ok(status)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Applies `ops` in order, or none of them.
fn apply_all(state: &mut BillingState, ops: &[BillingOp]) -> Result<(), BillingStateError> {
    let mut inverses = Vec::with_capacity(ops.len());
    for op in ops {
        match state.apply(*op) {
            Ok(inverse) => inverses.extend(inverse),
            Err(error) => {
                for inverse in inverses.into_iter().rev() {
                    // An inverse undoes an op just applied, so it cannot fail.
                    let _ = state.apply(inverse);
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

/// A full state fails closed: it could be missing the registration a request needs.
fn ready(inner: &Inner) -> bool {
    inner.caught_up && !inner.state.is_full()
}

/// A store that bills nothing holds no registrations.
fn max_registrations(target: Option<BillingTarget>) -> usize {
    target.map_or(0, |target| target.max_registrations)
}

fn status(inner: &Inner, max_registrations: usize) -> BillingStatus {
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    BillingStatus {
        registrations: count(inner.state.registration_count()),
        max_registrations: count(max_registrations),
        ready: ready(inner),
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
            head_block: seq,
            backfill_done,
        }
    }

    fn registered(store: &BillingStore, nullifier: u64) -> bool {
        store
            .lock()
            .state
            .registration(FieldElement::from(nullifier))
            .is_some()
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
        let store = BillingStore::new(Some(TARGET));
        store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        // The second op conflicts with the first registration, so the first must not stay.
        let conflicting = BillingOp::AddRegistration {
            nullifier: FieldElement::from(1u64),
            registration: Registration {
                rp_id: RpId::new(8),
                period_start: NOV_2026,
            },
        };
        assert_eq!(
            store.apply(&update(1, vec![add(2, NOV_2026), conflicting], true), NOW),
            Err(enclave_types::Error::BillingRejected)
        );
        assert!(!registered(&store, 2));
        store.apply(&update(1, Vec::new(), true), NOW).unwrap();
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
    fn a_full_store_is_not_ready() {
        let store = BillingStore::new(Some(BillingTarget {
            max_registrations: 1,
            ..TARGET
        }));
        let status = store
            .apply(&update(0, vec![add(1, NOV_2026)], true), NOW)
            .unwrap();
        assert!(!status.ready);
        assert_eq!(
            store.apply(&update(1, vec![add(2, NOV_2026)], true), NOW),
            Err(enclave_types::Error::BillingRejected)
        );
        assert!(!store.is_ready());
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
