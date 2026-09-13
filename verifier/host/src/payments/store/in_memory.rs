//! A [`PaymentStore`] that keeps everything in this process.
//!
//! Nothing survives a restart and nothing is shared between hosts, so two replicas will hand out
//! the same counters. Good enough to develop against, and the reason the trait exists.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Mutex, PoisonError};

use alloy_primitives::B256;
use async_trait::async_trait;

use super::{PaymentStore, StoreError, Version, Versioned};
use crate::payments::ledger::EpochLedger;

/// In-process channels and epochs behind one lock.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    epochs: HashMap<(B256, u64), Versioned<EpochLedger>>,
}

impl InMemoryStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the lock, recovering it if a previous holder panicked.
    ///
    /// Every critical section here is a map operation that cannot panic partway, so a poisoned
    /// lock would mean refusing all payment traffic over an unrelated bug.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl PaymentStore for InMemoryStore {
    async fn ready(&self) -> bool {
        true
    }

    async fn load_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
    ) -> Result<Versioned<EpochLedger>, StoreError> {
        let stored = self.state().epochs.get(&(channel_id, epoch)).cloned();

        // An epoch nobody has written yet reads as empty at version 0, so a first writer and a
        // later one take the same path.
        Ok(stored.unwrap_or_else(|| Versioned {
            value: EpochLedger::default(),
            version: 0,
        }))
    }

    // The lint cannot see that `slot` borrows out of the guard, so the guard cannot be dropped
    // before the write it guards.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the borrow out of the guard outlives the guard in the lint's model"
    )]
    async fn store_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
        ledger: &EpochLedger,
        expected: Version,
    ) -> Result<Version, StoreError> {
        let mut state = self.state();
        let slot = state.epochs.entry((channel_id, epoch));

        let stored = match &slot {
            Entry::Occupied(entry) => entry.get().version,
            Entry::Vacant(_) => 0,
        };

        // The conditional write: a caller holding an older version has already been overtaken.
        if stored != expected {
            return Err(StoreError::Conflict);
        }

        let version = expected + 1;
        slot.insert_entry(Versioned {
            value: ledger.clone(),
            version,
        });

        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::b256;

    use super::{InMemoryStore, PaymentStore, StoreError};
    use crate::payments::ledger::EpochLedger;

    const CHANNEL: alloy_primitives::B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");

    #[tokio::test]
    async fn an_unwritten_epoch_reads_as_empty_at_version_zero() {
        let store = InMemoryStore::new();

        let stored = store
            .load_epoch(CHANNEL, 7)
            .await
            .expect("the in-memory store always answers");

        assert_eq!(stored.version, 0);
        assert_eq!(stored.value, EpochLedger::default());
    }

    /// The primitive the ledger's retry is built on: a write only lands on the version it read.
    #[tokio::test]
    async fn a_write_against_a_stale_version_conflicts() {
        let store = InMemoryStore::new();
        let ledger = EpochLedger::default();

        let version = store
            .store_epoch(CHANNEL, 7, &ledger, 0)
            .await
            .expect("the first write starts from version zero");
        assert_eq!(version, 1);

        assert_eq!(
            store.store_epoch(CHANNEL, 7, &ledger, 0).await,
            Err(StoreError::Conflict),
            "a second writer holding the old version must lose"
        );
        assert_eq!(store.store_epoch(CHANNEL, 7, &ledger, version).await, Ok(2));
    }

    #[tokio::test]
    async fn the_in_memory_store_is_always_ready() {
        assert!(InMemoryStore::new().ready().await);
    }
}
