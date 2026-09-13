//! A [`PaymentStore`] that keeps everything in this process.
//!
//! Nothing survives a restart and nothing is shared between hosts, so two replicas will hand out
//! the same counters. Good enough to develop against, and the reason the trait exists.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use alloy_primitives::B256;
use async_trait::async_trait;

use super::{PaymentStore, StoreError};
use crate::payments::ledger::EpochLedger;

/// In-process epoch ledgers behind one lock.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    epochs: Mutex<HashMap<(B256, u64), (EpochLedger, u64)>>,
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
    fn epochs(&self) -> std::sync::MutexGuard<'_, HashMap<(B256, u64), (EpochLedger, u64)>> {
        self.epochs.lock().unwrap_or_else(PoisonError::into_inner)
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
    ) -> Result<(EpochLedger, u64), StoreError> {
        // An epoch nobody has written yet reads as empty at version 0, so a first writer and a
        // later one take the same path.
        Ok(self
            .epochs()
            .get(&(channel_id, epoch))
            .cloned()
            .unwrap_or_default())
    }

    // The read and the write are one critical section, so the guard cannot end between them.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the compare and the write must share the guard"
    )]
    async fn store_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
        ledger: &EpochLedger,
        expected: u64,
    ) -> Result<(), StoreError> {
        let mut epochs = self.epochs();
        let stored = epochs.get(&(channel_id, epoch)).map_or(0, |(_, v)| *v);

        // The conditional write: a caller holding an older version has already been overtaken.
        if stored != expected {
            return Err(StoreError::Conflict);
        }

        epochs.insert((channel_id, epoch), (ledger.clone(), expected + 1));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, b256};

    use super::{InMemoryStore, PaymentStore, StoreError};
    use crate::payments::ledger::EpochLedger;

    const CHANNEL: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");

    #[tokio::test]
    async fn an_unwritten_epoch_reads_as_empty_at_version_zero() {
        let store = InMemoryStore::new();

        let (ledger, version) = store
            .load_epoch(CHANNEL, 7)
            .await
            .expect("the in-memory store always answers");

        assert_eq!(version, 0);
        assert_eq!(ledger, EpochLedger::default());
    }

    /// The primitive the ledger's retry is built on: a write only lands on the version it read.
    #[tokio::test]
    async fn a_write_against_a_stale_version_conflicts() {
        let store = InMemoryStore::new();
        let ledger = EpochLedger::default();

        assert_eq!(store.store_epoch(CHANNEL, 7, &ledger, 0).await, Ok(()));
        assert_eq!(
            store.store_epoch(CHANNEL, 7, &ledger, 0).await,
            Err(StoreError::Conflict),
            "a second writer holding the old version must lose"
        );
        assert_eq!(store.store_epoch(CHANNEL, 7, &ledger, 1).await, Ok(()));
    }

    #[tokio::test]
    async fn the_in_memory_store_is_always_ready() {
        assert!(InMemoryStore::new().ready().await);
    }
}
