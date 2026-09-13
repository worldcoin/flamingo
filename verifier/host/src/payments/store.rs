//! Storage behind the payment ledger.
//!
//! The trait carries storage primitives only. Every rule about counters, capacity and admission
//! lives in [`super::ledger`], so a persistent backend cannot quietly disagree with the
//! in-memory one about what a nonce means.

pub mod in_memory;

use alloy_primitives::B256;
use async_trait::async_trait;

use super::ledger::EpochLedger;

pub use in_memory::InMemoryStore;

/// Monotonic version of one stored epoch. A fresh epoch reads as version 0.
pub type Version = u64;

/// A stored value and the version it was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versioned<T> {
    /// The value as stored.
    pub value: T,
    /// The version to pass back as `expected` when writing it again.
    pub version: Version,
}

/// Why the store could not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The epoch changed between the read and the write.
    #[error("the epoch was written by someone else")]
    Conflict,
    /// The backend is unreachable or failed. Carries context for the log, never for the client.
    #[error("the payments store is unavailable: {0}")]
    Unavailable(String),
}

/// Reads and writes epoch ledgers.
///
/// Channels are not stored: they live in the fee escrow, and this host only ever reads them.
///
/// [`Self::store_epoch`] is the concurrency primitive: it writes only if the stored version is
/// still the one the caller read. `DynamoDB` satisfies this with a conditional write on a version
/// attribute (`attribute_not_exists(version) OR version = :expected`), and the ledger turns a
/// [`StoreError::Conflict`] into a bounded retry rather than a lost update.
#[async_trait]
pub trait PaymentStore: Send + Sync {
    /// Whether the store can serve traffic. Reported by the readiness probe.
    async fn ready(&self) -> bool;

    /// Reads one epoch, or an empty ledger at version 0 when it has never been written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when the backend cannot answer.
    async fn load_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
    ) -> Result<Versioned<EpochLedger>, StoreError>;

    /// Writes one epoch if its stored version is still `expected`, returning the new version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] when the stored version moved on, and
    /// [`StoreError::Unavailable`] when the backend cannot answer.
    async fn store_epoch(
        &self,
        channel_id: B256,
        epoch: u64,
        ledger: &EpochLedger,
        expected: Version,
    ) -> Result<Version, StoreError>;
}
