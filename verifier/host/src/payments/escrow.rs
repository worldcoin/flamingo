//! Reads of the fee escrow contract.
//!
//! Everything this host knows about a channel comes from the chain. Nothing registers a channel
//! with the verifier, so a caller cannot invent one by talking to this API.

pub mod rpc;

use alloy_primitives::{Address, B256};
use async_trait::async_trait;

pub use rpc::RpcEscrowReader;

/// The part of the escrow's `ChannelSettings` this host acts on.
///
/// The contract stores more: a relying party id, the payment token, the price per unit and a
/// salt. None of them decide whether a nonce is admitted, so none of them are carried here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSettings {
    /// Address whose signature authorizes spending from the channel.
    pub spend_key: Address,
    /// Verifier the channel's fees settle to. Only that verifier may admit its nonces.
    pub collector: Address,
    /// Unix seconds at which epoch 0 began.
    pub epoch_zero: u64,
    /// Seconds each epoch lasts. Never zero on-chain.
    pub epoch_length: u64,
}

impl ChannelSettings {
    /// The epoch `now` falls in.
    ///
    /// Everything before `epoch_zero` reads as epoch 0 rather than wrapping, so a clock that is
    /// behind cannot mint an epoch below the first one.
    #[must_use]
    pub const fn epoch_at(&self, now: u64) -> u64 {
        if self.epoch_length == 0 || now <= self.epoch_zero {
            return 0;
        }

        (now - self.epoch_zero) / self.epoch_length
    }
}

/// Why the escrow could not be read.
///
/// Every variant is fail-closed at the call site: a channel this host cannot verify is a channel
/// it will not spend from.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EscrowError {
    /// The node answered with an error, or not at all. Carries context for the log.
    #[error("the fee escrow rpc is unavailable: {0}")]
    Unavailable(String),
    /// The node did not answer inside the call deadline.
    #[error("the fee escrow rpc timed out")]
    Timeout,
    /// The node is serving a different chain than the escrow address belongs to.
    #[error("the fee escrow rpc is on chain {actual}, expected {expected}")]
    WrongChain {
        /// The chain this host is configured for.
        expected: u64,
        /// The chain the node reported.
        actual: u64,
    },
}

/// Reads channel settings and per-epoch capacity from the fee escrow.
#[async_trait]
pub trait EscrowReader: Send + Sync {
    /// Reads a channel's settings, or `None` when the escrow does not know it.
    ///
    /// # Errors
    ///
    /// Returns [`EscrowError`] when the node cannot be reached or answers with an error.
    async fn channel(&self, channel_id: B256) -> Result<Option<ChannelSettings>, EscrowError>;

    /// Units the channel may spend in `epoch`, which is its funding over the price per unit.
    ///
    /// # Errors
    ///
    /// Returns [`EscrowError`] when the node cannot be reached or answers with an error.
    async fn capacity(&self, channel_id: B256, epoch: u64) -> Result<u64, EscrowError>;

    /// Checks the node is reachable and serving the configured chain.
    ///
    /// # Errors
    ///
    /// Returns [`EscrowError`] when the node is unreachable or on another chain.
    async fn ready(&self) -> Result<(), EscrowError>;
}
