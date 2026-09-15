//! Fixed-rate payment channels: nonce issuance and the admission of the payments that come back.
//!
//! A relying party reserves a channel nonce before serving a request, then presents the
//! authorization its spend key signed alongside the match. The escrow contract settles a lane
//! from its latest authorization alone, which is why counters are dense and lanes are reused.

pub mod eip712;
pub mod escrow;
pub mod ledger;
pub mod store;

use alloy_primitives::{Address, U256};
use alloy_sol_types::Eip712Domain;

pub use eip712::SignatureError;
pub use escrow::{ChannelSettings, EscrowError, EscrowReader, RpcEscrowReader};
pub use ledger::{
    AdmitRequest, CapacityProof, EpochLedger, LedgerError, MAX_LANES_PER_EPOCH,
    PaymentAuthorization, PaymentLedger, RESERVATION_CLOCK_SKEW_SECS, RESERVATION_LIFETIME_SECS,
    ReserveOutcome, ReserveRequest,
};
pub use store::{InMemoryStore, PaymentStore, StoreError};

/// Payment settings this host runs with.
///
/// Read once at startup: the escrow deployment cannot change under a running process without a
/// restart, and neither can the signing domain derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentConfig {
    domain: Eip712Domain,
    collector: Address,
    token: Address,
    min_price_per_unit: U256,
}

impl PaymentConfig {
    /// Builds the configuration for a fee escrow deployment.
    #[must_use]
    pub const fn new(
        chain_id: u64,
        fee_escrow: Address,
        collector: Address,
        token: Address,
        min_price_per_unit: U256,
    ) -> Self {
        Self {
            domain: eip712::domain(chain_id, fee_escrow),
            collector,
            token,
            min_price_per_unit,
        }
    }

    /// The signing domain relying parties authorize under.
    #[must_use]
    pub const fn domain(&self) -> &Eip712Domain {
        &self.domain
    }

    /// The address this host settles to. Only channels naming it may be spent here.
    #[must_use]
    pub const fn collector(&self) -> Address {
        self.collector
    }

    /// The only token this host accepts payment in.
    #[must_use]
    pub const fn token(&self) -> Address {
        self.token
    }

    /// The least this host will sell a verification for, in that token's smallest unit.
    #[must_use]
    pub const fn min_price_per_unit(&self) -> U256 {
        self.min_price_per_unit
    }
}
