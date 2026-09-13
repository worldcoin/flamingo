//! Fixed-rate payment channels: nonce issuance and the admission of the payments that come back.
//!
//! A relying party reserves a channel nonce before serving a request, then presents the
//! authorization its spend key signed alongside the match. The escrow contract settles a lane
//! from its latest authorization alone, which is why counters are dense and lanes are reused.

pub mod eip712;
pub mod escrow;
pub mod ledger;
pub mod store;

use alloy_primitives::Address;
use alloy_sol_types::Eip712Domain;

pub use eip712::SignatureError;
pub use escrow::{ChannelSettings, EscrowError, EscrowReader, RpcEscrowReader};
pub use ledger::{
    AdmitRequest, CapacityProof, EpochLedger, LedgerError, PaymentAuthorization, PaymentLedger,
    ReserveOutcome,
};
pub use store::{InMemoryStore, PaymentStore, StoreError, Version, Versioned};

/// Payment settings this host runs with.
///
/// Read once at startup: the escrow deployment cannot change under a running process without a
/// restart, and neither can the signing domain derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentConfig {
    domain: Eip712Domain,
    collector: Address,
    max_request_lifetime_secs: u64,
    max_pending_per_epoch: usize,
    payment_required: bool,
}

impl PaymentConfig {
    /// Builds the configuration for a fee escrow deployment.
    #[must_use]
    pub const fn new(
        chain_id: u64,
        fee_escrow: Address,
        collector: Address,
        max_request_lifetime_secs: u64,
        max_pending_per_epoch: usize,
        payment_required: bool,
    ) -> Self {
        Self {
            domain: eip712::domain(chain_id, fee_escrow),
            collector,
            max_request_lifetime_secs,
            max_pending_per_epoch,
            payment_required,
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

    /// How long a reservation is held before another request may take the counter.
    #[must_use]
    pub const fn max_request_lifetime_secs(&self) -> u64 {
        self.max_request_lifetime_secs
    }

    /// How many reservations one channel may hold open in one epoch.
    ///
    /// A reservation costs a lane that is never reclaimed within the epoch, so an unbounded
    /// caller could grow this host's memory without ever paying for anything.
    #[must_use]
    pub const fn max_pending_per_epoch(&self) -> usize {
        self.max_pending_per_epoch
    }

    /// Whether a match without a payment is refused. The kill switch for metering.
    ///
    /// Off by default so metering can be turned on per environment after the channels are
    /// funded, rather than as a flag day that refuses every caller at once.
    #[must_use]
    pub const fn payment_required(&self) -> bool {
        self.payment_required
    }
}
