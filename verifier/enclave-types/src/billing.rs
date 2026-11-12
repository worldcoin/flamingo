use flamingo_verifier_billing_state::BillingOp;
use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// The most ops one [`BillingUpdateRequest`] may carry. The host splits larger changes.
pub const MAX_BILLING_OPS: usize = 8192;

/// Applies the host's next WIP-107 billing state change to the enclave's copy (WIP-107 §4.8).
///
/// Updates form a stream. `seq = 0` replaces the copy, and every later update carries the
/// previous `seq + 1`. Repeating the last `seq` changes nothing, so the host can retry an update
/// whose answer it lost. A rejected update changes nothing; the host then follows the chain again
/// and starts a new stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingUpdateRequest {
    /// The chain hosting the Billing Contract.
    pub chain_id: u64,
    /// The Billing Contract's address.
    pub contract: [u8; 20],
    /// The update's position in its stream.
    pub seq: u64,
    /// The state changes, in chain order. At most [`MAX_BILLING_OPS`].
    pub ops: Vec<BillingOp>,
    /// Whether the host's state has caught up with the chain.
    pub backfill_done: bool,
}

/// The enclave's billing state after an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingStatus {
    /// Registrations the enclave holds.
    pub registrations: u64,
    /// The bound on them, from the enclave image. The host's should not be larger.
    pub max_registrations: u64,
    /// Whether the enclave serves requests: its state has caught up and no update was rejected since.
    pub ready: bool,
}

impl Request for BillingUpdateRequest {
    const ROUTE_ID: &'static str = "/v1/billing";
    type Response = Result<BillingStatus, Error>;
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::BillingUpdateRequest;

    #[test]
    fn the_billing_route_id_is_versioned_and_stable() {
        assert_eq!(BillingUpdateRequest::ROUTE_ID, "/v1/billing");
    }
}
