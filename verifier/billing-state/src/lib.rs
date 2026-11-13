//! The ops the Flamingo host sends to change the enclave's WIP-107 billing state.

use serde::{Deserialize, Serialize};

use world_id_primitives::{FieldElement, rp::RpId};

/// One absolute change to the billing state, so applying it twice changes nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BillingOp {
    /// Sets whether the Billing Contract bills `rp_id`, from a `BilledRpUpdated` log.
    SetBilledRp {
        /// The RP.
        rp_id: RpId,
        /// Whether it is billed.
        billed: bool,
    },
    /// Adds a registration, from a `Registered` log.
    AddRegistration {
        /// The registered `billingNullifier`.
        nullifier: FieldElement,
        /// Its RP and period.
        registration: Registration,
    },
    /// Removes a registration, when a reorganization drops its `Registered` log.
    RemoveRegistration {
        /// The registered `billingNullifier`.
        nullifier: FieldElement,
        /// Its RP and period, so a copy that stores only digests can find it.
        registration: Registration,
    },
}

/// A World ID's registration in one RP's billing period, as `registrationOf` returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Registration {
    /// The RP the registration consumed capacity of.
    pub rp_id: RpId,
    /// The start of the registration's billing period.
    pub period_start: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_round_trip_through_serde() {
        let registration = Registration {
            rp_id: RpId::new(7),
            period_start: 1_793_534_400,
        };
        for op in [
            BillingOp::SetBilledRp {
                rp_id: RpId::new(7),
                billed: true,
            },
            BillingOp::AddRegistration {
                nullifier: FieldElement::from(1u64),
                registration,
            },
            BillingOp::RemoveRegistration {
                nullifier: FieldElement::from(1u64),
                registration,
            },
        ] {
            let json = serde_json::to_string(&op).unwrap();
            assert_eq!(serde_json::from_str::<BillingOp>(&json).unwrap(), op);
        }
    }
}
