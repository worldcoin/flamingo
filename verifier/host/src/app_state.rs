use std::sync::Arc;

use crate::{Environment, enclave::EnclaveClient, payments::PaymentLedger};

/// The payment gate, present only when payments are switched on.
///
/// Absent is the rollback position: no escrow is read, no store is kept, and a match relays as
/// it did before metering existed. Present but not required is the middle setting, where a
/// caller that pays is metered and one that does not is still served.
#[derive(Clone)]
pub struct PaymentGate {
    ledger: Arc<PaymentLedger>,
    required: bool,
}

impl PaymentGate {
    /// Creates a gate over `ledger`.
    #[must_use]
    pub const fn new(ledger: Arc<PaymentLedger>, required: bool) -> Self {
        Self { ledger, required }
    }

    /// The ledger behind the gate.
    #[must_use]
    pub fn ledger(&self) -> &PaymentLedger {
        &self.ledger
    }

    /// Whether a match without a payment is refused.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
    payments: Option<PaymentGate>,
}

impl AppState {
    /// Creates API state from the runtime environment, enclave client and payment ledger.
    #[must_use]
    pub fn new(
        environment: Environment,
        enclave_client: Arc<dyn EnclaveClient>,
        payments: Option<PaymentGate>,
    ) -> Self {
        Self {
            environment,
            enclave_client,
            payments,
        }
    }

    /// Returns the runtime environment.
    #[must_use]
    pub const fn environment(&self) -> Environment {
        self.environment
    }

    /// Returns a shared enclave client.
    #[must_use]
    pub fn enclave_client(&self) -> Arc<dyn EnclaveClient> {
        Arc::clone(&self.enclave_client)
    }

    /// Returns the payment gate, or `None` when payments are switched off.
    #[must_use]
    pub const fn payments(&self) -> Option<&PaymentGate> {
        self.payments.as_ref()
    }
}
