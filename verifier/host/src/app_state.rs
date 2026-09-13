use std::sync::Arc;

use crate::{Environment, enclave::EnclaveClient, payments::PaymentLedger};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
    payments: Arc<PaymentLedger>,
}

impl AppState {
    /// Creates API state from the runtime environment, enclave client and payment ledger.
    #[must_use]
    pub fn new(
        environment: Environment,
        enclave_client: Arc<dyn EnclaveClient>,
        payments: Arc<PaymentLedger>,
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

    /// Returns the payment ledger, which every handler shares.
    #[must_use]
    pub fn payments(&self) -> &PaymentLedger {
        &self.payments
    }
}
