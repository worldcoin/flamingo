use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{HostConfig, enclave::EnclaveClient};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    config: HostConfig,
    enclave_client: Arc<dyn EnclaveClient>,
    ws_connections: Arc<Semaphore>,
}

impl AppState {
    /// Creates API state from the host configuration and enclave client.
    #[must_use]
    pub fn new(config: HostConfig, enclave_client: Arc<dyn EnclaveClient>) -> Self {
        Self {
            ws_connections: Arc::new(Semaphore::new(config.ws_max_connections.get())),
            config,
            enclave_client,
        }
    }

    /// Returns the host configuration.
    #[must_use]
    pub const fn config(&self) -> &HostConfig {
        &self.config
    }

    /// Returns a shared enclave client.
    #[must_use]
    pub fn enclave_client(&self) -> Arc<dyn EnclaveClient> {
        Arc::clone(&self.enclave_client)
    }

    /// Returns how long a WebSocket session may idle before it is closed.
    #[must_use]
    pub const fn ws_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.config.ws_idle_timeout.get())
    }

    /// Takes a WebSocket slot, or returns `None` when the host is at its connection limit.
    ///
    /// The permit is released when it is dropped, so a session must hold it for its whole lifetime.
    #[must_use]
    pub fn try_acquire_ws(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.ws_connections).try_acquire_owned().ok()
    }
}
