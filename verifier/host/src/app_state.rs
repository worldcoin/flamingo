use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Semaphore;

use crate::{Environment, enclave::EnclaveClient};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
    pub(crate) uploads: Arc<Semaphore>,
    draining: Arc<AtomicBool>,
    worker_ready_file: Option<std::path::PathBuf>,
}

impl AppState {
    /// Creates API state from the runtime environment and enclave client.
    #[must_use]
    pub fn new(environment: Environment, enclave_client: Arc<dyn EnclaveClient>) -> Self {
        Self {
            environment,
            enclave_client,
            uploads: Arc::new(Semaphore::new(4)),
            draining: Arc::new(AtomicBool::new(false)),
            worker_ready_file: std::env::var_os("WORKER_READY_FILE").map(std::path::PathBuf::from),
        }
    }

    /// Stops admission and makes readiness fail while active requests drain.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
        self.uploads.close();
    }

    /// Whether shutdown has started.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
            || self
                .worker_ready_file
                .as_ref()
                .is_some_and(|path| !path.exists())
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
}
