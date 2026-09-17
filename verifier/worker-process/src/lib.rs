//! Bounded external-worker IPC and Linux Minijail lifecycle.
mod client;
mod transport;
pub use client::{WorkerClient, WorkerClientConfig, WorkerClientError};
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
pub use process::{SandboxConfig, WORKER_UID, Worker, WorkerError};
