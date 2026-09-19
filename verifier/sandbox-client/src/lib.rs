//! Verifier-enclave client for a sandboxed external worker.
//!
//! Owns worker launch under Linux Minijail, readiness, bounded IPC and teardown.
mod client;
mod transport;
pub use client::{SandboxClient, SandboxClientConfig, SandboxClientError};
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
pub use process::{SandboxConfig, WORKER_UID, Worker, WorkerError};
