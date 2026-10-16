//! Typed face client for the sandboxed biometric worker.
//!
//! Launch, jail, seccomp policy and framed IPC come from `tabernaculum`; this crate owns the
//! face request validation, encoding and response checks.
mod client;
#[cfg(target_os = "linux")]
pub use client::SandboxClient;
pub use client::{FaceLimits, Rejection, SandboxClientError};
