//! Bounded verdict client for the sandboxed Flamingo Engine.
//!
//! Tabernaculum owns process isolation and framed transport; this crate checks readiness,
//! request correlation and verdicts without interpreting the canonical Payload.
mod client;
#[cfg(target_os = "linux")]
pub use client::SandboxClient;
pub use client::{EngineLimits, Rejection, SandboxClientError};
