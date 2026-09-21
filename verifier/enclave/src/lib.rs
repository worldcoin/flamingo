//! Secure-enclave runtime for private face comparison.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// Nitro Secure Module attestation.
pub mod attestation;
/// Inference operations implemented by the sandboxed biometric worker.
pub mod biometric_engine;
/// Single-threaded runtime provisioning with integrity checks.
#[cfg(target_os = "linux")]
pub mod bootstrap;
mod execution;
/// Boot-scoped key material.
pub mod keys;
mod operations;
/// PCP binding verification (transport-free).
pub mod pcp;
/// Nitro hardware RNG verification.
pub mod rng;
/// Pontifex operations exposed to the host.
pub mod routes;
/// Pontifex server setup and lifecycle.
pub mod server;
/// Boot-scoped enclave state.
pub mod state;
#[cfg(test)]
mod test_support;

#[cfg(any(target_os = "linux", test))]
mod error;
