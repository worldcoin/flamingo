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
/// Authenticated single-threaded runtime provisioning.
pub mod bootstrap;
/// Face embedding generation and comparison.
pub mod face_engine;
/// Boot-scoped key material.
pub mod keys;
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
