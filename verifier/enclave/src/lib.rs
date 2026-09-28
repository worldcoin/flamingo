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

#[cfg(any(target_os = "linux", test))]
mod error;

/// Runs synchronous enclave work without blocking the async runtime.
pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, flamingo_verifier_enclave_types::Error> {
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _entered = span.enter();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|_| {
            tracing::error!("blocking enclave task panicked");
            std::process::exit(1);
        })
    })
    .await
    .map_err(|_| flamingo_verifier_enclave_types::Error::Internal)
}
