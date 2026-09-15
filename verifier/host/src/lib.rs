//! HTTP host for the Flamingo Verifier — the untrusted side of the enclave boundary.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

// The mock enclave answers without attesting anything. Shipping one would turn every statement
// this host relays into an unsigned claim, so the release profile refuses to build it at all.
#[cfg(all(feature = "mock-enclave", not(debug_assertions)))]
compile_error!("the mock-enclave feature must not be enabled in a release build");

mod app_state;
mod environment;

pub mod enclave;
pub mod error;
pub mod payments;
pub mod routes;
pub mod server;

pub use app_state::{AppState, PaymentGate};
pub use environment::Environment;
