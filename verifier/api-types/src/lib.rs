//! The HTTP contract between the `Verifier` client and its host.
//!
//! One definition per message, so the two ends cannot drift apart. Host-side only: the contract
//! stops at the host, so no enclave links it.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod assignment;
mod error;
mod matches;
mod websocket;

pub use assignment::EnclaveAssignmentResponse;
pub use error::{ErrorBody, ErrorEnvelope};
pub use matches::*;
pub use websocket::{ClientMessage, HostMessage};
