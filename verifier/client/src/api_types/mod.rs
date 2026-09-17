//! The HTTP contract between the `Verifier` client and its host.
//!
//! One definition per message, so the two ends cannot drift apart. Shared limits also apply
//! to the sealed payload handled by the enclave.

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

pub use assignment::EnclaveAssignmentResponse;
pub use error::{ApiErrorResponse, ErrorBody};
pub use matches::*;
