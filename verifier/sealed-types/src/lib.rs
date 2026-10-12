//! The sealed client↔enclave match payload. The host relays the ciphertext and does not link this.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod aat;
mod errors;
mod messages;
mod response;

/// Pontifex channel domain shared by the consumer and enclave.
pub const MATCH_CHANNEL_DOMAIN: &str = "flamingo-verifier/matches/v3";

pub use aat::{AatInputs, provider_key_hash};
pub use errors::{
    ComparisonRole, Error, FailureReason, ImageFailureReason, ImageRole, InputFailureReason,
    ValidationTarget,
};
pub use messages::*;
pub use response::*;
pub use serde_bytes::ByteBuf;

/// Bound on sealed match bytes before decryption.
pub use flamingo_verifier_api_types::MAX_MATCH_BODY_BYTES;
