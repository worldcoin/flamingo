//! The sealed client↔enclave match payload. The host relays the ciphertext and does not link this.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod errors;
mod messages;

/// Pontifex channel domain shared by the consumer and enclave.
pub const MATCH_CHANNEL_DOMAIN: &str = "flamingo-verifier/matches/v2";

pub use errors::{ComparisonRole, Error, FailureReason, ImageFailureReason, ImageRole};
pub use messages::*;
pub use serde_bytes::ByteBuf;

/// Bound on sealed match bytes before decryption.
pub use crate::api_types::MAX_MATCH_BODY_BYTES;
