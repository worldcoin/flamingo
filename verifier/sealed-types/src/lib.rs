//! The sealed client↔enclave match payload. The host relays the ciphertext and does not link this.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod messages;

/// Pontifex channel domain shared by the consumer and enclave.
pub const MATCH_CHANNEL_DOMAIN: &str = "flamingo-verifier/matches/v2";

pub use error::Error;
pub use flamingo_verifier_protocol::match_token::LightGuardMatchingFrame;
pub use messages::*;
pub use serde_bytes::ByteBuf;

mod validation;
pub use validation::{ValidationFailure, ValidationReason, ValidationTarget};

/// Bound on sealed match bytes before decryption.
pub use flamingo_verifier_api_types::MAX_MATCH_BODY_BYTES;
