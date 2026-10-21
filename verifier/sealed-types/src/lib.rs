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
mod response;

/// The WIP-201 request channel: `info` is `CHANNEL_DOMAIN || direction`, and the channel
/// attestation commits to `SHA-256(CHANNEL_KEY_DOMAIN || channel_key)`.
pub const CHANNEL_DOMAIN: pontifex::ChannelDomain =
    pontifex::ChannelDomain::new("WORLD-ID/WIP-201/CHANNEL")
        .with_key_commitment_domain(world_id_flamingo::CHANNEL_KEY_DOMAIN);

/// WIP-201 `MAX_ATTESTATION_AGE`: the oldest channel or signing-key attestation to accept.
pub const MAX_ATTESTATION_AGE: std::time::Duration =
    std::time::Duration::from_secs(world_id_flamingo::MAX_ATTESTATION_AGE);

pub use errors::{
    ComparisonRole, Error, FailureReason, ImageFailureReason, ImageRole, InputFailureReason,
    ValidationTarget,
};
pub use messages::*;
pub use response::*;
pub use serde_bytes::ByteBuf;
pub use world_id_flamingo::{
    AatClaims, AatInputs, Entry, FlamingoClaims, FlamingoToken, Payload, Request, RequestError,
};

/// Bound on sealed match bytes before decryption.
pub use flamingo_verifier_api_types::MAX_MATCH_BODY_BYTES;
