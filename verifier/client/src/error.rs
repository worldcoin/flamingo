//! The crate's error type.

use pontifex::{ChannelError, attestation};

/// Failures while configuring or calling the host.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A configuration field was not usable.
    #[error("invalid {attribute}: {reason}")]
    InvalidConfig {
        /// Which field.
        attribute: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The configuration JSON could not be parsed.
    #[error("failed to parse config: {0}")]
    MalformedConfig(String),

    /// An attestation document did not verify.
    #[error(transparent)]
    Attestation(#[from] attestation::Error),

    /// The assignment document or public key was not valid base64.
    #[error("assignment document or public key was not valid base64")]
    MalformedAssignment,

    /// The assignment is stale: re-assign, re-seal, and retry once.
    #[error("the request was not sealed to the enclave's current key; re-assign and retry once")]
    ReassignRequired,

    /// Channel attestation, key binding, sealing or opening failed.
    #[error("sealed channel failure: {0:?}")]
    Channel(#[source] ChannelError),

    /// The sealed plaintext was not a match result.
    #[error("sealed response was not a match result")]
    MalformedResult,

    /// The attested signing public key was not a valid `BabyJubJub` point.
    #[error("attested signing public key was invalid")]
    InvalidSigningKey,

    /// The statement did not verify under the attested signing key.
    #[error("match statement did not verify under the attested signing key")]
    StatementInvalid,

    /// The WebSocket handshake or an I/O operation on it failed.
    #[error("WebSocket transport failed: {0}")]
    WebSocket(#[source] tokio_tungstenite::tungstenite::Error),

    /// An operation did not finish within its configured deadline.
    #[error("the host did not respond within the configured deadline")]
    Timeout,

    /// The host closed the WebSocket before the exchange completed.
    #[error("the host closed the connection before the exchange completed")]
    ConnectionClosed,

    /// A frame was not the message the protocol expects at that point.
    #[error("the host sent an unexpected or malformed message")]
    MalformedMessage,

    /// The host returned an error envelope over the WebSocket.
    #[error("host returned error ({code})")]
    ApiFrame {
        /// Machine-readable code from the envelope.
        code: String,
        /// Whether the host says the request may be retried.
        allow_retry: bool,
    },
}
