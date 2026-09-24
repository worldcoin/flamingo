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

    /// The HTTP client could not be constructed.
    #[error("failed to build HTTP client: {0}")]
    Transport(#[source] reqwest::Error),

    /// The request failed, timed out, or the body could not be read.
    #[error("request to the host failed: {0}")]
    Request(#[source] reqwest::Error),

    /// The host answered with a non-success status.
    #[error("host returned HTTP {0}")]
    Status(u16),

    /// The response was not the JSON the endpoint is specified to return.
    #[error("response was not valid JSON: {0}")]
    MalformedResponse(#[source] reqwest::Error),

    /// An attestation document did not verify.
    #[error(transparent)]
    Attestation(#[from] attestation::Error),

    /// The assignment document or public key was not valid base64.
    #[error("assignment document or public key was not valid base64")]
    MalformedAssignment,

    /// The host answered with an error envelope.
    #[error("host returned HTTP {status} ({code})")]
    Api {
        /// HTTP status the host chose.
        status: u16,
        /// Machine-readable code from the envelope.
        code: String,
        /// Whether the host says the request may be retried.
        allow_retry: bool,
    },

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

    /// A frame was not the message the v2 protocol expects at that point.
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
