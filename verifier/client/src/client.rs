//! Verification helpers for the Flamingo Verifier host, and the client that opens a session.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use flamingo_verifier_api_types::{EnclaveAssignmentResponse, ErrorEnvelope};
use flamingo_verifier_protocol::match_token::{self, EdDSAPublicKey, MatchClaims};
use flamingo_verifier_sealed_types::{MATCH_CHANNEL_DOMAIN, MatchInputs, MatchResult};
use pontifex::attestation::{VerifiedAttestation, Verifier};
use pontifex::{ChannelConsumer, ChannelDomain};

use crate::FlamingoVerifierSession;
use crate::config::Config;
use crate::error::Error;

/// Error code the host uses for a request that did not open.
const REASSIGN_REQUIRED: &str = "reassign_required";

/// Verifies an assignment response's attestation and binds it to the supplied public key.
pub fn verify_assignment(
    verifier: &Verifier,
    response: &EnclaveAssignmentResponse,
) -> Result<VerifiedAssignment, Error> {
    let document = STANDARD
        .decode(&response.attestation)
        .map_err(|_| Error::MalformedAssignment)?;
    let public_key = STANDARD
        .decode(&response.public_key)
        .map_err(|_| Error::MalformedAssignment)?;
    let (consumer, attestation) = ChannelConsumer::from_attestation(
        ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
        verifier,
        &document,
        &public_key,
    )
    .map_err(Error::Channel)?;

    Ok(VerifiedAssignment {
        attestation,
        consumer,
    })
}

/// Opens a sealed match response and verifies the statement it carries, if any.
pub fn open_verified_match(
    verifier: &Verifier,
    ciphertext: &[u8],
    opener: pontifex::ResponseOpener,
) -> Result<VerifiedMatchResult, Error> {
    let plaintext = opener
        .open_from_enclave(ciphertext)
        .map_err(Error::Channel)?;
    let result = MatchResult::from_padded_cbor(&plaintext).map_err(|_| Error::MalformedResult)?;

    // Only a statement needs the key, so a rejection skips the attestation entirely.
    if let MatchResult::Success(statement) = result {
        // Response encryption alone does not authenticate the signing key.
        let attested = verifier.verify_attestation_document(&statement.signing_key_attestation)?;
        let signing_key = <[u8; 32]>::try_from(
            attested
                .document()
                .public_key
                .as_ref()
                .ok_or(Error::InvalidSigningKey)?
                .as_slice(),
        )
        .map_err(|_| Error::InvalidSigningKey)
        .and_then(|bytes| {
            EdDSAPublicKey::from_compressed_bytes(bytes).map_err(|_| Error::InvalidSigningKey)
        })?;

        let claims = match_token::verify(&statement.token, &signing_key)
            .map_err(|_| Error::StatementInvalid)?;
        return Ok(VerifiedMatchResult::Success(Box::new(VerifiedMatch {
            statement,
            claims,
        })));
    }

    match result {
        MatchResult::Failed(reason) => Ok(VerifiedMatchResult::Failed(reason)),
        MatchResult::Success(_) => unreachable!("success was verified above"),
    }
}

/// Rejects a verified result whose claims do not match the requested inputs.
pub fn ensure_claims_match(
    inputs: &MatchInputs,
    result: &VerifiedMatchResult,
) -> Result<(), Error> {
    if let VerifiedMatchResult::Success(verified) = result
        && !inputs.matches_claims(&verified.claims)
    {
        return Err(Error::StatementInvalid);
    }

    Ok(())
}

/// Classifies an error envelope received over the WebSocket.
pub fn classify_envelope(envelope: &ErrorEnvelope) -> Error {
    if envelope.error.code == REASSIGN_REQUIRED {
        return Error::ReassignRequired;
    }

    Error::ApiFrame {
        code: envelope.error.code.clone(),
        allow_retry: envelope.allow_retry,
    }
}

/// An assignment whose attestation verified and whose encryption key is ready for sealing.
#[derive(Debug, Clone)]
pub struct VerifiedAssignment {
    /// Metadata read from the signed attestation document.
    attestation: VerifiedAttestation,
    consumer: ChannelConsumer,
}

impl VerifiedAssignment {
    /// Metadata from the verified channel-key attestation.
    #[must_use]
    pub const fn attestation(&self) -> &VerifiedAttestation {
        &self.attestation
    }

    /// The channel consumer bound to this assignment's verified key.
    #[must_use]
    pub const fn consumer(&self) -> &ChannelConsumer {
        &self.consumer
    }
}

/// Opens a WebSocket session with the Flamingo Verifier host.
///
/// Nothing is returned until the enclave that produced the assignment has been verified, so
/// callers cannot accidentally use an unattested key.
#[derive(Debug)]
pub struct FlamingoVerifierClient {
    config: Config,
}

impl FlamingoVerifierClient {
    /// Builds a client from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configuration is invalid.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.verifier()?;

        Ok(Self { config })
    }

    /// Creates the WebSocket upgrade request without sending it.
    ///
    /// Native-only: callers may add headers before passing the builder to [`Self::connect_with`].
    /// Browsers cannot set custom WebSocket handshake headers.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configured host URL cannot be used as a WebSocket endpoint.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn build_request(
        &self,
    ) -> Result<tokio_tungstenite::tungstenite::ClientRequestBuilder, Error> {
        crate::session::build_request(&self.config)
    }

    /// Opens the WebSocket, verifies the enclave assignment delivered on it, and returns a
    /// session that runs exactly one match over that same socket.
    ///
    /// The session owns both the socket and the verified assignment, so its match cannot be sent
    /// over a connection whose assignment was not verified.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the handshake fails, the host rejects or closes the connection, the
    /// assignment does not arrive or verify, or the exchange exceeds the configured deadline.
    pub async fn connect(&self) -> Result<FlamingoVerifierSession, Error> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.connect_with(self.build_request()?).await
        }
        #[cfg(target_arch = "wasm32")]
        {
            crate::session_browser::connect(&self.config, self.config.verifier()?).await
        }
    }

    /// Opens a WebSocket with a caller-customized upgrade request (native only).
    ///
    /// The `request` should be created from [`Self::build_request`] so it targets this client's
    /// configured endpoint. The assignment is verified before the session is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the handshake fails, the host rejects or closes the connection, the
    /// assignment does not arrive or verify, or the exchange exceeds the configured deadline.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_with(
        &self,
        request: tokio_tungstenite::tungstenite::ClientRequestBuilder,
    ) -> Result<FlamingoVerifierSession, Error> {
        crate::session::connect(&self.config, self.config.verifier()?, request).await
    }
}

/// A statement whose attestation and signature have been verified by the client.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedMatch {
    /// Encoded statement and attestation for proof consumers.
    pub statement: flamingo_verifier_sealed_types::AttestedStatement,
    /// Already-verified operation-specific claims.
    pub claims: MatchClaims,
}

/// Verified success or an encrypted unsigned rejection.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifiedMatchResult {
    /// Attested signed result and parsed claims.
    Success(Box<VerifiedMatch>),
    /// No statement issued.
    Failed(flamingo_verifier_sealed_types::FailureReason),
}
