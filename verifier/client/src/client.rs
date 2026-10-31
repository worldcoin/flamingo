//! Verification helpers for the Flamingo Verifier host, and the client that opens a session.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use eddsa_babyjubjub::EdDSAPublicKey;
use flamingo_verifier_api_types::{EnclaveAssignmentResponse, ErrorEnvelope};
use flamingo_verifier_sealed_types::{
    CHANNEL_DOMAIN, DebugReport, FlamingoClaims, FlamingoToken, MatchResult,
};
use pontifex::ChannelConsumer;
use pontifex::attestation::{VerifiedAttestation, Verifier};
use world_id_primitives::FieldElement;

use crate::config::Config;
use crate::error::Error;
use crate::session::FlamingoVerifierSession;

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
    let (consumer, attestation) =
        ChannelConsumer::from_attestation(CHANNEL_DOMAIN, verifier, &document, &public_key)
            .map_err(Error::Channel)?;

    Ok(VerifiedAssignment {
        attestation,
        consumer,
        release_hashes: response.release_hashes.clone(),
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
    let response = MatchResult::from_padded_cbor(&plaintext).map_err(|_| Error::MalformedResult)?;

    match response {
        MatchResult::Success {
            statement,
            debug_report,
        } => {
            // Response encryption alone does not authenticate the signing key.
            let attested =
                verifier.verify_attestation_document(&statement.signing_key_attestation)?;
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

            let claims = FlamingoToken::from_cwt(&statement.token)
                .and_then(|token| token.verify(&signing_key).copied())
                .map_err(|_| Error::StatementInvalid)?;
            Ok(VerifiedMatchResult::Success {
                verified: Box::new(VerifiedMatch { statement, claims }),
                debug_report,
            })
        }
        MatchResult::Failed {
            reason,
            debug_report,
        } => Ok(VerifiedMatchResult::Failed {
            reason,
            debug_report,
        }),
    }
}

/// Rejects a verified result whose claims differ from `expected`.
pub fn ensure_claims_match(
    expected: &FlamingoClaims,
    result: &VerifiedMatchResult,
) -> Result<(), Error> {
    let VerifiedMatchResult::Success { verified, .. } = result else {
        return Ok(());
    };
    // A Verifier that does not bill the RP signs `billing_nullifier = 0`, whatever the request
    // carried (WIP-107 §4.7); any other value must be the one sent.
    let unbilled = FlamingoClaims {
        billing_nullifier: FieldElement::ZERO,
        ..*expected
    };
    if verified.claims == *expected || verified.claims == unbilled {
        Ok(())
    } else {
        Err(Error::StatementInvalid)
    }
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
    /// Not attested: a wrong list only makes requests fail.
    release_hashes: Vec<[u8; 32]>,
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

    /// The `release_hash` of every release the host says this enclave serves.
    #[must_use]
    pub fn release_hashes(&self) -> &[[u8; 32]] {
        &self.release_hashes
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
    /// Callers may add headers before passing the builder to [`Self::connect_with`].
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configured host URL cannot be used as a WebSocket endpoint.
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
        self.connect_with(self.build_request()?).await
    }

    /// Opens a WebSocket with a caller-customized upgrade request.
    ///
    /// The `request` should be created from [`Self::build_request`] so it targets this client's
    /// configured endpoint. The assignment is verified before the session is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the handshake fails, the host rejects or closes the connection, the
    /// assignment does not arrive or verify, or the exchange exceeds the configured deadline.
    pub async fn connect_with(
        &self,
        request: tokio_tungstenite::tungstenite::ClientRequestBuilder,
    ) -> Result<FlamingoVerifierSession, Error> {
        crate::session::connect(&self.config, self.config.verifier()?, request).await
    }
}

/// A Flamingo Token whose attestation, signature and claims the client verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMatch {
    /// Encoded token and attestation for proof consumers.
    pub statement: flamingo_verifier_sealed_types::AttestedStatement,
    /// The token's claims, equal to those the request implies.
    pub claims: FlamingoClaims,
}

/// Verified success or an encrypted unsigned rejection, with bounded worker diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedMatchResult {
    /// Attested signed result and parsed claims.
    Success {
        /// Signature-verified statement and claims.
        verified: Box<VerifiedMatch>,
        /// Original worker diagnostics, not signed proof claims.
        debug_report: DebugReport,
    },
    /// No statement issued.
    Failed {
        /// Input or biometric rejection.
        reason: flamingo_verifier_sealed_types::FailureReason,
        /// Original worker diagnostics, if produced.
        debug_report: DebugReport,
    },
}

#[cfg(test)]
mod tests {
    use super::{Error, FlamingoClaims, VerifiedMatch, VerifiedMatchResult, ensure_claims_match};
    use flamingo_verifier_sealed_types::{AttestedStatement, DebugReport};
    use world_id_primitives::FieldElement;

    fn success(claims: &FlamingoClaims) -> VerifiedMatchResult {
        VerifiedMatchResult::Success {
            verified: Box::new(VerifiedMatch {
                statement: AttestedStatement {
                    token: vec![],
                    signing_key_attestation: vec![],
                },
                claims: *claims,
            }),
            debug_report: DebugReport::NotProduced,
        }
    }

    #[test]
    fn claims_must_be_the_ones_the_request_implies() {
        let expected = FlamingoClaims {
            compared_entry_hashes: [
                1u64.into(),
                2u64.into(),
                FieldElement::ZERO,
                FieldElement::ZERO,
            ],
            aud: 1u64.into(),
            nonce: 2u64.into(),
            aat: None,
            engine_config_hash: 3u64.into(),
            billing_nullifier: 5u64.into(),
        };
        assert!(ensure_claims_match(&expected, &success(&expected)).is_ok());
        let unbilled = FlamingoClaims {
            billing_nullifier: FieldElement::ZERO,
            ..expected
        };
        assert!(ensure_claims_match(&expected, &success(&unbilled)).is_ok());
        for changed in [
            FlamingoClaims {
                nonce: 3u64.into(),
                ..expected
            },
            FlamingoClaims {
                engine_config_hash: 4u64.into(),
                ..expected
            },
            FlamingoClaims {
                compared_entry_hashes: [3u64.into(); 4],
                ..expected
            },
            FlamingoClaims {
                billing_nullifier: 6u64.into(),
                ..expected
            },
        ] {
            assert!(matches!(
                ensure_claims_match(&expected, &success(&changed)),
                Err(Error::StatementInvalid)
            ));
        }
    }
}
