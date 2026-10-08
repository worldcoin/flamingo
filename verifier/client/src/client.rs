//! Verification helpers for the Flamingo Verifier host, and the client that opens a session.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use flamingo_verifier_api_types::{EnclaveAssignmentResponse, ErrorEnvelope};
use flamingo_verifier_protocol::{
    EdDSAPublicKey,
    flamingo_token::{self, FlamingoClaims, canonical_field},
};
use flamingo_verifier_sealed_types::{DebugReport, MATCH_CHANNEL_DOMAIN, MatchResult, Payload};
use pontifex::attestation::{VerifiedAttestation, Verifier};
use pontifex::{ChannelConsumer, ChannelDomain};

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
        engine_hashes: parse_engine_hashes(&response.engine_hashes)?,
    })
}

/// Decodes the host's lowercase hex Engine hashes.
fn parse_engine_hashes(hashes: &[String]) -> Result<Vec<[u8; 32]>, Error> {
    hashes
        .iter()
        .map(|hash| {
            let mut bytes = [0; 32];
            // Lowercase only, so one Engine has one spelling.
            (!hash.bytes().any(|b| b.is_ascii_uppercase())
                && hex::decode_to_slice(hash, &mut bytes).is_ok())
            .then_some(bytes)
            .ok_or(Error::MalformedAssignment)
        })
        .collect()
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

            let claims = flamingo_token::verify(&statement.token, &signing_key)
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

/// Rejects a verified result whose claims do not match the request it answers.
pub fn ensure_claims_match(
    payload: &Payload,
    context: &RequestContext,
    result: &VerifiedMatchResult,
) -> Result<(), Error> {
    if let VerifiedMatchResult::Success { verified, .. } = result {
        let field = |bytes| canonical_field(bytes).map_err(|_| Error::StatementInvalid);
        let expected = payload.claims(field(&context.aud)?, field(&context.nonce)?, None);
        if verified.claims != expected {
            return Err(Error::StatementInvalid);
        }
    }
    Ok(())
}

/// The RP's binding for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestContext {
    /// The RP's `rpId`, a canonical big-endian field element.
    pub aud: [u8; 32],
    /// The RP's single-use nonce, a nonzero canonical big-endian field element.
    pub nonce: [u8; 32],
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
    engine_hashes: Vec<[u8; 32]>,
}

impl VerifiedAssignment {
    /// Metadata from the verified channel-key attestation.
    #[must_use]
    pub const fn attestation(&self) -> &VerifiedAttestation {
        &self.attestation
    }

    /// The host's list of loaded Engine bundles. Not attested: pick an `engine_hash` from it,
    /// and the enclave rejects a request for a bundle it did not load.
    #[must_use]
    pub fn engine_hashes(&self) -> &[[u8; 32]] {
        &self.engine_hashes
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
    use super::{
        Error, FlamingoClaims, RequestContext, VerifiedMatch, VerifiedMatchResult, canonical_field,
        ensure_claims_match, parse_engine_hashes,
    };
    use flamingo_verifier_protocol::{Fq, flamingo_token::FlamingoToken};
    use flamingo_verifier_sealed_types::{AttestedStatement, ByteBuf, DebugReport, Entry, Payload};

    fn payload() -> Payload {
        let entry = |data: &[u8]| Entry {
            data: data.to_vec().into(),
            meta: ByteBuf::new(),
        };
        Payload {
            meta: ByteBuf::new(),
            compare: vec![0, 1],
            entries: vec![entry(b"live"), entry(b"challenge")],
            pipeline: 2,
            engine_hash: [0x2a; 32].into(),
            match_strictness: 2,
        }
    }

    fn success(claims: &FlamingoClaims) -> VerifiedMatchResult {
        VerifiedMatchResult::Success {
            verified: Box::new(VerifiedMatch {
                statement: AttestedStatement {
                    token: FlamingoToken::from_bytes(vec![]),
                    signing_key_attestation: vec![],
                },
                claims: *claims,
            }),
            debug_report: DebugReport::NotProduced,
        }
    }

    #[test]
    fn claims_must_be_the_ones_the_request_implies() {
        let context = RequestContext {
            aud: [1; 32],
            nonce: [2; 32],
        };
        let expected = payload().claims(
            canonical_field(&context.aud).unwrap(),
            canonical_field(&context.nonce).unwrap(),
            None,
        );
        assert!(ensure_claims_match(&payload(), &context, &success(&expected)).is_ok());
        for changed in [
            FlamingoClaims {
                nonce: Fq::from(3u64),
                ..expected
            },
            FlamingoClaims {
                engine_config_hash: Fq::from(3u64),
                ..expected
            },
            FlamingoClaims {
                compared_entry_hashes: [Fq::from(3u64); 4],
                ..expected
            },
        ] {
            assert!(matches!(
                ensure_claims_match(&payload(), &context, &success(&changed)),
                Err(Error::StatementInvalid)
            ));
        }
    }

    #[test]
    fn engine_hashes_are_32_byte_lowercase_hex() {
        assert_eq!(
            parse_engine_hashes(&["2a".repeat(32)]).unwrap(),
            vec![[0x2a; 32]]
        );
        for invalid in [
            "2A".repeat(32),
            "2a".repeat(31),
            "2a".repeat(33),
            "zz".repeat(32),
        ] {
            assert!(matches!(
                parse_engine_hashes(&[invalid]),
                Err(Error::MalformedAssignment)
            ));
        }
    }
}
