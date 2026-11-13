//! Verification helpers for the Flamingo Verifier host, and the client that opens a session.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use eddsa_babyjubjub::EdDSAPublicKey;
use flamingo_verifier_api_types::{EnclaveAssignmentResponse, ErrorEnvelope};
#[cfg(feature = "dev")]
use flamingo_verifier_sealed_types::ByteBuf;
use flamingo_verifier_sealed_types::{
    CHANNEL_DOMAIN, DebugReport, FlamingoClaims, FlamingoToken, MatchResult, ReleaseManifest,
};
use pontifex::ChannelConsumer;
use pontifex::attestation::{VerifiedAttestation, Verifier};
use world_id_primitives::FieldElement;

use crate::config::Config;
use crate::error::Error;
use crate::session::FlamingoVerifierSession;

/// Error code the host uses for a request that did not open.
const REASSIGN_REQUIRED: &str = "reassign_required";

/// How the client verifies the enclave's attestations.
#[derive(Debug)]
pub enum Attestations {
    /// Nitro documents, verified by Pontifex.
    Nitro(Verifier),
    /// The unsigned documents of a `dev` Verifier, no older than `max_age`.
    #[cfg(feature = "dev")]
    Dev {
        /// How old a document's own timestamp may be.
        max_age: std::time::Duration,
    },
}

/// Verifies an assignment response's attestation, binds it to the supplied public key, and checks
/// that it attests the release manifest sent with it (WIP-201 §4.6 step 1).
pub fn verify_assignment(
    attestations: &Attestations,
    response: &EnclaveAssignmentResponse,
) -> Result<VerifiedAssignment, Error> {
    let document = STANDARD
        .decode(&response.attestation)
        .map_err(|_| Error::MalformedAssignment)?;
    let public_key = STANDARD
        .decode(&response.public_key)
        .map_err(|_| Error::MalformedAssignment)?;
    let (consumer, attestation, user_data) = match attestations {
        Attestations::Nitro(verifier) => {
            let (consumer, attestation) =
                ChannelConsumer::from_attestation(CHANNEL_DOMAIN, verifier, &document, &public_key)
                    .map_err(Error::Channel)?;
            let user_data = attestation
                .document()
                .user_data
                .as_ref()
                .map(|data| data.to_vec());
            (consumer, Some(attestation), user_data)
        }
        #[cfg(feature = "dev")]
        Attestations::Dev { max_age } => {
            let (consumer, user_data) = verify_dev_attestation(&document, &public_key, *max_age)?;
            (consumer, None, user_data)
        }
    };
    let release = attested_release(&response.release_manifest, user_data.as_deref())?;

    Ok(VerifiedAssignment {
        attestation,
        consumer,
        release,
    })
}

/// Checks a `dev` channel document as Pontifex checks a Nitro one, except for the signature: it is
/// fresh and commits to `public_key`. Returns the consumer and the document's `user_data`.
#[cfg(feature = "dev")]
fn verify_dev_attestation(
    document: &[u8],
    public_key: &[u8],
    max_age: std::time::Duration,
) -> Result<(ChannelConsumer, Option<Vec<u8>>), Error> {
    use pontifex::ChannelError;

    let document = fresh_dev_attestation(document, max_age)
        .map_err(|error| Error::Channel(ChannelError::Attestation(error)))?;
    if document.public_key.as_slice() != CHANNEL_DOMAIN.public_key_commitment(public_key) {
        return Err(Error::Channel(ChannelError::KeyCommitmentMismatch));
    }
    let consumer = ChannelConsumer::from_unverified_public_key(CHANNEL_DOMAIN, public_key)
        .map_err(Error::Channel)?;
    Ok((consumer, document.user_data.map(ByteBuf::into_vec)))
}

/// Decodes a `dev` document and checks that it is no older than `max_age`.
#[cfg(feature = "dev")]
fn fresh_dev_attestation(
    document: &[u8],
    max_age: std::time::Duration,
) -> Result<flamingo_verifier_sealed_types::dev::DevAttestation, pontifex::attestation::Error> {
    use flamingo_verifier_sealed_types::dev::DevAttestation;
    use pontifex::attestation;

    let document = DevAttestation::from_cbor(document)
        .map_err(|_| attestation::Error::ParseError("not a dev attestation".to_owned()))?;
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let age_millis = now_millis.saturating_sub(document.timestamp_millis);
    let max_age = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
    if age_millis > max_age {
        return Err(attestation::Error::Stale {
            age_millis,
            max_age,
        });
    }
    Ok(document)
}

/// The release manifest `jws`, if the channel attestation's `user_data` is its `release_hash`.
fn attested_release(jws: &str, user_data: Option<&[u8]>) -> Result<ReleaseManifest, Error> {
    let release = ReleaseManifest::from_jws(jws).map_err(|_| Error::MalformedAssignment)?;
    if user_data != Some(release.release_hash().as_slice()) {
        return Err(Error::ReleaseNotAttested);
    }
    Ok(release)
}

/// Opens a sealed match response and verifies the statement it carries, if any.
pub fn open_verified_match(
    attestations: &Attestations,
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
            let signing_key =
                attested_signing_key(attestations, &statement.signing_key_attestation)?;

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

/// The signing key `document` attests.
fn attested_signing_key(
    attestations: &Attestations,
    document: &[u8],
) -> Result<EdDSAPublicKey, Error> {
    let attested;
    #[cfg(feature = "dev")]
    let dev;
    let key = match attestations {
        Attestations::Nitro(verifier) => {
            // Response encryption alone does not authenticate the signing key.
            attested = verifier.verify_attestation_document(document)?;
            attested
                .document()
                .public_key
                .as_ref()
                .ok_or(Error::InvalidSigningKey)?
                .as_slice()
        }
        #[cfg(feature = "dev")]
        Attestations::Dev { max_age } => {
            dev = fresh_dev_attestation(document, *max_age)?;
            // Only the channel key's document carries `user_data`.
            if dev.user_data.is_some() {
                return Err(Error::InvalidSigningKey);
            }
            dev.public_key.as_slice()
        }
    };
    <[u8; 32]>::try_from(key)
        .map_err(|_| Error::InvalidSigningKey)
        .and_then(|bytes| {
            EdDSAPublicKey::from_compressed_bytes(bytes).map_err(|_| Error::InvalidSigningKey)
        })
}

/// Rejects a verified result whose claims differ from `expected`.
///
/// The Verifier sets `now` from its own clock, and signs either the `billing_nullifier` the request
/// carried or `0` for an RP it does not bill (WIP-201 §4.5), so those two claims are checked apart.
pub fn ensure_claims_match(
    expected: &FlamingoClaims,
    billing_nullifier: FieldElement,
    result: &VerifiedMatchResult,
) -> Result<(), Error> {
    let VerifiedMatchResult::Success { verified, .. } = result else {
        return Ok(());
    };
    let claims = &verified.claims;
    let expected = FlamingoClaims {
        now: claims.now,
        billing_nullifier: claims.billing_nullifier,
        ..*expected
    };
    let billing = claims.billing_nullifier == FieldElement::ZERO
        || claims.billing_nullifier == billing_nullifier;
    if *claims == expected && billing {
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
    /// Metadata read from the signed attestation document; `None` for a `dev` Verifier's.
    attestation: Option<VerifiedAttestation>,
    consumer: ChannelConsumer,
    /// The release whose `release_hash` the attestation carries.
    release: ReleaseManifest,
}

impl VerifiedAssignment {
    /// Metadata from the verified channel-key Nitro attestation; `None` for a `dev` Verifier's.
    #[must_use]
    pub const fn attestation(&self) -> Option<&VerifiedAttestation> {
        self.attestation.as_ref()
    }

    /// The channel consumer bound to this assignment's verified key.
    #[must_use]
    pub const fn consumer(&self) -> &ChannelConsumer {
        &self.consumer
    }

    /// The attested release the enclave runs. Its manifest signature is not verified here
    /// (WIP-201 §4.3.4).
    #[must_use]
    pub const fn release(&self) -> &ReleaseManifest {
        &self.release
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
        crate::session::connect(&self.config, self.config.attestations()?, request).await
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
        Attestations, CHANNEL_DOMAIN, Error, FlamingoClaims, ReleaseManifest, STANDARD,
        VerifiedMatch, VerifiedMatchResult, attested_release, attested_signing_key,
        ensure_claims_match, verify_assignment,
    };
    use base64::Engine as _;
    use flamingo_verifier_api_types::EnclaveAssignmentResponse;
    use flamingo_verifier_sealed_types::{
        AttestedStatement, ByteBuf, DebugReport, dev::DevAttestation, testing,
    };
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

    /// An assignment for a fresh channel key, attested by a `dev` document built by `attest` from
    /// the key's commitment and the manifest's `release_hash`.
    fn dev_assignment(
        attest: impl FnOnce([u8; 32], Vec<u8>) -> DevAttestation,
    ) -> EnclaveAssignmentResponse {
        let enclave = pontifex::ChannelEnclave::generate(CHANNEL_DOMAIN).unwrap();
        let manifest = testing::manifest(testing::TEST_ENGINE_HASH, 1);
        let release_hash = ReleaseManifest::from_jws(&manifest).unwrap().release_hash();
        let document = attest(enclave.public_key_commitment(), release_hash.to_vec());
        EnclaveAssignmentResponse {
            attestation: STANDARD.encode(document.to_cbor().unwrap()),
            public_key: STANDARD.encode(enclave.public_key()),
            release_manifest: manifest,
        }
    }

    fn dev_document(commitment: [u8; 32], user_data: Vec<u8>) -> DevAttestation {
        DevAttestation {
            public_key: ByteBuf::from(commitment),
            user_data: Some(ByteBuf::from(user_data)),
            timestamp_millis: u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn a_nitro_policy_rejects_dev_attestations() {
        let nitro = Attestations::Nitro(
            crate::Config::dangerously_skip_measurements("http://localhost:8000")
                .unwrap()
                .verifier()
                .unwrap(),
        );
        assert!(matches!(
            verify_assignment(&nitro, &dev_assignment(dev_document)),
            Err(Error::Channel(_))
        ));
        let key = eddsa_babyjubjub::EdDSAPrivateKey::from_bytes([7; 32]).public();
        assert!(matches!(
            attested_signing_key(&nitro, &key.to_compressed_bytes().unwrap()),
            Err(Error::Attestation(_))
        ));
    }

    #[cfg(feature = "dev")]
    #[test]
    fn a_dev_policy_binds_the_channel_key_and_release() {
        use pontifex::{ChannelError, attestation};

        let Attestations::Dev { max_age } =
            crate::Config::dangerously_accept_dev_attestation("http://localhost:8000")
                .unwrap()
                .attestations()
                .unwrap()
        else {
            panic!("expected a dev policy")
        };
        let dev = Attestations::Dev { max_age };
        let assignment = verify_assignment(&dev, &dev_assignment(dev_document)).unwrap();
        assert!(assignment.attestation().is_none());

        assert!(matches!(
            verify_assignment(
                &dev,
                &dev_assignment(|_, release_hash| dev_document([0; 32], release_hash))
            ),
            Err(Error::Channel(ChannelError::KeyCommitmentMismatch))
        ));
        assert!(matches!(
            verify_assignment(
                &dev,
                &dev_assignment(|commitment, _| dev_document(commitment, vec![0; 32]))
            ),
            Err(Error::ReleaseNotAttested)
        ));
        assert!(matches!(
            verify_assignment(
                &dev,
                &dev_assignment(|commitment, _| DevAttestation {
                    user_data: None,
                    ..dev_document(commitment, vec![])
                })
            ),
            Err(Error::ReleaseNotAttested)
        ));
        assert!(matches!(
            verify_assignment(
                &dev,
                &dev_assignment(|commitment, release_hash| DevAttestation {
                    timestamp_millis: 0,
                    ..dev_document(commitment, release_hash)
                })
            ),
            Err(Error::Channel(ChannelError::Attestation(
                attestation::Error::Stale { .. }
            )))
        ));

        let key = eddsa_babyjubjub::EdDSAPrivateKey::from_bytes([7; 32]).public();
        let raw = key.to_compressed_bytes().unwrap();
        let signing = |public_key: &[u8], user_data: Option<Vec<u8>>, timestamp_millis| {
            DevAttestation {
                public_key: ByteBuf::from(public_key),
                user_data: user_data.map(ByteBuf::from),
                timestamp_millis,
            }
            .to_cbor()
            .unwrap()
        };
        let now = dev_document([0; 32], vec![]).timestamp_millis;
        assert_eq!(
            attested_signing_key(&dev, &signing(&raw, None, now)).unwrap(),
            key
        );
        assert!(matches!(
            attested_signing_key(&dev, &raw),
            Err(Error::Attestation(attestation::Error::ParseError(_)))
        ));
        assert!(matches!(
            attested_signing_key(&dev, &signing(&raw[1..], None, now)),
            Err(Error::InvalidSigningKey)
        ));
        assert!(matches!(
            attested_signing_key(&dev, &signing(&raw, Some(vec![0; 32]), now)),
            Err(Error::InvalidSigningKey)
        ));
        assert!(matches!(
            attested_signing_key(&dev, &signing(&raw, None, 0)),
            Err(Error::Attestation(attestation::Error::Stale { .. }))
        ));
    }

    #[test]
    fn the_release_must_be_the_attested_one() {
        use flamingo_verifier_sealed_types::{ReleaseManifest, testing};
        let jws = testing::manifest(testing::TEST_ENGINE_HASH, 1);
        let release_hash = ReleaseManifest::from_jws(&jws).unwrap().release_hash();
        assert_eq!(
            attested_release(&jws, Some(&release_hash))
                .unwrap()
                .release_hash(),
            release_hash
        );
        let other = testing::manifest(testing::TEST_ENGINE_HASH, 2);
        for (jws, user_data) in [
            (&jws, None),
            (&jws, Some(&[0u8; 32][..])),
            (&other, Some(&release_hash[..])),
        ] {
            assert!(matches!(
                attested_release(jws, user_data),
                Err(Error::ReleaseNotAttested)
            ));
        }
        assert!(matches!(
            attested_release("not.a.jws", Some(&release_hash)),
            Err(Error::MalformedAssignment)
        ));
    }

    #[test]
    fn claims_must_be_the_ones_the_request_implies() {
        let expected = FlamingoClaims {
            now: 1,
            compared_entry_hashes: [
                1u64.into(),
                2u64.into(),
                FieldElement::ZERO,
                FieldElement::ZERO,
            ],
            aud: 1u64.into(),
            nonce: 2u64.into(),
            aat: None,
            compare_sources: 256,
            engine_config_hash: 3u64.into(),
            billing_nullifier: FieldElement::ZERO,
        };
        let billed = 7u64.into();
        for accepted in [
            expected,
            FlamingoClaims { now: 9, ..expected },
            FlamingoClaims {
                billing_nullifier: billed,
                ..expected
            },
        ] {
            assert!(ensure_claims_match(&expected, billed, &success(&accepted)).is_ok());
        }
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
                compare_sources: 1,
                ..expected
            },
            FlamingoClaims {
                billing_nullifier: 8u64.into(),
                ..expected
            },
        ] {
            assert!(matches!(
                ensure_claims_match(&expected, billed, &success(&changed)),
                Err(Error::StatementInvalid)
            ));
        }
    }
}
