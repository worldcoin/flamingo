//! An in-process Verifier for tests. Never in an enclave binary.
//!
//! Runs outside Nitro with unsigned attestations and a stub Engine, and calls the enclave
//! operations without vsock. `main.rs` keeps it out of enclave binaries.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use flamingo_verifier_enclave_types::{
    self as enclave_types, BillingStatus, BillingUpdateRequest, GetEncryptionKeyRequest,
    HealthRequest, KeyAttestation, LoadReleaseRequest, MatchRequest, MatchResponse,
};
use flamingo_verifier_sealed_types::{ByteBuf, DebugReport, dev::DevAttestation};
use tokio::time::Instant;
use world_id_flamingo::ReleaseManifest;

use crate::{
    attestation::{Attestation, Attestor},
    biometric_engine::{
        BiometricEngine, BiometricError, DeepFaceScores, GrayBadgeScores, LiveCapture,
    },
    routes,
    state::EnclaveState,
};

/// The similarity the stub Engine reports for every pair: match strictness 2 passes, 3 fails.
pub const DEV_SCORE: f64 = 0.92;

/// A Verifier with the stub Engine and `manifest` loaded, billing nothing.
///
/// Its signing key attestation is the raw 32-byte compressed key. Its channel key attestation is
/// a CBOR [`DevAttestation`] carrying the loaded `release_hash`.
///
/// # Errors
/// Returns [`enclave_types::Error::ReleaseRejected`] for a manifest the Verifier rejects.
pub fn verifier(manifest: &str) -> Result<Arc<EnclaveState>, enclave_types::Error> {
    let engine_hash = ReleaseManifest::from_jws(manifest)
        .map_err(|_| enclave_types::Error::ReleaseRejected)?
        .payload()
        .engine_hash;
    let state = EnclaveState::generate_with(
        Arc::new(SigningKeyAttestor),
        Arc::new(ChannelKeyAttestor),
        Box::new(StubEngine),
        engine_hash,
        None,
    )?;
    state.load_release(manifest)?;
    Ok(Arc::new(state))
}

/// The enclave's health operation.
///
/// # Errors
/// As the enclave's operation.
pub async fn health(state: Arc<EnclaveState>) -> Result<(), enclave_types::Error> {
    routes::health::handler(state, HealthRequest).await
}

/// The enclave's encryption key operation.
///
/// # Errors
/// As the enclave's operation.
pub async fn encryption_key(
    state: Arc<EnclaveState>,
) -> Result<KeyAttestation, enclave_types::Error> {
    routes::encryption_key::handler(state, GetEncryptionKeyRequest).await
}

/// The enclave's match operation.
///
/// # Errors
/// As the enclave's operation.
pub async fn run_match(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    routes::matches::handler(state, request).await
}

/// The enclave's release load operation.
///
/// # Errors
/// As the enclave's operation.
pub async fn load_release(
    state: Arc<EnclaveState>,
    request: LoadReleaseRequest,
) -> Result<(), enclave_types::Error> {
    routes::release::handler(state, request).await
}

/// The enclave's billing state update operation.
///
/// # Errors
/// As the enclave's operation.
pub async fn update_billing(
    state: Arc<EnclaveState>,
    request: BillingUpdateRequest,
) -> Result<BillingStatus, enclave_types::Error> {
    routes::billing::handler(state, request).await
}

/// Attests the signing key as the key itself.
struct SigningKeyAttestor;

impl Attestor for SigningKeyAttestor {
    fn attest(
        &self,
        public_key: &[u8],
        user_data: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error> {
        if user_data.is_some() {
            tracing::error!("the dev signing key attestation carries no user_data");
            return Err(enclave_types::Error::AttestationFailed);
        }
        Ok(Attestation {
            document: public_key.to_vec(),
            timestamp_millis: now_millis()?,
        })
    }
}

/// Attests the channel key commitment in a [`DevAttestation`].
struct ChannelKeyAttestor;

impl Attestor for ChannelKeyAttestor {
    fn attest(
        &self,
        public_key: &[u8],
        user_data: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error> {
        let timestamp_millis = now_millis()?;
        let document = DevAttestation {
            public_key: ByteBuf::from(public_key),
            user_data: user_data.map(ByteBuf::from),
            timestamp_millis,
        }
        .to_cbor()
        .map_err(|_| enclave_types::Error::AttestationFailed)?;
        Ok(Attestation {
            document,
            timestamp_millis,
        })
    }
}

/// The system time, which the dev Verifier clock syncs to.
fn now_millis() -> Result<u64, enclave_types::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or(enclave_types::Error::AttestationFailed)
}

/// Scores every compared pair [`DEV_SCORE`] without looking at the images.
struct StubEngine;

#[async_trait]
impl BiometricEngine for StubEngine {
    async fn deepface(
        &self,
        _: Vec<u8>,
        _: LiveCapture,
        _: Vec<u8>,
        _: Instant,
    ) -> Result<DeepFaceScores, BiometricError> {
        Ok(DeepFaceScores {
            credential_live: DEV_SCORE,
            credential_challenge: DEV_SCORE,
            live_challenge: DEV_SCORE,
            debug_report: DebugReport::NotProduced,
        })
    }

    async fn graybadge(
        &self,
        _: LiveCapture,
        _: Vec<u8>,
        _: Instant,
    ) -> Result<GrayBadgeScores, BiometricError> {
        Ok(GrayBadgeScores {
            live_challenge: DEV_SCORE,
            debug_report: DebugReport::NotProduced,
        })
    }

    fn terminate(&self) {}
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use eddsa_babyjubjub::EdDSAPublicKey;
    use flamingo_verifier_sealed_types::{
        CHANNEL_DOMAIN, ComparisonRole, Entry, FailureReason, FlamingoToken, MatchResult, Payload,
        Request, dev::DevAttestation, testing,
    };
    use pontifex::ChannelConsumer;
    use world_id_primitives::FieldElement;

    use super::{EnclaveState, MatchRequest, encryption_key, health, run_match, verifier};
    use crate::pipeline::{PIPELINE_DEEPFACE, PIPELINE_GRAYBADGE_LIGHTGUARD};

    fn state() -> Arc<EnclaveState> {
        verifier(&testing::manifest(testing::TEST_ENGINE_HASH, 1)).unwrap()
    }

    fn entry(data: &[u8], meta: &[u8]) -> Entry {
        Entry {
            data: data.to_vec(),
            meta: meta.to_vec(),
        }
    }

    fn deep_face(match_strictness: u8) -> Payload {
        Payload {
            pipeline_id: PIPELINE_DEEPFACE,
            match_strictness,
            hints: Vec::new(),
            entries: vec![
                entry(b"orb", b""),
                entry(b"live", b""),
                entry(b"challenge", b""),
            ],
            pipeline_inputs: vec![1],
            compare: vec![0, 1, 2],
        }
    }

    fn gray_badge() -> Payload {
        Payload {
            pipeline_id: PIPELINE_GRAYBADGE_LIGHTGUARD,
            match_strictness: 2,
            hints: Vec::new(),
            entries: vec![
                entry(b"lit", b"illuminated"),
                entry(b"challenge", b""),
                entry(b"dark", b"unilluminated"),
            ],
            pipeline_inputs: vec![0, 2],
            compare: vec![0, 1],
        }
    }

    async fn exchange(state: &Arc<EnclaveState>, payload: &Payload, nonce: u64) -> MatchResult {
        let request = Request::new(
            1u64.into(),
            nonce.into(),
            state.now() + 300,
            FieldElement::ZERO,
            payload,
            None,
        )
        .unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            CHANNEL_DOMAIN,
            &state.channel().public_key(),
        )
        .unwrap();
        let (sealed, opener) = consumer.seal_to_enclave(&request.encode()).unwrap();
        let response = run_match(
            Arc::clone(state),
            MatchRequest {
                body: sealed.into(),
            },
        )
        .await
        .unwrap();
        MatchResult::from_padded_cbor(&opener.open_from_enclave(&response.ciphertext).unwrap())
            .unwrap()
    }

    #[tokio::test]
    async fn serves_the_dev_attestations_of_the_loaded_release() {
        let state = state();
        health(Arc::clone(&state)).await.unwrap();
        let key = encryption_key(Arc::clone(&state)).await.unwrap();
        let document = DevAttestation::from_cbor(&key.document).unwrap();
        assert_eq!(
            document.public_key.as_slice(),
            CHANNEL_DOMAIN.public_key_commitment(&key.public_key)
        );
        assert_eq!(
            document.user_data.unwrap().as_slice(),
            state.release().unwrap().release_hash()
        );
        assert_eq!(document.timestamp_millis / 1000, state.now());
        assert_eq!(
            state.signing_key_attestation(),
            state.signing_public_key().to_compressed_bytes().unwrap()
        );
    }

    #[tokio::test]
    async fn strictness_2_signs_and_3_fails() {
        let state = state();
        let MatchResult::Success { statement, .. } = exchange(&state, &deep_face(2), 1).await
        else {
            panic!("strictness 2 should pass")
        };
        let signing_key = EdDSAPublicKey::from_compressed_bytes(
            statement.signing_key_attestation.try_into().unwrap(),
        )
        .unwrap();
        FlamingoToken::from_cwt(&statement.token)
            .unwrap()
            .verify(&signing_key)
            .unwrap();

        assert_eq!(
            exchange(&state, &deep_face(3), 2).await,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(ComparisonRole::OrbSelfie),
                debug_report: flamingo_verifier_sealed_types::DebugReport::NotProduced,
            }
        );
        assert!(matches!(
            exchange(&state, &gray_badge(), 3).await,
            MatchResult::Success { .. }
        ));
    }

    #[test]
    fn rejects_a_malformed_manifest() {
        assert!(verifier("not.a.jws").is_err());
    }
}
