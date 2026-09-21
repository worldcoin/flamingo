use std::sync::Arc;

use flamingo_verifier_enclave_types::{self as enclave_types, MatchRequest, MatchResponse};
use flamingo_verifier_sealed_types::{MatchInputs, MatchResult};

use crate::{execution::blocking, operations, state::EnclaveState};

/// Opens one request, dispatches its operation and seals the outcome.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    if request.body.len() > flamingo_verifier_sealed_types::MAX_MATCH_BODY_BYTES {
        return Err(enclave_types::Error::RequestNotOpened);
    }
    let admission = Arc::new(state.admit()?);
    let opening_state = Arc::clone(&state);
    let (sealer, inputs, admission) = blocking(move || {
        let (plaintext, sealer) = opening_state
            .channel()
            .open(&request.body)
            .map_err(|_| enclave_types::Error::RequestNotOpened)?;
        Ok::<_, enclave_types::Error>((sealer, MatchInputs::from_cbor(&plaintext), admission))
    })
    .await??;
    let result = match inputs {
        Ok(MatchInputs::DeepFace(inputs)) => {
            operations::deepface(state, inputs, Arc::clone(&admission)).await?
        }
        Ok(MatchInputs::GrayBadge(inputs)) => operations::graybadge(inputs),
        Err(reason) => MatchResult::Failed(reason),
    };
    blocking(move || {
        let _admission = admission;
        let encoded = result
            .to_padded_cbor()
            .map_err(|_| enclave_types::Error::Internal)?;
        Ok(MatchResponse {
            ciphertext: sealer
                .seal(&encoded)
                .map_err(|_| enclave_types::Error::Internal)?,
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        biometric_engine::{BiometricEngine, BiometricError, DeepFaceScores, GrayBadgeScores},
        test_support::{EchoAttestor, UnusedBiometricEngine},
    };
    use flamingo_verifier_protocol::match_token;
    use flamingo_verifier_sealed_types::{ComparisonRole, FailureReason, LiveCapture};
    use flamingo_verifier_sealed_types::{
        DeepFaceInputs, GrayBadgeInputs, LightGuardMatchingFrame, MATCH_CHANNEL_DOMAIN,
    };
    use pontifex::{ChannelConsumer, ChannelDomain};
    use sha2::{Digest, Sha256};

    struct Engine {
        third: f64,
    }
    #[async_trait::async_trait]
    impl BiometricEngine for Engine {
        async fn deepface(
            &self,
            credential: Vec<u8>,
            live: Vec<u8>,
            challenge: Vec<u8>,
        ) -> Result<DeepFaceScores, BiometricError> {
            assert_eq!(&credential[..], b"orb");
            assert_eq!(&live[..], b"live");
            assert_eq!(&challenge[..], b"challenge");
            Ok(DeepFaceScores {
                credential_live: 0.95,
                credential_challenge: 0.9,
                live_challenge: self.third,
            })
        }

        async fn graybadge(
            &self,
            _: Vec<u8>,
            _: Vec<u8>,
        ) -> Result<GrayBadgeScores, BiometricError> {
            panic!("GrayBadge must be rejected before inference")
        }
    }
    fn inputs() -> MatchInputs {
        let hash = hex::encode(Sha256::digest(b"orb"));
        MatchInputs::DeepFace(DeepFaceInputs {
            orb_credential: b"orb".to_vec().into(),
            live: LiveCapture::Vanilla(b"live".to_vec().into()),
            rtms_challenge: b"challenge".to_vec().into(),
            hashes_json: format!(r#"{{"thumbnail.png":"{hash}"}}"#)
                .into_bytes()
                .into(),
            match_threshold: 0.8,
        })
    }
    fn gray(threshold: f64) -> MatchInputs {
        MatchInputs::GrayBadge(GrayBadgeInputs {
            live: LiveCapture::Vanilla(b"live".to_vec().into()),
            rtms_challenge: b"challenge".to_vec().into(),
            match_threshold: threshold,
        })
    }
    fn state(engine: impl BiometricEngine + 'static) -> Arc<EnclaveState> {
        Arc::new(EnclaveState::generate(Arc::new(EchoAttestor), Box::new(engine)).unwrap())
    }
    async fn exchange(state: Arc<EnclaveState>, inputs: &MatchInputs) -> (MatchResult, usize) {
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &state.channel().public_key(),
        )
        .unwrap();
        let (sealed, opener) = consumer
            .seal_to_enclave(&inputs.to_cbor().unwrap())
            .unwrap();
        let response = handler(
            state,
            MatchRequest {
                body: sealed.into(),
            },
        )
        .await
        .unwrap();
        let size = response.ciphertext.len();
        (
            MatchResult::from_padded_cbor(&opener.open_from_enclave(&response.ciphertext).unwrap())
                .unwrap(),
            size,
        )
    }
    #[tokio::test]
    async fn deep_face_returns_the_legacy_claims_bound_to_the_request() {
        let state = state(Engine { third: 0.85 });
        let inputs = inputs();
        let (result, _) = exchange(Arc::clone(&state), &inputs).await;
        let MatchResult::Success(statement) = result else {
            panic!("expected signed result")
        };
        let claims = match_token::verify(&statement.token, state.signing_public_key()).unwrap();
        assert!(inputs.matches_claims(&claims));
        assert_eq!(
            claims.live_image_hash,
            <[u8; 32]>::from(Sha256::digest(b"live"))
        );
        assert_eq!(
            claims.challenger_image_hash,
            <[u8; 32]>::from(Sha256::digest(b"challenge"))
        );
        let MatchInputs::DeepFace(inputs) = inputs else {
            unreachable!()
        };
        assert_eq!(
            claims.credential_claim,
            <[u8; 32]>::from(Sha256::digest(&inputs.hashes_json))
        );
        assert_eq!(claims.match_coefficient.to_bits(), 0.95f32.to_bits());
    }
    #[tokio::test]
    async fn third_comparison_is_a_required_gate_and_failure_is_padded() {
        let (success, success_len) = exchange(state(Engine { third: 0.9 }), &inputs()).await;
        assert!(matches!(success, MatchResult::Success(_)));
        let (failure, failure_len) = exchange(state(Engine { third: 0.1 }), &inputs()).await;
        assert_eq!(
            failure,
            MatchResult::Failed(FailureReason::MatchBelowThreshold(
                ComparisonRole::SelfieChallenge
            ))
        );
        assert_eq!(success_len, failure_len);
    }
    #[tokio::test]
    async fn gray_badge_rejects_before_inference_until_its_token_is_agreed() {
        let (result, length) = exchange(state(UnusedBiometricEngine), &gray(0.5)).await;
        assert_eq!(
            result,
            MatchResult::Failed(FailureReason::UnsupportedOperation)
        );
        let (_, success_length) = exchange(state(Engine { third: 0.9 }), &inputs()).await;
        assert_eq!(length, success_length);
    }
    #[tokio::test]
    async fn bad_pcp_and_light_guard_reject_before_inference() {
        let state = state(UnusedBiometricEngine);
        let MatchInputs::DeepFace(mut i) = inputs() else {
            unreachable!()
        };
        i.orb_credential = b"other".to_vec().into();
        assert_eq!(
            exchange(Arc::clone(&state), &MatchInputs::DeepFace(i))
                .await
                .0,
            MatchResult::Failed(FailureReason::ThumbnailHashMismatch)
        );
        let MatchInputs::GrayBadge(mut i) = gray(0.5) else {
            unreachable!()
        };
        i.live = LiveCapture::LightGuard {
            illuminated: vec![1].into(),
            unilluminated: vec![2].into(),
            matching_frame: LightGuardMatchingFrame::Unilluminated,
        };
        assert_eq!(
            exchange(state, &MatchInputs::GrayBadge(i)).await.0,
            MatchResult::Failed(FailureReason::UnsupportedCapture)
        );
    }
    #[tokio::test]
    async fn malformed_payload_is_sealed_and_another_boot_cannot_open_request() {
        let state = state(UnusedBiometricEngine);
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &state.channel().public_key(),
        )
        .unwrap();
        let (sealed, opener) = consumer.seal_to_enclave(b"invalid CBOR").unwrap();
        let response = handler(
            Arc::clone(&state),
            MatchRequest {
                body: sealed.into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            MatchResult::from_padded_cbor(&opener.open_from_enclave(&response.ciphertext).unwrap())
                .unwrap(),
            MatchResult::Failed(FailureReason::MalformedInputs)
        );
        let other = super::tests::state(UnusedBiometricEngine);
        let (sealed, _) = consumer.seal_to_enclave(b"invalid").unwrap();
        assert_eq!(
            handler(
                other,
                MatchRequest {
                    body: sealed.into()
                }
            )
            .await
            .unwrap_err(),
            enclave_types::Error::RequestNotOpened
        );
    }
}
