use crate::{pcp, state::EnclaveState};
use flamingo_verifier_enclave_types::{self as enclave_types, MatchRequest, MatchResponse};
use flamingo_verifier_protocol::match_token::MatchClaims;
use flamingo_verifier_sealed_types::{
    AttestedStatement, ComparisonRole, FailureReason, LiveCapture, MatchInputs, MatchResult,
    valid_similarity,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Decrypt, validate and sign; every request-derived outcome stays encrypted.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    if request.body.len() > flamingo_verifier_sealed_types::MAX_MATCH_BODY_BYTES {
        return Err(enclave_types::Error::RequestNotOpened);
    }
    let (plaintext, sealer) = state
        .channel()
        .open(&request.body)
        .map_err(|_| enclave_types::Error::RequestNotOpened)?;
    let inputs = MatchInputs::from_cbor(&plaintext).map_err(|_| enclave_types::Error::Internal)?;

    let result = match evaluate(&state, &inputs) {
        Ok(claims) => MatchResult::Success(AttestedStatement {
            token: state
                .signing_key()
                .sign_claims(&claims)
                .map_err(|_| enclave_types::Error::Internal)?,
            signing_key_attestation: state.signing_key_attestation().await,
        }),
        Err(FailureReason::Internal) => return Err(enclave_types::Error::Internal),
        Err(reason) => MatchResult::Failed(reason),
    };

    let encoded = result
        .to_padded_cbor()
        .map_err(|_| enclave_types::Error::Internal)?;

    Ok(MatchResponse {
        ciphertext: sealer
            .seal(&encoded)
            .map_err(|_| enclave_types::Error::Internal)?,
    })
}

fn evaluate(state: &EnclaveState, inputs: &MatchInputs) -> Result<MatchClaims, FailureReason> {
    inputs.validate()?;
    let live = match inputs {
        MatchInputs::DeepFace(i) => &i.live,
        MatchInputs::GrayBadge(i) => &i.live,
    };
    let LiveCapture::Vanilla(live) = live else {
        return Err(FailureReason::UnsupportedCapture);
    };
    let MatchInputs::DeepFace(i) = inputs else {
        return Err(FailureReason::UnsupportedOperation);
    };
    let threshold = i.match_threshold;
    let live_image_hash = Sha256::digest(live).into();
    let credential_claim = pcp::bind_credential_claim(&i.orb_credential, &i.hashes_json)?;
    let challenger_image_hash = Sha256::digest(&i.rtms_challenge).into();
    let check = |score: f64, comparison| {
        if !valid_similarity(score) {
            return Err(FailureReason::Internal);
        }
        if score < threshold {
            return Err(FailureReason::MatchBelowThreshold(comparison));
        }
        Ok(())
    };
    let scores = state
        .face_engine()
        .deep_face(&i.orb_credential, live, &i.rtms_challenge)?;
    check(scores.similarity_orb_selfie, ComparisonRole::OrbSelfie)?;
    check(
        scores.similarity_orb_challenge,
        ComparisonRole::OrbChallenge,
    )?;
    check(
        scores.similarity_selfie_challenge,
        ComparisonRole::SelfieChallenge,
    )?;
    // Preserve the legacy score representation and signed statement. Other scores
    // remain enclave policy checks until the expanded protocol is agreed.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the legacy token uses f32; the engine's normalized score was widened from f32"
    )]
    let match_coefficient = scores.similarity_orb_selfie as f32;
    Ok(MatchClaims {
        live_image_hash,
        credential_claim,
        challenger_image_hash,
        match_coefficient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        face_engine::{DeepFaceScores, FaceComparator, GrayBadgeScores},
        test_support::{EchoAttestor, UnusedFaceEngine},
    };
    use flamingo_verifier_protocol::match_token;
    use flamingo_verifier_sealed_types::{
        DeepFaceInputs, GrayBadgeInputs, LightGuardMatchingFrame, MATCH_CHANNEL_DOMAIN,
    };
    use pontifex::{ChannelConsumer, ChannelDomain};

    struct Engine {
        third: f64,
    }
    impl FaceComparator for Engine {
        fn deep_face(
            &self,
            credential: &[u8],
            live: &[u8],
            challenge: &[u8],
        ) -> Result<DeepFaceScores, FailureReason> {
            assert_eq!(credential, b"orb");
            assert_eq!(live, b"live");
            assert_eq!(challenge, b"challenge");
            Ok(DeepFaceScores {
                similarity_orb_selfie: 0.95,
                similarity_orb_challenge: 0.9,
                similarity_selfie_challenge: self.third,
            })
        }

        fn gray_badge(&self, _: &[u8], _: &[u8]) -> Result<GrayBadgeScores, FailureReason> {
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
    fn state(engine: impl FaceComparator + 'static) -> Arc<EnclaveState> {
        Arc::new(EnclaveState::generate(Arc::new(EchoAttestor), Arc::new(engine)).unwrap())
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
        let (result, length) = exchange(state(UnusedFaceEngine), &gray(0.5)).await;
        assert_eq!(
            result,
            MatchResult::Failed(FailureReason::UnsupportedOperation)
        );
        let (_, success_length) = exchange(state(Engine { third: 0.9 }), &inputs()).await;
        assert_eq!(length, success_length);
    }
    #[tokio::test]
    async fn bad_pcp_and_light_guard_reject_before_inference() {
        let state = state(UnusedFaceEngine);
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
        let state = state(UnusedFaceEngine);
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
        let other = super::tests::state(UnusedFaceEngine);
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
    #[test]
    fn invalid_backend_scores_fail_as_infrastructure_errors() {
        for third in [f64::NAN, f64::INFINITY, 1.01, -0.01] {
            assert!(matches!(
                evaluate(&state(Engine { third }), &inputs()),
                Err(FailureReason::Internal)
            ));
        }
    }
}
