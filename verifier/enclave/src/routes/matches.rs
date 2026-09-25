use std::sync::Arc;

use flamingo_verifier_enclave_types::{self as enclave_types, MatchRequest, MatchResponse};
use flamingo_verifier_protocol::match_token::{MatchClaims, MatchOperation};
use flamingo_verifier_sealed_types::{
    AttestedStatement, ComparisonRole, DeepFaceInputs, FailureReason, GrayBadgeInputs, MatchInputs,
    MatchResult, valid_similarity,
};
use sha2::{Digest, Sha256};

use crate::{blocking, pcp, state::EnclaveState};

/// Opens one request, dispatches its operation and seals the outcome.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    if request.body.len() > flamingo_verifier_sealed_types::MAX_MATCH_BODY_BYTES {
        return Err(enclave_types::Error::RequestNotOpened);
    }

    let opening_state = Arc::clone(&state);
    let (sealer, inputs) = blocking(move || {
        let (plaintext, sealer) = opening_state
            .channel()
            .open(&request.body)
            .map_err(|_| enclave_types::Error::RequestNotOpened)?;
        Ok::<_, enclave_types::Error>((sealer, MatchInputs::from_cbor(&plaintext)))
    })
    .await??;

    let result = match inputs {
        Ok(MatchInputs::DeepFace(inputs)) => deepface(state, inputs).await?,
        Ok(MatchInputs::GrayBadge(inputs)) => graybadge(state, inputs).await?,
        Err(reason) => MatchResult::Failed(reason),
    };

    blocking(move || {
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

async fn deepface(
    state: Arc<EnclaveState>,
    inputs: DeepFaceInputs,
) -> Result<MatchResult, enclave_types::Error> {
    let prepared = blocking(move || {
        let input = MatchInputs::DeepFace(inputs);
        input.validate()?;
        let MatchInputs::DeepFace(inputs) = input else {
            unreachable!()
        };
        let credential_claim =
            pcp::bind_credential_claim(&inputs.orb_credential, &inputs.hashes_json)?;
        let claims = MatchClaims {
            operation: MatchOperation::DeepFace { credential_claim },
            live_capture_hash: inputs.live.commitment(),
            challenger_image_hash: Sha256::digest(&inputs.rtms_challenge).into(),
            match_coefficient: 0.0,
        };

        Ok((inputs, claims))
    })
    .await?;
    let (inputs, mut claims) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return Ok(MatchResult::Failed(reason)),
    };

    let scores = match state
        .engine()
        .deepface(
            inputs.orb_credential.into_vec(),
            inputs.live,
            inputs.rtms_challenge.into_vec(),
        )
        .await
    {
        Ok(scores) => scores,
        Err(error) => return error.into_result(),
    };

    for (score, role) in [
        (scores.credential_live, ComparisonRole::OrbSelfie),
        (scores.credential_challenge, ComparisonRole::OrbChallenge),
        (scores.live_challenge, ComparisonRole::SelfieChallenge),
    ] {
        if let Err(reason) = check_score(score, inputs.match_threshold, role) {
            return crate::biometric_engine::BiometricError::Rejected(reason).into_result();
        }
    }

    claims.match_coefficient = token_score(scores.credential_live);
    sign(state, claims).await
}

async fn graybadge(
    state: Arc<EnclaveState>,
    inputs: GrayBadgeInputs,
) -> Result<MatchResult, enclave_types::Error> {
    let prepared = blocking(move || {
        let input = MatchInputs::GrayBadge(inputs);
        input.validate()?;
        let MatchInputs::GrayBadge(inputs) = input else {
            unreachable!()
        };
        let claims = MatchClaims {
            operation: MatchOperation::GrayBadge,
            live_capture_hash: inputs.live.commitment(),
            challenger_image_hash: Sha256::digest(&inputs.rtms_challenge).into(),
            match_coefficient: 0.0,
        };

        Ok((inputs, claims))
    })
    .await?;
    let (inputs, mut claims) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return Ok(MatchResult::Failed(reason)),
    };

    let scores = match state
        .engine()
        .graybadge(inputs.live, inputs.rtms_challenge.into_vec())
        .await
    {
        Ok(scores) => scores,
        Err(error) => return error.into_result(),
    };
    if let Err(reason) = check_score(
        scores.live_challenge,
        inputs.match_threshold,
        ComparisonRole::SelfieChallenge,
    ) {
        return crate::biometric_engine::BiometricError::Rejected(reason).into_result();
    }

    claims.match_coefficient = token_score(scores.live_challenge);
    sign(state, claims).await
}

fn check_score(
    score: f64,
    threshold: f64,
    comparison: ComparisonRole,
) -> Result<(), FailureReason> {
    if !valid_similarity(score) {
        return Err(FailureReason::Internal);
    }

    if score < threshold {
        return Err(FailureReason::MatchBelowThreshold(comparison));
    }

    Ok(())
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "worker scores are normalized as f32 before widening"
)]
const fn token_score(score: f64) -> f32 {
    score as f32
}

async fn sign(
    state: Arc<EnclaveState>,
    claims: MatchClaims,
) -> Result<MatchResult, enclave_types::Error> {
    let signing_key_attestation = state.signing_key_attestation().await;

    blocking(move || {
        Ok(MatchResult::Success(AttestedStatement {
            token: state
                .signing_key()
                .sign_claims(&claims)
                .map_err(|_| enclave_types::Error::Internal)?,
            signing_key_attestation,
        }))
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
        DeepFaceInputs, GrayBadgeInputs, MATCH_CHANNEL_DOMAIN, capture_profile,
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
            live: LiveCapture,
            challenge: Vec<u8>,
        ) -> Result<DeepFaceScores, BiometricError> {
            assert_eq!(&credential[..], b"orb");
            let frames: Vec<&[u8]> = live.frames.iter().map(|frame| &frame[..]).collect();
            match live.profile.as_str() {
                capture_profile::VANILLA => assert_eq!(frames, [b"live"]),
                _ => assert_eq!(frames, [&b"lit"[..], b"dark"]),
            }
            assert_eq!(&challenge[..], b"challenge");
            Ok(DeepFaceScores {
                credential_live: 0.95,
                credential_challenge: 0.9,
                live_challenge: self.third,
            })
        }

        async fn graybadge(
            &self,
            _: LiveCapture,
            _: Vec<u8>,
        ) -> Result<GrayBadgeScores, BiometricError> {
            Ok(GrayBadgeScores {
                live_challenge: self.third,
            })
        }
    }

    fn inputs() -> MatchInputs {
        let hash = hex::encode(Sha256::digest(b"orb"));
        MatchInputs::DeepFace(DeepFaceInputs {
            orb_credential: b"orb".to_vec().into(),
            live: LiveCapture::vanilla(b"live".to_vec().into()),
            rtms_challenge: b"challenge".to_vec().into(),
            hashes_json: format!(r#"{{"thumbnail.png":"{hash}"}}"#)
                .into_bytes()
                .into(),
            match_threshold: 0.8,
        })
    }

    fn gray(threshold: f64) -> MatchInputs {
        MatchInputs::GrayBadge(GrayBadgeInputs {
            live: LiveCapture::vanilla(b"live".to_vec().into()),
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
    async fn deep_face_returns_claims_bound_to_the_request() {
        let state = state(Engine { third: 0.85 });
        let inputs = inputs();
        let (result, _) = exchange(Arc::clone(&state), &inputs).await;
        let MatchResult::Success(statement) = result else {
            panic!("expected signed result")
        };
        let claims = match_token::verify(&statement.token, state.signing_public_key()).unwrap();
        assert!(inputs.matches_claims(&claims));
        assert_eq!(
            claims.live_capture_hash,
            LiveCapture::vanilla(b"live".to_vec().into()).commitment()
        );
        assert_eq!(
            claims.challenger_image_hash,
            <[u8; 32]>::from(Sha256::digest(b"challenge"))
        );
        let MatchInputs::DeepFace(inputs) = inputs else {
            unreachable!()
        };
        assert_eq!(
            claims.operation,
            MatchOperation::DeepFace {
                credential_claim: Sha256::digest(&inputs.hashes_json).into()
            }
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
    async fn gray_badge_signs_without_a_credential_and_enforces_threshold() {
        let state = state(Engine { third: 0.9 });
        let inputs = gray(0.8);
        let (result, length) = exchange(Arc::clone(&state), &inputs).await;
        let MatchResult::Success(statement) = result else {
            panic!("expected signed GrayBadge result")
        };
        let claims = match_token::verify(&statement.token, state.signing_public_key()).unwrap();
        assert_eq!(claims.operation, MatchOperation::GrayBadge);
        assert!(inputs.matches_claims(&claims));

        let (failure, failure_length) = exchange(state, &gray(0.95)).await;
        assert_eq!(
            failure,
            MatchResult::Failed(FailureReason::MatchBelowThreshold(
                ComparisonRole::SelfieChallenge
            ))
        );
        assert_eq!(length, failure_length);
    }

    #[tokio::test]
    async fn light_guard_supports_both_operations_and_frame_selections() {
        for matching_frame in [0, 1] {
            for mut inputs in [inputs(), gray(0.8)] {
                let live = match &mut inputs {
                    MatchInputs::DeepFace(i) => &mut i.live,
                    MatchInputs::GrayBadge(i) => &mut i.live,
                };
                *live = LiveCapture {
                    profile: capture_profile::LIGHT_GUARD.to_owned(),
                    frames: vec![b"lit".to_vec().into(), b"dark".to_vec().into()],
                    matching_frame,
                };
                let state = state(Engine { third: 0.9 });
                let (result, _) = exchange(Arc::clone(&state), &inputs).await;
                let MatchResult::Success(statement) = result else {
                    panic!("expected LightGuard result")
                };
                let claims =
                    match_token::verify(&statement.token, state.signing_public_key()).unwrap();
                assert!(inputs.matches_claims(&claims));
            }
        }
    }

    #[test]
    fn all_comparisons_reject_invalid_or_low_scores() {
        for role in [
            ComparisonRole::OrbSelfie,
            ComparisonRole::OrbChallenge,
            ComparisonRole::SelfieChallenge,
        ] {
            for score in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
                assert_eq!(check_score(score, 0.8, role), Err(FailureReason::Internal));
            }
            assert_eq!(
                check_score(0.7, 0.8, role),
                Err(FailureReason::MatchBelowThreshold(role))
            );
            assert_eq!(check_score(0.8, 0.8, role), Ok(()));
        }
    }

    #[tokio::test]
    async fn bad_pcp_rejects_before_inference() {
        let MatchInputs::DeepFace(mut inputs) = inputs() else {
            unreachable!()
        };
        inputs.orb_credential = b"other".to_vec().into();
        assert_eq!(
            exchange(state(UnusedBiometricEngine), &MatchInputs::DeepFace(inputs))
                .await
                .0,
            MatchResult::Failed(FailureReason::ThumbnailHashMismatch)
        );
    }
}
