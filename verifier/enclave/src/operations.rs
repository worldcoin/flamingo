//! Product operations: input provenance, inference policy and signed statements.

use std::sync::Arc;

use flamingo_verifier_enclave_types::Error;
use flamingo_verifier_protocol::match_token::MatchClaims;
use flamingo_verifier_sealed_types::{
    AttestedStatement, ComparisonRole, DeepFaceInputs, FailureReason, GrayBadgeInputs, LiveCapture,
    MatchInputs, MatchResult, valid_similarity,
};
use sha2::{Digest, Sha256};

use crate::{
    biometric_engine::{BiometricError, DeepFaceScores},
    execution::blocking,
    pcp,
    state::EnclaveState,
};

pub async fn deepface(
    state: Arc<EnclaveState>,
    inputs: DeepFaceInputs,
    admission: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<MatchResult, Error> {
    let preparation_admission = Arc::clone(&admission);
    let prepared = blocking(move || {
        let _admission = preparation_admission;
        let input = MatchInputs::DeepFace(inputs);
        input.validate()?;
        let MatchInputs::DeepFace(inputs) = input else {
            unreachable!()
        };
        if !matches!(inputs.live, LiveCapture::Vanilla(_)) {
            return Err(FailureReason::UnsupportedCapture);
        }
        let credential_claim =
            pcp::bind_credential_claim(&inputs.orb_credential, &inputs.hashes_json)?;
        Ok((inputs, credential_claim))
    })
    .await?;
    let (inputs, credential_claim) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return Ok(MatchResult::Failed(reason)),
    };
    let LiveCapture::Vanilla(live) = &inputs.live else {
        unreachable!("validated capture")
    };
    let scores = match state
        .engine()
        .deepface(
            inputs.orb_credential.to_vec(),
            live.to_vec(),
            inputs.rtms_challenge.to_vec(),
        )
        .await
    {
        Ok(scores) => scores,
        Err(BiometricError::Rejected(FailureReason::Internal) | BiometricError::Internal) => {
            return Err(Error::Internal);
        }
        Err(BiometricError::Rejected(reason)) => return Ok(MatchResult::Failed(reason)),
        Err(BiometricError::Busy) => return Err(Error::NotReady),
    };
    let signing_key_attestation = state.signing_key_attestation().await;
    blocking(move || {
        let _admission = admission;
        let claims = match evaluate(&inputs, credential_claim, scores) {
            Ok(claims) => claims,
            Err(FailureReason::Internal) => return Err(Error::Internal),
            Err(reason) => return Ok(MatchResult::Failed(reason)),
        };
        Ok(MatchResult::Success(AttestedStatement {
            token: state
                .signing_key()
                .sign_claims(&claims)
                .map_err(|_| Error::Internal)?,
            signing_key_attestation,
        }))
    })
    .await?
}

pub fn graybadge(inputs: GrayBadgeInputs) -> MatchResult {
    let input = MatchInputs::GrayBadge(inputs);
    let result: Result<(), FailureReason> = input.validate().and_then(|()| {
        let MatchInputs::GrayBadge(inputs) = input else {
            unreachable!()
        };
        if !matches!(inputs.live, LiveCapture::Vanilla(_)) {
            return Err(FailureReason::UnsupportedCapture);
        }
        // A GrayBadge signed statement needs an agreed credential-free claim contract.
        Err(FailureReason::UnsupportedOperation)
    });
    MatchResult::Failed(result.unwrap_err())
}

fn evaluate(
    i: &flamingo_verifier_sealed_types::DeepFaceInputs,
    credential_claim: [u8; 32],
    scores: DeepFaceScores,
) -> Result<MatchClaims, FailureReason> {
    let LiveCapture::Vanilla(live) = &i.live else {
        unreachable!("validated capture")
    };
    let threshold = i.match_threshold;
    let live_image_hash = Sha256::digest(live).into();
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
    check(scores.credential_live, ComparisonRole::OrbSelfie)?;
    check(scores.credential_challenge, ComparisonRole::OrbChallenge)?;
    check(scores.live_challenge, ComparisonRole::SelfieChallenge)?;
    // Preserve the legacy score representation and signed statement. Other scores
    // remain enclave policy checks until the expanded protocol is agreed.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the legacy token uses f32; the engine's normalized score was widened from f32"
    )]
    let match_coefficient = scores.credential_live as f32;
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

    #[test]
    fn every_comparison_must_pass_and_invalid_scores_are_internal() {
        let inputs = DeepFaceInputs {
            orb_credential: vec![1].into(),
            live: LiveCapture::Vanilla(vec![2].into()),
            rtms_challenge: vec![3].into(),
            hashes_json: vec![4].into(),
            match_threshold: 0.8,
        };
        for index in 0..3 {
            for invalid in [f64::NAN, f64::INFINITY, -0.01, 1.01, 0.7] {
                let mut scores = [0.9; 3];
                scores[index] = invalid;
                let result = evaluate(
                    &inputs,
                    [0; 32],
                    DeepFaceScores {
                        credential_live: scores[0],
                        credential_challenge: scores[1],
                        live_challenge: scores[2],
                    },
                );
                let expected = if invalid.to_bits() == 0.7_f64.to_bits() {
                    FailureReason::MatchBelowThreshold(
                        [
                            ComparisonRole::OrbSelfie,
                            ComparisonRole::OrbChallenge,
                            ComparisonRole::SelfieChallenge,
                        ][index],
                    )
                } else {
                    FailureReason::Internal
                };
                assert_eq!(result.unwrap_err(), expected);
            }
        }
    }
    struct InternalEngine;
    #[async_trait::async_trait]
    impl crate::biometric_engine::BiometricEngine for InternalEngine {
        async fn deepface(
            &self,
            _: Vec<u8>,
            _: Vec<u8>,
            _: Vec<u8>,
        ) -> Result<DeepFaceScores, BiometricError> {
            Err(BiometricError::Rejected(FailureReason::Internal))
        }
        async fn graybadge(
            &self,
            _: Vec<u8>,
            _: Vec<u8>,
        ) -> Result<crate::biometric_engine::GrayBadgeScores, BiometricError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn internal_inference_fault_is_an_infrastructure_error() {
        let state = Arc::new(
            EnclaveState::generate(
                Arc::new(crate::test_support::EchoAttestor),
                Box::new(InternalEngine),
            )
            .unwrap(),
        );
        let admission = Arc::new(state.admit().unwrap());
        let hash = hex::encode(Sha256::digest([1]));
        let inputs = DeepFaceInputs {
            orb_credential: vec![1].into(),
            live: LiveCapture::Vanilla(vec![2].into()),
            rtms_challenge: vec![3].into(),
            hashes_json: format!(r#"{{"thumbnail.png":"{hash}"}}"#)
                .into_bytes()
                .into(),
            match_threshold: 0.8,
        };
        assert_eq!(
            deepface(state, inputs, admission).await.unwrap_err(),
            Error::Internal
        );
    }
}
