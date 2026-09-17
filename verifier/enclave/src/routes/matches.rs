use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{MatchRequest, MatchResponse};
use flamingo_verifier_protocol::match_token::MatchClaims;
use flamingo_verifier_sealed_types::{AttestedStatement, FailureReason, MatchInputs, MatchResult};
use pontifex::Request;
use sha2::{Digest, Sha256};

use crate::{pcp, state::EnclaveState};

/// Runs a 3-way face match: the credential image against both the live and challenge images.
///
/// Everything the enclave learns after opening the request goes back sealed, so a successful return
/// tells the host only that the enclave answered.
///
/// # Errors
///
/// Returns [`enclave_types::Error`] for the only two things the host may see: a request that would not open
/// (no channel exists, so nothing can be sealed) and an enclave fault. Every other failure is a
/// sealed [`FailureReason`].
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    let (plaintext, sealer) = state.channel().open(&request.body).map_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "failed to open sealed request"
        );
        enclave_types::Error::RequestNotOpened
    })?;

    // Read before `run`, which is sync. A clone of the cached document, not an attest.
    let signing_key_attestation = state.signing_key_attestation().await;

    // Past this point there is a channel to answer on, so every input-derived failure is sealed.
    let result = run(&state, &plaintext, &signing_key_attestation)?;

    Ok(MatchResponse {
        ciphertext: seal(sealer, &result)?,
    })
}

/// Decodes the opened plaintext and runs the match.
///
/// # Errors
///
/// Only for an enclave fault. Anything the request itself caused comes back as
/// [`MatchResult::Failed`].
fn run(
    state: &EnclaveState,
    plaintext: &[u8],
    signing_key_attestation: &[u8],
) -> Result<MatchResult, enclave_types::Error> {
    let inputs = match MatchInputs::from_cbor(plaintext) {
        Ok(inputs) => inputs,
        Err(error) => {
            tracing::warn!(
                ?error,
                route = MatchRequest::ROUTE_ID,
                "unusable match payload"
            );
            return Ok(MatchResult::Failed(FailureReason::MalformedInputs));
        }
    };

    match evaluate(state, &inputs) {
        // Only a held match carries the document; a rejection has no statement to check.
        Ok(claims) => Ok(MatchResult::Success(AttestedStatement {
            token: sign(state, &claims)?,
            signing_key_attestation: signing_key_attestation.to_vec(),
        })),
        Err(reason) => Ok(MatchResult::Failed(reason)),
    }
}

/// Evaluates the opened inputs. Every failure here is a fact about the plaintext, so it is sealed.
///
/// # Panics
///
/// Panics if the inputs carry a `LightGuard` image. The flow behind it does not exist yet, and
/// there is no sensible fallback: silently running the vanilla comparison would answer a
/// `LightGuard` request with a statement that never saw the second frame.
fn evaluate(state: &EnclaveState, inputs: &MatchInputs) -> Result<MatchClaims, FailureReason> {
    // TODO: Add LightGuard here. A second liveness frame selects the challenge-response spoof
    // detection the biometrics team owns; everything below is vanilla mode. Until that pipeline
    // lands, the enclave must not answer such a request at all — see the panic note above.
    if inputs.light_guard_image.is_some() {
        unimplemented!("LightGuard matching over the second liveness image");
    }

    // Binds the credential image to the hash its PCP commits. A commitment, not proof of
    // enrollment — nothing here checks who issued the PCP.
    let credential_claim =
        match pcp::bind_credential_claim(&inputs.credential_image, &inputs.hashes_json) {
            Ok(claim) => claim,
            Err(reason) => {
                tracing::warn!(
                    ?reason,
                    route = MatchRequest::ROUTE_ID,
                    "pcp binding failed"
                );
                return Err(reason);
            }
        };

    let scores = state.face_engine().compare_reference_to_probes(
        &inputs.credential_image,
        &inputs.live_image,
        &inputs.challenge_image,
    )?;

    if scores.live_similarity < inputs.match_threshold
        || scores.challenge_similarity < inputs.match_threshold
    {
        // Scores stay out of the log: they measure a person, and the log has no sealed channel.
        tracing::warn!(
            route = MatchRequest::ROUTE_ID,
            "match scored below threshold"
        );
        return Err(FailureReason::MatchBelowThreshold);
    }

    Ok(MatchClaims {
        live_image_hash: Sha256::digest(&inputs.live_image).into(),
        credential_claim,
        challenger_image_hash: Sha256::digest(&inputs.challenge_image).into(),
        // Only the credential-vs-live score is surfaced; the challenge comparison is a gate.
        match_coefficient: scores.live_similarity,
    })
}

/// Signs a statement with this boot's signing key.
fn sign(
    state: &EnclaveState,
    claims: &MatchClaims,
) -> Result<flamingo_verifier_protocol::match_token::MatchToken, enclave_types::Error> {
    state.signing_key().sign_claims(claims).map_err(|error| {
        tracing::error!(?error, "failed to build the match statement");
        enclave_types::Error::Internal
    })
}

/// Seals the authoritative result back to the requester.
fn seal(
    sealer: pontifex::ResponseSealer,
    result: &MatchResult,
) -> Result<Vec<u8>, enclave_types::Error> {
    let encoded = result.to_padded_cbor().map_err(|error| {
        tracing::error!(?error, "failed to encode the match result");
        enclave_types::Error::Internal
    })?;

    sealer.seal(&encoded).map_err(|error| {
        tracing::error!(?error, "failed to seal the match response");
        enclave_types::Error::Internal
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use flamingo_verifier_enclave_types as enclave_types;
    use flamingo_verifier_enclave_types::MatchRequest;
    use flamingo_verifier_protocol::match_token;
    use flamingo_verifier_sealed_types::MATCH_CHANNEL_DOMAIN;
    use flamingo_verifier_sealed_types::{FailureReason, MatchInputs, MatchResult};
    use pontifex::{ChannelConsumer, ChannelDomain, ResponseOpener};
    use sha2::{Digest, Sha256};

    use super::handler;
    use crate::{
        face_engine::{ComparisonScores, FaceComparator},
        state::EnclaveState,
        test_support::EchoAttestor,
    };

    const CREDENTIAL: &[u8] = b"credential-thumbnail";
    const LIVE: &[u8] = b"liveness-frame";
    const CHALLENGE: &[u8] = b"challenge-frame";

    struct MockFaceEngine {
        result: Result<ComparisonScores, FailureReason>,
        /// The challenge frame the engine must be handed, byte for byte.
        expected_challenge: &'static [u8],
    }

    impl MockFaceEngine {
        const fn scoring(live: f32, challenge: f32) -> Self {
            Self {
                result: Ok(ComparisonScores {
                    live_similarity: live,
                    challenge_similarity: challenge,
                }),
                expected_challenge: CHALLENGE,
            }
        }

        const fn failing(reason: FailureReason) -> Self {
            Self {
                result: Err(reason),
                expected_challenge: CHALLENGE,
            }
        }

        /// For inputs that seal something other than the usual fixture.
        const fn expecting(challenge: &'static [u8], live: f32, challenge_score: f32) -> Self {
            Self {
                result: Ok(ComparisonScores {
                    live_similarity: live,
                    challenge_similarity: challenge_score,
                }),
                expected_challenge: challenge,
            }
        }

        const fn failing_on(reason: FailureReason, challenge: &'static [u8]) -> Self {
            Self {
                result: Err(reason),
                expected_challenge: challenge,
            }
        }
    }

    impl FaceComparator for MockFaceEngine {
        fn compare_reference_to_probes(
            &self,
            credential_image: &[u8],
            live_image: &[u8],
            challenge_image: &[u8],
        ) -> Result<ComparisonScores, FailureReason> {
            assert_eq!(credential_image, CREDENTIAL);
            assert_eq!(live_image, LIVE);
            assert_eq!(challenge_image, self.expected_challenge);
            self.result
        }
    }

    fn state_with(face_engine: MockFaceEngine) -> Arc<EnclaveState> {
        Arc::new(
            EnclaveState::generate(Arc::new(EchoAttestor), Arc::new(face_engine))
                .expect("boot state should generate"),
        )
    }

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
    }

    fn inputs(credential: &[u8], threshold: f32) -> MatchInputs {
        MatchInputs {
            live_image: LIVE.to_vec(),
            credential_image: credential.to_vec(),
            light_guard_image: None,
            hashes_json: hashes_json_for(credential),
            challenge_image: CHALLENGE.to_vec(),
            match_threshold: threshold,
        }
    }

    /// Seals `inputs` to `state`, which is the whole request.
    fn request_for(state: &EnclaveState, inputs: &MatchInputs) -> (ResponseOpener, MatchRequest) {
        let requester = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &state.encryption_public_key(),
        )
        .expect("valid key");
        let plaintext = inputs.to_cbor().expect("encoding should succeed");
        let (sealed, opener) = requester
            .seal_to_enclave(&plaintext)
            .expect("sealing should succeed");

        (opener, MatchRequest { body: sealed })
    }

    #[tokio::test]
    async fn seals_a_signed_statement_to_the_requester() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        // Outlives the move into `handler`, so the statement can be checked against this boot's key.
        let signer = Arc::clone(&state);
        let inputs = inputs(CREDENTIAL, 0.5);
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request).await.expect("match should succeed");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("the requester should open its own response");
        let MatchResult::Success(attested) =
            MatchResult::from_padded_cbor(&plaintext).expect("result should decode")
        else {
            panic!("a held match should carry a statement");
        };

        // Without the document the requester cannot tell which enclave signed the token.
        assert_eq!(
            attested.signing_key_attestation,
            signer.signing_key_attestation().await,
            "the sealed document must be this boot's signing-key attestation"
        );

        // The statement verifies under the key this boot attests, and commits to every input.
        let statement = match_token::verify(&attested.token, signer.signing_public_key())
            .expect("statement should verify");
        assert_eq!(
            statement.live_image_hash,
            <[u8; 32]>::from(Sha256::digest(LIVE))
        );
        assert_eq!(
            statement.credential_claim,
            <[u8; 32]>::from(Sha256::digest(&inputs.hashes_json))
        );
        assert_eq!(
            statement.challenger_image_hash,
            <[u8; 32]>::from(Sha256::digest(CHALLENGE))
        );
    }

    #[tokio::test]
    async fn a_below_threshold_score_is_a_sealed_rejection_not_an_error() {
        let state = state_with(MockFaceEngine::scoring(0.95, 0.40));
        let (opener, request) = request_for(&state, &inputs(CREDENTIAL, 0.9));

        let response = handler(state, request)
            .await
            .expect("a rejection is still a successful response");

        // The host sees only the coarse class...
        // ...while the reason travels sealed.
        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert_eq!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Failed(FailureReason::MatchBelowThreshold)
        );
    }

    #[tokio::test]
    async fn sealed_outcomes_are_indistinguishable_by_length() {
        let success_state = state_with(MockFaceEngine::scoring(0.95, 0.90));
        let failure_state = state_with(MockFaceEngine::scoring(0.95, 0.40));
        let (_, success_request) = request_for(&success_state, &inputs(CREDENTIAL, 0.5));
        let (_, failure_request) = request_for(&failure_state, &inputs(CREDENTIAL, 0.9));

        let success = handler(success_state, success_request)
            .await
            .expect("success should seal");
        let failure = handler(failure_state, failure_request)
            .await
            .expect("failure should seal");

        assert_eq!(success.ciphertext.len(), failure.ciphertext.len());
    }

    #[tokio::test]
    async fn a_thumbnail_mismatch_is_a_sealed_rejection() {
        let state = state_with(MockFaceEngine::failing(FailureReason::ImageAnalysisFailed));
        let mut inputs = inputs(b"the-enrolled-image", 0.5);
        inputs.credential_image = b"a-different-image".to_vec();
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request)
            .await
            .expect("should seal a rejection");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert_eq!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Failed(FailureReason::ThumbnailHashMismatch)
        );
    }

    #[tokio::test]
    async fn no_score_appears_in_the_cleartext_response() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        let (_, request) = request_for(&state, &inputs(CREDENTIAL, 0.5));

        let response = handler(state, request).await.expect("match should succeed");

        // The credential claim is the most sensitive thing the host must not learn.
        let claim: [u8; 32] = Sha256::digest(hashes_json_for(CREDENTIAL)).into();
        assert!(
            !response
                .ciphertext
                .windows(claim.len())
                .any(|window| window == claim)
        );
    }

    #[tokio::test]
    async fn rejects_a_request_sealed_to_another_boot() {
        let state = state_with(MockFaceEngine::failing(FailureReason::ImageAnalysisFailed));
        let other = state_with(MockFaceEngine::failing(FailureReason::ImageAnalysisFailed));
        let (_, request) = request_for(&other, &inputs(CREDENTIAL, 0.5));

        assert_eq!(
            handler(state, request).await.err(),
            Some(enclave_types::Error::RequestNotOpened)
        );
    }

    #[tokio::test]
    async fn a_non_cbor_plaintext_is_a_sealed_failure() {
        let state = state_with(MockFaceEngine::failing(FailureReason::ImageAnalysisFailed));
        let requester = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &state.encryption_public_key(),
        )
        .expect("valid key");
        let (sealed, opener) = requester
            .seal_to_enclave(b"not cbor framing")
            .expect("sealing should succeed");

        let response = handler(state, MatchRequest { body: sealed })
            .await
            .expect("a malformed plaintext is answered, not errored");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert_eq!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Failed(FailureReason::MalformedInputs)
        );
    }

    /// An unusable challenge frame reaches the engine, so it must come back sealed, not as a panic.
    #[tokio::test]
    async fn an_empty_challenge_image_fails_the_analysis_sealed() {
        let state = state_with(MockFaceEngine::failing_on(
            FailureReason::ImageAnalysisFailed,
            b"",
        ));
        let mut inputs = inputs(CREDENTIAL, 0.5);
        inputs.challenge_image = Vec::new();
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request)
            .await
            .expect("an unusable frame is answered, not errored");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert_eq!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Failed(FailureReason::ImageAnalysisFailed)
        );
    }

    /// `challenger_image_hash` is what catches a substituted frame, so it has to track the bytes
    /// actually sealed rather than any fixed value.
    #[tokio::test]
    async fn the_statement_commits_to_the_challenge_bytes_the_requester_sealed() {
        const OTHER_CHALLENGE: &[u8] = b"a-different-challenge-frame";

        let state = state_with(MockFaceEngine::expecting(OTHER_CHALLENGE, 0.92, 0.87));
        let signer = Arc::clone(&state);
        let mut inputs = inputs(CREDENTIAL, 0.5);
        inputs.challenge_image = OTHER_CHALLENGE.to_vec();
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request).await.expect("match should succeed");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        let MatchResult::Success(attested) =
            MatchResult::from_padded_cbor(&plaintext).expect("result should decode")
        else {
            panic!("a held match should carry a statement");
        };
        let statement = match_token::verify(&attested.token, signer.signing_public_key())
            .expect("statement should verify");

        assert_eq!(
            statement.challenger_image_hash,
            <[u8; 32]>::from(Sha256::digest(OTHER_CHALLENGE))
        );
    }

    #[tokio::test]
    async fn an_image_quality_failure_is_a_sealed_failure() {
        // The client needs this, the host must not have it: it says the photo was unusable.
        let state = state_with(MockFaceEngine::failing(FailureReason::ImageAnalysisFailed));
        let (opener, request) = request_for(&state, &inputs(CREDENTIAL, 0.5));

        let response = handler(state, request)
            .await
            .expect("a quality failure is answered, not errored");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert_eq!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Failed(FailureReason::ImageAnalysisFailed)
        );
    }

    /// The whole point of the redesign: a malformed `hashes.json` is a fact about the sealed
    /// plaintext, so the host is told the request succeeded.
    #[tokio::test]
    async fn an_invalid_hashes_json_is_a_sealed_failure() {
        let state = state_with(MockFaceEngine::failing(FailureReason::ImageAnalysisFailed));
        let mut inputs = inputs(CREDENTIAL, 0.5);
        inputs.hashes_json = b"not json".to_vec();
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request)
            .await
            .expect("bad hashes.json is answered, not errored");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert_eq!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Failed(FailureReason::InvalidHashesJson)
        );
    }

    /// Vanilla mode is the absent-field flow, and nothing above changes it: the engine is still
    /// asked for the same three images.
    #[tokio::test]
    async fn no_light_guard_image_runs_the_vanilla_flow() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        let inputs = inputs(CREDENTIAL, 0.5);
        assert_eq!(inputs.light_guard_image, None);
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request).await.expect("match should succeed");

        let plaintext = opener
            .open_from_enclave(&response.ciphertext)
            .expect("should open");
        assert!(matches!(
            MatchResult::from_padded_cbor(&plaintext).expect("should decode"),
            MatchResult::Success(_)
        ));
    }

    #[tokio::test]
    async fn a_second_requester_cannot_open_the_response() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        let (_, request) = request_for(&state, &inputs(CREDENTIAL, 0.5));
        // A different response keypair for each request.
        let (eavesdropper, _) = request_for(&state, &inputs(CREDENTIAL, 0.5));

        let response = handler(state, request).await.expect("match should succeed");

        assert!(
            eavesdropper
                .open_from_enclave(&response.ciphertext)
                .is_err()
        );
    }
}
