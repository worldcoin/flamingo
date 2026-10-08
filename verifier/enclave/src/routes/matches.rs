use std::sync::Arc;

use flamingo_verifier_enclave_types::{self as enclave_types, MatchRequest, MatchResponse};
use flamingo_verifier_protocol::flamingo_token::{FlamingoClaims, canonical_field};
use flamingo_verifier_sealed_types::{
    AttestedStatement, ComparisonRole, DebugReport, FailureReason, MatchResult, Request,
};

use crate::{
    biometric_engine::BiometricError,
    blocking,
    pipeline::{self, Operation},
    state::EnclaveState,
};

/// Opens one request, runs it on the requested Engine and seals the outcome.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    if request.body.len() > flamingo_verifier_sealed_types::MAX_MATCH_BODY_BYTES {
        return Err(enclave_types::Error::RequestNotOpened);
    }

    let opening_state = Arc::clone(&state);
    let (sealer, prepared) = blocking(move || {
        let (plaintext, sealer) = opening_state
            .channel()
            .open(&request.body)
            .map_err(|_| enclave_types::Error::RequestNotOpened)?;
        let request = Request::from_cbor(&plaintext);
        drop(plaintext);
        let prepared = request.and_then(|request| prepare(&opening_state, &request));
        Ok::<_, enclave_types::Error>((sealer, prepared))
    })
    .await??;

    let result = match prepared {
        Ok(prepared) => run(state, prepared).await?,
        Err(reason) => MatchResult::Failed {
            reason,
            debug_report: DebugReport::NotProduced,
        },
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

/// A request that passed every check before inference.
struct Prepared {
    claims: FlamingoClaims,
    threshold: f64,
    operation: Operation,
}

/// Checks the request and computes its claims; a failure here never reaches the engine.
fn prepare(state: &EnclaveState, request: &Request) -> Result<Prepared, FailureReason> {
    request.validate()?;
    let payload = request.payload()?;
    if !state.engine_hashes().contains(&*payload.engine_hash) {
        return Err(FailureReason::UnsupportedEngine);
    }
    let threshold = pipeline::threshold(payload.match_strictness)?;
    let field = |bytes| canonical_field(bytes).map_err(|_| FailureReason::MalformedInputs);
    let claims = payload.claims(field(&request.aud)?, field(&request.nonce)?, None);
    let operation = pipeline::operation(payload)?;
    Ok(Prepared {
        claims,
        threshold,
        operation,
    })
}

async fn run(
    state: Arc<EnclaveState>,
    prepared: Prepared,
) -> Result<MatchResult, enclave_types::Error> {
    let scores = match prepared.operation {
        Operation::DeepFace {
            credential,
            live,
            challenge,
        } => state
            .engine()
            .deepface(credential, live, challenge)
            .await
            .map(|scores| {
                (
                    vec![
                        (scores.credential_live, ComparisonRole::OrbSelfie),
                        (scores.credential_challenge, ComparisonRole::OrbChallenge),
                        (scores.live_challenge, ComparisonRole::SelfieChallenge),
                    ],
                    scores.debug_report,
                )
            }),
        Operation::GrayBadge { live, challenge } => state
            .engine()
            .graybadge(live, challenge)
            .await
            .map(|scores| {
                (
                    vec![(scores.live_challenge, ComparisonRole::SelfieChallenge)],
                    scores.debug_report,
                )
            }),
    };
    let (scores, debug_report) = match scores {
        Ok(scores) => scores,
        Err(error) => return error.into_result(),
    };

    // The token carries no score; every compared pair must clear the strictness level.
    for (score, role) in scores {
        if let Err(reason) = pipeline::check_score(score, prepared.threshold, role) {
            return BiometricError::AnalysisRejected {
                reason,
                debug_report,
            }
            .into_result();
        }
    }

    sign(state, &prepared.claims, debug_report).await
}

async fn sign(
    state: Arc<EnclaveState>,
    claims: &FlamingoClaims,
    debug_report: DebugReport,
) -> Result<MatchResult, enclave_types::Error> {
    let claims = *claims;
    let signing_key_attestation = state.signing_key_attestation().await;

    blocking(move || {
        Ok(MatchResult::Success {
            statement: AttestedStatement {
                token: state
                    .signing_key()
                    .sign_claims(&claims)
                    .map_err(|_| enclave_types::Error::Internal)?,
                signing_key_attestation,
            },
            debug_report,
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        biometric_engine::{BiometricEngine, DeepFaceScores, GrayBadgeScores, LiveCapture},
        pipeline::{PIPELINE_DEEPFACE, PIPELINE_GRAYBADGE},
        test_support::{EchoAttestor, TEST_ENGINE_HASH, UnusedBiometricEngine},
    };
    use flamingo_verifier_protocol::{Fq, flamingo_token};
    use flamingo_verifier_sealed_types::{ByteBuf, Entry, MATCH_CHANNEL_DOMAIN, Payload};
    use pontifex::{ChannelConsumer, ChannelDomain};

    struct Engine {
        third: f32,
    }

    #[async_trait::async_trait]
    impl BiometricEngine for Engine {
        fn engine_hash(&self) -> [u8; 32] {
            TEST_ENGINE_HASH
        }

        async fn deepface(
            &self,
            credential: Vec<u8>,
            live: LiveCapture,
            challenge: Vec<u8>,
        ) -> Result<DeepFaceScores, BiometricError> {
            assert_eq!(&credential[..], b"orb");
            let LiveCapture::Vanilla(image) = live else {
                panic!("expected a vanilla capture")
            };
            assert_eq!(&image[..], b"live");
            assert_eq!(&challenge[..], b"challenge");
            Ok(DeepFaceScores {
                credential_live: f64::from(0.99f32),
                credential_challenge: f64::from(0.99f32),
                live_challenge: f64::from(self.third),
                debug_report: Some("{\"engine\":\"test\"}".to_owned()).into(),
            })
        }

        async fn graybadge(
            &self,
            live: LiveCapture,
            _: Vec<u8>,
        ) -> Result<GrayBadgeScores, BiometricError> {
            let LiveCapture::LightGuard { .. } = live else {
                panic!("expected a LightGuard capture")
            };
            Ok(GrayBadgeScores {
                live_challenge: f64::from(self.third),
                debug_report: Some("{\"engine\":\"test\"}".to_owned()).into(),
            })
        }
    }

    fn entry(data: &[u8], meta: &[u8]) -> Entry {
        Entry {
            data: data.to_vec().into(),
            meta: meta.to_vec().into(),
        }
    }

    fn deep_face() -> Payload {
        Payload {
            meta: ByteBuf::new(),
            compare: vec![0, 1, 2],
            entries: vec![
                entry(b"orb", b""),
                entry(b"live", b""),
                entry(b"challenge", b""),
            ],
            pipeline: PIPELINE_DEEPFACE,
            engine_hash: TEST_ENGINE_HASH.into(),
            match_strictness: 2,
        }
    }

    fn gray_badge() -> Payload {
        Payload {
            meta: ByteBuf::new(),
            compare: vec![0, 1],
            entries: vec![
                entry(b"lit", b"illuminated"),
                entry(b"challenge", b""),
                entry(b"dark", b"unilluminated"),
            ],
            pipeline: PIPELINE_GRAYBADGE,
            engine_hash: TEST_ENGINE_HASH.into(),
            match_strictness: 2,
        }
    }

    const AUD: [u8; 32] = [7; 32];

    fn nonce() -> [u8; 32] {
        let mut nonce = [0; 32];
        nonce[31] = 42;
        nonce
    }

    fn state(engine: impl BiometricEngine + 'static) -> Arc<EnclaveState> {
        Arc::new(EnclaveState::generate(Arc::new(EchoAttestor), Box::new(engine)).unwrap())
    }

    async fn exchange_bytes(state: Arc<EnclaveState>, plaintext: &[u8]) -> (MatchResult, usize) {
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &state.channel().public_key(),
        )
        .unwrap();
        let (sealed, opener) = consumer.seal_to_enclave(plaintext).unwrap();
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

    async fn exchange(state: Arc<EnclaveState>, payload: &Payload) -> (MatchResult, usize) {
        let request = Request::new(payload, AUD, nonce()).unwrap();
        exchange_bytes(state, &request.to_cbor().unwrap()).await
    }

    fn rejected(reason: FailureReason) -> MatchResult {
        MatchResult::Failed {
            reason,
            debug_report: DebugReport::NotProduced,
        }
    }

    #[tokio::test]
    async fn signs_claims_bound_to_the_request() {
        for payload in [deep_face(), gray_badge()] {
            let state = state(Engine { third: 0.95 });
            let (result, _) = exchange(Arc::clone(&state), &payload).await;
            let MatchResult::Success {
                statement,
                debug_report,
            } = result
            else {
                panic!("expected a signed result")
            };
            assert!(matches!(debug_report, DebugReport::Available { .. }));
            let claims =
                flamingo_token::verify(&statement.token, state.signing_public_key()).unwrap();
            let expected = payload.claims(
                canonical_field(&AUD).unwrap(),
                canonical_field(&nonce()).unwrap(),
                None,
            );
            assert_eq!(claims, expected);
            assert_eq!(
                claims.engine_config_hash,
                flamingo_token::engine_config_hash(
                    &TEST_ENGINE_HASH,
                    u32::from(payload.pipeline),
                    2
                )
            );
            assert_eq!(claims.compared_entry_hashes[3], Fq::from(0u64));
        }
    }

    #[tokio::test]
    async fn every_comparison_must_clear_the_strictness_level_and_failure_is_padded() {
        let (success, success_len) = exchange(state(Engine { third: 0.92 }), &deep_face()).await;
        let MatchResult::Success { debug_report, .. } = success else {
            panic!("expected success")
        };
        let (failure, failure_len) = exchange(state(Engine { third: 0.89 }), &deep_face()).await;
        assert_eq!(
            failure,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(ComparisonRole::SelfieChallenge),
                debug_report,
            }
        );
        assert_eq!(success_len, failure_len);

        let mut strict = deep_face();
        strict.match_strictness = 3;
        let (failure, _) = exchange(state(Engine { third: 0.92 }), &strict).await;
        assert!(matches!(
            failure,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(ComparisonRole::SelfieChallenge),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn rejects_before_inference() {
        type Change = (fn(&mut Payload), FailureReason);
        let changes: [Change; 3] = [
            (
                |p| p.engine_hash = [0; 32].into(),
                FailureReason::UnsupportedEngine,
            ),
            (
                |p| p.match_strictness = 0,
                FailureReason::UnsupportedMatchStrictness,
            ),
            (|p| p.pipeline = 9, FailureReason::UnsupportedPipeline),
        ];
        for (change, reason) in changes {
            let mut payload = deep_face();
            change(&mut payload);
            assert_eq!(
                exchange(state(UnusedBiometricEngine), &payload).await.0,
                rejected(reason)
            );
        }

        let mut request = Request::new(&deep_face(), AUD, nonce()).unwrap();
        request.nonce = [0; 32].into();
        assert_eq!(
            exchange_bytes(state(UnusedBiometricEngine), &request.to_cbor().unwrap())
                .await
                .0,
            rejected(FailureReason::MalformedInputs)
        );
        assert_eq!(
            exchange_bytes(state(UnusedBiometricEngine), b"invalid")
                .await
                .0,
            rejected(FailureReason::MalformedInputs)
        );
    }
}
