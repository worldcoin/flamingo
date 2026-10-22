use std::{sync::Arc, time::Duration};

use flamingo_verifier_enclave_types::{self as enclave_types, MatchRequest, MatchResponse};
use flamingo_verifier_sealed_types::{
    AttestedStatement, ComparisonRole, DebugReport, FailureReason, FlamingoClaims, MatchResult,
    Request, expected_claims,
};
use tokio::time::{Instant, sleep_until};
use world_id_flamingo::{ReleaseManifest, ResponseSlots};

use crate::{
    biometric_engine::BiometricError,
    blocking,
    pipeline::{self, Operation},
    state::EnclaveState,
};

/// Opens one request, runs it on the loaded release and seals the outcome, released at the
/// pipeline's next response slot (WIP-201 §3.5.4).
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, enclave_types::Error> {
    let arrival = Instant::now();
    let Some(release) = state.release() else {
        return Err(enclave_types::Error::NotReady);
    };
    if state.engine_overran() {
        return Err(enclave_types::Error::NotReady);
    }
    // WIP-201 §3.2: a sealed request above every pipeline's limit is rejected before opening.
    let sealed_len = u64::try_from(request.body.len()).unwrap_or(u64::MAX);
    if request.body.len() > flamingo_verifier_sealed_types::MAX_MATCH_BODY_BYTES
        || sealed_len > release.max_request_bytes()
    {
        return Err(enclave_types::Error::RequestTooLarge);
    }

    let opening_state = Arc::clone(&state);
    let (sealer, slots, prepared) = blocking(move || {
        let (plaintext, sealer) = opening_state
            .channel()
            .open(&request.body)
            .map_err(|_| enclave_types::Error::RequestNotOpened)?;
        let release = opening_state
            .release()
            .ok_or(enclave_types::Error::Internal)?;
        let (slots, prepared) = prepare(&opening_state, release, &plaintext, sealed_len);
        drop(plaintext);
        Ok::<_, enclave_types::Error>((sealer, slots, prepared))
    })
    .await??;

    // Loaded manifests have at least one slot.
    let last = slots.last().unwrap_or_default();
    let last_slot = arrival + Duration::from_millis(last);
    let result = match prepared {
        Ok(prepared) => run(Arc::clone(&state), prepared, last_slot).await,
        Err(reason) => Ok(MatchResult::Failed {
            reason,
            debug_report: DebugReport::NotProduced,
        }),
    };
    let response = match result {
        Ok(result) => {
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
        Err(error) => Err(error),
    };

    // Every outcome after opening, errors included, leaves at a slot.
    let elapsed = u64::try_from(arrival.elapsed().as_millis()).unwrap_or(u64::MAX);
    let slot = slots.release_at(elapsed).unwrap_or(last);
    sleep_until(arrival + Duration::from_millis(slot)).await;
    response
}

/// A request that passed every check before inference.
struct Prepared {
    claims: FlamingoClaims,
    threshold: f64,
    operation: Operation,
}

/// Checks the request against the release, verifies its AAT and records its (`aud`, `nonce`).
/// A failure here never reaches the Engine.
///
/// Returns the slots the response is released at: the pipeline's, or, before the pipeline is
/// known, the latest first slot of any pipeline, so an early rejection never leaves sooner than
/// a completed run.
fn prepare(
    state: &EnclaveState,
    release: &ReleaseManifest,
    plaintext: &[u8],
    sealed_len: u64,
) -> (ResponseSlots, Result<Prepared, FailureReason>) {
    let latest_first_slot = release
        .payload()
        .pipelines
        .iter()
        .filter_map(|pipeline| pipeline.response_slots.first())
        .max()
        .unwrap_or_default();
    let unresolved = ResponseSlots(vec![latest_first_slot]);
    let request = match Request::decode(plaintext, release.max_request_bytes()) {
        Ok(request) => request,
        Err(error) => return (unresolved, Err(error.into())),
    };
    let payload = match request.payload() {
        Ok(payload) => payload,
        Err(error) => return (unresolved, Err(error.into())),
    };
    if payload.release_hash != release.release_hash() {
        return (unresolved, Err(FailureReason::UnsupportedRelease));
    }
    let Some(pipeline) = release.pipeline(payload.pipeline) else {
        return (unresolved, Err(FailureReason::UnsupportedPipeline));
    };
    let slots = pipeline.response_slots.clone();
    let checked = (|| {
        if sealed_len > pipeline.max_request_bytes {
            return Err(FailureReason::RequestTooLarge);
        }
        if release
            .match_strictness_level(payload.match_strictness)
            .is_none()
        {
            return Err(FailureReason::UnsupportedMatchStrictness);
        }
        let threshold = pipeline::threshold(payload.match_strictness)?;
        // Verifies the AAT, so every WIP-106 check holds before the Engine sees the request.
        let claims = expected_claims(&request, &payload)?;
        let operation = pipeline::operation(payload)?;
        // Reserve last; a Busy result releases it because inference never started.
        state.replay().reserve(request.aud, request.nonce)?;
        Ok(Prepared {
            claims,
            threshold,
            operation,
        })
    })();
    (slots, checked)
}

async fn run(
    state: Arc<EnclaveState>,
    prepared: Prepared,
    deadline: Instant,
) -> Result<MatchResult, enclave_types::Error> {
    let scores = match prepared.operation {
        Operation::DeepFace {
            credential,
            live,
            challenge,
        } => state
            .engine()
            .deepface(credential, live, challenge, deadline)
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
            .graybadge(live, challenge, deadline)
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
        Err(BiometricError::Busy) => {
            state
                .replay()
                .release(prepared.claims.aud, prepared.claims.nonce);
            return BiometricError::Busy.into_result();
        }
        Err(BiometricError::EngineTimeout) => {
            state.reset_overrunning_engine();
            return BiometricError::EngineTimeout.into_result();
        }
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
        test_support::{
            TEST_MAX_REQUEST_BYTES, UnusedBiometricEngine, loaded_state, loaded_state_with_slots,
        },
    };
    use eddsa_babyjubjub::EdDSAPrivateKey;
    use flamingo_verifier_sealed_types::{AatInputs, CHANNEL_DOMAIN, Entry, Payload};
    use pontifex::ChannelConsumer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use world_id_flamingo::{FlamingoToken, engine_config_hash};
    use world_id_primitives::{
        FieldElement,
        authenticator_assertion::{
            AatClaims, AuthenticatorAssertionToken, AuthenticatorMeta, Platform, SecFlags,
            SecLevel, TaktClaims, TrustAnchorKeyToken, UserPresence,
        },
    };

    const AUD: u64 = 1_928_118;
    const NOW: u32 = 1_783_446_000;

    struct Engine {
        third: f32,
        delay: Duration,
        calls: Arc<AtomicUsize>,
        busy: std::sync::atomic::AtomicBool,
        terminated: Arc<AtomicUsize>,
        queue: Arc<tokio::sync::Mutex<()>>,
    }

    fn engine(third: f32) -> Engine {
        Engine {
            third,
            delay: Duration::ZERO,
            calls: Arc::default(),
            busy: std::sync::atomic::AtomicBool::new(false),
            terminated: Arc::default(),
            queue: Arc::default(),
        }
    }

    #[async_trait::async_trait]
    impl BiometricEngine for Engine {
        async fn deepface(
            &self,
            credential: Vec<u8>,
            live: LiveCapture,
            challenge: Vec<u8>,
            deadline: Instant,
        ) -> Result<DeepFaceScores, BiometricError> {
            if self.busy.swap(false, Ordering::SeqCst) {
                return Err(BiometricError::Busy);
            }
            let _guard = tokio::time::timeout_at(deadline, self.queue.lock())
                .await
                .map_err(|_| BiometricError::Busy)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::timeout_at(deadline, tokio::time::sleep(self.delay))
                .await
                .map_err(|_| BiometricError::EngineTimeout)?;
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
            deadline: Instant,
        ) -> Result<GrayBadgeScores, BiometricError> {
            if self.busy.swap(false, Ordering::SeqCst) {
                return Err(BiometricError::Busy);
            }
            let _guard = tokio::time::timeout_at(deadline, self.queue.lock())
                .await
                .map_err(|_| BiometricError::Busy)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            let LiveCapture::LightGuard { .. } = live else {
                panic!("expected a LightGuard capture")
            };
            Ok(GrayBadgeScores {
                live_challenge: f64::from(self.third),
                debug_report: Some("{\"engine\":\"test\"}".to_owned()).into(),
            })
        }

        fn terminate(&self) {
            self.terminated.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn entry(data: &[u8], meta: &[u8]) -> Entry {
        Entry {
            data: data.to_vec(),
            meta: meta.to_vec(),
        }
    }

    fn deep_face(state: &EnclaveState) -> Payload {
        Payload {
            pipeline: PIPELINE_DEEPFACE,
            match_strictness: 2,
            hints: Vec::new(),
            entries: vec![
                entry(b"orb", b""),
                entry(b"live", b""),
                entry(b"challenge", b""),
            ],
            compare: vec![0, 1, 2],
            release_hash: state.release().unwrap().release_hash(),
        }
    }

    fn gray_badge(state: &EnclaveState) -> Payload {
        Payload {
            pipeline: PIPELINE_GRAYBADGE,
            match_strictness: 2,
            hints: Vec::new(),
            entries: vec![
                entry(b"lit", b"illuminated"),
                entry(b"challenge", b""),
                entry(b"dark", b"unilluminated"),
            ],
            compare: vec![0, 1],
            release_hash: state.release().unwrap().release_hash(),
        }
    }

    fn request(payload: &Payload, nonce: u64) -> Request {
        Request::new(AUD.into(), nonce.into(), payload, None).unwrap()
    }

    /// A TAKT and an AAT over `request`'s exact payload.
    fn with_aat(mut request: Request) -> Request {
        let trust_anchor_key = EdDSAPrivateKey::from_bytes([0x07; 32]);
        let assertion_key = p256::ecdsa::SigningKey::from_bytes(&[0x09; 32].into()).unwrap();
        let sec_flags =
            SecFlags::new(Platform::Ios.into(), SecLevel::HardwareKey.into(), 2006, 3).unwrap();
        let exp = NOW + 3600;
        let takt_claims =
            TaktClaims::new(NOW, exp, exp, *assertion_key.verifying_key(), sec_flags).unwrap();
        let takt = TrustAnchorKeyToken::sign(takt_claims, &trust_anchor_key)
            .unwrap()
            .to_cwt();
        let meta = AuthenticatorMeta::new(UserPresence::PresentVerified, 0b01).unwrap();
        let aat_claims =
            AatClaims::new(NOW, AUD, NOW + 300, request.nonce, request.cdh(), meta).unwrap();
        let aat = AuthenticatorAssertionToken::sign(aat_claims, &assertion_key).to_cwt();
        request.aat_inputs = Some(AatInputs {
            trust_anchor_key: trust_anchor_key.public().to_compressed_bytes().unwrap(),
            takt,
            aat,
            now: NOW,
            min_build_version: 2006,
        });
        request
    }

    async fn exchange_bytes(state: Arc<EnclaveState>, plaintext: &[u8]) -> MatchResult {
        let consumer = ChannelConsumer::from_unverified_public_key(
            CHANNEL_DOMAIN,
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
        MatchResult::from_padded_cbor(&opener.open_from_enclave(&response.ciphertext).unwrap())
            .unwrap()
    }

    async fn exchange(state: Arc<EnclaveState>, request: &Request) -> MatchResult {
        exchange_bytes(state, &request.encode()).await
    }

    fn rejected(reason: FailureReason) -> MatchResult {
        MatchResult::Failed {
            reason,
            debug_report: DebugReport::NotProduced,
        }
    }

    fn verify(state: &EnclaveState, result: MatchResult) -> FlamingoClaims {
        let MatchResult::Success {
            statement,
            debug_report,
        } = result
        else {
            panic!("expected a signed result, got {result:?}")
        };
        assert!(matches!(debug_report, DebugReport::Available { .. }));
        *FlamingoToken::from_cwt(&statement.token)
            .unwrap()
            .verify(state.signing_public_key())
            .unwrap()
    }

    #[tokio::test]
    async fn busy_request_can_retry_without_consuming_its_nonce() {
        let passing = engine(0.95);
        passing.busy.store(true, Ordering::SeqCst);
        let calls = Arc::clone(&passing.calls);
        let state = loaded_state(passing);
        let request = request(&deep_face(&state), 77);
        let consumer = ChannelConsumer::from_unverified_public_key(
            CHANNEL_DOMAIN,
            &state.channel().public_key(),
        )
        .unwrap();
        let (sealed, _) = consumer.seal_to_enclave(&request.encode()).unwrap();
        assert_eq!(
            handler(
                Arc::clone(&state),
                MatchRequest {
                    body: sealed.into()
                }
            )
            .await,
            Err(enclave_types::Error::NotReady)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        verify(&state, exchange(Arc::clone(&state), &request).await);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            exchange(state, &request).await,
            rejected(FailureReason::Replayed)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_fresh_duplicates_run_once() {
        let passing = engine(0.95);
        let calls = Arc::clone(&passing.calls);
        let state = loaded_state(passing);
        let request = request(&deep_face(&state), 77);
        let (a, b) = tokio::join!(
            exchange(Arc::clone(&state), &request),
            exchange(Arc::clone(&state), &request)
        );
        assert_eq!(
            [&a, &b]
                .into_iter()
                .filter(|result| **result == rejected(FailureReason::Replayed))
                .count(),
            1
        );
        assert_eq!(
            [&a, &b]
                .into_iter()
                .filter(|result| matches!(result, MatchResult::Success { .. }))
                .count(),
            1
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn signs_claims_bound_to_the_request() {
        let state = loaded_state(engine(0.95));
        for (nonce, payload) in [(1, deep_face(&state)), (2, gray_badge(&state))] {
            let request = request(&payload, nonce);
            let claims = verify(&state, exchange(Arc::clone(&state), &request).await);
            assert_eq!(claims, expected_claims(&request, &payload).unwrap());
            assert_eq!(
                claims.engine_config_hash,
                engine_config_hash(&payload.release_hash, payload.pipeline, 2)
            );
            assert_eq!(claims.compared_entry_hashes[3], FieldElement::ZERO);
        }
    }

    #[tokio::test]
    async fn signs_the_verified_aat_values() {
        let state = loaded_state(engine(0.95));
        let request = with_aat(request(&deep_face(&state), 1));
        let aat = request.verify_aat().unwrap();
        let claims = verify(&state, exchange(Arc::clone(&state), &request).await);
        assert_eq!(claims.aat, aat);
        assert_eq!(claims.aat.unwrap().now, NOW);
    }

    #[tokio::test]
    async fn malformed_takt_or_aat_is_rejected_before_inference() {
        for corrupt_takt in [true, false] {
            let state = loaded_state(UnusedBiometricEngine);
            let mut request = with_aat(request(&deep_face(&state), 1));
            let inputs = request.aat_inputs.as_mut().unwrap();
            let token = if corrupt_takt {
                &mut inputs.takt
            } else {
                &mut inputs.aat
            };
            *token = vec![0xff];
            assert_eq!(
                exchange(state, &request).await,
                rejected(FailureReason::AatRejected)
            );
        }
    }

    #[tokio::test]
    async fn an_aat_for_another_payload_rejects_before_inference() {
        let state = loaded_state(UnusedBiometricEngine);
        let mut request = with_aat(request(&deep_face(&state), 1));
        let mut other = deep_face(&state);
        other.match_strictness = 3;
        request.payload = other.encode().unwrap();
        assert_eq!(
            exchange(state, &request).await,
            rejected(FailureReason::AatRejected)
        );
    }

    #[tokio::test]
    async fn every_comparison_must_clear_the_strictness_level() {
        let state = loaded_state(engine(0.89));
        assert_eq!(
            exchange(Arc::clone(&state), &request(&deep_face(&state), 1)).await,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(ComparisonRole::SelfieChallenge),
                debug_report: Some("{\"engine\":\"test\"}".to_owned()).into(),
            }
        );

        let state = loaded_state(engine(0.92));
        let mut strict = deep_face(&state);
        strict.match_strictness = 3;
        assert!(matches!(
            exchange(state, &request(&strict, 1)).await,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(ComparisonRole::SelfieChallenge),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn rejects_before_inference() {
        type Change = (fn(&mut Payload), FailureReason);
        let changes: [Change; 4] = [
            (
                |p| p.release_hash = [0; 32],
                FailureReason::UnsupportedRelease,
            ),
            (
                |p| p.match_strictness = 4,
                FailureReason::UnsupportedMatchStrictness,
            ),
            (|p| p.pipeline = 9, FailureReason::UnsupportedPipeline),
            (
                |p| p.compare = vec![0, 1],
                FailureReason::UnsupportedPipeline,
            ),
        ];
        for (change, reason) in changes {
            let state = loaded_state(UnusedBiometricEngine);
            let mut payload = deep_face(&state);
            change(&mut payload);
            assert_eq!(
                exchange(state, &request(&payload, 1)).await,
                rejected(reason)
            );
        }

        let state = loaded_state(UnusedBiometricEngine);
        assert_eq!(
            exchange_bytes(state, b"invalid").await,
            rejected(FailureReason::MalformedInputs)
        );
    }

    #[tokio::test]
    async fn enforces_the_pipeline_request_limit_after_opening() {
        let state = loaded_state(UnusedBiometricEngine);
        // Pipeline 2 allows half of pipeline 1, so this passes the pre-opening check only.
        let mut payload = gray_badge(&state);
        payload.entries[1].data = vec![0; usize::try_from(TEST_MAX_REQUEST_BYTES / 2).unwrap()];
        assert_eq!(
            exchange(state, &request(&payload, 1)).await,
            rejected(FailureReason::RequestTooLarge)
        );
    }

    #[tokio::test]
    async fn rejects_a_request_above_every_limit_before_opening() {
        let state = loaded_state(UnusedBiometricEngine);
        let body = vec![0; usize::try_from(TEST_MAX_REQUEST_BYTES).unwrap() + 1];
        assert_eq!(
            handler(state, MatchRequest { body: body.into() }).await,
            Err(enclave_types::Error::RequestTooLarge)
        );
    }

    #[tokio::test]
    async fn refuses_requests_until_a_release_is_loaded() {
        let state = crate::test_support::state_with(Arc::new(crate::test_support::EchoAttestor));
        assert_eq!(
            handler(
                state,
                MatchRequest {
                    body: vec![0; 2048].into()
                }
            )
            .await,
            Err(enclave_types::Error::NotReady)
        );
    }

    #[tokio::test]
    async fn a_processed_request_never_runs_again() {
        let failing = engine(0.5);
        let calls = Arc::clone(&failing.calls);
        let state = loaded_state(failing);
        let request = request(&deep_face(&state), 1);
        // A failed comparison still consumes the nonce.
        assert!(matches!(
            exchange(Arc::clone(&state), &request).await,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(_),
                ..
            }
        ));
        let (first, second) = tokio::join!(
            exchange(Arc::clone(&state), &request),
            exchange(Arc::clone(&state), &request)
        );
        assert_eq!(first, rejected(FailureReason::Replayed));
        assert_eq!(second, rejected(FailureReason::Replayed));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Another `aud` or `nonce` is a new request; a new boot starts a new set.
        let payload = deep_face(&state);
        let other_aud = Request::new(7u64.into(), 1u64.into(), &payload, None).unwrap();
        assert!(matches!(
            exchange(Arc::clone(&state), &other_aud).await,
            MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(_),
                ..
            }
        ));
        assert!(matches!(
            exchange(loaded_state(engine(0.95)), &request).await,
            MatchResult::Success { .. }
        ));
    }

    /// Explicit, non-geometric slots, far apart so a debug build's decryption fits the first.
    const SLOTS: &[u64] = &[400, 900, 1600];

    async fn timed(state: Arc<EnclaveState>, request: &Request) -> (MatchResult, Duration) {
        let start = Instant::now();
        let result = exchange(state, request).await;
        (result, start.elapsed())
    }

    #[tokio::test]
    async fn an_early_rejection_waits_for_the_first_slot() {
        let state = loaded_state_with_slots(UnusedBiometricEngine, SLOTS);
        let mut payload = deep_face(&state);
        payload.match_strictness = 4;
        let (result, elapsed) = timed(state, &request(&payload, 1)).await;
        assert_eq!(result, rejected(FailureReason::UnsupportedMatchStrictness));
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
    }

    #[tokio::test]
    async fn an_undecodable_request_waits_for_the_latest_first_slot() {
        let state = loaded_state_with_slots(UnusedBiometricEngine, SLOTS);
        let start = Instant::now();
        assert_eq!(
            exchange_bytes(state, b"invalid").await,
            rejected(FailureReason::MalformedInputs)
        );
        assert!(start.elapsed() >= Duration::from_millis(400));
    }

    #[tokio::test]
    async fn a_result_is_released_at_the_next_slot() {
        let slow = Engine {
            delay: Duration::from_millis(500),
            ..engine(0.95)
        };
        let state = loaded_state_with_slots(slow, SLOTS);
        let (result, elapsed) = timed(Arc::clone(&state), &request(&deep_face(&state), 1)).await;
        assert!(matches!(result, MatchResult::Success { .. }));
        assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1600), "{elapsed:?}");
    }

    #[tokio::test]
    async fn queued_request_can_retry_without_resetting_an_active_engine() {
        use crate::test_support::{EchoAttestor, TEST_ENGINE_HASH, manifest_with_slots};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let slow = Engine {
            delay: Duration::from_millis(800),
            ..engine(0.95)
        };
        let calls = Arc::clone(&slow.calls);
        let terminated = Arc::clone(&slow.terminated);
        let state = Arc::new(
            EnclaveState::generate(Arc::new(EchoAttestor), Box::new(slow), TEST_ENGINE_HASH)
                .unwrap(),
        );
        // DeepFace has time to finish, but the queued GrayBadge request expires first.
        let manifest = manifest_with_slots(TEST_ENGINE_HASH, "1.0.0", SLOTS);
        let parts: Vec<_> = manifest.split('.').collect();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        payload["pipelines"][1]["response_slots"] = serde_json::json!([200]);
        state
            .load_release(&format!(
                "{}.{}.{}",
                parts[0],
                URL_SAFE_NO_PAD.encode(payload.to_string()),
                parts[2]
            ))
            .unwrap();
        let first = request(&deep_face(&state), 1);
        let running = tokio::spawn({
            let state = Arc::clone(&state);
            async move { exchange(state, &first).await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let queued = request(&gray_badge(&state), 2);
        let consumer = ChannelConsumer::from_unverified_public_key(
            CHANNEL_DOMAIN,
            &state.channel().public_key(),
        )
        .unwrap();
        let (sealed, _) = consumer.seal_to_enclave(&queued.encode()).unwrap();
        assert_eq!(
            handler(
                Arc::clone(&state),
                MatchRequest {
                    body: sealed.into()
                }
            )
            .await,
            Err(enclave_types::Error::NotReady)
        );
        assert!(!state.engine_overran());
        assert_eq!(terminated.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        verify(&state, running.await.unwrap());
        verify(&state, exchange(Arc::clone(&state), &queued).await);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!state.engine_overran());
    }

    #[tokio::test]
    async fn an_engine_past_the_last_slot_fails_and_is_terminated() {
        let stuck = Engine {
            delay: Duration::from_secs(5),
            ..engine(0.95)
        };
        let terminated = Arc::clone(&stuck.terminated);
        let state = loaded_state_with_slots(stuck, SLOTS);
        let (result, elapsed) = timed(Arc::clone(&state), &request(&deep_face(&state), 1)).await;
        assert_eq!(result, rejected(FailureReason::EngineTimeout));
        assert!(elapsed >= Duration::from_millis(1600), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(terminated.load(Ordering::SeqCst), 1);
        assert!(state.engine_overran());
        assert_eq!(
            handler(
                state,
                MatchRequest {
                    body: vec![0; 2048].into()
                }
            )
            .await,
            Err(enclave_types::Error::NotReady)
        );
    }
}
