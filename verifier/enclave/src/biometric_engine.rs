//! Inference boundary and exclusive, cancellation-safe sandbox execution.

#[cfg(any(target_os = "linux", test))]
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
#[cfg(any(target_os = "linux", test))]
use biometric_engines_protocol::face::{LightGuard, LightGuardMatchingFrame, face_image::Source};
#[cfg(any(target_os = "linux", test))]
use flamingo_verifier_sealed_types::{ByteBuf, capture_profile};
use flamingo_verifier_sealed_types::{FailureReason, LiveCapture};
#[cfg(any(target_os = "linux", test))]
use tokio::{sync::Mutex, time::timeout};

#[cfg(any(target_os = "linux", test))]
use crate::blocking;

/// Maximum encoded bytes per image, derived from the public API.
pub const MAX_IMAGE_BYTES: usize = flamingo_verifier_api_types::MAX_IMAGE_BYTES;
/// API image budget plus protobuf envelope overhead.
pub const MAX_REQUEST_BYTES: usize = flamingo_verifier_api_types::MAX_TOTAL_IMAGE_BYTES + 1024;
#[cfg(any(target_os = "linux", test))]
const QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

/// Normalized inference scores; policy and signed claims belong to the operation.
#[derive(Clone, Copy, Debug)]
pub struct DeepFaceScores {
    /// Credential versus live image.
    pub credential_live: f64,
    /// Credential versus challenge image.
    pub credential_challenge: f64,
    /// Live versus challenge image.
    pub live_challenge: f64,
}

/// Normalized credential-free inference score.
#[derive(Debug)]
pub struct GrayBadgeScores {
    /// Live versus challenge image.
    pub live_challenge: f64,
}

/// Separates image rejections from unavailable infrastructure.
#[derive(Debug, PartialEq, Eq)]
pub enum BiometricError {
    /// A bounded wait for inference expired.
    Busy,
    /// Structured input or biological rejection.
    Rejected(FailureReason),
    /// Infrastructure could not complete the operation.
    Internal,
}

impl BiometricError {
    pub(crate) const fn into_result(
        self,
    ) -> Result<flamingo_verifier_sealed_types::MatchResult, flamingo_verifier_enclave_types::Error>
    {
        use flamingo_verifier_enclave_types::Error;
        use flamingo_verifier_sealed_types::MatchResult;

        match self {
            Self::Busy => Err(Error::NotReady),
            Self::Internal | Self::Rejected(FailureReason::Internal) => Err(Error::Internal),
            Self::Rejected(reason) => Ok(MatchResult::Failed(reason)),
        }
    }
}

/// Image-only operations; PCP verification, policy and signing stay in the enclave operations.
#[async_trait]
pub trait BiometricEngine: Send + Sync {
    /// Compares the credential, live and challenge images.
    /// # Errors
    /// Returns a structured image rejection or infrastructure failure.
    async fn deepface(
        &self,
        credential: Vec<u8>,
        live: LiveCapture,
        challenge: Vec<u8>,
    ) -> Result<DeepFaceScores, BiometricError>;
    /// Compares live and challenge images.
    /// # Errors
    /// Returns a structured image rejection or infrastructure failure.
    async fn graybadge(
        &self,
        live: LiveCapture,
        challenge: Vec<u8>,
    ) -> Result<GrayBadgeScores, BiometricError>;
    /// Checks liveness without waiting for an active inference operation.
    fn check_health(&self) {}
}

#[cfg(any(target_os = "linux", test))]
struct Executor<W> {
    worker: Arc<Mutex<W>>,
}

#[cfg(any(target_os = "linux", test))]
impl<W: Send + 'static> Executor<W> {
    fn new(worker: W) -> Self {
        Self {
            worker: Arc::new(Mutex::new(worker)),
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut W) -> T + Send + 'static,
    ) -> Result<T, BiometricError> {
        // TODO: Bound waiting request memory if traffic requires more than this single mutex.
        let mut worker = timeout(QUEUE_TIMEOUT, Arc::clone(&self.worker).lock_owned())
            .await
            .map_err(|_| BiometricError::Busy)?;
        // The blocking task owns the guard even when its async caller disconnects.
        blocking(move || work(&mut worker))
            .await
            .map_err(|_| BiometricError::Internal)
    }
}

#[cfg(any(target_os = "linux", test))]
#[expect(
    clippy::cast_possible_truncation,
    reason = "preserve the existing f32 cosine normalization"
)]
fn normalized(score: f64) -> f64 {
    f64::from(f32::midpoint(1.0, score as f32))
}

/// Maps a capture profile onto the engine's image source; unknown profiles never reach the engine.
#[cfg(any(target_os = "linux", test))]
fn live_source(capture: LiveCapture) -> Result<Source, BiometricError> {
    let LiveCapture {
        profile,
        frames,
        matching_frame,
    } = capture;
    let unsupported = || BiometricError::Rejected(FailureReason::UnsupportedCapture);
    let mut frames = frames.into_iter().map(ByteBuf::into_vec);

    match (profile.as_str(), frames.len(), matching_frame) {
        (capture_profile::VANILLA, 1, 0) => Ok(Source::VanillaSelfie(
            frames.next().ok_or_else(unsupported)?,
        )),
        (capture_profile::LIGHT_GUARD, 2, 0 | 1) => Ok(Source::LightGuard(LightGuard {
            illuminated: frames.next().ok_or_else(unsupported)?,
            unilluminated: frames.next().ok_or_else(unsupported)?,
            matching_frame: if matching_frame == 0 {
                LightGuardMatchingFrame::Illuminated
            } else {
                LightGuardMatchingFrame::Unilluminated
            } as i32,
        })),
        _ => Err(unsupported()),
    }
}

#[cfg(target_os = "linux")]
pub use sandboxed::SandboxBiometricEngine;

#[cfg(target_os = "linux")]
mod sandboxed {
    use super::{
        BiometricEngine, BiometricError, DeepFaceScores, Executor, GrayBadgeScores, live_source,
        normalized,
    };
    use async_trait::async_trait;
    use biometric_engines_protocol::{
        face::{DeepFaceRequest, FaceImage, GrayBadgeRequest, face_image::Source},
        request::Operation,
        response::Outcome,
    };
    use flamingo_verifier_sandbox_client::{SandboxClientError, Worker, WorkerError};
    use flamingo_verifier_sealed_types::{FailureReason, LiveCapture};

    /// Owns the sandboxed worker, queue and IPC execution for one enclave boot.
    pub struct SandboxBiometricEngine {
        executor: Executor<Worker>,
    }

    impl SandboxBiometricEngine {
        /// Takes a worker initialized before enclave key generation.
        #[must_use]
        pub fn new(worker: Worker) -> Self {
            Self {
                executor: Executor::new(worker),
            }
        }

        async fn run(&self, operation: Operation) -> Result<Outcome, BiometricError> {
            self.executor
                .run(move |worker| worker.evaluate(operation))
                .await?
                .map_err(|error| match error {
                    WorkerError::Rpc(SandboxClientError::AnalysisFailed(failure)) => {
                        BiometricError::from(&failure)
                    }
                    WorkerError::Rpc(SandboxClientError::InvalidImages) => {
                        BiometricError::Rejected(FailureReason::MalformedInputs)
                    }
                    _ => {
                        tracing::error!("sandboxed biometric worker failed");
                        std::process::exit(1);
                    }
                })
        }
    }

    const fn image(source: Source) -> FaceImage {
        FaceImage {
            source: Some(source),
        }
    }

    #[async_trait]
    impl BiometricEngine for SandboxBiometricEngine {
        async fn deepface(
            &self,
            credential: Vec<u8>,
            live: LiveCapture,
            challenge: Vec<u8>,
        ) -> Result<DeepFaceScores, BiometricError> {
            let Outcome::DeepFace(scores) = self
                .run(Operation::DeepFace(DeepFaceRequest {
                    credential: Some(image(Source::Orb(credential))),
                    live: Some(image(live_source(live)?)),
                    challenge: Some(image(Source::Rtms(challenge))),
                }))
                .await?
            else {
                unreachable!("client validates response operation")
            };
            Ok(DeepFaceScores {
                credential_live: normalized(
                    scores
                        .similarity_credential_live
                        .expect("client validates required scores"),
                ),
                credential_challenge: normalized(
                    scores
                        .similarity_credential_challenge
                        .expect("client validates required scores"),
                ),
                live_challenge: normalized(
                    scores
                        .similarity_live_challenge
                        .expect("client validates required scores"),
                ),
            })
        }

        async fn graybadge(
            &self,
            live: LiveCapture,
            challenge: Vec<u8>,
        ) -> Result<GrayBadgeScores, BiometricError> {
            let Outcome::GrayBadge(scores) = self
                .run(Operation::GrayBadge(GrayBadgeRequest {
                    live: Some(image(live_source(live)?)),
                    challenge: Some(image(Source::Rtms(challenge))),
                }))
                .await?
            else {
                unreachable!("client validates response operation")
            };
            Ok(GrayBadgeScores {
                live_challenge: normalized(
                    scores
                        .similarity_live_challenge
                        .expect("client validates required score"),
                ),
            })
        }

        fn check_health(&self) {
            if let Ok(worker) = self.executor.worker.try_lock() {
                worker.check_alive();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::sync::Notify;

    #[test]
    fn infrastructure_errors_stay_distinct_from_encrypted_rejections() {
        use flamingo_verifier_enclave_types::Error;
        use flamingo_verifier_sealed_types::MatchResult;

        assert_eq!(BiometricError::Busy.into_result(), Err(Error::NotReady));
        for error in [
            BiometricError::Internal,
            BiometricError::Rejected(FailureReason::Internal),
        ] {
            assert_eq!(error.into_result(), Err(Error::Internal));
        }
        assert_eq!(
            BiometricError::Rejected(FailureReason::MalformedInputs).into_result(),
            Ok(MatchResult::Failed(FailureReason::MalformedInputs))
        );
    }

    #[test]
    fn preserves_existing_score_normalization() {
        for (raw, expected) in [
            (-1.0, 0.0),
            (0.0, 0.5),
            (1.0, 1.0),
            (0.8, f64::from(0.9f32)),
        ] {
            assert_eq!(normalized(raw).to_bits(), expected.to_bits());
        }
    }

    #[tokio::test]
    async fn cancelling_active_inference_keeps_exclusive_worker_ownership() {
        let executor = Arc::new(Executor::new(()));
        let entered = Arc::new(Notify::new());
        let (release, receiver) = mpsc::sync_channel(1);
        let first = tokio::spawn({
            let executor = Arc::clone(&executor);
            let entered = Arc::clone(&entered);
            async move {
                executor
                    .run(move |()| {
                        entered.notify_one();
                        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                    })
                    .await
            }
        });
        timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        let mut second = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.run(|()| 42).await }
        });
        assert!(
            timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err()
        );
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(executor.worker.try_lock().is_err());
        assert!(
            timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), second)
                .await
                .unwrap()
                .unwrap(),
            Ok(42)
        );
    }

    #[tokio::test]
    async fn cancelled_waiter_never_runs_inference() {
        let executor = Arc::new(Executor::new(()));
        let guard = executor.worker.lock().await;
        let mut task = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.run(|()| panic!("cancelled waiter executed")).await }
        });
        assert!(timeout(Duration::from_millis(50), &mut task).await.is_err());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(guard);
        assert!(executor.worker.try_lock().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn queue_wait_is_bounded() {
        let executor = Executor::new(());
        let _guard = executor.worker.lock().await;
        assert_eq!(executor.run(|()| ()).await, Err(BiometricError::Busy));
    }

    #[test]
    fn detached_inference_panic_is_terminal() {
        const ENV: &str = "FLAMINGO_TEST_DETACHED_INFERENCE_PANIC";
        if std::env::var_os(ENV).is_some() {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let executor = Arc::new(Executor::new(()));
                    let entered = Arc::new(Notify::new());
                    let (release, receiver) = mpsc::sync_channel(1);
                    let task = tokio::spawn({
                        let executor = Arc::clone(&executor);
                        let entered = Arc::clone(&entered);
                        async move {
                            executor
                                .run(move |()| {
                                    entered.notify_one();
                                    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                                    panic!("detached inference panic");
                                })
                                .await
                        }
                    });
                    timeout(Duration::from_secs(2), entered.notified())
                        .await
                        .unwrap();
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                    release.send(()).unwrap();
                    let _guard = timeout(Duration::from_secs(2), executor.worker.lock())
                        .await
                        .unwrap();
                });
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "biometric_engine::tests::detached_inference_panic_is_terminal",
            ])
            .env(ENV, "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(1));
    }

    fn capture(profile: &str, frames: Vec<Vec<u8>>, matching_frame: u32) -> LiveCapture {
        LiveCapture {
            profile: profile.to_owned(),
            frames: frames.into_iter().map(Into::into).collect(),
            matching_frame,
        }
    }

    #[test]
    fn light_guard_preserves_both_frames_and_the_selected_matching_frame() {
        for (matching_frame, expected) in [
            (0, LightGuardMatchingFrame::Illuminated),
            (1, LightGuardMatchingFrame::Unilluminated),
        ] {
            let illuminated = vec![1, 2, 3];
            let pointer = illuminated.as_ptr();
            let Ok(Source::LightGuard(pair)) = live_source(capture(
                capture_profile::LIGHT_GUARD,
                vec![illuminated, vec![4, 5]],
                matching_frame,
            )) else {
                panic!("must preserve LightGuard source")
            };
            assert_eq!(pair.illuminated, vec![1, 2, 3]);
            assert_eq!(pair.illuminated.as_ptr(), pointer);
            assert_eq!(pair.unilluminated, vec![4, 5]);
            assert_eq!(pair.matching_frame, expected as i32);
        }
    }

    #[test]
    fn vanilla_maps_to_a_single_selfie() {
        assert_eq!(
            live_source(LiveCapture::vanilla(vec![7].into())),
            Ok(Source::VanillaSelfie(vec![7]))
        );
    }

    #[test]
    fn unknown_profiles_and_frame_shapes_are_rejected_before_the_engine() {
        for live in [
            capture("future_pad", vec![vec![1]], 0),
            capture(capture_profile::VANILLA, vec![vec![1], vec![2]], 0),
            capture(capture_profile::LIGHT_GUARD, vec![vec![1]], 0),
            capture(
                capture_profile::LIGHT_GUARD,
                vec![vec![1], vec![2], vec![3]],
                2,
            ),
        ] {
            assert_eq!(
                live_source(live),
                Err(BiometricError::Rejected(FailureReason::UnsupportedCapture))
            );
        }
    }
}
