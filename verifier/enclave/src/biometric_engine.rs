//! Inference boundary and exclusive, cancellation-safe sandbox execution.

#[cfg(any(target_os = "linux", test))]
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use flamingo_verifier_sealed_types::{DebugReport, FailureReason, MatchResult};
use tokio::time::Instant;
#[cfg(test)]
use tokio::time::timeout;
#[cfg(any(target_os = "linux", test))]
use tokio::{sync::Mutex, time::timeout_at};

#[cfg(any(target_os = "linux", test))]
use crate::blocking;

#[cfg(any(target_os = "linux", test))]
const QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
/// Delay between an Engine overrun and the enclave exit that resets the worker.
#[cfg(target_os = "linux")]
const RESET_GRACE: Duration = Duration::from_secs(2);

/// Separates image rejections from unavailable infrastructure.
#[derive(Debug, PartialEq, Eq)]
pub enum BiometricError {
    /// A bounded wait for inference expired.
    Busy,
    /// Inference started but did not finish by the final response slot.
    EngineTimeout,
    /// Structured input or biological rejection.
    Rejected(FailureReason),
    /// Worker rejection with its bounded report.
    AnalysisRejected {
        /// Semantic rejection.
        reason: FailureReason,
        /// Diagnostics produced before rejection.
        debug_report: DebugReport,
    },
    /// Infrastructure could not complete the operation.
    Internal,
}

impl BiometricError {
    pub(crate) fn into_result(self) -> Result<MatchResult, flamingo_verifier_enclave_types::Error> {
        use flamingo_verifier_enclave_types::Error;

        match self {
            Self::Busy => Err(Error::NotReady),
            Self::EngineTimeout => Ok(MatchResult::Failed {
                reason: FailureReason::EngineTimeout,
                debug_report: DebugReport::NotProduced,
            }),
            Self::Internal
            | Self::Rejected(FailureReason::Internal)
            | Self::AnalysisRejected {
                reason: FailureReason::Internal,
                ..
            } => Err(Error::Internal),
            Self::AnalysisRejected {
                reason,
                debug_report,
            } => Ok(MatchResult::Failed {
                reason,
                debug_report,
            }),
            Self::Rejected(reason) => Ok(MatchResult::Failed {
                reason,
                debug_report: DebugReport::NotProduced,
            }),
        }
    }
}

/// Executes canonical Payload bytes; the worker owns pipeline and strictness policy.
///
/// Implementations respect the absolute response deadline: queue expiry returns `Busy`,
/// while expiry after starting inference returns `EngineTimeout`.
#[async_trait]
pub trait BiometricEngine: Send + Sync {
    /// Returns a bounded report only after the Engine declares Pass.
    /// # Errors
    /// Returns a structured rejection or infrastructure failure.
    async fn evaluate(&self, payload: Vec<u8>, deadline: Instant) -> Result<DebugReport, BiometricError>;
    /// Checks liveness without waiting for an active inference operation.
    fn check_health(&self) {}
    /// Terminates an Engine whose request overran its last response slot, so no state from that
    /// request reaches the next one.
    fn terminate(&self);
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
        deadline: Instant,
        work: impl FnOnce(&mut W) -> T + Send + 'static,
    ) -> Result<T, BiometricError> {
        // TODO: Bound waiting request memory if traffic requires more than this single mutex.
        let mut worker = timeout_at(
            deadline.min(Instant::now() + QUEUE_TIMEOUT),
            Arc::clone(&self.worker).lock_owned(),
        )
        .await
        .map_err(|_| BiometricError::Busy)?;
        if Instant::now() >= deadline {
            return Err(BiometricError::Busy);
        }
        // The blocking task owns the guard even when its async caller disconnects.
        timeout_at(deadline, blocking(move || work(&mut worker)))
            .await
            .map_err(|_| BiometricError::EngineTimeout)?
            .map_err(|_| BiometricError::Internal)
    }
}

#[cfg(target_os = "linux")]
pub use sandboxed::SandboxBiometricEngine;

#[cfg(target_os = "linux")]
mod sandboxed {
    use super::{BiometricEngine, BiometricError, DebugReport, Executor, Instant};
    use async_trait::async_trait;
    use flamingo_engine_interface::ErrorCode;
    use flamingo_verifier_sandbox_client::{Rejection, SandboxClient};
    use flamingo_verifier_sealed_types::FailureReason;

    /// Owns the sandboxed worker, queue and IPC execution for one enclave boot.
    pub struct SandboxBiometricEngine {
        executor: Executor<SandboxClient>,
    }

    impl SandboxBiometricEngine {
        /// Takes a worker initialized before enclave key generation.
        #[must_use]
        pub fn new(worker: SandboxClient) -> Self {
            Self {
                executor: Executor::new(worker),
            }
        }
    }

    #[async_trait]
    impl BiometricEngine for SandboxBiometricEngine {
        async fn evaluate(&self, payload: Vec<u8>, deadline: Instant) -> Result<DebugReport, BiometricError> {
            self.executor
                .run(deadline, move |worker| worker.evaluate(&payload))
                .await?
                .map(DebugReport::from)
                .map_err(|rejection| match rejection {
                    Rejection::InvalidPayload => {
                        BiometricError::Rejected(FailureReason::MalformedInputs)
                    }
                    Rejection::Engine { code, debug_report } => BiometricError::AnalysisRejected {
                        reason: match code {
                            ErrorCode::InvalidPayload => FailureReason::MalformedInputs,
                            ErrorCode::UnsupportedPipeline => FailureReason::UnsupportedPipeline,
                            ErrorCode::UnsupportedMatchStrictness => {
                                FailureReason::UnsupportedMatchStrictness
                            }
                            ErrorCode::BiometricRejected => FailureReason::BiometricRejected,
                            ErrorCode::MatchRejected => FailureReason::MatchRejected,
                            ErrorCode::Internal => FailureReason::Internal,
                        },
                        debug_report: debug_report.into(),
                    },
                })
        }

        // The overrunning request holds the worker. A new boot resets it; allow its sealed
        // failure to reach the client before exiting.
        fn terminate(&self) {
            tokio::spawn(async {
                tokio::time::sleep(super::RESET_GRACE).await;
                tracing::error!(
                    dependency = "biometric_worker",
                    "exiting to reset the worker"
                );
                std::process::exit(1);
            });
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

        assert_eq!(BiometricError::Busy.into_result(), Err(Error::NotReady));
        for error in [
            BiometricError::Internal,
            BiometricError::Rejected(FailureReason::Internal),
        ] {
            assert_eq!(error.into_result(), Err(Error::Internal));
        }
        assert_eq!(
            BiometricError::Rejected(FailureReason::MalformedInputs).into_result(),
            Ok(MatchResult::Failed {
                reason: FailureReason::MalformedInputs,
                debug_report: DebugReport::NotProduced
            })
        );
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
                    .run(Instant::now() + Duration::from_secs(30), move |()| {
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
            async move {
                executor
                    .run(Instant::now() + Duration::from_secs(30), |()| 42)
                    .await
            }
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
            async move {
                executor
                    .run(Instant::now() + Duration::from_secs(30), |()| {
                        panic!("cancelled waiter executed")
                    })
                    .await
            }
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
        assert_eq!(
            executor
                .run(Instant::now() + Duration::from_secs(30), |()| ())
                .await,
            Err(BiometricError::Busy)
        );
    }

    #[tokio::test]
    async fn active_inference_timeout_keeps_worker_exclusive() {
        let executor = Executor::new(());
        let (release, receiver) = mpsc::sync_channel(1);
        let result = executor
            .run(Instant::now() + Duration::from_millis(100), move |()| {
                receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            })
            .await;
        assert_eq!(result, Err(BiometricError::EngineTimeout));
        assert!(executor.worker.try_lock().is_err());
        release.send(()).unwrap();
        let _guard = timeout(Duration::from_secs(2), executor.worker.lock())
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn response_deadline_expires_in_queue_without_starting_inference() {
        let executor = Executor::new(());
        let guard = executor.worker.lock().await;
        let start = Instant::now();
        assert_eq!(
            executor
                .run(start + Duration::from_secs(1), |()| panic!(
                    "queued request ran"
                ))
                .await,
            Err(BiometricError::Busy)
        );
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        drop(guard);
        assert_eq!(
            executor
                .run(Instant::now(), |()| panic!("expired request ran"))
                .await,
            Err(BiometricError::Busy)
        );
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
                                .run(Instant::now() + Duration::from_secs(30), move |()| {
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
}
