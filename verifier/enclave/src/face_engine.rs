//! Synchronous comparison boundary to the separately sandboxed worker.

use flamingo_verifier_sealed_types::FailureReason;
pub use flamingo_verifier_worker_protocol::ComparisonScores;

/// Maximum accepted encoded bytes per image; matches the public sealed-input limit.
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum comparison message, including bounded CBOR overhead.
pub const MAX_REQUEST_BYTES: usize = 3 * MAX_IMAGE_BYTES + 1024;

/// Face comparison behavior required by the enclave match operation.
pub trait FaceComparator: Send + Sync {
    /// Compares the credential image with both probes without exposing embeddings.
    ///
    /// # Errors
    ///
    /// Returns a sealed rejection when the images cannot be analyzed.
    fn compare_reference_to_probes(
        &self,
        credential_image: &[u8],
        live_image: &[u8],
        challenge_image: &[u8],
    ) -> Result<ComparisonScores, FailureReason>;

    /// Checks idle worker liveness without blocking an in-flight comparison.
    /// Fatal production failures terminate the enclave; test comparators need no process probe.
    fn check_health(&self) {}
}

#[cfg(target_os = "linux")]
pub use sandboxed::FaceEngine;

#[cfg(target_os = "linux")]
mod sandboxed {
    use std::sync::{Mutex, TryLockError};

    use flamingo_verifier_sealed_types::FailureReason;
    use flamingo_verifier_worker_process::{Worker, WorkerError};
    use flamingo_verifier_worker_protocol::CompareRequest;
    use flamingo_verifier_worker_rpc::WorkerClientError;

    use super::{ComparisonScores, FaceComparator, MAX_IMAGE_BYTES};

    /// One exclusively owned worker; admission happens before creating the blocking task.
    pub struct FaceEngine {
        /// Admission prevents a second comparison; health only holds this for a nonblocking probe.
        worker: Mutex<Worker>,
    }

    impl FaceEngine {
        /// Takes the already authenticated and sandboxed worker before generating broker keys.
        #[must_use]
        pub const fn new(worker: Worker) -> Self {
            Self {
                worker: Mutex::new(worker),
            }
        }
    }

    impl FaceComparator for FaceEngine {
        /// Rejects local bad input; worker transport, deadline and model faults exit the enclave.
        fn compare_reference_to_probes(
            &self,
            credential_image: &[u8],
            live_image: &[u8],
            challenge_image: &[u8],
        ) -> Result<ComparisonScores, FailureReason> {
            if [credential_image, live_image, challenge_image]
                .iter()
                .any(|image| image.is_empty() || image.len() > MAX_IMAGE_BYTES)
            {
                return Err(FailureReason::MalformedInputs);
            }

            let Ok(mut worker) = self.worker.lock() else {
                tracing::error!(
                    failure_class = "worker_ownership",
                    "exclusive worker ownership violated"
                );
                std::process::exit(1);
            };
            worker
                .compare(CompareRequest {
                    credential_image: credential_image.to_vec(),
                    live_image: live_image.to_vec(),
                    challenge_image: challenge_image.to_vec(),
                })
                .map_err(|error| match error {
                    WorkerError::Rpc(WorkerClientError::AnalysisFailed) => {
                        FailureReason::ImageAnalysisFailed
                    }
                    WorkerError::Rpc(
                        WorkerClientError::InvalidImages | WorkerClientError::RequestEncoding(_),
                    ) => FailureReason::MalformedInputs,
                    _ => {
                        tracing::error!(
                            failure_class = "worker_failure",
                            "unexpected worker comparison failure"
                        );
                        std::process::exit(1);
                    }
                })
        }

        /// In-flight RPC has a hard deadline; an idle exited child must not stay healthy.
        fn check_health(&self) {
            match self.worker.try_lock() {
                Ok(worker) => worker.check_alive(),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => {
                    tracing::error!(
                        failure_class = "worker_ownership",
                        "worker ownership poisoned"
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}
