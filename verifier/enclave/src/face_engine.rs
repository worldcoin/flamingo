//! Synchronous image-only boundary to the sandboxed worker.
use flamingo_verifier_sealed_types::FailureReason;
/// Maximum encoded bytes per image.
pub const MAX_IMAGE_BYTES: usize = flamingo_verifier_api_types::MAX_IMAGE_BYTES;
/// Worker request budget for three vanilla images and protobuf overhead.
pub const MAX_REQUEST_BYTES: usize = flamingo_verifier_api_types::MAX_TOTAL_IMAGE_BYTES + 1024;

/// Internal normalized scores; these do not define the signed-token contract.
#[derive(Clone, Copy)]
pub struct DeepFaceScores {
    /// Orb credential versus live selfie.
    pub similarity_orb_selfie: f64,
    /// Orb credential versus RTMS challenge.
    pub similarity_orb_challenge: f64,
    /// Live selfie versus RTMS challenge.
    pub similarity_selfie_challenge: f64,
}

/// Internal normalized score for the credential-free operation.
pub struct GrayBadgeScores {
    /// Live selfie versus RTMS challenge.
    pub similarity_selfie_challenge: f64,
}

/// Image-only inference operations. PCP verification and threshold policy belong to the caller.
pub trait FaceComparator: Send + Sync {
    /// Compare the credential, live selfie and challenge using the worker protocol.
    /// # Errors
    /// Returns structured analysis failures or infrastructure faults.
    fn deep_face(
        &mut self,
        credential: &[u8],
        live: &[u8],
        challenge: &[u8],
    ) -> Result<DeepFaceScores, FailureReason>;

    /// Compare the live selfie and challenge using the worker protocol.
    /// # Errors
    /// Returns structured analysis failures or infrastructure faults.
    fn gray_badge(
        &mut self,
        live: &[u8],
        challenge: &[u8],
    ) -> Result<GrayBadgeScores, FailureReason>;
    /// Checks idle worker liveness without waiting for active inference.
    fn check_health(&self) {}
}

/// Preserve the existing engine's f32 normalization before applying public policy.
#[cfg(any(target_os = "linux", test))]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the pinned worker emits raw cosine widened from f32; preserve existing normalization"
)]
fn normalized(score: f64) -> f64 {
    f64::from(f32::midpoint(1.0, score as f32))
}

#[cfg(target_os = "linux")]
pub use sandboxed::FaceEngine;
#[cfg(target_os = "linux")]
mod sandboxed {
    use super::{DeepFaceScores, FaceComparator, FailureReason, GrayBadgeScores, normalized};
    use biometric_engines_protocol::{
        Operation, ResponseBody,
        face::{DeepFaceRequest, GrayBadgeRequest, ImageBytes, LiveCapture},
    };
    use flamingo_verifier_sandbox_client::{Worker, WorkerClientError, WorkerError};
    /// Owns the eagerly initialized worker under the broker's exclusive mutex.
    pub struct FaceEngine {
        worker: Worker,
    }
    impl FaceEngine {
        /// Takes an initialized worker before broker key generation.
        #[must_use]
        pub const fn new(worker: Worker) -> Self {
            Self { worker }
        }
        fn run(&mut self, op: Operation) -> Result<ResponseBody, FailureReason> {
            self.worker.evaluate(op).map_err(|error| match error {
                WorkerError::Rpc(WorkerClientError::AnalysisFailed(failure)) => {
                    crate::error::worker_failure(failure)
                }
                WorkerError::Rpc(
                    WorkerClientError::InvalidImages | WorkerClientError::RequestEncoding(_),
                ) => FailureReason::MalformedInputs,
                _ => {
                    tracing::error!(%error, "unexpected worker failure");
                    std::process::exit(1);
                }
            })
        }
    }
    impl FaceComparator for FaceEngine {
        fn deep_face(
            &mut self,
            credential: &[u8],
            live: &[u8],
            challenge: &[u8],
        ) -> Result<DeepFaceScores, FailureReason> {
            let ResponseBody::DeepFace(scores) =
                self.run(Operation::DeepFace(DeepFaceRequest {
                    orb_credential: ImageBytes(credential.to_vec()),
                    live: LiveCapture::Vanilla(ImageBytes(live.to_vec())),
                    rtms_challenge: ImageBytes(challenge.to_vec()),
                }))?
            else {
                unreachable!("client validates response type")
            };
            Ok(DeepFaceScores {
                similarity_orb_selfie: normalized(scores.similarity_orb_selfie),
                similarity_orb_challenge: normalized(scores.similarity_orb_challenge),
                similarity_selfie_challenge: normalized(scores.similarity_selfie_challenge),
            })
        }
        fn gray_badge(
            &mut self,
            live: &[u8],
            challenge: &[u8],
        ) -> Result<GrayBadgeScores, FailureReason> {
            let ResponseBody::GrayBadge(scores) =
                self.run(Operation::GrayBadge(GrayBadgeRequest {
                    live: LiveCapture::Vanilla(ImageBytes(live.to_vec())),
                    rtms_challenge: ImageBytes(challenge.to_vec()),
                }))?
            else {
                unreachable!("client validates response type")
            };
            Ok(GrayBadgeScores {
                similarity_selfie_challenge: normalized(scores.similarity_selfie_challenge),
            })
        }
        fn check_health(&self) {
            self.worker.check_alive();
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn raw_cosine_keeps_existing_public_normalization() {
        for (raw, expected) in [
            (-1.0, 0.0),
            (0.0, 0.5),
            (1.0, 1.0),
            (0.8, f64::from(0.9f32)),
        ] {
            assert_eq!(super::normalized(raw).to_bits(), expected.to_bits());
        }
    }
}
