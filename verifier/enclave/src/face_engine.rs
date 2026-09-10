//! Temporary in-process adapter until the broker is wired to the sandboxed worker.

use std::path::Path;

use flamingo_verifier_sealed_types::FailureReason;
pub use flamingo_verifier_worker_protocol::ComparisonScores;

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
}

/// Legacy in-process owner; the implementation and configs now live with the worker.
pub struct FaceEngine {
    /// Shared implementation, not yet an RPC client.
    inner: flamingo_verifier_worker::FaceEngine,
}

impl Default for FaceEngine {
    /// Preserves eager loading for the existing enclave boot path.
    fn default() -> Self {
        Self {
            inner: flamingo_verifier_worker::FaceEngine::load(Path::new("/models"))
                .expect("Face Engine models must load before enclave startup"),
        }
    }
}

impl FaceComparator for FaceEngine {
    /// Preserves the legacy API's failure mapping until terminal RPC handling is integrated.
    fn compare_reference_to_probes(
        &self,
        credential_image: &[u8],
        live_image: &[u8],
        challenge_image: &[u8],
    ) -> Result<ComparisonScores, FailureReason> {
        self.inner
            .compare(credential_image, live_image, challenge_image)
            .map_err(|error| {
                tracing::warn!(%error, "Face Engine comparison failed");
                FailureReason::ImageAnalysisFailed
            })
    }
}
