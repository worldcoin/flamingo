//! Repo-local model implementation; only images and scores cross the worker RPC boundary.

mod model;

use std::{os::unix::net::UnixStream, path::Path};

use flamingo_verifier_worker_protocol::WorkerResult;
use flamingo_verifier_worker_rpc::{WorkerServerConfig, WorkerServerError, serve_worker};

pub use model::{ComparisonError, FaceEngine};

/// Maximum compressed size of each JPEG, PNG or WebP image.
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
/// Three maximum-size images plus CBOR field names and headers.
pub const MAX_REQUEST_BYTES: usize = 3 * MAX_IMAGE_BYTES + 1024;
/// Serves sequential comparisons, loading the two models only on the first valid request.
/// The caller must terminate the process on error; there is no reinitialization or retry.
/// `model_dir` is trusted local boot configuration, never an RPC field.
pub fn run_worker(stream: UnixStream, model_dir: &Path) -> Result<(), WorkerServerError> {
    let mut engine = None;
    serve_worker(
        stream,
        WorkerServerConfig {
            max_request_bytes: MAX_REQUEST_BYTES,
            max_image_bytes: MAX_IMAGE_BYTES,
        },
        |request| {
            if engine.is_none() {
                engine = Some(FaceEngine::load(model_dir)?);
            }
            match engine.as_ref().expect("model was initialized").compare(
                &request.credential_image,
                &request.live_image,
                &request.challenge_image,
            ) {
                Ok(scores) => Ok(WorkerResult::Compared(scores)),
                Err(ComparisonError::AnalysisFailed) => Ok(WorkerResult::AnalysisFailed),
                Err(error) => Err(error.into()),
            }
        },
    )
}
