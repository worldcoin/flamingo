//! Opt-in real-model test; use only an approved non-production face fixture.

use std::{fs::File, io::Read, os::unix::net::UnixStream, path::PathBuf, thread};

use flamingo_verifier_worker::{
    FIRST_REQUEST_TIMEOUT, MAX_IMAGE_BYTES, MAX_REQUEST_BYTES, REQUEST_TIMEOUT, run_worker,
};
use flamingo_verifier_worker_protocol::CompareRequest;
use flamingo_verifier_worker_rpc::{WorkerClient, WorkerClientConfig, WorkerClientError};

/// Covers cold inference, expected rejection and successful reuse with the actual ONNX models.
#[test]
#[ignore = "requires WORKER_MODEL_DIR and WORKER_FACE_FIXTURE; not sandbox qualification"]
fn real_model_roundtrip() {
    let model_dir =
        PathBuf::from(std::env::var_os("WORKER_MODEL_DIR").expect("set WORKER_MODEL_DIR"));
    let fixture = std::env::var_os("WORKER_FACE_FIXTURE").expect("set WORKER_FACE_FIXTURE");
    let mut bytes = Vec::new();
    File::open(fixture)
        .unwrap()
        .take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= MAX_IMAGE_BYTES);
    let request = CompareRequest {
        credential_image: bytes.clone(),
        live_image: bytes.clone(),
        challenge_image: bytes,
    };
    let (broker, worker) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || run_worker(worker, &model_dir));
    let mut client = WorkerClient::new(
        broker,
        WorkerClientConfig {
            first_request_timeout: FIRST_REQUEST_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
            max_request_bytes: MAX_REQUEST_BYTES,
            max_image_bytes: MAX_IMAGE_BYTES,
            score_range: -1.0..=1.0,
        },
    )
    .unwrap();

    let cold = client.compare(request.clone()).unwrap();
    assert!((cold.live_similarity - 1.0).abs() < 1e-5);
    assert!((cold.challenge_similarity - 1.0).abs() < 1e-5);
    let invalid = CompareRequest {
        credential_image: vec![1],
        live_image: vec![2],
        challenge_image: vec![3],
    };
    assert!(matches!(
        client.compare(invalid),
        Err(WorkerClientError::AnalysisFailed)
    ));
    assert!(client.failure().is_none());
    let warm = client.compare(request).unwrap();
    assert!((cold.live_similarity - warm.live_similarity).abs() < 1e-6);
    assert!((cold.challenge_similarity - warm.challenge_similarity).abs() < 1e-6);
    drop(client);
    server.join().unwrap().unwrap();
}
