//! Opt-in Linux smoke test of the packaged worker under the production Minijail policy.

#[cfg(target_os = "linux")]
/// Uses explicit resource budgets and an approved face fixture; never starts a broker runtime.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use flamingo_verifier_worker_process::{SandboxConfig, Worker, WorkerError};
    use flamingo_verifier_worker_protocol::CompareRequest;
    use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerClientError};
    use std::{fs::File, io::Read, path::Path, time::Duration};

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: qualify-worker RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS FACE_FIXTURE"
                .into(),
        );
    }
    let root = Path::new(&args[1]);
    let mut image = Vec::new();
    File::open(&args[4])?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut image)?;
    if image.is_empty() || image.len() > 8 * 1024 * 1024 {
        return Err("fixture exceeds the worker's encoded image limit".into());
    }
    let request = CompareRequest {
        credential_image: image.clone(),
        live_image: image.clone(),
        challenge_image: image,
    };
    let binary = File::open(root.join("bin/verifier-worker"))?;
    let mut worker = Worker::spawn(
        &binary,
        SandboxConfig {
            root,
            address_space_bytes: args[2].parse()?,
            max_threads: args[3].parse()?,
        },
        // Deliberately no dependency on the private implementation in this public launcher.
        // This profile must match docs/worker-protocol.md when the artifact changes.
        WorkerClientConfig {
            first_request_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(10),
            max_request_bytes: 24 * 1024 * 1024 + 1024,
            max_image_bytes: 8 * 1024 * 1024,
            score_range: -1.0..=1.0,
        },
        fatal,
    )?;
    let cold = worker.compare(request.clone())?;
    assert!((cold.live_similarity - 1.0).abs() < 1e-5);
    assert!((cold.challenge_similarity - 1.0).abs() < 1e-5);
    let invalid = CompareRequest {
        credential_image: vec![1],
        live_image: vec![2],
        challenge_image: vec![3],
    };
    assert!(matches!(
        worker.compare(invalid),
        Err(WorkerError::Rpc(WorkerClientError::AnalysisFailed))
    ));
    let warm = worker.compare(request)?;
    assert!((warm.live_similarity - cold.live_similarity).abs() < 1e-6);
    assert!((warm.challenge_similarity - cold.challenge_similarity).abs() < 1e-6);
    Ok(())
}

#[cfg(target_os = "linux")]
/// A terminal RPC error always ends this broker lifetime; no retry or worker restart.
fn fatal(error: flamingo_verifier_worker_rpc::WorkerClientError) -> ! {
    eprintln!("worker qualification failed: {error}");
    std::process::exit(1)
}

#[cfg(not(target_os = "linux"))]
/// Fails explicitly instead of silently skipping the sandbox.
fn main() {
    eprintln!("worker sandbox qualification requires x86_64 Linux");
    std::process::exit(1)
}
