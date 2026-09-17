//! Opt-in Linux smoke test of the packaged worker under the production Minijail policy.

#[cfg(target_os = "linux")]
/// Uses explicit resource budgets and an approved face fixture; never starts a broker runtime.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use biometric_engines_protocol::{
        Operation, ResponseBody,
        face::{DeepFaceRequest, ImageBytes, LiveCapture},
    };
    use flamingo_verifier_worker_process::{SandboxConfig, Worker, WorkerError};
    use flamingo_verifier_worker_process::{WorkerClientConfig, WorkerClientError};
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
    let request = || {
        Operation::DeepFace(DeepFaceRequest {
            orb_credential: ImageBytes(image.clone()),
            live: LiveCapture::Vanilla(ImageBytes(image.clone())),
            rtms_challenge: ImageBytes(image.clone()),
        })
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
            startup_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(10),
            max_request_bytes: 24 * 1024 * 1024 + 1024,
            max_image_bytes: 8 * 1024 * 1024,
        },
        fatal,
    )?;
    let cold = worker.evaluate(request())?;
    let ResponseBody::DeepFace(scores) = &cold else {
        unreachable!()
    };
    for score in [
        scores.similarity_orb_selfie,
        scores.similarity_orb_challenge,
        scores.similarity_selfie_challenge,
    ] {
        assert!((score - 1.0).abs() < 1e-5);
    }
    let invalid = Operation::DeepFace(DeepFaceRequest {
        orb_credential: ImageBytes(vec![1]),
        live: LiveCapture::Vanilla(ImageBytes(vec![2])),
        rtms_challenge: ImageBytes(vec![3]),
    });
    assert!(matches!(
        worker.evaluate(invalid),
        Err(WorkerError::Rpc(WorkerClientError::AnalysisFailed(_)))
    ));
    assert_eq!(worker.evaluate(request())?, cold);
    let gray = worker.evaluate(Operation::GrayBadge(
        biometric_engines_protocol::face::GrayBadgeRequest {
            live: LiveCapture::Vanilla(ImageBytes(image.clone())),
            rtms_challenge: ImageBytes(image),
        },
    ))?;
    let ResponseBody::GrayBadge(scores) = gray else {
        unreachable!()
    };
    assert!((scores.similarity_selfie_challenge - 1.0).abs() < 1e-5);
    Ok(())
}

#[cfg(target_os = "linux")]
/// A terminal RPC error always ends this broker lifetime; no retry or worker restart.
fn fatal(error: flamingo_verifier_worker_process::WorkerClientError) -> ! {
    eprintln!("worker qualification failed: {error}");
    std::process::exit(1)
}

#[cfg(not(target_os = "linux"))]
/// Fails explicitly instead of silently skipping the sandbox.
fn main() {
    eprintln!("worker sandbox qualification requires x86_64 Linux");
    std::process::exit(1)
}
