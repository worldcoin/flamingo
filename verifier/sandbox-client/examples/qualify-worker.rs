//! Opt-in Linux smoke test of the packaged worker under the production Minijail policy.

#[cfg(target_os = "linux")]
/// Uses explicit resource budgets and an approved face fixture; never starts a broker runtime.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use biometric_engines_protocol::{
        face::{DeepFaceRequest, FaceImage, face_image::Source},
        request::Operation,
        response::Outcome,
    };
    use flamingo_verifier_sandbox_client::{SandboxClientConfig, SandboxClientError};
    use flamingo_verifier_sandbox_client::{SandboxConfig, Worker, WorkerError};
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
            credential: Some(FaceImage {
                source: Some(Source::Orb(image.clone())),
            }),
            live: Some(FaceImage {
                source: Some(Source::VanillaSelfie(image.clone())),
            }),
            challenge: Some(FaceImage {
                source: Some(Source::Rtms(image.clone())),
            }),
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
        // Explicit IPC budgets for qualification.
        SandboxClientConfig {
            startup_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(10),
            max_request_bytes: 24 * 1024 * 1024 + 1024,
            max_image_bytes: 8 * 1024 * 1024,
        },
        fatal,
    )?;
    let cold = worker.evaluate(request())?;
    let Outcome::DeepFace(scores) = &cold else {
        unreachable!()
    };
    for score in [
        scores.similarity_credential_live,
        scores.similarity_credential_challenge,
        scores.similarity_live_challenge,
    ] {
        assert!((score.unwrap() - 1.0).abs() < 1e-5);
    }

    let invalid = Operation::DeepFace(DeepFaceRequest {
        credential: Some(FaceImage {
            source: Some(Source::Orb(vec![1])),
        }),
        live: Some(FaceImage {
            source: Some(Source::VanillaSelfie(vec![2])),
        }),
        challenge: Some(FaceImage {
            source: Some(Source::Rtms(vec![3])),
        }),
    });
    assert!(matches!(
        worker.evaluate(invalid),
        Err(WorkerError::Rpc(SandboxClientError::AnalysisFailed(_)))
    ));
    assert_eq!(worker.evaluate(request())?, cold);
    let gray = worker.evaluate(Operation::GrayBadge(
        biometric_engines_protocol::face::GrayBadgeRequest {
            live: Some(FaceImage {
                source: Some(Source::VanillaSelfie(image.clone())),
            }),
            challenge: Some(FaceImage {
                source: Some(Source::Rtms(image)),
            }),
        },
    ))?;
    let Outcome::GrayBadge(scores) = gray else {
        unreachable!()
    };
    assert!((scores.similarity_live_challenge.unwrap() - 1.0).abs() < 1e-5);
    Ok(())
}

#[cfg(target_os = "linux")]
/// A terminal RPC error always ends this broker lifetime; no retry or worker restart.
fn fatal(error: flamingo_verifier_sandbox_client::SandboxClientError) -> ! {
    eprintln!("worker qualification failed: {error}");
    std::process::exit(1)
}

#[cfg(not(target_os = "linux"))]
/// Fails explicitly instead of silently skipping the sandbox.
fn main() {
    eprintln!("worker sandbox qualification requires x86_64 Linux");
    std::process::exit(1)
}
