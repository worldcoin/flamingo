//! Opt-in Linux smoke test of the packaged worker under the production Minijail policy.

#[cfg(target_os = "linux")]
/// Uses explicit resource budgets and approved fixtures; never starts a broker runtime.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use flamingo_engine_interface::ErrorCode;
    use flamingo_verifier_sandbox_client::{EngineLimits, Rejection, SandboxClient};
    use std::{fs::File, io::Read, path::Path};
    use tabernaculum::{Limits, Policy, SandboxConfig, Worker, bundle::WORKER_PATH};
    use world_id_flamingo::{Entry, Payload};

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err("usage: qualify-worker RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS CREDENTIAL LIVE CHALLENGE".into());
    }
    let root = Path::new(&args[1]);
    let mut entries = Vec::new();
    for path in &args[4..7] {
        let mut data = Vec::new();
        File::open(path)?
            .take(flamingo_engine_interface::MAX_PAYLOAD_BYTES as u64 + 1)
            .read_to_end(&mut data)?;
        if data.is_empty() || data.len() > flamingo_engine_interface::MAX_PAYLOAD_BYTES {
            return Err("fixture exceeds the worker's encoded payload limit".into());
        }
        entries.push(Entry {
            data,
            meta: Vec::new(),
        });
    }
    // Release selection is a verifier responsibility, exercised by the separate sealed E2E test.
    let payload = Payload {
        pipeline: 1,
        match_strictness: 2,
        hints: Vec::new(),
        entries,
        compare: vec![0, 1, 2],
        release_hash: [0; 32],
    };
    let deepface = payload
        .encode()
        .map_err(|e| format!("invalid fixture payload: {e:?}"))?;
    let limits = EngineLimits {
        max_payload_bytes: flamingo_engine_interface::MAX_PAYLOAD_BYTES,
    };
    let policy = Policy::default_worker();
    let (worker, ready) = Worker::spawn(
        &File::open(root.join(WORKER_PATH))?,
        SandboxConfig {
            root,
            limits: Limits {
                address_space_bytes: args[2].parse()?,
                max_threads: args[3].parse()?,
            },
            policy: &policy,
        },
        limits.connection()?,
        fatal,
    )?;
    let mut worker = SandboxClient::new(worker, &ready, limits)?;
    // Each call must be Pass; a rejection is not a successful biometric smoke test.
    worker.evaluate(&deepface)?;
    let mut invalid = payload.clone();
    for entry in &mut invalid.entries {
        entry.data = vec![1];
    }
    assert!(matches!(
        worker.evaluate(&invalid.encode().unwrap()),
        Err(Rejection::Engine {
            code: ErrorCode::InvalidPayload,
            ..
        })
    ));
    worker.evaluate(&deepface)?;
    let graybadge = Payload {
        pipeline: 2,
        entries: payload.entries[1..].to_vec(),
        compare: vec![0, 1],
        ..payload
    };
    worker.evaluate(&graybadge.encode().unwrap())?;
    println!("DeepFace and GrayBadge passed under the production sandbox policy");
    Ok(())
}

#[cfg(target_os = "linux")]
fn fatal(error: tabernaculum::ConnectionError) -> ! {
    eprintln!("worker qualification failed: {error}");
    std::process::exit(1)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("worker sandbox qualification requires x86_64 Linux");
    std::process::exit(1)
}
