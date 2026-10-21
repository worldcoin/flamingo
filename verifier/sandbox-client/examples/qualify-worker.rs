//! Opt-in Linux smoke test of the packaged worker under the production Minijail policy.

#[cfg(target_os = "linux")]
/// Uses explicit resource budgets and approved fixtures; never starts a broker runtime.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use flamingo_engine_interface::ErrorCode;
    use flamingo_verifier_sandbox_client::{EngineLimits, Rejection, SandboxClient};
    use std::{fs::File, io::Read, path::Path};
    use tabernaculum::{Limits, Policy, SandboxConfig, Worker, bundle::WORKER_PATH};

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err("usage: qualify-worker RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS CREDENTIAL LIVE CHALLENGE".into());
    }
    let root = Path::new(&args[1]);
    let mut images = Vec::new();
    for path in &args[4..7] {
        let mut data = Vec::new();
        File::open(path)?
            .take(flamingo_engine_interface::MAX_PAYLOAD_BYTES as u64 + 1)
            .read_to_end(&mut data)?;
        if data.is_empty() || data.len() > flamingo_engine_interface::MAX_PAYLOAD_BYTES {
            return Err("fixture exceeds the worker's encoded payload limit".into());
        }
        images.push(data);
    }
    let unilluminated = std::env::var("LIGHT_GUARD_UNILLUMINATED_IMAGE");
    let matching_frame = std::env::var("LIGHT_GUARD_MATCHING_FRAME");
    let light_guard = match unilluminated {
        Ok(path) => {
            let frame = match &matching_frame {
                Ok(value) => value.as_str(),
                Err(std::env::VarError::NotPresent) => "illuminated",
                Err(error) => return Err(error.clone().into()),
            };
            let mut data = Vec::new();
            File::open(path)?
                .take(flamingo_engine_interface::MAX_PAYLOAD_BYTES as u64 + 1)
                .read_to_end(&mut data)?;
            if data.is_empty() || data.len() > flamingo_engine_interface::MAX_PAYLOAD_BYTES {
                return Err("LightGuard fixture exceeds the worker's encoded payload limit".into());
            }
            Some((data, frame))
        }
        Err(std::env::VarError::NotPresent) => {
            if !matches!(matching_frame, Err(std::env::VarError::NotPresent)) {
                return Err(
                    "LIGHT_GUARD_MATCHING_FRAME requires LIGHT_GUARD_UNILLUMINATED_IMAGE".into(),
                );
            }
            None
        }
        Err(error) => return Err(error.into()),
    };
    let [credential, live, challenge] = images.try_into().expect("three fixture paths");
    let (payload, graybadge) = payloads(credential, live, challenge, light_guard)?;
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
    worker.evaluate(&graybadge.encode().unwrap())?;
    println!(
        "DeepFace pipeline {} and GrayBadge pipeline {} passed under the production sandbox policy",
        payload.pipeline, graybadge.pipeline
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn payloads(
    credential: Vec<u8>,
    live: Vec<u8>,
    challenge: Vec<u8>,
    light_guard: Option<(Vec<u8>, &str)>,
) -> Result<(world_id_flamingo::Payload, world_id_flamingo::Payload), &'static str> {
    use world_id_flamingo::{Entry, Payload};
    let entry = |data, meta: &[u8]| Entry {
        data,
        meta: meta.to_vec(),
    };
    let has_light_guard = light_guard.is_some();
    let (live, partner) = match light_guard {
        None => (entry(live, b""), None),
        Some((unilluminated, "illuminated")) => (
            entry(live, b"illuminated"),
            Some(entry(unilluminated, b"unilluminated")),
        ),
        Some((unilluminated, "unilluminated")) => (
            entry(unilluminated, b"unilluminated"),
            Some(entry(live, b"illuminated")),
        ),
        Some(_) => return Err("LIGHT_GUARD_MATCHING_FRAME must be illuminated or unilluminated"),
    };
    let mut entries = vec![entry(credential, b""), live, entry(challenge, b"")];
    entries.extend(partner);
    // Release selection is a verifier responsibility, exercised by the separate sealed E2E test.
    let deepface = Payload {
        pipeline: if has_light_guard { 3 } else { 1 },
        match_strictness: 2,
        hints: Vec::new(),
        entries,
        compare: vec![0, 1, 2],
        release_hash: [0; 32],
    };
    let graybadge = Payload {
        pipeline: if has_light_guard { 4 } else { 2 },
        entries: deepface.entries[1..].to_vec(),
        compare: vec![0, 1],
        ..deepface.clone()
    };
    Ok((deepface, graybadge))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::payloads;

    #[test]
    fn qualification_uses_explicit_pipeline_ids_and_matching_frames() {
        for frame in [None, Some("illuminated"), Some("unilluminated")] {
            let light_guard = frame.map(|frame| (vec![40], frame));
            let (deepface, graybadge) =
                payloads(vec![10], vec![20], vec![30], light_guard).unwrap();
            let expected_ids = if frame.is_some() { [3, 4] } else { [1, 2] };
            for (index, payload) in [deepface, graybadge].into_iter().enumerate() {
                assert_eq!(payload.pipeline, expected_ids[index]);
                assert_eq!(
                    payload.compare,
                    if index == 0 {
                        vec![0, 1, 2]
                    } else {
                        vec![0, 1]
                    }
                );
                let live = &payload.entries[1 - index];
                let challenge = &payload.entries[2 - index];
                assert_eq!(challenge.data, [30]);
                assert!(challenge.meta.is_empty());
                if let Some(frame) = frame {
                    let illuminated = frame == "illuminated";
                    assert_eq!(live.data, if illuminated { vec![20] } else { vec![40] });
                    assert_eq!(live.meta, frame.as_bytes());
                    let partner = payload.entries.last().unwrap();
                    assert_eq!(partner.data, if illuminated { vec![40] } else { vec![20] });
                    assert_eq!(
                        partner.meta,
                        if illuminated {
                            b"unilluminated".as_slice()
                        } else {
                            b"illuminated".as_slice()
                        }
                    );
                    assert_eq!(payload.entries.len(), payload.compare.len() + 1);
                } else {
                    assert_eq!(live.data, [20]);
                    assert!(payload.entries.iter().all(|entry| entry.meta.is_empty()));
                    assert_eq!(payload.entries.len(), payload.compare.len());
                }
                assert!(payload.encode().is_ok());
            }
        }
        assert!(payloads(vec![10], vec![20], vec![30], Some((vec![40], "automatic"))).is_err());
    }
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
