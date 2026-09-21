use biometric_engines_protocol::{
    EmptyReason, Response,
    face::{
        DeepFaceRequest, DeepFaceResult, FaceImage, Failure as FaceFailure, FailureCode,
        GrayBadgeRequest, GrayBadgeResult, face_image::Source,
    },
    framing, protobuf, protocol_failure,
    request::Operation,
    response::Outcome,
};
use flamingo_verifier_sandbox_client::{SandboxClient, SandboxClientConfig, SandboxClientError};
use std::{io::Write, os::unix::net::UnixStream, thread, time::Duration};

fn config() -> SandboxClientConfig {
    SandboxClientConfig {
        startup_timeout: Duration::from_millis(100),
        request_timeout: Duration::from_millis(100),
        max_request_bytes: 4096,
        max_image_bytes: 100,
    }
}
fn request() -> Operation {
    Operation::DeepFace(DeepFaceRequest {
        credential: Some(FaceImage {
            source: Some(Source::Orb(vec![1])),
        }),
        live: Some(FaceImage {
            source: Some(Source::VanillaSelfie(vec![2])),
        }),
        challenge: Some(FaceImage {
            source: Some(Source::Rtms(vec![3])),
        }),
    })
}
fn scores() -> Outcome {
    Outcome::DeepFace(DeepFaceResult {
        similarity_credential_live: Some(0.8),
        similarity_credential_challenge: Some(0.9),
        similarity_live_challenge: Some(0.85),
        debug_report: None,
    })
}
fn ready(stream: &mut UnixStream) {
    framing::write_frame(stream, &protobuf::encode_ready()).unwrap();
}

#[test]
fn startup_requires_framed_compatible_readiness() {
    for bytes in [
        vec![],
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 65],
        vec![0, 0, 0, 2, 8, 2],
        b"FWR1".to_vec(),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        server.write_all(&bytes).unwrap();
        drop(server);
        assert!(SandboxClient::new(client, config()).is_err());
    }
    let (client, _server) = UnixStream::pair().unwrap();
    assert!(matches!(
        SandboxClient::new(client, config()),
        Err(SandboxClientError::StartupTimeout)
    ));
}

#[test]
fn deepface_graybadge_and_typed_biological_failure_share_one_connection() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let (done, wait) = std::sync::mpsc::channel();
    let peer = thread::spawn(move || {
        ready(&mut server);
        for id in 1..=3 {
            let r = protobuf::decode_request(&framing::read_frame(&mut server).unwrap().unwrap())
                .unwrap();
            assert_eq!(r.request_id, id);
            let outcome = match id {
                1 => {
                    assert!(matches!(r.operation, Some(Operation::DeepFace(_))));
                    Outcome::Failure(FaceFailure::new(FailureCode::InvalidImage).into())
                }
                2 => scores(),
                _ => {
                    assert!(matches!(r.operation, Some(Operation::GrayBadge(_))));
                    Outcome::GrayBadge(GrayBadgeResult {
                        similarity_live_challenge: Some(0.7),
                        debug_report: None,
                    })
                }
            };
            framing::write_frame(
                &mut server,
                &protobuf::encode_response(&Response::new(id, outcome)),
            )
            .unwrap();
        }
        wait.recv().unwrap();
    });
    let mut client = SandboxClient::new(client, config()).unwrap();
    assert!(matches!(
        client.evaluate(request()),
        Err(SandboxClientError::AnalysisFailed(_))
    ));
    assert!(client.failure().is_none());
    assert_eq!(client.evaluate(request()).unwrap(), scores());
    assert!(matches!(
        client
            .evaluate(Operation::GrayBadge(GrayBadgeRequest {
                live: Some(FaceImage {
                    source: Some(Source::VanillaSelfie(vec![1]))
                }),
                challenge: Some(FaceImage {
                    source: Some(Source::Rtms(vec![2]))
                })
            }))
            .unwrap(),
        Outcome::GrayBadge(_)
    ));
    done.send(()).unwrap();
    peer.join().unwrap();
}

#[test]
fn response_corruption_poisoning_is_permanent() {
    for case in 0..15 {
        let (client, mut server) = UnixStream::pair().unwrap();
        let peer = thread::spawn(move || {
            ready(&mut server);
            let r = protobuf::decode_request(&framing::read_frame(&mut server).unwrap().unwrap())
                .unwrap();
            let mut response = Response::new(r.request_id, scores());
            match case {
                0 => response.request_id += 1,
                1 => {
                    response.outcome = Some(Outcome::GrayBadge(GrayBadgeResult {
                        similarity_live_challenge: Some(0.8),
                        debug_report: None,
                    }))
                }
                2..=4 => {
                    let Some(Outcome::DeepFace(ref mut scores)) = response.outcome else {
                        unreachable!()
                    };
                    scores.similarity_live_challenge =
                        Some([f64::NAN, f64::INFINITY, 1.1][case - 2]);
                }
                5 => {
                    response.outcome = Some(Outcome::Failure(
                        FaceFailure::new(FailureCode::Internal).into(),
                    ))
                }
                6 => {
                    response.outcome = Some(Outcome::Failure(
                        protocol_failure::Reason::UnsupportedVersion(EmptyReason {}).into(),
                    ))
                }
                7 => {
                    server.write_all(&u32::MAX.to_be_bytes()).unwrap();
                    return;
                }
                8 => {
                    framing::write_frame(&mut server, &[0xff]).unwrap();
                    return;
                }
                9 => return,
                10 => response.outcome = None,
                11 => response.protocol_version += 1,
                12 => {
                    let Some(Outcome::DeepFace(ref mut scores)) = response.outcome else {
                        unreachable!()
                    };
                    scores.similarity_credential_live = None;
                }
                13 => {
                    response.outcome = Some(Outcome::Failure(
                        FaceFailure {
                            code: 999,
                            ..FaceFailure::default()
                        }
                        .into(),
                    ))
                }
                14 => {
                    response.outcome = None;
                    let mut bytes = protobuf::encode_response(&response);
                    bytes.extend([0x3a, 0]); // Unknown future outcome field 7.
                    framing::write_frame(&mut server, &bytes).unwrap();
                    return;
                }
                _ => unreachable!(),
            }
            framing::write_frame(&mut server, &protobuf::encode_response(&response)).unwrap();
        });
        let mut client = SandboxClient::new(client, config()).unwrap();
        assert!(client.evaluate(request()).is_err(), "case {case}");
        assert!(client.failure().is_some(), "case {case}");
        assert!(client.evaluate(request()).is_err());
        peer.join().unwrap();
    }
}

#[test]
fn local_validation_does_not_touch_or_poison_socket() {
    let (client, mut server) = UnixStream::pair().unwrap();
    ready(&mut server);
    let mut client = SandboxClient::new(client, config()).unwrap();
    let Operation::DeepFace(mut r) = request() else {
        unreachable!()
    };
    r.credential = Some(FaceImage {
        source: Some(Source::Orb(vec![0; 101])),
    });
    assert!(matches!(
        client.evaluate(Operation::DeepFace(r)),
        Err(SandboxClientError::InvalidImages)
    ));
    assert!(client.failure().is_none());
    server.set_nonblocking(true).unwrap();
    use std::io::Read;
    assert_eq!(
        server.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn partial_progress_does_not_extend_the_request_deadline() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let peer = thread::spawn(move || {
        ready(&mut server);
        framing::read_frame(&mut server).unwrap().unwrap();
        for byte in [0, 0, 0, 20, 1, 2] {
            if server.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }
    });
    let mut client = SandboxClient::new(client, config()).unwrap();
    assert!(matches!(
        client.evaluate(request()),
        Err(SandboxClientError::RequestTimeout)
    ));
    assert!(client.failure().is_some());
    peer.join().unwrap();
}

#[test]
fn worker_diagnostics_never_escape_the_client() {
    for internal in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let (done, wait) = std::sync::mpsc::channel();
        let peer = thread::spawn(move || {
            ready(&mut server);
            let request =
                protobuf::decode_request(&framing::read_frame(&mut server).unwrap().unwrap())
                    .unwrap();
            let mut result = scores();
            if let Outcome::DeepFace(result) = &mut result {
                result.debug_report = Some("sensitive model diagnostic".to_owned());
            }
            framing::write_frame(
                &mut server,
                &protobuf::encode_response(&Response::new(request.request_id, result)),
            )
            .unwrap();
            let request =
                protobuf::decode_request(&framing::read_frame(&mut server).unwrap().unwrap())
                    .unwrap();
            let failure = FaceFailure {
                debug_report: Some("sensitive image diagnostic".to_owned()),
                ..FaceFailure::new(if internal {
                    FailureCode::Internal
                } else {
                    FailureCode::InvalidImage
                })
            };
            framing::write_frame(
                &mut server,
                &protobuf::encode_response(&Response::new(
                    request.request_id,
                    Outcome::Failure(failure.into()),
                )),
            )
            .unwrap();
            // A real worker stays alive after replying. On macOS, setting a socket
            // timeout after peer close fails even when response bytes remain buffered.
            wait.recv().unwrap();
        });
        let mut client = SandboxClient::new(client, config()).unwrap();
        assert_eq!(client.evaluate(request()).unwrap(), scores());
        let error = client.evaluate(request()).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("sensitive"));
        match error {
            SandboxClientError::AnalysisFailed(failure) => assert!(failure.debug_report.is_none()),
            SandboxClientError::Protocol(failure) => {
                let Some(biometric_engines_protocol::failure::Kind::Face(failure)) = failure.kind
                else {
                    panic!("expected face failure")
                };
                assert!(failure.debug_report.is_none());
            }
            error => panic!("unexpected error: {error}"),
        }
        assert_eq!(client.failure().is_some(), internal);
        done.send(()).unwrap();
        peer.join().unwrap();
    }
}

#[test]
fn malformed_or_oversized_image_sources_are_rejected_locally() {
    use biometric_engines_protocol::face::LightGuard;
    for image in [
        None,
        Some(FaceImage { source: None }),
        Some(FaceImage {
            source: Some(Source::Orb(vec![])),
        }),
        Some(FaceImage {
            source: Some(Source::LightGuard(LightGuard {
                illuminated: vec![1],
                unilluminated: vec![2],
                matching_frame: 0,
            })),
        }),
        Some(FaceImage {
            source: Some(Source::LightGuard(LightGuard {
                illuminated: vec![1],
                unilluminated: vec![2; 101],
                matching_frame: 1,
            })),
        }),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        ready(&mut server);
        let mut client = SandboxClient::new(client, config()).unwrap();
        let Operation::DeepFace(mut input) = request() else {
            unreachable!()
        };
        input.live = image;
        assert!(matches!(
            client.evaluate(Operation::DeepFace(input)),
            Err(SandboxClientError::InvalidImages)
        ));
        assert!(client.failure().is_none());
        server.set_nonblocking(true).unwrap();
        use std::io::Read;
        assert_eq!(
            server.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
