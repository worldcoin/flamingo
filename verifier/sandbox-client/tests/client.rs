use biometric_engines_protocol::{
    Failure, Operation, ProtocolFailure, Response, ResponseBody,
    face::{
        DeepFaceRequest, DeepFaceResult, Failure as FaceFailure, FailureCode, GrayBadgeRequest,
        GrayBadgeResult, ImageBytes, LiveCapture,
    },
    framing, protobuf,
};
use flamingo_verifier_sandbox_client::{WorkerClient, WorkerClientConfig, WorkerClientError};
use std::{io::Write, os::unix::net::UnixStream, thread, time::Duration};

fn config() -> WorkerClientConfig {
    WorkerClientConfig {
        startup_timeout: Duration::from_millis(100),
        request_timeout: Duration::from_millis(100),
        max_request_bytes: 4096,
        max_image_bytes: 100,
    }
}
fn request() -> Operation {
    Operation::DeepFace(DeepFaceRequest {
        orb_credential: ImageBytes(vec![1]),
        live: LiveCapture::Vanilla(ImageBytes(vec![2])),
        rtms_challenge: ImageBytes(vec![3]),
    })
}
fn scores() -> ResponseBody {
    ResponseBody::DeepFace(DeepFaceResult {
        similarity_orb_selfie: 0.8,
        similarity_orb_challenge: 0.9,
        similarity_selfie_challenge: 0.85,
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
        assert!(WorkerClient::new(client, config()).is_err());
    }
    let (client, _server) = UnixStream::pair().unwrap();
    assert!(matches!(
        WorkerClient::new(client, config()),
        Err(WorkerClientError::StartupTimeout)
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
                    assert!(matches!(r.operation, Operation::DeepFace(_)));
                    Err(Failure::Face(FaceFailure::new(FailureCode::InvalidImage)))
                }
                2 => Ok(scores()),
                _ => {
                    assert!(matches!(r.operation, Operation::GrayBadge(_)));
                    Ok(ResponseBody::GrayBadge(GrayBadgeResult {
                        similarity_selfie_challenge: 0.7,
                    }))
                }
            };
            framing::write_frame(
                &mut server,
                &protobuf::encode_response(Response {
                    request_id: id,
                    outcome,
                }),
            )
            .unwrap();
        }
        wait.recv().unwrap();
    });
    let mut client = WorkerClient::new(client, config()).unwrap();
    assert!(matches!(
        client.evaluate(request()),
        Err(WorkerClientError::AnalysisFailed(_))
    ));
    assert!(client.failure().is_none());
    assert_eq!(client.evaluate(request()).unwrap(), scores());
    assert!(matches!(
        client
            .evaluate(Operation::GrayBadge(GrayBadgeRequest {
                live: LiveCapture::Vanilla(ImageBytes(vec![1])),
                rtms_challenge: ImageBytes(vec![2])
            }))
            .unwrap(),
        ResponseBody::GrayBadge(_)
    ));
    done.send(()).unwrap();
    peer.join().unwrap();
}

#[test]
fn response_corruption_poisoning_is_permanent() {
    for case in 0..10 {
        let (client, mut server) = UnixStream::pair().unwrap();
        let peer = thread::spawn(move || {
            ready(&mut server);
            let r = protobuf::decode_request(&framing::read_frame(&mut server).unwrap().unwrap())
                .unwrap();
            let mut response = Response {
                request_id: r.request_id,
                outcome: Ok(scores()),
            };
            match case {
                0 => response.request_id += 1,
                1 => {
                    response.outcome = Ok(ResponseBody::GrayBadge(GrayBadgeResult {
                        similarity_selfie_challenge: 0.8,
                    }))
                }
                2..=4 => {
                    let Ok(ResponseBody::DeepFace(ref mut scores)) = response.outcome else {
                        unreachable!()
                    };
                    scores.similarity_selfie_challenge = [f64::NAN, f64::INFINITY, 1.1][case - 2];
                }
                5 => response.outcome = Err(Failure::Face(FaceFailure::new(FailureCode::Internal))),
                6 => response.outcome = Err(Failure::Protocol(ProtocolFailure::UnsupportedVersion)),
                7 => {
                    server.write_all(&u32::MAX.to_be_bytes()).unwrap();
                    return;
                }
                8 => {
                    framing::write_frame(&mut server, &[0xff]).unwrap();
                    return;
                }
                9 => return,
                _ => unreachable!(),
            }
            framing::write_frame(&mut server, &protobuf::encode_response(response)).unwrap();
        });
        let mut client = WorkerClient::new(client, config()).unwrap();
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
    let mut client = WorkerClient::new(client, config()).unwrap();
    let Operation::DeepFace(mut r) = request() else {
        unreachable!()
    };
    r.orb_credential.0.resize(101, 0);
    assert!(matches!(
        client.evaluate(Operation::DeepFace(r)),
        Err(WorkerClientError::InvalidImages)
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
    let mut client = WorkerClient::new(client, config()).unwrap();
    assert!(matches!(
        client.evaluate(request()),
        Err(WorkerClientError::RequestTimeout)
    ));
    assert!(client.failure().is_some());
    peer.join().unwrap();
}
