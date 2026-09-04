use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use flamingo_verifier_worker_protocol::{
    CompareRequest, ComparisonScores, MAX_RESPONSE_BYTES, WorkerResult, decode_message,
    encode_message,
};
use flamingo_verifier_worker_rpc::{
    WorkerClient, WorkerClientConfig, WorkerClientError, WorkerServerConfig, WorkerServerError,
    serve_worker,
};

const WAIT: Duration = Duration::from_secs(3);
const SCORES: ComparisonScores = ComparisonScores {
    live_similarity: 0.8,
    challenge_similarity: 0.9,
};

/// Uses generous correctness-test deadlines; timeout tests override them explicitly.
fn config() -> WorkerClientConfig {
    WorkerClientConfig {
        first_request_timeout: WAIT,
        request_timeout: WAIT,
        max_request_bytes: 1024,
        max_image_bytes: 100,
        score_range: -1.0..=1.0,
    }
}

/// Keeps server limits independent from the client's timeout tests.
fn server_config() -> WorkerServerConfig {
    WorkerServerConfig {
        max_request_bytes: 1024,
        max_image_bytes: 100,
        first_request_timeout: WAIT,
        request_timeout: WAIT,
    }
}

/// Encodes a recognizable small comparison.
fn images(id: u8) -> CompareRequest {
    CompareRequest {
        credential_image: vec![id; 8],
        live_image: vec![2; 8],
        challenge_image: vec![3; 8],
    }
}

/// Produces a raw length-prefixed CBOR frame for adversarial peers.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

/// Bounds fixture I/O so a regression cannot hang a reader indefinitely.
fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    stream.set_read_timeout(Some(WAIT)).unwrap();
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 1024);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).unwrap();
    payload
}

/// Sends a valid result without an HTTP or startup wrapper.
fn reply(stream: &mut UnixStream, result: WorkerResult) {
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
        .write_all(&frame(
            &encode_message(&result, MAX_RESPONSE_BYTES).unwrap(),
        ))
        .unwrap();
}

#[test]
/// Neither construction nor idle time requires a ready message; model state can be non-Sync.
fn no_handshake_and_sequential_round_trips() {
    let (broker, mut worker) = UnixStream::pair().unwrap();
    let mut client = WorkerClient::new(broker, config()).unwrap();
    worker
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert!(
        matches!(worker.read(&mut [0]), Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
    );

    let server = thread::spawn(move || {
        let calls = std::cell::Cell::new(0);
        let mut expected = 1;
        serve_worker(worker, server_config(), |request| {
            assert_eq!(request.credential_image[0], expected);
            expected += 1;
            calls.set(calls.get() + 1);
            Ok(WorkerResult::Compared(SCORES))
        })
        .unwrap();
        assert_eq!(calls.get(), 10);
    });

    for id in 1..=10 {
        assert_eq!(client.compare(images(id)).unwrap(), SCORES);
    }
    drop(client);
    server.join().unwrap();
}

#[test]
/// Pre-wire rejection does not consume the first-request initialization budget.
fn invalid_input_and_encoding_errors_leave_connection_usable() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let mut limits = config();
    limits.max_request_bytes = 80;
    limits.max_image_bytes = 80;
    limits.request_timeout = Duration::from_millis(40);
    let mut client = WorkerClient::new(broker, limits).unwrap();
    let server = thread::spawn(move || {
        serve_worker(worker, server_config(), |_| {
            thread::sleep(Duration::from_millis(100));
            Ok(WorkerResult::Compared(SCORES))
        })
    });

    let mut invalid = images(1);
    invalid.live_image.clear();
    assert!(matches!(
        client.compare(invalid),
        Err(WorkerClientError::InvalidImages)
    ));
    let large = CompareRequest {
        credential_image: vec![1; 50],
        live_image: vec![2; 50],
        challenge_image: vec![3; 50],
    };
    assert!(matches!(
        client.compare(large),
        Err(WorkerClientError::RequestEncoding(_))
    ));
    assert!(client.failure().is_none());
    let small = CompareRequest {
        credential_image: vec![1],
        live_image: vec![2],
        challenge_image: vec![3],
    };
    assert_eq!(client.compare(small).unwrap(), SCORES);
    drop(client);
    server.join().unwrap().unwrap();
}

#[test]
/// A completed analysis failure consumes the cold-start allowance but is otherwise recoverable.
fn first_request_allows_initialization_then_uses_normal_deadline() {
    let (broker, mut worker) = UnixStream::pair().unwrap();
    let mut limits = config();
    limits.request_timeout = Duration::from_millis(50);
    let mut client = WorkerClient::new(broker, limits).unwrap();
    let server = thread::spawn(move || {
        read_frame(&mut worker);
        thread::sleep(Duration::from_millis(120));
        reply(&mut worker, WorkerResult::AnalysisFailed);
        read_frame(&mut worker);
        reply(&mut worker, WorkerResult::Compared(SCORES));
        read_frame(&mut worker);
        thread::sleep(Duration::from_millis(150));
    });

    assert!(matches!(
        client.compare(images(1)),
        Err(WorkerClientError::AnalysisFailed)
    ));
    assert!(client.failure().is_none());
    assert_eq!(client.compare(images(2)).unwrap(), SCORES);
    assert!(matches!(
        client.compare(images(3)),
        Err(WorkerClientError::RequestTimeout)
    ));
    assert!(matches!(
        client.failure(),
        Some(WorkerClientError::RequestTimeout)
    ));
    assert!(matches!(
        client.compare(images(4)),
        Err(WorkerClientError::RequestTimeout)
    ));
    server.join().unwrap();
}

#[test]
/// A fatal frame failure closes the stream and cannot be mistaken for the next reply.
fn invalid_and_truncated_frames_permanently_close_client() {
    for bytes in [
        vec![],
        vec![0],
        vec![0, 0],
        vec![0, 0, 0],
        vec![0; 4],
        u32::MAX.to_be_bytes().to_vec(),
        frame(&vec![0; MAX_RESPONSE_BYTES + 1]),
        vec![0, 0, 0, 5, 1, 2],
    ] {
        let (broker, mut worker) = UnixStream::pair().unwrap();
        let mut client = WorkerClient::new(broker, config()).unwrap();
        let server = thread::spawn(move || {
            read_frame(&mut worker);
            worker.write_all(&bytes).unwrap();
        });

        assert!(matches!(
            client.compare(images(1)),
            Err(WorkerClientError::Transport(_))
        ));
        assert!(client.failure().is_some());
        assert!(client.compare(images(2)).is_err());
        server.join().unwrap();
    }
}

#[test]
/// Malformed CBOR, trailing data and nonfinite/out-of-range scores invalidate the client.
fn malformed_results_and_invalid_scores_are_fatal() {
    let mut payloads = vec![vec![0xff], encode_message(&images(1), 1024).unwrap()];
    let mut trailing = encode_message(&WorkerResult::Compared(SCORES), MAX_RESPONSE_BYTES).unwrap();
    trailing.push(0);
    payloads.push(trailing);
    for score in [f32::NAN, f32::INFINITY, -1.1, 1.1] {
        for scores in [
            ComparisonScores {
                live_similarity: score,
                ..SCORES
            },
            ComparisonScores {
                challenge_similarity: score,
                ..SCORES
            },
        ] {
            payloads
                .push(encode_message(&WorkerResult::Compared(scores), MAX_RESPONSE_BYTES).unwrap());
        }
    }

    for payload in payloads {
        let (broker, mut worker) = UnixStream::pair().unwrap();
        let mut client = WorkerClient::new(broker, config()).unwrap();
        let server = thread::spawn(move || {
            read_frame(&mut worker);
            worker.write_all(&frame(&payload)).unwrap();
            let mut byte = [0];
            assert_eq!(worker.read(&mut byte).unwrap(), 0);
        });
        assert!(matches!(
            client.compare(images(1)),
            Err(WorkerClientError::Protocol(_) | WorkerClientError::InvalidScore)
        ));
        assert!(client.failure().is_some());
        server.join().unwrap();
    }
}

#[test]
/// Packet boundaries do not define message boundaries.
fn fragmented_replies_are_reassembled() {
    let (broker, mut worker) = UnixStream::pair().unwrap();
    let mut client = WorkerClient::new(broker, config()).unwrap();
    let server = thread::spawn(move || {
        read_frame(&mut worker);
        for byte in
            frame(&encode_message(&WorkerResult::Compared(SCORES), MAX_RESPONSE_BYTES).unwrap())
        {
            worker.write_all(&[byte]).unwrap();
            thread::sleep(Duration::from_millis(1));
        }
    });
    assert_eq!(client.compare(images(1)).unwrap(), SCORES);
    server.join().unwrap();
}

#[test]
/// A trickle of bytes cannot extend the whole-response deadline.
fn slow_drip_response_times_out() {
    let (broker, mut worker) = UnixStream::pair().unwrap();
    let mut limits = config();
    limits.first_request_timeout = Duration::from_millis(100);
    limits.request_timeout = limits.first_request_timeout;
    let mut client = WorkerClient::new(broker, limits).unwrap();
    let server = thread::spawn(move || {
        read_frame(&mut worker);
        for byte in
            frame(&encode_message(&WorkerResult::Compared(SCORES), MAX_RESPONSE_BYTES).unwrap())
        {
            if worker.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let started = Instant::now();
    assert!(matches!(
        client.compare(images(1)),
        Err(WorkerClientError::RequestTimeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    server.join().unwrap();
}

#[test]
/// A worker that never reads cannot leave a large upload blocked indefinitely.
fn blocked_upload_uses_same_deadline() {
    let (broker, mut worker) = UnixStream::pair().unwrap();
    worker.set_read_timeout(Some(WAIT)).unwrap();
    let mut limits = config();
    limits.first_request_timeout = Duration::from_millis(500);
    limits.request_timeout = limits.first_request_timeout;
    limits.max_image_bytes = 4 * 1024 * 1024;
    limits.max_request_bytes = 3 * limits.max_image_bytes + 1024;
    let max_image_bytes = limits.max_image_bytes;
    let mut client = WorkerClient::new(broker, limits).unwrap();
    let request = CompareRequest {
        credential_image: vec![1; max_image_bytes],
        live_image: vec![2; max_image_bytes],
        challenge_image: vec![3; max_image_bytes],
    };
    let started = Instant::now();
    assert!(matches!(
        client.compare(request),
        Err(WorkerClientError::RequestTimeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    let mut length = [0; 4];
    worker.read_exact(&mut length).unwrap();
    assert!(u32::from_be_bytes(length) as usize > max_image_bytes);
}

#[test]
/// Rejects bad limits before any traffic or model invocation.
fn invalid_configuration_is_rejected() {
    let mut cases = Vec::new();
    let mut invalid = config();
    invalid.first_request_timeout = Duration::ZERO;
    cases.push(invalid);
    let mut invalid = config();
    invalid.request_timeout = Duration::ZERO;
    cases.push(invalid);
    let mut invalid = config();
    invalid.first_request_timeout = Duration::MAX;
    cases.push(invalid);
    let mut invalid = config();
    invalid.max_image_bytes = 0;
    cases.push(invalid);
    let mut invalid = config();
    invalid.max_request_bytes = usize::MAX;
    cases.push(invalid);
    let mut invalid = config();
    invalid.score_range = f32::NAN..=1.0;
    cases.push(invalid);
    let mut invalid = config();
    invalid.score_range = 2.0..=1.0;
    cases.push(invalid);
    for limits in cases {
        let (broker, _worker) = UnixStream::pair().unwrap();
        assert!(matches!(
            WorkerClient::new(broker, limits),
            Err(WorkerClientError::InvalidConfig)
        ));
    }
    let (broker, _worker) = UnixStream::pair().unwrap();
    let mut limits = server_config();
    limits.request_timeout = Duration::ZERO;
    assert!(matches!(
        serve_worker(broker, limits, |_| unreachable!()),
        Err(WorkerServerError::InvalidConfig)
    ));
}

#[test]
/// Server limits are enforced even when the broker bypasses the typed client.
fn server_rejects_bad_frames_and_inputs_before_inference() {
    let mut empty = images(1);
    empty.live_image.clear();
    let mut large = images(1);
    large.live_image.resize(101, 2);
    for bytes in [
        vec![0; 4],
        u32::MAX.to_be_bytes().to_vec(),
        frame(&[0xff]),
        frame(&encode_message(&empty, 1024).unwrap()),
        frame(&encode_message(&large, 1024).unwrap()),
        vec![0, 0, 0, 20, 1],
    ] {
        let (mut broker, worker) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            serve_worker(worker, server_config(), |_| {
                panic!("invalid input reached inference")
            })
        });
        broker.write_all(&bytes).unwrap();
        broker.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(matches!(
            server.join().unwrap(),
            Err(WorkerServerError::Transport(_)
                | WorkerServerError::Protocol(_)
                | WorkerServerError::InvalidImages)
        ));
    }
}

#[test]
/// Idle time is allowed, but an incomplete header must finish under its original deadline.
fn server_deadline_starts_at_first_byte_not_at_launch() {
    let (mut broker, worker) = UnixStream::pair().unwrap();
    let mut limits = server_config();
    limits.first_request_timeout = Duration::from_millis(100);
    limits.request_timeout = limits.first_request_timeout;
    let (done, completed) = mpsc::channel();
    let server = thread::spawn(move || {
        done.send(serve_worker(worker, limits, |_| unreachable!()))
            .unwrap()
    });
    assert!(matches!(
        completed.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    broker.write_all(&[0]).unwrap();
    let error = completed.recv_timeout(WAIT).unwrap().unwrap_err();
    assert_eq!(error.failure_class(), "request_timeout");
    server.join().unwrap();
}

#[test]
/// The server must not return scores produced after its inference deadline.
fn server_rejects_late_computation() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let mut limits = server_config();
    limits.first_request_timeout = Duration::from_millis(50);
    limits.request_timeout = limits.first_request_timeout;
    let mut client = WorkerClient::new(broker, config()).unwrap();
    let server = thread::spawn(move || {
        serve_worker(worker, limits, |_| {
            thread::sleep(Duration::from_millis(120));
            Ok(WorkerResult::Compared(SCORES))
        })
    });
    assert!(client.compare(images(1)).is_err());
    assert_eq!(
        server.join().unwrap().unwrap_err().failure_class(),
        "request_timeout"
    );
}

#[test]
/// Infrastructure failure and panic terminate rather than returning an ordinary analysis failure.
fn model_failure_and_panic_close_connection() {
    for panic in [false, true] {
        let (broker, worker) = UnixStream::pair().unwrap();
        let mut client = WorkerClient::new(broker, config()).unwrap();
        let server = thread::spawn(move || {
            serve_worker(worker, server_config(), |_| {
                if panic {
                    panic!("fixture model panic");
                }
                Err(Box::new(io::Error::other("fixture initialization failure")))
            })
        });
        assert!(matches!(
            client.compare(images(1)),
            Err(WorkerClientError::Transport(_))
        ));
        assert!(matches!(
            server.join().unwrap(),
            Err(WorkerServerError::Model(_) | WorkerServerError::ModelPanic)
        ));
    }
}

#[test]
/// Even a raw peer that pipelines frames cannot overlap model invocations.
fn server_finishes_each_comparison_before_reading_the_next() {
    let (mut broker, worker) = UnixStream::pair().unwrap();
    let (entered, entries) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let server = thread::spawn(move || {
        serve_worker(worker, server_config(), |request| {
            entered.send(request.credential_image[0]).unwrap();
            released.recv_timeout(WAIT).unwrap();
            Ok(WorkerResult::Compared(SCORES))
        })
    });
    for id in [1, 2] {
        broker
            .write_all(&frame(&encode_message(&images(id), 1024).unwrap()))
            .unwrap();
    }
    assert_eq!(entries.recv_timeout(WAIT).unwrap(), 1);
    assert!(matches!(
        entries.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release.send(()).unwrap();
    assert_eq!(
        decode_message::<WorkerResult>(&read_frame(&mut broker), MAX_RESPONSE_BYTES).unwrap(),
        WorkerResult::Compared(SCORES)
    );
    assert_eq!(entries.recv_timeout(WAIT).unwrap(), 2);
    release.send(()).unwrap();
    read_frame(&mut broker);
    drop(broker);
    server.join().unwrap().unwrap();
}
