use std::{
    error::Error,
    num::NonZeroU16,
    range::RangeInclusive,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::StatusCode,
    response::Response,
    routing::{get, post},
};
use flamingo_verifier_worker_protocol::{
    COMPARE_PATH, CONTENT_TYPE, CompareRequest, ComparisonScores, MAX_RESPONSE_BYTES, READY_PATH,
    WorkerProtocolError, WorkerReady, WorkerResult, encode_message,
};
use flamingo_verifier_worker_rpc::{
    WorkerClient, WorkerClientConfig, WorkerClientError, WorkerServerConfig, WorkerServerError,
    WorkerSession, serve_worker,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use tokio::{net::UnixStream, sync::mpsc, task::JoinHandle, time::timeout};

const WAIT: Duration = Duration::from_secs(3);
const SCORES: ComparisonScores = ComparisonScores {
    live_similarity: 0.8,
    challenge_similarity: 0.9,
};

fn client_config(capacity: u16) -> WorkerClientConfig {
    WorkerClientConfig {
        max_in_flight: NonZeroU16::new(capacity).unwrap(),
        handshake_timeout: WAIT,
        request_timeout: WAIT,
        max_request_bytes: 1024,
        max_image_bytes: 100,
        score_range: RangeInclusive {
            start: -1.0,
            last: 1.0,
        },
    }
}

fn server_config(capacity: u16) -> WorkerServerConfig {
    WorkerServerConfig {
        max_in_flight: NonZeroU16::new(capacity).unwrap(),
        max_request_bytes: 1024,
        max_image_bytes: 100,
        request_timeout: WAIT,
        shutdown_timeout: WAIT,
    }
}

fn images(id: u8) -> CompareRequest {
    CompareRequest {
        credential_image: vec![id; 8],
        live_image: vec![2; 8],
        challenge_image: vec![3; 8],
    }
}

async fn start<F>(
    client: WorkerClientConfig,
    server: WorkerServerConfig,
    comparator: F,
) -> (
    WorkerSession,
    WorkerClient,
    JoinHandle<Result<(), WorkerServerError>>,
)
where
    F: Fn(CompareRequest) -> Result<WorkerResult, Box<dyn Error + Send + Sync>>
        + Send
        + Sync
        + 'static,
{
    let (broker, worker) = UnixStream::pair().unwrap();
    let task = tokio::spawn(serve_worker(worker, server, comparator));
    let (owner, client) = WorkerSession::connect(broker, client).await.unwrap();

    (owner, client, task)
}

async fn shutdown(owner: WorkerSession, server: JoinHandle<Result<(), WorkerServerError>>) {
    timeout(WAIT, owner.shutdown()).await.unwrap().unwrap();
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

fn assert_peer_closed(result: Result<(), hyper::Error>) {
    if let Err(error) = result {
        let mut cause: Option<&(dyn Error + 'static)> = Some(&error);
        while let Some(current) = cause {
            if let Some(io) = current.downcast_ref::<std::io::Error>() {
                assert!(
                    matches!(
                        io.kind(),
                        std::io::ErrorKind::NotConnected
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::UnexpectedEof
                    ),
                    "{error:?}"
                );
                return;
            }
            cause = current.source();
        }

        assert!(
            error.is_closed() || error.is_incomplete_message(),
            "{error:?}"
        );
    }
}

fn assert_worker_closed(result: Result<(), WorkerServerError>) {
    match result {
        Ok(()) => {}
        Err(WorkerServerError::Transport(error)) => assert_peer_closed(Err(error)),
        Err(error) => panic!("unexpected worker shutdown error: {error:?}"),
    }
}

fn gate() -> Arc<(Mutex<bool>, Condvar)> {
    Arc::new((Mutex::new(false), Condvar::new()))
}

fn wait(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let released = gate.0.lock().unwrap();
    let result = gate
        .1
        .wait_timeout_while(released, WAIT, |released| !*released)
        .unwrap();
    assert!(*result.0, "test did not release inference");
}

fn release(gate: &Arc<(Mutex<bool>, Condvar)>) {
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
}

fn cbor(value: &impl serde::Serialize) -> Response {
    Response::builder()
        .header("content-type", CONTENT_TYPE)
        .body(Body::from(
            encode_message(value, MAX_RESPONSE_BYTES).unwrap(),
        ))
        .unwrap()
}

async fn peer(router: Router) -> (UnixStream, JoinHandle<Result<(), hyper::Error>>) {
    let (broker, worker) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(worker), TowerToHyperService::new(router))
            .await
    });

    (broker, task)
}

fn ready_router() -> Router {
    Router::new().route(
        READY_PATH,
        get(|| async {
            cbor(&WorkerReady {
                protocol_version: 1,
                max_in_flight: 2,
            })
        }),
    )
}

#[tokio::test]
async fn real_server_round_trip_and_inclusive_scores() {
    let (owner, client, server) = start(client_config(2), server_config(2), |request| {
        assert_eq!(request, images(0));

        Ok(WorkerResult::Compared(ComparisonScores {
            live_similarity: -1.0,
            challenge_similarity: 1.0,
        }))
    })
    .await;

    assert!(client.is_available());
    assert_eq!(
        client.compare(images(0)).await.unwrap().live_similarity,
        -1.0
    );

    shutdown(owner, server).await;
    assert!(matches!(
        client.wait_unavailable().await,
        WorkerClientError::Closed
    ));
}

#[tokio::test]
async fn oversized_encoded_request_is_rejected_locally_without_harming_session() {
    let mut config = client_config(1);
    config.max_request_bytes = 100;
    let (owner, client, server) = start(config, server_config(1), |request| {
        assert_eq!(
            request,
            images(1),
            "rejected request must not reach the worker"
        );

        Ok(WorkerResult::Compared(SCORES))
    })
    .await;

    let mut oversized = images(0);
    oversized.credential_image = vec![0; config.max_image_bytes];
    assert!(matches!(
        client.compare(oversized).await,
        Err(WorkerClientError::RequestEncoding(
            WorkerProtocolError::TooLarge
        ))
    ));
    assert!(client.is_available());
    assert_eq!(client.compare(images(1)).await.unwrap(), SCORES);

    shutdown(owner, server).await;
}

#[tokio::test]
async fn responses_are_correlated_out_of_order() {
    let blocked = gate();
    let model_gate = Arc::clone(&blocked);
    let (started, mut starts) = mpsc::unbounded_channel();
    let (owner, client, server) = start(client_config(2), server_config(2), move |request| {
        if request.credential_image[0] == 0 {
            started.send(()).unwrap();
            wait(&model_gate);
            Ok(WorkerResult::Compared(SCORES))
        } else {
            Ok(WorkerResult::Compared(ComparisonScores {
                live_similarity: 0.1,
                challenge_similarity: 0.2,
            }))
        }
    })
    .await;

    let slow_client = client.clone();
    let slow = tokio::spawn(async move { slow_client.compare(images(0)).await });
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    assert_eq!(
        client.compare(images(1)).await.unwrap().live_similarity,
        0.1
    );
    assert!(!slow.is_finished());

    release(&blocked);
    assert_eq!(slow.await.unwrap().unwrap(), SCORES);

    shutdown(owner, server).await;
}

#[tokio::test]
async fn capacity_is_the_minimum_of_broker_and_worker_and_survives_cancellation() {
    for (broker_capacity, worker_capacity) in [(1, 3), (3, 1)] {
        let blocked = gate();
        let model_gate = Arc::clone(&blocked);
        let (started, mut starts) = mpsc::unbounded_channel();
        let (owner, client, server) = start(
            client_config(broker_capacity),
            server_config(worker_capacity),
            move |_| {
                started.send(()).unwrap();
                wait(&model_gate);
                Ok(WorkerResult::Compared(SCORES))
            },
        )
        .await;

        let cancelled_client = client.clone();
        let cancelled = tokio::spawn(async move { cancelled_client.compare(images(0)).await });
        timeout(WAIT, starts.recv()).await.unwrap().unwrap();

        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert!(matches!(
            client.compare(images(1)).await,
            Err(WorkerClientError::AtCapacity)
        ));

        release(&blocked);
        timeout(WAIT, async {
            loop {
                match client.compare(images(1)).await {
                    Err(WorkerClientError::AtCapacity) => tokio::task::yield_now().await,
                    Ok(scores) => {
                        assert_eq!(scores, SCORES);
                        break;
                    }
                    other => panic!("unexpected result: {other:?}"),
                }
            }
        })
        .await
        .unwrap();

        shutdown(owner, server).await;
    }
}

#[tokio::test]
async fn ordinary_analysis_failure_and_local_input_rejection_preserve_readiness() {
    let (owner, client, server) = start(client_config(1), server_config(1), |request| {
        Ok(if request.credential_image[0] == 0 {
            WorkerResult::AnalysisFailed
        } else {
            WorkerResult::Compared(SCORES)
        })
    })
    .await;

    let mut empty = images(1);
    empty.live_image.clear();
    assert!(matches!(
        client.compare(empty).await,
        Err(WorkerClientError::InvalidImages)
    ));

    let mut oversized = images(1);
    oversized.live_image = vec![0; 101];
    assert!(matches!(
        client.compare(oversized).await,
        Err(WorkerClientError::InvalidImages)
    ));
    assert!(matches!(
        client.compare(images(0)).await,
        Err(WorkerClientError::AnalysisFailed)
    ));
    assert!(client.is_available());
    assert_eq!(client.compare(images(1)).await.unwrap(), SCORES);

    shutdown(owner, server).await;
}

#[tokio::test]
async fn all_nonfinite_and_out_of_range_scores_are_fatal() {
    for score in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.01, 1.01] {
        for live in [true, false] {
            let (owner, client, server) = start(client_config(1), server_config(1), move |_| {
                Ok(WorkerResult::Compared(ComparisonScores {
                    live_similarity: if live { score } else { 0.5 },
                    challenge_similarity: if live { 0.5 } else { score },
                }))
            })
            .await;

            assert!(matches!(
                client.compare(images(0)).await,
                Err(WorkerClientError::InvalidScore)
            ));
            assert!(!client.is_available());

            assert!(matches!(
                owner.shutdown().await,
                Err(WorkerClientError::InvalidScore)
            ));
            assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
        }
    }
}

#[tokio::test]
async fn cancelled_call_still_validates_its_response() {
    let blocked = gate();
    let model_gate = Arc::clone(&blocked);
    let (started, mut starts) = mpsc::unbounded_channel();
    let (owner, client, server) = start(client_config(1), server_config(1), move |_| {
        started.send(()).unwrap();
        wait(&model_gate);
        Ok(WorkerResult::Compared(ComparisonScores {
            live_similarity: f32::NAN,
            challenge_similarity: 0.5,
        }))
    })
    .await;

    let cancelled_client = client.clone();
    let cancelled = tokio::spawn(async move { cancelled_client.compare(images(0)).await });
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());

    release(&blocked);
    assert!(matches!(
        timeout(WAIT, client.wait_unavailable()).await.unwrap(),
        WorkerClientError::InvalidScore
    ));
    assert!(matches!(
        owner.shutdown().await,
        Err(WorkerClientError::InvalidScore)
    ));
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test]
async fn request_timeout_is_fatal_for_all_callers_even_after_cancellation() {
    let blocked = gate();
    let model_gate = Arc::clone(&blocked);
    let (started, mut starts) = mpsc::unbounded_channel();
    let mut config = client_config(2);
    config.request_timeout = Duration::from_millis(100);
    let (owner, client, server) = start(config, server_config(2), move |_| {
        started.send(()).unwrap();
        wait(&model_gate);
        Ok(WorkerResult::Compared(SCORES))
    })
    .await;

    let cancelled_client = client.clone();
    let cancelled = tokio::spawn(async move { cancelled_client.compare(images(0)).await });
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert!(matches!(
        client.compare(images(1)).await,
        Err(WorkerClientError::RequestTimeout)
    ));
    assert!(matches!(
        client.wait_unavailable().await,
        WorkerClientError::RequestTimeout
    ));

    release(&blocked);
    assert!(matches!(
        owner.shutdown().await,
        Err(WorkerClientError::RequestTimeout)
    ));
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test]
async fn dropping_owner_invalidates_all_clones_and_closes_connection() {
    let (owner, client, server) = start(client_config(1), server_config(1), |_| {
        Ok(WorkerResult::Compared(SCORES))
    })
    .await;

    let clone = client.clone();
    drop(owner);
    assert!(matches!(
        timeout(WAIT, clone.wait_unavailable()).await.unwrap(),
        WorkerClientError::Closed
    ));
    assert!(!client.is_available());
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_use_real_server() {
    let (owner, client, server) = start(client_config(16), server_config(16), |request| {
        let score = f32::from(request.credential_image[0]) / 100.0;
        Ok(WorkerResult::Compared(ComparisonScores {
            live_similarity: score,
            challenge_similarity: score,
        }))
    })
    .await;

    let mut calls = tokio::task::JoinSet::new();
    for id in 0..16 {
        let client = client.clone();
        calls.spawn(async move {
            let scores = client.compare(images(id)).await.unwrap();
            assert_eq!(scores.live_similarity, f32::from(id) / 100.0);
        });
    }

    while let Some(result) = calls.join_next().await {
        result.unwrap();
    }

    shutdown(owner, server).await;
}

#[tokio::test]
async fn invalid_configuration_is_rejected_without_starting_a_session() {
    let mut cases = Vec::new();
    for duration in [Duration::ZERO, Duration::MAX] {
        let mut config = client_config(1);
        config.handshake_timeout = duration;
        cases.push(config);
        config = client_config(1);
        config.request_timeout = duration;
        cases.push(config);
    }

    for range in [
        RangeInclusive {
            start: 1.0,
            last: 0.0,
        },
        RangeInclusive {
            start: f32::NAN,
            last: 1.0,
        },
        RangeInclusive {
            start: -1.0,
            last: f32::INFINITY,
        },
    ] {
        let mut config = client_config(1);
        config.score_range = range;
        cases.push(config);
    }
    let mut config = client_config(1);
    config.max_image_bytes = 0;
    cases.push(config);

    for config in cases {
        let (broker, _worker) = UnixStream::pair().unwrap();
        assert!(matches!(
            WorkerSession::connect(broker, config).await,
            Err(WorkerClientError::InvalidConfig)
        ));
    }
}

#[tokio::test]
async fn startup_checks_version_capacity_and_deadline() {
    for (version, capacity) in [(2, 1), (1, 0)] {
        let (stream, task) = peer(Router::new().route(
            READY_PATH,
            get(move || async move {
                cbor(&WorkerReady {
                    protocol_version: version,
                    max_in_flight: capacity,
                })
            }),
        ))
        .await;
        let error = WorkerSession::connect(stream, client_config(1))
            .await
            .unwrap_err();
        assert!(matches!(
            (version, error),
            (2, WorkerClientError::IncompatibleProtocol) | (1, WorkerClientError::InvalidCapacity)
        ));
        assert_peer_closed(timeout(WAIT, task).await.unwrap().unwrap());
    }

    let (broker, _worker) = UnixStream::pair().unwrap();
    let mut config = client_config(1);
    config.handshake_timeout = Duration::from_millis(30);
    assert!(matches!(
        WorkerSession::connect(broker, config).await,
        Err(WorkerClientError::HandshakeTimeout)
    ));
}

#[tokio::test]
async fn remote_429_is_nonfatal_but_5xx_and_unexpected_status_are_fatal() {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::BAD_REQUEST,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (stream, task) =
            peer(ready_router().route(COMPARE_PATH, post(move || async move { status }))).await;
        let (owner, client) = WorkerSession::connect(stream, client_config(1))
            .await
            .unwrap();
        let error = client.compare(images(0)).await.unwrap_err();

        if status == StatusCode::TOO_MANY_REQUESTS {
            assert!(matches!(error, WorkerClientError::AtCapacity));
            assert!(client.is_available());
            owner.shutdown().await.unwrap();
        } else {
            assert!(matches!(error, WorkerClientError::HttpStatus(code) if code == status));
            assert!(!client.is_available());
            assert!(
                matches!(owner.shutdown().await, Err(WorkerClientError::HttpStatus(code)) if code == status)
            );
        }

        assert_peer_closed(timeout(WAIT, task).await.unwrap().unwrap());
    }
}

#[tokio::test]
async fn malformed_oversized_and_wrong_media_type_responses_are_fatal() {
    for mode in 0..3 {
        let (stream, task) = peer(ready_router().route(
            COMPARE_PATH,
            post(move || async move {
                let bytes = if mode == 1 {
                    vec![0; MAX_RESPONSE_BYTES + 1]
                } else {
                    vec![0xff]
                };
                // Unknown-length stream exercises actual body limits, not Content-Length.
                Response::builder()
                    .header(
                        "content-type",
                        if mode == 2 {
                            "application/json"
                        } else {
                            CONTENT_TYPE
                        },
                    )
                    .body(Body::from_stream(futures_util::stream::iter([Ok::<
                        _,
                        std::convert::Infallible,
                    >(
                        bytes
                    )])))
                    .unwrap()
            }),
        ))
        .await;
        let (owner, client) = WorkerSession::connect(stream, client_config(1))
            .await
            .unwrap();
        let error = client.compare(images(0)).await.unwrap_err();

        assert!(matches!(
            (mode, error),
            (0, WorkerClientError::Protocol(_))
                | (1, WorkerClientError::ResponseBody(_))
                | (2, WorkerClientError::UnexpectedContentType)
        ));
        assert!(!client.is_available());
        assert!(owner.shutdown().await.is_err());
        assert_peer_closed(timeout(WAIT, task).await.unwrap().unwrap());
    }
}

#[tokio::test]
async fn model_failure_and_panic_stop_server_and_invalidate_client() {
    for panic in [false, true] {
        let (owner, client, server) = start(client_config(1), server_config(1), move |_| {
            assert!(!panic, "injected model panic");
            Err(std::io::Error::other("injected model fault").into())
        })
        .await;

        assert!(client.compare(images(0)).await.is_err());
        assert!(!client.is_available());
        assert!(owner.shutdown().await.is_err());
        let result = timeout(WAIT, server).await.unwrap().unwrap();
        assert!(matches!(
            (panic, result),
            (false, Err(WorkerServerError::Model(_))) | (true, Err(WorkerServerError::Task(_)))
        ));
    }
}

async fn raw_client(
    stream: UnixStream,
) -> (
    hyper::client::conn::http2::SendRequest<Body>,
    JoinHandle<Result<(), hyper::Error>>,
) {
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();

    (sender, tokio::spawn(connection))
}

fn raw_request(body: Body) -> hyper::Request<Body> {
    hyper::Request::builder()
        .method("POST")
        .uri("http://worker/v1/compare")
        .header("content-type", CONTENT_TYPE)
        .body(body)
        .unwrap()
}

fn request_body(id: u8) -> Body {
    Body::from(encode_message(&images(id), 1024).unwrap())
}

#[tokio::test]
async fn resetting_http_stream_does_not_release_actual_compute_capacity() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let blocked = gate();
    let model_gate = Arc::clone(&blocked);
    let (started, mut starts) = mpsc::unbounded_channel();
    let server = tokio::spawn(serve_worker(worker, server_config(1), move |_| {
        started.send(()).unwrap();
        wait(&model_gate);
        Ok(WorkerResult::Compared(SCORES))
    }));
    let (mut sender, driver) = raw_client(broker).await;

    let cancelled = sender.send_request(raw_request(request_body(0)));
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    drop(cancelled); // A real HTTP/2 RST_STREAM while spawn_blocking is executing.
    let rejected = sender
        .send_request(raw_request(request_body(1)))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(starts.try_recv().is_err());
    drop(rejected);

    release(&blocked);
    timeout(WAIT, async {
        loop {
            let response = sender
                .send_request(raw_request(request_body(1)))
                .await
                .unwrap();
            if response.status() == StatusCode::OK {
                break;
            }
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    drop(sender);
    assert_peer_closed(timeout(WAIT, driver).await.unwrap().unwrap());
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test]
async fn server_enforces_body_media_type_image_and_decode_limits_before_inference() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let server = tokio::spawn(serve_worker(worker, server_config(1), |_| {
        panic!("invalid request reached inference");
    }));
    let (mut sender, driver) = raw_client(broker).await;

    for (body, expected) in [
        (Body::from(vec![0xff]), StatusCode::BAD_REQUEST),
        (
            Body::from_stream(futures_util::stream::iter([Ok::<
                _,
                std::convert::Infallible,
            >(vec![0; 1025])])),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            Body::from(
                encode_message(
                    &CompareRequest {
                        credential_image: vec![],
                        live_image: vec![1],
                        challenge_image: vec![1],
                    },
                    1024,
                )
                .unwrap(),
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            Body::from(
                encode_message(
                    &CompareRequest {
                        credential_image: vec![0; 101],
                        live_image: vec![1],
                        challenge_image: vec![1],
                    },
                    1024,
                )
                .unwrap(),
            ),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = sender.send_request(raw_request(body)).await.unwrap();
        assert_eq!(response.status(), expected);
    }

    let mut wrong_type = raw_request(request_body(1));
    wrong_type
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    assert_eq!(
        sender.send_request(wrong_type).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    drop(sender);
    assert_peer_closed(timeout(WAIT, driver).await.unwrap().unwrap());
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test]
async fn incomplete_request_body_has_a_server_deadline() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let mut config = server_config(1);
    config.request_timeout = Duration::from_millis(30);
    let server = tokio::spawn(serve_worker(worker, config, |_| {
        panic!("incomplete body reached inference")
    }));
    let (mut sender, driver) = raw_client(broker).await;

    let body = Body::from_stream(futures_util::stream::pending::<
        Result<Vec<u8>, std::io::Error>,
    >());
    let response = timeout(WAIT, sender.send_request(raw_request(body)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

    drop(response);
    drop(sender);
    assert_peer_closed(timeout(WAIT, driver).await.unwrap().unwrap());
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test]
async fn server_deadline_survives_stream_reset_and_reports_unstoppable_inference() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let blocked = gate();
    let model_gate = Arc::clone(&blocked);
    let (started, mut starts) = mpsc::unbounded_channel();
    let mut config = server_config(1);
    config.request_timeout = Duration::from_millis(60);
    config.shutdown_timeout = Duration::from_millis(30);
    let server = tokio::spawn(serve_worker(worker, config, move |_| {
        started.send(()).unwrap();
        wait(&model_gate);
        Ok(WorkerResult::Compared(SCORES))
    }));
    let (mut sender, driver) = raw_client(broker).await;

    let cancelled = sender.send_request(raw_request(request_body(0)));
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    drop(cancelled);
    let result = timeout(WAIT, server).await.unwrap().unwrap();
    release(&blocked);
    assert!(
        matches!(result, Err(WorkerServerError::ShutdownTimeout { cause: Some(cause) })
        if matches!(*cause, WorkerServerError::RequestTimeout))
    );

    drop(sender);
    assert_peer_closed(timeout(WAIT, driver).await.unwrap().unwrap());
}

#[tokio::test]
async fn owner_shutdown_fails_pending_calls_but_server_waits_for_actual_inference() {
    let blocked = gate();
    let model_gate = Arc::clone(&blocked);
    let (started, mut starts) = mpsc::unbounded_channel();
    let (owner, client, server) = start(client_config(1), server_config(1), move |_| {
        started.send(()).unwrap();
        wait(&model_gate);
        Ok(WorkerResult::Compared(SCORES))
    })
    .await;

    let pending = tokio::spawn(async move { client.compare(images(0)).await });
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    owner.shutdown().await.unwrap();
    assert!(matches!(
        pending.await.unwrap(),
        Err(WorkerClientError::Closed)
    ));
    assert!(!server.is_finished());

    release(&blocked);
    assert_worker_closed(timeout(WAIT, server).await.unwrap().unwrap());
}

#[tokio::test]
async fn peer_crash_fails_pending_calls_and_readiness() {
    let (started, mut starts) = mpsc::unbounded_channel();
    let (stream, peer) = peer(ready_router().route(
        COMPARE_PATH,
        post(move || {
            let started = started.clone();
            async move {
                started.send(()).unwrap();
                std::future::pending::<Response>().await
            }
        }),
    ))
    .await;
    let (owner, client) = WorkerSession::connect(stream, client_config(2))
        .await
        .unwrap();
    let pending_client = client.clone();
    let pending = tokio::spawn(async move { pending_client.compare(images(0)).await });
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();

    // Intentional crash injection; normal teardown tests await server completion.
    peer.abort();
    assert!(peer.await.unwrap_err().is_cancelled());
    assert!(timeout(WAIT, pending).await.unwrap().unwrap().is_err());
    assert!(!client.is_available());
    assert!(owner.shutdown().await.is_err());
}

#[tokio::test]
async fn blocked_upload_is_included_in_client_deadline() {
    let (started, mut starts) = mpsc::unbounded_channel();
    let (stream, peer) = peer(ready_router().route(
        COMPARE_PATH,
        post(move |request: axum::extract::Request| {
            let started = started.clone();
            async move {
                started.send(()).unwrap();
                // Keep the unread body alive: HTTP/2 flow control must block a large upload.
                let _request = request;
                std::future::pending::<Response>().await
            }
        }),
    ))
    .await;
    let mut config = client_config(1);
    config.request_timeout = Duration::from_millis(100);
    config.max_request_bytes = 4 * 1024 * 1024;
    config.max_image_bytes = 1024 * 1024;
    let (owner, client) = WorkerSession::connect(stream, config).await.unwrap();

    let pending_client = client.clone();
    let pending = tokio::spawn(async move {
        pending_client
            .compare(CompareRequest {
                credential_image: vec![1; 1024 * 1024],
                live_image: vec![2; 1024 * 1024],
                challenge_image: vec![3; 1024 * 1024],
            })
            .await
    });
    timeout(WAIT, starts.recv()).await.unwrap().unwrap();
    assert!(matches!(
        timeout(WAIT, pending).await.unwrap().unwrap(),
        Err(WorkerClientError::RequestTimeout)
    ));
    assert!(matches!(
        owner.shutdown().await,
        Err(WorkerClientError::RequestTimeout)
    ));
    assert_peer_closed(timeout(WAIT, peer).await.unwrap().unwrap());
}
