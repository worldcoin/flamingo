use std::{
    error::Error, io, num::NonZeroU16, os::fd::FromRawFd, path::Path, range::RangeInclusive,
    sync::Arc, time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Response, header},
    routing::{get, post},
};
use flamingo_verifier_worker_process::{WorkerProcess, WorkerProcessConfig};
use flamingo_verifier_worker_protocol::{
    COMPARE_PATH, CONTENT_TYPE, ComparisonScores, MAX_RESPONSE_BYTES, READY_PATH, WorkerReady,
    WorkerResult, encode_message,
};
use flamingo_verifier_worker_rpc::{
    WorkerClientConfig, WorkerServerConfig, WorkerServerError, serve_worker,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};

fn config() -> WorkerProcessConfig {
    WorkerProcessConfig {
        rpc: WorkerClientConfig {
            max_in_flight: NonZeroU16::new(4).unwrap(),
            handshake_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(3),
            max_request_bytes: 1024,
            max_image_bytes: 100,
            score_range: RangeInclusive {
                start: -1.0,
                last: 1.0,
            },
        },
        shutdown_timeout: Duration::from_millis(300),
        reap_timeout: Duration::from_secs(3),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "normal".into());
    if mode == "closed-stdio-parent" {
        let executable = std::env::current_exe()?;
        // Isolated fixture process: exercise FD allocation with all three standard FDs absent.
        unsafe {
            libc::close(0);
            libc::close(1);
            libc::close(2);
        }
        let worker = WorkerProcess::spawn(Path::new(&executable), &["normal"], config())?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return runtime.block_on(async {
            let (worker, _) = worker.connect().await?;
            worker.shutdown().await?;
            Ok(())
        });
    }

    assert!(
        std::env::vars_os().next().is_none(),
        "inherited environment"
    );
    assert_eq!(
        close_fds::iter_open_fds(4).next(),
        None,
        "inherited unintended descriptor"
    );
    // SAFETY: This is the process entry point, before any owner or runtime could take FD 3.
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    socket.set_nonblocking(true)?;

    if mode == "startup-exit" {
        std::process::exit(23);
    }
    if mode == "startup-stall" {
        forever();
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let socket = tokio::net::UnixStream::from_std(socket)?;
        if mode == "malformed" || mode == "bad-version" {
            let version = if mode == "bad-version" { 99 } else { 1 };
            let router = Router::new()
                .route(
                    READY_PATH,
                    get(move || async move {
                        let payload = encode_message(
                            &WorkerReady {
                                protocol_version: version,
                                max_in_flight: 4,
                            },
                            MAX_RESPONSE_BYTES,
                        )
                        .unwrap();
                        response(payload)
                    }),
                )
                .route(COMPARE_PATH, post(|| async { response(vec![0xff]) }));
            let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(socket), TowerToHyperService::new(router))
                .await;
            return result
                .or_else(|error| {
                    if expected_close(&error) {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(|error| Box::new(error) as Box<dyn Error>);
        }

        let callback_mode = Arc::new(mode.clone());
        let result = serve_worker(
            socket,
            WorkerServerConfig {
                max_in_flight: NonZeroU16::new(4).unwrap(),
                max_request_bytes: 1024,
                max_image_bytes: 100,
                request_timeout: Duration::from_secs(10),
                shutdown_timeout: Duration::from_millis(500),
            },
            move |request| {
                assert_eq!(request.live_image, vec![2; 8]);
                assert_eq!(request.challenge_image, vec![3; 8]);
                match request.credential_image[0] {
                    250 => return Ok(WorkerResult::AnalysisFailed),
                    251 => std::process::exit(42),
                    252 => forever(),
                    253 => std::thread::sleep(Duration::from_millis(200)),
                    _ => {}
                }
                let score = if callback_mode.as_str() == "invalid-score" {
                    f32::NAN
                } else {
                    0.8
                };
                Ok(WorkerResult::Compared(ComparisonScores {
                    live_similarity: score,
                    challenge_similarity: 0.9,
                }))
            },
        )
        .await;

        if mode == "ignore-shutdown" {
            forever();
        }
        match result {
            Ok(()) => Ok(()),
            Err(WorkerServerError::Transport(error)) if expected_close(&error) => Ok(()),
            Err(error) => Err(Box::new(error) as Box<dyn Error>),
        }
    })
}

fn response(payload: Vec<u8>) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .body(Body::from(payload))
        .unwrap()
}

fn forever() -> ! {
    loop {
        std::thread::park();
    }
}

fn expected_close(error: &hyper::Error) -> bool {
    if error.is_closed() || error.is_incomplete_message() {
        return true;
    }
    let mut cause = error.source();
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return matches!(
                error.kind(),
                io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof
            );
        }
        cause = error.source();
    }
    false
}
