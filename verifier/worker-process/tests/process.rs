use std::{
    fs::File,
    io,
    num::NonZeroU16,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    process::Command,
    range::RangeInclusive,
    time::{Duration, Instant},
};

use flamingo_verifier_worker_process::{WorkerProcess, WorkerProcessConfig, WorkerProcessError};
use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerClientError};
use tokio::time::{sleep, timeout};

const PEER: &str = env!("CARGO_BIN_EXE_worker-process-test-peer");
const WAIT: Duration = Duration::from_secs(5);
const SCORES: ComparisonScores = ComparisonScores {
    live_similarity: 0.8,
    challenge_similarity: 0.9,
};

fn config() -> WorkerProcessConfig {
    WorkerProcessConfig {
        rpc: WorkerClientConfig {
            max_in_flight: NonZeroU16::new(4).unwrap(),
            handshake_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            max_request_bytes: 1024,
            max_image_bytes: 100,
            score_range: RangeInclusive {
                start: -1.0,
                last: 1.0,
            },
        },
        shutdown_timeout: Duration::from_millis(300),
        reap_timeout: Duration::from_secs(2),
    }
}

fn spawn(mode: &str, config: WorkerProcessConfig) -> WorkerProcess {
    WorkerProcess::spawn(Path::new(PEER), &[mode], config).unwrap()
}

fn images(id: u8) -> CompareRequest {
    CompareRequest {
        credential_image: vec![id; 8],
        live_image: vec![2; 8],
        challenge_image: vec![3; 8],
    }
}

fn assert_reaped(pid: u32) {
    let mut status = 0;
    // SAFETY: This exact PID was created by this test; WNOHANG never blocks.
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1,
        "worker was not reaped"
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

async fn wait_reaped(pid: u32) {
    timeout(WAIT, async {
        // kill(0) only checks existence; it never signals or reaps the process.
        while unsafe { libc::kill(pid as i32, 0) } == 0 {
            sleep(Duration::from_millis(10)).await;
        }
        assert_reaped(pid);
    })
    .await
    .unwrap();
}

fn rpc_cause(error: &WorkerProcessError) -> Option<&WorkerClientError> {
    match error {
        WorkerProcessError::Rpc(error) => Some(error),
        WorkerProcessError::ForcedTermination { cause, .. }
        | WorkerProcessError::ReapTimeout { cause, .. }
        | WorkerProcessError::Cleanup { cause, .. } => cause.as_deref().and_then(rpc_cause),
        _ => None,
    }
}

#[test]
fn launch_before_runtime_and_round_trip() {
    let worker = spawn("normal", config());
    let pid = worker.id();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let (worker, client) = timeout(WAIT, worker.connect()).await.unwrap().unwrap();
        assert_eq!(client.compare(images(1)).await.unwrap(), SCORES);
        assert!(matches!(
            client.compare(images(250)).await,
            Err(WorkerClientError::AnalysisFailed)
        ));
        assert!(client.is_available());
        assert!(
            timeout(WAIT, worker.shutdown())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(!client.is_available());
    });
    assert_reaped(pid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_share_a_real_process() {
    let worker = spawn("normal", config());
    let pid = worker.id();
    let (worker, client) = worker.connect().await.unwrap();
    let mut calls = tokio::task::JoinSet::new();
    for id in 0..4 {
        let client = client.clone();
        calls.spawn(async move { client.compare(images(id)).await });
    }
    while let Some(result) = timeout(WAIT, calls.join_next()).await.unwrap() {
        assert_eq!(result.unwrap().unwrap(), SCORES);
    }
    worker.shutdown().await.unwrap();
    assert_reaped(pid);
}

#[tokio::test]
async fn cancellation_retains_capacity_until_inference_finishes() {
    let mut config = config();
    config.rpc.max_in_flight = NonZeroU16::new(1).unwrap();
    let (worker, client) = spawn("normal", config).connect().await.unwrap();
    let pid = worker.id();
    let mut call = Box::pin(client.compare(images(253)));
    tokio::select! {
        result = &mut call => panic!("slow comparison finished early: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    drop(call);
    assert!(matches!(
        client.compare(images(0)).await,
        Err(WorkerClientError::AtCapacity)
    ));

    timeout(WAIT, async {
        loop {
            match client.compare(images(0)).await {
                Err(WorkerClientError::AtCapacity) => sleep(Duration::from_millis(10)).await,
                result => {
                    assert_eq!(result.unwrap(), SCORES);
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    worker.shutdown().await.unwrap();
    assert_reaped(pid);
}

#[tokio::test]
async fn startup_failures_are_reaped() {
    for mode in ["startup-exit", "bad-version", "startup-stall"] {
        let mut config = config();
        if mode == "startup-stall" {
            config.rpc.handshake_timeout = Duration::from_millis(200);
        }
        let worker = spawn(mode, config);
        let pid = worker.id();
        let error = timeout(WAIT, worker.connect()).await.unwrap().unwrap_err();
        match mode {
            "startup-exit" => assert!(
                matches!(error, WorkerProcessError::Exited(status) if status.code() == Some(23)),
                "{error:?}"
            ),
            "bad-version" => assert!(matches!(
                rpc_cause(&error),
                Some(WorkerClientError::IncompatibleProtocol)
            )),
            _ => assert!(matches!(
                rpc_cause(&error),
                Some(WorkerClientError::HandshakeTimeout)
            )),
        }
        assert_reaped(pid);
    }
}

#[tokio::test]
async fn startup_budget_starts_at_launch_even_without_connect() {
    let mut config = config();
    config.rpc.handshake_timeout = Duration::from_millis(50);
    let worker = spawn("startup-stall", config);
    let pid = worker.id();
    let error = timeout(WAIT, worker.wait()).await.unwrap().unwrap_err();
    assert!(matches!(
        rpc_cause(&error),
        Some(WorkerClientError::HandshakeTimeout)
    ));
    assert_reaped(pid);
}

#[tokio::test]
async fn dropping_or_cancelling_startup_cleans_up() {
    let worker = spawn("startup-stall", config());
    let pid = worker.id();
    let mut connection = Box::pin(worker.connect());
    tokio::select! {
        result = &mut connection => panic!("stalled startup completed: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    drop(connection);
    wait_reaped(pid).await;

    let worker = spawn("startup-stall", config());
    let pid = worker.id();
    drop(worker);
    wait_reaped(pid).await;
}

#[tokio::test]
async fn crash_invalidates_all_clients_and_reaps() {
    let (worker, client) = spawn("normal", config()).connect().await.unwrap();
    let pid = worker.id();
    let clone = client.clone();
    assert!(
        timeout(WAIT, client.compare(images(251)))
            .await
            .unwrap()
            .is_err()
    );
    timeout(WAIT, clone.wait_unavailable()).await.unwrap();
    assert!(!clone.is_available());
    let error = timeout(WAIT, worker.wait()).await.unwrap().unwrap_err();
    assert!(matches!(error, WorkerProcessError::Exited(status) if status.code() == Some(42)));
    assert_reaped(pid);
}

#[tokio::test]
async fn fatal_rpc_errors_stop_the_child() {
    for mode in ["malformed", "invalid-score", "normal"] {
        let mut config = config();
        config.rpc.request_timeout = Duration::from_millis(200);
        let (worker, client) = spawn(mode, config).connect().await.unwrap();
        let pid = worker.id();
        let id = if mode == "normal" { 252 } else { 0 };
        let error = timeout(WAIT, client.compare(images(id)))
            .await
            .unwrap()
            .unwrap_err();
        match mode {
            "malformed" => assert!(matches!(error, WorkerClientError::Protocol(_))),
            "invalid-score" => assert!(matches!(error, WorkerClientError::InvalidScore)),
            _ => assert!(matches!(error, WorkerClientError::RequestTimeout)),
        }
        assert!(!client.is_available());
        let process_error = timeout(WAIT, worker.wait()).await.unwrap().unwrap_err();
        assert_eq!(
            rpc_cause(&process_error).unwrap().failure_class(),
            error.failure_class()
        );
        assert_reaped(pid);
    }
}

#[tokio::test]
async fn unresponsive_shutdown_is_killed_and_reported() {
    let (worker, client) = spawn("ignore-shutdown", config()).connect().await.unwrap();
    let pid = worker.id();
    let error = timeout(WAIT, worker.shutdown()).await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        WorkerProcessError::ForcedTermination { .. }
    ));
    assert!(!client.is_available());
    assert_reaped(pid);
}

#[tokio::test]
async fn cancelled_stuck_inference_still_times_out_and_is_reaped() {
    let mut config = config();
    config.rpc.request_timeout = Duration::from_millis(200);
    let (worker, client) = spawn("normal", config).connect().await.unwrap();
    let pid = worker.id();
    let mut call = Box::pin(client.compare(images(252)));
    tokio::select! {
        result = &mut call => panic!("stuck inference completed: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    drop(call);

    assert!(matches!(
        timeout(WAIT, client.wait_unavailable()).await.unwrap(),
        WorkerClientError::RequestTimeout
    ));
    let error = timeout(WAIT, worker.wait()).await.unwrap().unwrap_err();
    assert!(matches!(
        rpc_cause(&error),
        Some(WorkerClientError::RequestTimeout)
    ));
    assert_reaped(pid);
}

#[tokio::test]
async fn connecting_twice_is_an_error_and_still_cleans_up() {
    let (worker, client) = spawn("normal", config()).connect().await.unwrap();
    let pid = worker.id();
    assert!(matches!(
        worker.connect().await,
        Err(WorkerProcessError::AlreadyConnected)
    ));
    timeout(WAIT, client.wait_unavailable()).await.unwrap();
    wait_reaped(pid).await;
}

#[tokio::test]
async fn dropping_owner_closes_clones_and_reaps() {
    let (worker, client) = spawn("ignore-shutdown", config()).connect().await.unwrap();
    let pid = worker.id();
    drop(worker);
    timeout(WAIT, client.wait_unavailable()).await.unwrap();
    wait_reaped(pid).await;
}

#[test]
fn runtime_shutdown_does_not_abandon_the_process() {
    let worker = spawn("ignore-shutdown", config());
    let pid = worker.id();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (worker, client) = runtime.block_on(worker.connect()).unwrap();
    drop(runtime);
    assert!(!client.is_available());

    let observer = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    observer.block_on(wait_reaped(pid));
    drop(worker);
}

#[tokio::test]
async fn extra_descriptors_and_environment_are_not_inherited() {
    let file = File::open("/dev/null").unwrap();
    // Deliberately non-CLOEXEC and high-numbered, without changing any other thread's FD.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 512) };
    assert!(fd >= 512);
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    let (worker, _) = spawn("normal", config()).connect().await.unwrap();
    let pid = worker.id();
    worker.shutdown().await.unwrap();
    assert_reaped(pid);
    assert!(
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } >= 0,
        "parent FD was changed"
    );
}

#[test]
fn closed_standard_descriptors_do_not_clobber_ipc_or_exec_errors() {
    let mut child = Command::new(PEER)
        .arg("closed-stdio-parent")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "isolated launch probe: {status}");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("isolated launch probe timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn invalid_configuration_and_exec_failure_are_explicit() {
    let mut invalid = config();
    invalid.shutdown_timeout = Duration::ZERO;
    assert!(matches!(
        WorkerProcess::spawn(Path::new(PEER), &["normal"], invalid),
        Err(WorkerProcessError::InvalidConfig)
    ));
    assert!(matches!(
        WorkerProcess::spawn(Path::new("relative"), &["normal"], config()),
        Err(WorkerProcessError::InvalidConfig)
    ));
    assert!(matches!(
        WorkerProcess::spawn(Path::new("/"), &["normal"], config()),
        Err(WorkerProcessError::Io {
            operation: "launch worker",
            ..
        })
    ));
}
