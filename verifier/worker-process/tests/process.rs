use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use flamingo_verifier_worker_process::{WorkerProcess, WorkerProcessConfig, WorkerProcessError};
use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerClientError};

const PEER: &str = env!("CARGO_BIN_EXE_worker-process-test-peer");
const WAIT: Duration = Duration::from_secs(5);
const SCORES: ComparisonScores = ComparisonScores {
    live_similarity: 0.8,
    challenge_similarity: 0.9,
};

/// Keeps subprocess scheduling separate from intentionally short comparison deadlines.
fn config() -> WorkerProcessConfig {
    WorkerProcessConfig {
        rpc: WorkerClientConfig {
            first_request_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(1),
            max_request_bytes: 1024,
            max_image_bytes: 100,
            score_range: -1.0..=1.0,
        },
        shutdown_timeout: Duration::from_millis(100),
        reap_timeout: Duration::from_secs(2),
    }
}

/// Launches only the explicitly built fixture executable.
fn spawn(mode: &str, config: WorkerProcessConfig) -> WorkerProcess {
    WorkerProcess::spawn(Path::new(PEER), &[mode], config).unwrap()
}

/// Selects fixture behavior with an otherwise valid comparison.
fn images(id: u8) -> CompareRequest {
    CompareRequest {
        credential_image: vec![id; 8],
        live_image: vec![2; 8],
        challenge_image: vec![3; 8],
    }
}

/// Confirms the supervisor already reaped this exact child.
fn assert_reaped(pid: u32) {
    let mut status = 0;
    // SAFETY: This test created the exact PID; WNOHANG never blocks.
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

/// Observes background cleanup without racing the supervisor to reap the child.
fn wait_reaped(pid: u32) {
    let deadline = Instant::now() + WAIT;
    // SAFETY: Signal zero probes existence; it never signals or reaps a process.
    while unsafe { libc::kill(pid as i32, 0) } == 0 {
        assert!(Instant::now() < deadline, "worker cleanup timed out");
        thread::sleep(Duration::from_millis(10));
    }
    assert_reaped(pid);
}

/// Finds the comparison error preserved through forced termination or secondary cleanup failures.
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
/// The entire launch, comparison and shutdown path works without Tokio or a handshake.
fn sequential_round_trips_and_analysis_recovery() {
    let mut worker = spawn("normal", config());
    let pid = worker.id();
    for id in 1..=10 {
        assert_eq!(worker.compare(images(id)).unwrap(), SCORES);
    }
    assert!(matches!(
        worker.compare(images(250)),
        Err(WorkerProcessError::Rpc(WorkerClientError::AnalysisFailed))
    ));
    assert_eq!(worker.compare(images(1)).unwrap(), SCORES);
    assert!(worker.try_wait().unwrap().is_none());
    assert!(worker.shutdown().unwrap().success());
    assert_reaped(pid);
}

#[test]
/// Idle time consumes no initialization allowance; loading happens inside the first comparison.
fn lazy_initialization_uses_first_comparison_budget() {
    let mut limits = config();
    limits.rpc.request_timeout = Duration::from_millis(80);
    let mut worker = spawn("lazy-load", limits);
    let pid = worker.id();
    thread::sleep(Duration::from_millis(120));
    assert!(worker.try_wait().unwrap().is_none());
    assert_eq!(worker.compare(images(1)).unwrap(), SCORES);
    assert_eq!(worker.compare(images(2)).unwrap(), SCORES);

    let error = worker.compare(images(253)).unwrap_err();
    assert!(matches!(
        rpc_cause(&error),
        Some(WorkerClientError::RequestTimeout)
    ));
    assert!(worker.try_wait().is_err());
    assert_reaped(pid);
}

#[test]
/// A hung initializer is allowed to be idle but is killed when the first request expires.
fn first_request_timeout_kills_and_reaps_uninitialized_worker() {
    let mut limits = config();
    limits.rpc.first_request_timeout = Duration::from_millis(100);
    limits.rpc.request_timeout = limits.rpc.first_request_timeout;
    let mut worker = spawn("startup-stall", limits);
    let pid = worker.id();
    thread::sleep(Duration::from_millis(150));
    assert!(worker.try_wait().unwrap().is_none());
    let started = Instant::now();
    let error = worker.compare(images(1)).unwrap_err();
    assert!(matches!(
        error,
        WorkerProcessError::ForcedTermination { .. }
    ));
    assert!(matches!(
        rpc_cause(&error),
        Some(WorkerClientError::RequestTimeout)
    ));
    assert!(started.elapsed() < WAIT);
    assert_reaped(pid);
}

#[test]
/// Child exit invalidates later calls even when there has never been a comparison.
fn idle_exit_is_observed_and_cached() {
    let mut worker = spawn("startup-exit", config());
    let pid = worker.id();
    let error = worker.wait().unwrap_err();
    assert!(matches!(error, WorkerProcessError::Exited(status) if status.code() == Some(23)));
    assert!(
        matches!(worker.try_wait(), Err(WorkerProcessError::Exited(status)) if status.code() == Some(23))
    );
    assert!(worker.compare(images(1)).is_err());
    assert_reaped(pid);
}

#[test]
/// Unexpected model exits, initialization errors and panics are never analysis failures.
fn model_crash_and_failure_are_reaped() {
    for id in [251, 254, 255] {
        let mut worker = spawn("normal", config());
        let pid = worker.id();
        let error = worker.compare(images(id)).unwrap_err();
        assert!(matches!(error, WorkerProcessError::Exited(status) if !status.success()));
        assert_reaped(pid);
    }
}

#[test]
/// Invalid worker replies invalidate the connection and stop the process before returning.
fn fatal_rpc_errors_stop_the_child() {
    for mode in ["malformed", "oversized", "truncated", "invalid-score"] {
        let mut worker = spawn(mode, config());
        let pid = worker.id();
        let error = worker.compare(images(1)).unwrap_err();
        assert!(
            matches!(
                rpc_cause(&error),
                Some(
                    WorkerClientError::Protocol(_)
                        | WorkerClientError::Transport(_)
                        | WorkerClientError::InvalidScore
                )
            ),
            "{error:?}"
        );
        assert!(worker.compare(images(2)).is_err());
        assert_reaped(pid);
    }
}

#[test]
/// A stuck callback cannot outlive its comparison deadline plus bounded process cleanup.
fn stuck_inference_is_killed_without_a_runtime() {
    let mut limits = config();
    limits.rpc.request_timeout = Duration::from_millis(80);
    let mut worker = spawn("normal", limits);
    let pid = worker.id();
    worker.compare(images(1)).unwrap();
    let error = worker.compare(images(252)).unwrap_err();
    assert!(matches!(
        error,
        WorkerProcessError::ForcedTermination { .. }
    ));
    assert!(matches!(
        rpc_cause(&error),
        Some(WorkerClientError::RequestTimeout)
    ));
    assert_reaped(pid);
}

#[test]
/// Losing the caller's thread handle does not cancel an already-running comparison or its cleanup.
fn detached_caller_still_finishes_deadline_cleanup() {
    let mut limits = config();
    limits.rpc.first_request_timeout = Duration::from_millis(100);
    limits.rpc.request_timeout = limits.rpc.first_request_timeout;
    let mut worker = spawn("startup-stall", limits);
    let pid = worker.id();
    let (finished, result) = std::sync::mpsc::channel();
    drop(thread::spawn(move || {
        finished.send(worker.compare(images(1))).unwrap()
    }));
    let error = result.recv_timeout(WAIT).unwrap().unwrap_err();
    assert!(matches!(
        rpc_cause(&error),
        Some(WorkerClientError::RequestTimeout)
    ));
    assert_reaped(pid);
}

#[test]
/// Drop requests cleanup even before the first comparison and without a runtime to drive it.
fn owner_drop_cleans_up_idle_and_uninitialized_children() {
    for mode in ["normal", "startup-stall", "ignore-shutdown"] {
        let worker = spawn(mode, config());
        let pid = worker.id();
        drop(worker);
        wait_reaped(pid);
    }
}

#[test]
/// A process that ignores graceful IPC shutdown is killed and reported as a failure.
fn unresponsive_shutdown_is_explicit() {
    let mut worker = spawn("ignore-shutdown", config());
    let pid = worker.id();
    worker.compare(images(1)).unwrap();
    assert!(matches!(
        worker.shutdown(),
        Err(WorkerProcessError::ForcedTermination { .. })
    ));
    assert_reaped(pid);
}

#[test]
/// Launch does not inherit environment variables or unintended non-CLOEXEC descriptors.
fn extra_descriptors_and_environment_are_not_inherited() {
    let file = File::open("/dev/null").unwrap();
    // SAFETY: Duplicates this test's descriptor without modifying any other descriptor.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 512) };
    assert!(fd >= 512);
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut worker = spawn("normal", config());
    let pid = worker.id();
    worker.compare(images(1)).unwrap();
    worker.shutdown().unwrap();
    assert_reaped(pid);
    assert!(
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } >= 0,
        "parent FD was changed"
    );
}

#[test]
/// Closed standard descriptors cannot clobber FD 3 or Rust's exec-error pipe.
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
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
/// Configuration and executable failures are returned before handing back a process owner.
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
