//! Executable startup checks without ONNX artifacts or a Linux sandbox.

use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use flamingo_verifier_worker::{MAX_IMAGE_BYTES, MAX_REQUEST_BYTES, run_worker};
use flamingo_verifier_worker_protocol::CompareRequest;
use flamingo_verifier_worker_rpc::{WorkerClient, WorkerClientConfig, WorkerClientError};

/// Ensures a failed assertion cannot leak a worker process from the test suite.
struct WorkerChild {
    /// The real executable, never a model callback fixture.
    child: Child,
}

impl WorkerChild {
    /// Mirrors the broker's empty environment and inherited FD contract, without Minijail.
    fn spawn(fd: RawFd) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_verifier-worker"));
        command
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // SAFETY: only async-signal-safe descriptor operations occur between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if fd == -1 {
                    libc::close(3);
                } else if fd == 3 {
                    if libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            child: command.spawn().unwrap(),
        }
    }

    /// Bounds every subprocess test, including broken idle/EOF handling.
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "worker did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for WorkerChild {
    /// Reaps test children only; production still exits without a reaper or restart.
    fn drop(&mut self) {
        let _ = self.child.kill();
        self.child.wait().expect("test worker must be reaped");
    }
}

/// No handshake or model access is needed to idle or shut down at a frame boundary.
#[test]
fn executable_is_lazy_and_eof_is_clean() {
    let (mut broker, worker) = UnixStream::pair().unwrap();
    let mut child = WorkerChild::spawn(worker.as_raw_fd());
    drop(worker);
    broker
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let error = broker.read(&mut [0]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    assert!(child.child.try_wait().unwrap().is_none());
    // Keep the peer descriptor alive through EOF: Darwin rejects SO_RCVTIMEO changes
    // after a full peer close, which is correctly treated as a terminal transport error.
    broker.shutdown(std::net::Shutdown::Write).unwrap();
    let status = child.wait();
    let mut diagnostics = String::new();
    child
        .child
        .stderr
        .take()
        .unwrap()
        .take(4096)
        .read_to_string(&mut diagnostics)
        .unwrap();
    assert!(status.success(), "{status:?}: {diagnostics}");
}

/// Missing or unusable descriptors fail before serving anything.
#[test]
fn executable_rejects_invalid_startup() {
    assert!(!WorkerChild::spawn(-1).wait().success());
    let file = File::open("/dev/null").unwrap();
    assert!(!WorkerChild::spawn(file.as_raw_fd()).wait().success());
}

/// A truncated frame is terminal even when the model has never been initialized.
#[test]
fn executable_rejects_partial_frame() {
    let (mut broker, worker) = UnixStream::pair().unwrap();
    let mut child = WorkerChild::spawn(worker.as_raw_fd());
    drop(worker);
    broker.write_all(&[0, 0]).unwrap();
    broker.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(!child.wait().success());
    let mut diagnostics = String::new();
    child
        .child
        .stderr
        .take()
        .unwrap()
        .take(4096)
        .read_to_string(&mut diagnostics)
        .unwrap();
    assert!(diagnostics.contains("transport"));
}

/// Model initialization is inside the first request and never becomes AnalysisFailed.
#[test]
fn missing_models_terminate_the_session() {
    let (broker, worker) = UnixStream::pair().unwrap();
    let server =
        thread::spawn(move || run_worker(worker, std::path::Path::new("/dev/null/no-models")));
    let mut client = WorkerClient::new(
        broker,
        WorkerClientConfig {
            first_request_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(1),
            max_request_bytes: MAX_REQUEST_BYTES,
            max_image_bytes: MAX_IMAGE_BYTES,
            score_range: -1.0..=1.0,
        },
    )
    .unwrap();
    let request = CompareRequest {
        credential_image: vec![1],
        live_image: vec![2],
        challenge_image: vec![3],
    };
    assert!(client.compare(request.clone()).is_err());
    assert!(client.failure().is_some());
    let error = server.join().unwrap().unwrap_err();
    assert_eq!(error.failure_class(), "model");
    assert!(!matches!(
        client.compare(request),
        Err(WorkerClientError::AnalysisFailed)
    ));
}
