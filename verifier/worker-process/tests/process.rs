//! Runs without libtest threads because Minijail must fork from a single-threaded process.

#[cfg(target_os = "linux")]
use std::{fs::File, path::Path, time::Duration};

#[cfg(target_os = "linux")]
use flamingo_verifier_worker_process::{Worker, WorkerError};
#[cfg(target_os = "linux")]
use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
#[cfg(target_os = "linux")]
use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerClientError};

#[cfg(target_os = "linux")]
const PEER: &str = env!("CARGO_BIN_EXE_worker-process-test-peer");
#[cfg(target_os = "linux")]
const POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/worker.policy");

#[cfg(target_os = "linux")]
/// Allows lazy initialization while keeping deliberately stuck requests short.
fn config() -> WorkerClientConfig {
    WorkerClientConfig {
        first_request_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_millis(300),
        max_request_bytes: 1024,
        max_image_bytes: 100,
        score_range: -1.0..=1.0,
    }
}

#[cfg(target_os = "linux")]
/// Chooses fixture behavior through the existing comparison message.
fn images(id: u8) -> CompareRequest {
    CompareRequest {
        credential_image: vec![id; 8],
        live_image: vec![2; 8],
        challenge_image: vec![3; 8],
    }
}

#[cfg(target_os = "linux")]
/// Real Minijail tests require root; CI invokes this executable with a wall-clock timeout.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run this test executable as root"
    );
    let binary = File::open(PEER)?;
    let policy = Path::new(POLICY);
    let scores = ComparisonScores {
        live_similarity: 0.8,
        challenge_similarity: 0.9,
    };

    // The child also checks empty environment, null stdio and these unrelated descriptors.
    let secret = File::open("/dev/null")?;
    let unrelated_fd = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 64) };
    assert_eq!(unrelated_fd, 64);
    // SAFETY: fcntl returned a newly owned descriptor.
    use std::os::fd::{AsRawFd, FromRawFd};
    let _unrelated_fd = unsafe { File::from_raw_fd(unrelated_fd) };
    let mut worker = Worker::spawn(&binary, policy, config())?;
    let children_path = format!("/proc/self/task/{}/children", unsafe { libc::getpid() });
    let pid = std::fs::read_to_string(&children_path)?
        .trim()
        .parse::<i32>()?;

    // Invalid local input does not consume the first request or invalidate the worker.
    let mut invalid = images(1);
    invalid.credential_image.clear();
    assert!(matches!(
        worker.compare(invalid),
        Err(WorkerError::Rpc(WorkerClientError::InvalidImages))
    ));
    for id in 1..=3 {
        assert_eq!(worker.compare(images(id))?, scores);
    }
    assert!(matches!(
        worker.compare(images(250)),
        Err(WorkerError::Rpc(WorkerClientError::AnalysisFailed))
    ));
    assert_eq!(
        worker.compare(images(201))?,
        scores,
        "model threads must work"
    );
    worker.shutdown()?;
    worker.shutdown()?;
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    assert!(worker.compare(images(1)).is_err());
    drop(worker);

    // A forbidden syscall must terminate the worker, not return an ordinary analysis failure.
    let mut worker = Worker::spawn(&binary, policy, config())?;
    assert_eq!(worker.compare(images(1))?, scores);
    assert!(matches!(
        worker.compare(images(202)),
        // The pinned Rust wrapper exposes Minijail's 253 seccomp sentinel as a return code.
        Err(WorkerError::Jail(minijail::Error::ReturnCode(253)))
    ));
    assert!(std::fs::read_to_string(&children_path)?.trim().is_empty());

    // Descendants can hold IPC open and ignore SIGTERM. Killing namespace PID 1 must remove both.
    let mut worker = Worker::spawn(&binary, policy, config())?;
    assert_eq!(worker.compare(images(200))?, scores);
    let pid = std::fs::read_to_string(&children_path)?
        .trim()
        .parse::<i32>()?;
    let descendant = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))?
        .trim()
        .parse::<i32>()?;
    let started = std::time::Instant::now();
    assert!(matches!(
        worker.compare(images(252)),
        Err(WorkerError::Rpc(WorkerClientError::RequestTimeout))
    ));
    assert!(started.elapsed() < Duration::from_secs(3));
    for stopped in [pid, descendant] {
        assert_eq!(
            unsafe { libc::kill(stopped, 0) },
            -1,
            "process {stopped} survived"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    let mut worker = Worker::spawn(&binary, policy, config())?;
    assert_eq!(worker.compare(images(200))?, scores);
    drop(worker);
    assert!(std::fs::read_to_string(&children_path)?.trim().is_empty());

    // The first comparison must also kill a stuck model before it ever returns a result.
    let mut worker = Worker::spawn(&binary, policy, config())?;
    assert!(matches!(
        worker.compare(images(252)),
        Err(WorkerError::Rpc(WorkerClientError::RequestTimeout))
    ));
    assert!(std::fs::read_to_string(&children_path)?.trim().is_empty());

    // Initialization and executable errors cannot yield successful comparisons.
    let mut worker = Worker::spawn(&binary, policy, config())?;
    assert!(worker.compare(images(254)).is_err());
    let invalid_binary = File::open(policy)?;
    let mut worker = Worker::spawn(&invalid_binary, policy, config())?;
    assert!(worker.compare(images(1)).is_err());
    assert!(Worker::spawn(&binary, Path::new("/missing-worker.policy"), config()).is_err());
    let mut invalid_config = config();
    invalid_config.request_timeout = Duration::ZERO;
    assert!(Worker::spawn(&binary, policy, invalid_config).is_err());

    println!("Minijail launch, RPC, seccomp, timeout and namespace cleanup tests passed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// The broker RPC tests remain portable; Minijail execution requires Linux.
fn main() {
    eprintln!("worker-process integration tests require Linux");
}
