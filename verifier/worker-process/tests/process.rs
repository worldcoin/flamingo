//! Each broker runs as namespace init so its exit also removes every worker descendant.

#[cfg(target_os = "linux")]
use std::{fs::File, path::Path, process::Command, time::Duration};

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
const FATAL_EXIT: i32 = 70;

#[cfg(target_os = "linux")]
/// Allows lazy initialization while keeping deliberately stuck requests short.
fn config() -> WorkerClientConfig {
    WorkerClientConfig {
        first_request_timeout: Duration::from_secs(2),
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
/// The broker owns process termination; expose the original error for the test supervisor.
fn fatal(error: WorkerClientError) -> ! {
    eprintln!("fatal_worker:{}", error.failure_class());
    std::process::exit(FATAL_EXIT);
}

#[cfg(target_os = "linux")]
/// Executes one broker lifetime without libtest threads or in-process worker replacement.
fn broker(case: &str) -> Result<(), Box<dyn std::error::Error>> {
    let policy = Path::new(POLICY);
    let binary = File::open(if case == "bad-executable" {
        POLICY
    } else {
        PEER
    })?;
    let scores = ComparisonScores {
        live_similarity: 0.8,
        challenge_similarity: 0.9,
    };

    // The worker checks that unrelated descriptors do not survive launch.
    use std::os::fd::{AsRawFd, FromRawFd};
    let secret = File::open("/dev/null")?;
    let unrelated_fd = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 64) };
    assert_eq!(unrelated_fd, 64);
    // SAFETY: fcntl returned a newly owned descriptor.
    let _unrelated_fd = unsafe { File::from_raw_fd(unrelated_fd) };

    if case == "recoverable" {
        assert!(
            Worker::spawn(
                &binary,
                Path::new("/missing-worker.policy"),
                config(),
                fatal
            )
            .is_err()
        );
        let mut invalid_config = config();
        invalid_config.request_timeout = Duration::ZERO;
        assert!(Worker::spawn(&binary, policy, invalid_config, fatal).is_err());
    }
    let mut worker = Worker::spawn(&binary, policy, config(), fatal)?;

    if case == "recoverable" {
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
        assert_eq!(worker.compare(images(200))?, scores);
        let children_path = format!("/proc/self/task/{}/children", unsafe { libc::getpid() });
        let pid = std::fs::read_to_string(children_path)?
            .trim()
            .parse::<i32>()?;
        drop(worker);

        // Test-only reaping proves Drop requests SIGKILL without relying on guest teardown.
        // The outer timeout bounds this wait if the worker or its descendants survive.
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        return Ok(());
    }

    // A descendant holds IPC open and ignores SIGTERM during the warm timeout case.
    if !matches!(case, "cold-timeout" | "initialization" | "bad-executable") {
        assert_eq!(
            worker.compare(images(if case == "timeout" { 200 } else { 1 }))?,
            scores
        );
    }
    if case == "kill-failure" {
        // The root worker outlives this privilege drop; SIGKILL will fail with EPERM.
        // The fatal handler must still exit with the original timeout, not a cleanup error.
        assert_eq!(unsafe { libc::setuid(65534) }, 0);
    }
    let mode = match case {
        "seccomp" => 202,
        "malformed" => 203,
        "invalid-score" => 204,
        "crash" => 253,
        "timeout" | "cold-timeout" | "kill-failure" => 252,
        "initialization" => 254,
        "bad-executable" => 1,
        _ => panic!("unknown broker case: {case}"),
    };
    let result = worker.compare(images(mode));
    panic!("fatal comparison returned to the broker: {result:?}");
}

#[cfg(target_os = "linux")]
/// Supervises isolated broker processes under individual deadlines; requires root and util-linux.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run this test executable as root"
    );
    if let Some(case) = std::env::args().nth(1) {
        return broker(&case);
    }

    for (case, failure_class) in [
        ("recoverable", None),
        ("seccomp", Some("transport")),
        ("malformed", Some("invalid_response")),
        ("invalid-score", Some("invalid_score")),
        ("crash", Some("transport")),
        ("timeout", Some("request_timeout")),
        ("cold-timeout", Some("request_timeout")),
        ("kill-failure", Some("request_timeout")),
        ("initialization", Some("transport")),
        ("bad-executable", Some("transport")),
    ] {
        let output = Command::new("timeout")
            .args([
                "--kill-after=1s",
                "10s",
                "unshare",
                "--fork",
                "--pid",
                "--mount-proc",
                "--kill-child",
                "--",
            ])
            .arg(std::env::current_exe()?)
            .arg(case)
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(failure_class.map_or(0, |_| FATAL_EXIT)),
            "{case}: {stderr}"
        );
        if let Some(class) = failure_class {
            assert!(
                stderr.contains(&format!("fatal_worker:{class}")),
                "{case}: {stderr}"
            );
        }
    }

    println!("Minijail launch, recoverable errors, fatal broker exit and drop tests passed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// The broker RPC tests remain portable; Minijail execution requires Linux.
fn main() {
    eprintln!("worker-process integration tests require Linux");
}
