//! Each broker runs as namespace init so its exit also removes every worker descendant.

#[cfg(target_os = "linux")]
use std::{fs::File, os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

#[cfg(target_os = "linux")]
use flamingo_verifier_worker_process::{SandboxConfig, WORKER_UID, Worker, WorkerError};
#[cfg(target_os = "linux")]
use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
#[cfg(target_os = "linux")]
use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerClientError};

#[cfg(target_os = "linux")]
const PEER: &str = env!("CARGO_BIN_EXE_worker-process-test-peer");
#[cfg(target_os = "linux")]
const POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/worker.policy");
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
/// Explicit test budgets; production must size these against its enclave memory reservation.
fn sandbox(root: &Path) -> SandboxConfig<'_> {
    SandboxConfig {
        root,
        address_space_bytes: 1 << 30,
        max_threads: 8,
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
fn broker(case: &str, mut root: &Path) -> Result<(), Box<dyn std::error::Error>> {
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

    if case == "legacy-root" {
        // Reproduce old Nitro init: chroot without switching the mount namespace root.
        // Only the broker needs proc/dev; the nested worker must still see neither.
        use std::os::unix::ffi::OsStrExt;
        let outer_root = root.parent().unwrap();
        std::fs::create_dir(outer_root.join("proc"))?;
        std::fs::create_dir(outer_root.join("dev"))?;
        File::create(outer_root.join("dev/null"))?;
        for (source, target) in [("/proc", "proc"), ("/dev/null", "dev/null")] {
            assert!(
                Command::new("mount")
                    .args(["--bind", source])
                    .arg(outer_root.join(target))
                    .status()?
                    .success()
            );
        }
        let outer_root = std::ffi::CString::new(outer_root.as_os_str().as_bytes())?;
        assert_eq!(unsafe { libc::chroot(outer_root.as_ptr()) }, 0);
        assert_eq!(unsafe { libc::chdir(c"/".as_ptr()) }, 0);
        root = Path::new("/root");
    }

    if case == "recoverable" {
        assert!(
            Worker::spawn(
                &binary,
                sandbox(Path::new("/missing-worker-root")),
                config(),
                fatal
            )
            .is_err()
        );
        assert!(Worker::spawn(&binary, sandbox(Path::new("/")), config(), fatal).is_err());
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o777))?;
        assert!(Worker::spawn(&binary, sandbox(root), config(), fatal).is_err());
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))?;
        for (address_space_bytes, max_threads) in
            [(0, 8), (u64::MAX, 8), (1 << 30, 0), (1 << 30, 257)]
        {
            assert!(
                Worker::spawn(
                    &binary,
                    SandboxConfig {
                        root,
                        address_space_bytes,
                        max_threads
                    },
                    config(),
                    fatal
                )
                .is_err()
            );
        }
        let mut invalid_config = config();
        invalid_config.request_timeout = Duration::ZERO;
        assert!(Worker::spawn(&binary, sandbox(root), invalid_config, fatal).is_err());

        // This broker already has a private mount namespace. A host submount under
        // the runtime tree must not be carried into the worker by the root bind.
        assert!(
            Command::new("mount")
                .args(["--bind", "/proc"])
                .arg(root.join("proc"))
                .status()?
                .success()
        );
    }
    let mut worker = Worker::spawn(&binary, sandbox(root), config(), fatal)?;

    if matches!(case, "recoverable" | "legacy-root") {
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
        for id in 220..=222 {
            assert_eq!(
                worker.compare(images(id))?,
                scores,
                "resource limit check {id}"
            );
        }
        assert_eq!(worker.compare(images(200))?, scores);
        let children_path = format!("/proc/self/task/{}/children", unsafe { libc::getpid() });
        let pid = std::fs::read_to_string(children_path)?
            .trim()
            .parse::<i32>()?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert!(
                status
                    .lines()
                    .any(|line| line == format!("{name}:\t0000000000000000")),
                "{name} not cleared"
            );
        }
        assert!(status.contains(&format!(
            "Uid:\t{WORKER_UID}\t{WORKER_UID}\t{WORKER_UID}\t{WORKER_UID}"
        )));
        drop(worker);

        // Test-only reaping proves Drop requests SIGKILL without relying on guest teardown.
        // The outer timeout bounds this wait if the worker or its descendants survive.
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        return Ok(());
    }

    // An inference thread remains alive during the warm timeout case.
    if !matches!(case, "cold-timeout" | "initialization" | "bad-executable") {
        assert_eq!(
            worker.compare(images(if case == "timeout" { 200 } else { 1 }))?,
            scores
        );
    }
    if case == "kill-failure" {
        // A different unprivileged UID cannot kill the worker; SIGKILL fails with EPERM.
        // The fatal handler must still exit with the original timeout, not a cleanup error.
        assert_eq!(unsafe { libc::setuid(65534) }, 0);
    }
    let mode = match case {
        "seccomp" => 202,
        "vsock" => 205,
        "fork" => 206,
        "thread-seccomp" => 207,
        "ptrace" => 208,
        "process-memory" => 209,
        "setuid" => 210,
        "namespace" => 211,
        "filesystem-write" => 212,
        "raise-limit" => 213,
        "device-ioctl" => 214,
        "path-exec" => 215,
        "rwx-memory" => 216,
        "chroot-escape" => 217,
        "set-hostname" => 218,
        "read-hostname" => 219,
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
        let root = std::env::args_os().nth(2).expect("runtime root argument");
        return broker(&case, Path::new(&root));
    }

    // Only inspect our own trusted build with ldd, never a provisioned private executable.
    // Copy its exact loader/library dependencies, not the host /lib or /nix/store trees.
    let temp = Command::new("mktemp")
        .args(["-d", "/tmp/worker-process-test.XXXXXXXX"])
        .output()?;
    assert!(temp.status.success());
    let temp = std::path::PathBuf::from(String::from_utf8(temp.stdout)?.trim());
    let root = temp.join("root");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("proc"))?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
    let libraries = Command::new("ldd").arg(PEER).output()?;
    assert!(
        libraries.status.success(),
        "ldd failed: {}",
        String::from_utf8_lossy(&libraries.stderr)
    );
    for library in String::from_utf8(libraries.stdout)?
        .split_whitespace()
        .filter(|word| word.starts_with('/'))
    {
        let target = root.join(library.trim_start_matches('/'));
        std::fs::create_dir_all(target.parent().unwrap())?;
        std::fs::copy(library, target)?;
    }
    std::fs::write(root.join("fixture-data"), b"approved model data")?;
    std::fs::set_permissions(
        root.join("fixture-data"),
        std::fs::Permissions::from_mode(0o644),
    )?;
    std::fs::write(temp.join("broker-secret"), b"must not be visible")?;

    for (case, failure_class) in [
        ("recoverable", None),
        ("legacy-root", None),
        ("seccomp", Some("transport")),
        ("vsock", Some("transport")),
        ("fork", Some("transport")),
        ("thread-seccomp", Some("transport")),
        ("ptrace", Some("transport")),
        ("process-memory", Some("transport")),
        ("setuid", Some("transport")),
        ("namespace", Some("transport")),
        ("filesystem-write", Some("transport")),
        ("raise-limit", Some("transport")),
        ("device-ioctl", Some("transport")),
        ("path-exec", Some("transport")),
        ("rwx-memory", Some("transport")),
        ("chroot-escape", Some("transport")),
        ("set-hostname", Some("transport")),
        ("read-hostname", Some("transport")),
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
            .arg(&root)
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

    std::fs::remove_dir_all(&temp)?;
    println!("Production Minijail confinement, resource limits and broker lifecycle tests passed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// The broker RPC tests remain portable; Minijail execution requires Linux.
fn main() {
    eprintln!("worker-process integration tests require Linux");
}
