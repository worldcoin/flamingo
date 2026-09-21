//! Each broker runs as namespace init so its exit also removes every worker descendant.

#[cfg(target_os = "linux")]
use std::{fs::File, os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

#[cfg(target_os = "linux")]
use biometric_engines_protocol::{
    face::{DeepFaceRequest, DeepFaceResult, FaceImage, face_image::Source},
    request::Operation,
    response::Outcome,
};
#[cfg(target_os = "linux")]
use flamingo_verifier_sandbox_client::{SandboxClientConfig, SandboxClientError};
#[cfg(target_os = "linux")]
use flamingo_verifier_sandbox_client::{SandboxConfig, WORKER_UID, Worker, WorkerError};

#[cfg(target_os = "linux")]
fn peer() -> String {
    std::env::var("WORKER_TEST_PEER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_sandbox-client-test-peer").to_owned())
}
#[cfg(target_os = "linux")]
fn policy() -> String {
    std::env::var("WORKER_TEST_POLICY")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/worker.policy").to_owned())
}
#[cfg(target_os = "linux")]
const FATAL_EXIT: i32 = 70;

#[cfg(target_os = "linux")]
/// Allows startup initialization while keeping deliberately stuck comparisons short.
fn config() -> SandboxClientConfig {
    SandboxClientConfig {
        startup_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        max_request_bytes: 1024,
        max_image_bytes: 100,
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
fn images(id: u8) -> Operation {
    Operation::DeepFace(DeepFaceRequest {
        credential: Some(FaceImage {
            source: Some(Source::Orb(vec![id; 8])),
        }),
        live: Some(FaceImage {
            source: Some(Source::VanillaSelfie(vec![2; 8])),
        }),
        challenge: Some(FaceImage {
            source: Some(Source::Rtms(vec![3; 8])),
        }),
    })
}

#[cfg(target_os = "linux")]
/// The broker owns process termination; expose the original error for the test supervisor.
fn fatal(error: SandboxClientError) -> ! {
    eprintln!("fatal_worker:{error}");
    std::process::exit(FATAL_EXIT);
}

#[cfg(target_os = "linux")]
/// Executes one broker lifetime without libtest threads or in-process worker replacement.
fn broker(case: &str, mut root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let binary = File::open(if case == "bad-executable" {
        policy()
    } else {
        peer()
    })?;
    let scores = Outcome::DeepFace(DeepFaceResult {
        similarity_credential_live: Some(0.8),
        similarity_credential_challenge: Some(0.9),
        similarity_live_challenge: Some(0.85),
        debug_report: None,
    });

    // The worker checks that unrelated descriptors do not survive launch.
    use std::os::fd::{AsRawFd, FromRawFd};
    let secret = File::open("/dev/null")?;
    let unrelated_fd = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 64) };
    assert_eq!(unrelated_fd, 64);
    // SAFETY: fcntl returned a newly owned descriptor.
    let _unrelated_fd = unsafe { File::from_raw_fd(unrelated_fd) };

    if case == "nitro-root" {
        // Match the pinned AWS init's bind, move, chroot sequence.
        // Only the broker needs proc/dev; the nested worker must still see neither.
        use std::os::unix::ffi::OsStrExt;
        let outer_root = root.parent().unwrap();
        let outer_path = std::ffi::CString::new(outer_root.as_os_str().as_bytes())?;
        assert_eq!(
            unsafe {
                libc::mount(
                    outer_path.as_ptr(),
                    outer_path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0
        );
        // Install test-only proc/dev mounts before switching root, while mount is available.
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
        assert_eq!(unsafe { libc::chdir(outer_path.as_ptr()) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    c".".as_ptr(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_MOVE,
                    std::ptr::null(),
                )
            },
            0
        );
        assert_eq!(unsafe { libc::chroot(c".".as_ptr()) }, 0);
        assert_eq!(unsafe { libc::chdir(c"/".as_ptr()) }, 0);
        // Fail at the mount operation itself, before worker stderr is redirected.
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0,
            "Nitro root must support private mounts: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(std::env::current_dir()?, Path::new("/"));
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
    let verified_runtime = if case == "provisioned-runtime" {
        use flamingo_verifier_sandbox_bundle::{Manifest, WORKER_PATH};
        use sha2::{Digest, Sha384};

        let bytes = std::fs::read(root.join(WORKER_PATH))?;
        let manifest = serde_json::to_vec(&Manifest {
            manifest_version: 3,
            release_id: "public-test-fixture".to_owned(),
            sha384: hex::encode(Sha384::digest(&bytes)),
            size: bytes.len() as u64,
        })?;
        let mut bundle = Vec::new();
        flamingo_verifier_sandbox_bundle::package(&mut bundle, &manifest, &root.join(WORKER_PATH))?;
        Some(flamingo_verifier_sandbox_bundle::receive(
            &mut std::io::Cursor::new(bundle),
            1 << 30,
            root.parent().unwrap(),
        )?)
    } else {
        None
    };
    let executable = verified_runtime
        .as_ref()
        .map_or(&binary, |runtime| &runtime.binary);
    let runtime_root = verified_runtime
        .as_ref()
        .map_or(root, |runtime| runtime.root.path());
    let mut limits = config();
    if matches!(
        case,
        "timeout" | "first-comparison-timeout" | "kill-failure"
    ) {
        limits.request_timeout = Duration::from_millis(300);
    }
    if case == "startup-timeout" {
        limits.startup_timeout = Duration::from_millis(50);
    }
    let mut worker = match Worker::spawn(executable, sandbox(runtime_root), limits, fatal) {
        Ok(worker) => worker,
        Err(WorkerError::Rpc(error)) => fatal(error),
        Err(error) => return Err(error.into()),
    };

    if case == "provisioned-runtime" {
        assert_eq!(
            verified_runtime.as_ref().unwrap().release_id,
            "public-test-fixture"
        );
        worker.check_alive();
        assert_eq!(worker.evaluate(images(1))?, scores);
        assert!(matches!(
            worker.evaluate(images(250)),
            Err(WorkerError::Rpc(SandboxClientError::AnalysisFailed(_)))
        ));
        assert_eq!(worker.evaluate(images(2))?, scores);
        worker.evaluate(images(253))?;
        panic!("provisioned worker crash must terminate the broker");
    }

    if case == "moved-owner" {
        worker.check_alive();
        std::thread::spawn(move || {
            assert_eq!(worker.evaluate(images(1)).unwrap(), scores);
            worker.check_alive();
            assert_eq!(worker.evaluate(images(2)).unwrap(), scores);
        })
        .join()
        .expect("worker ownership transfer failed");
        return Ok(());
    }

    if matches!(case, "recoverable" | "nitro-root") {
        let mut invalid = images(1);
        let Operation::DeepFace(ref mut input) = invalid else {
            unreachable!()
        };
        input.credential = None;
        assert!(matches!(
            worker.evaluate(invalid),
            Err(WorkerError::Rpc(SandboxClientError::InvalidImages))
        ));
        for id in 1..=3 {
            assert_eq!(worker.evaluate(images(id))?, scores);
        }
        assert!(matches!(
            worker.evaluate(images(250)),
            Err(WorkerError::Rpc(SandboxClientError::AnalysisFailed(_)))
        ));
        assert_eq!(
            worker.evaluate(images(201))?,
            scores,
            "model threads must work"
        );
        for id in 220..=222 {
            assert_eq!(
                worker.evaluate(images(id))?,
                scores,
                "resource limit check {id}"
            );
        }
        assert_eq!(worker.evaluate(images(200))?, scores);
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
    if !matches!(
        case,
        "first-comparison-timeout" | "model-error" | "bad-executable"
    ) {
        assert_eq!(
            worker.evaluate(images(if case == "timeout" { 200 } else { 1 }))?,
            scores
        );
    }
    if case == "idle-exit" {
        worker.check_alive();
        let children_path = format!("/proc/self/task/{}/children", unsafe { libc::getpid() });
        let pid = std::fs::read_to_string(children_path)?
            .trim()
            .parse::<i32>()?;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);

        // No comparison, handshake or reaper is needed to detect the idle worker's exit.
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            worker.check_alive();
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("idle worker exit was not terminal");
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
        "timeout" | "first-comparison-timeout" | "kill-failure" => 252,
        "model-error" => 254,
        "bad-executable" => 1,
        _ => panic!("unknown broker case: {case}"),
    };
    let result = worker.evaluate(images(mode));
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

    // The provisioned-runtime test uses exactly one static executable, as production does.
    let headers = Command::new("readelf").args(["-lW", &peer()]).output()?;
    let dynamic = Command::new("readelf").args(["-dW", &peer()]).output()?;
    assert!(headers.status.success() && dynamic.status.success());
    assert!(
        !String::from_utf8_lossy(&headers.stdout).contains("INTERP"),
        "build the fixture with -C target-feature=+crt-static"
    );
    assert!(!String::from_utf8_lossy(&dynamic.stdout).contains("(NEEDED)"));
    let temp = Command::new("mktemp")
        .args(["-d", "/tmp/sandbox-client-test.XXXXXXXX"])
        .output()?;
    assert!(temp.status.success());
    let temp = std::path::PathBuf::from(String::from_utf8(temp.stdout)?.trim());
    let root = temp.join("root");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("bin"))?;
    std::fs::create_dir(root.join("proc"))?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
    std::fs::copy(peer(), root.join("bin/verifier-worker"))?;
    std::fs::write(temp.join("broker-secret"), b"must not be visible")?;

    for (case, expected_error) in [
        ("recoverable", None),
        ("startup-timeout", Some("worker startup timed out")),
        ("nitro-root", None),
        ("provisioned-runtime", Some("worker socket I/O failed")),
        ("moved-owner", None),
        ("idle-exit", Some("worker socket I/O failed")),
        ("seccomp", Some("worker socket I/O failed")),
        ("vsock", Some("worker socket I/O failed")),
        ("fork", Some("worker socket I/O failed")),
        ("thread-seccomp", Some("worker socket I/O failed")),
        ("ptrace", Some("worker socket I/O failed")),
        ("process-memory", Some("worker socket I/O failed")),
        ("setuid", Some("worker socket I/O failed")),
        ("namespace", Some("worker socket I/O failed")),
        ("filesystem-write", Some("worker socket I/O failed")),
        ("raise-limit", Some("worker socket I/O failed")),
        ("device-ioctl", Some("worker socket I/O failed")),
        ("path-exec", Some("worker socket I/O failed")),
        ("rwx-memory", Some("worker socket I/O failed")),
        ("chroot-escape", Some("worker socket I/O failed")),
        ("set-hostname", Some("worker socket I/O failed")),
        ("read-hostname", Some("worker socket I/O failed")),
        ("timeout", Some("worker request timed out")),
        ("first-comparison-timeout", Some("worker request timed out")),
        ("kill-failure", Some("worker request timed out")),
        ("model-error", Some("worker socket I/O failed")),
        ("bad-executable", Some("worker socket I/O failed")),
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
            Some(expected_error.map_or(0, |_| FATAL_EXIT)),
            "{case}: {stderr}"
        );
        if let Some(error) = expected_error {
            assert!(
                stderr.contains(&format!("fatal_worker:{error}")),
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
    eprintln!("sandbox-client integration tests require Linux");
}
