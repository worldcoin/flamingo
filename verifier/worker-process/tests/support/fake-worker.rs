//! Public fixture for the Minijail boundary; never ships with the production broker.

#[cfg(target_os = "linux")]
use std::{
    io::{self, Write},
    os::{fd::FromRawFd, unix::net::UnixStream},
    time::Duration,
};

#[cfg(target_os = "linux")]
use flamingo_verifier_worker_protocol::{ComparisonScores, WorkerResult};
#[cfg(target_os = "linux")]
use flamingo_verifier_worker_rpc::{WorkerServerConfig, serve_worker};

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
/// Checks confinement before Rust main, where a preload-based sandbox would be too late.
static CHECK_EARLY_SANDBOX: extern "C" fn() = {
    /// Uses only libc operations during loader initialization.
    extern "C" fn check() {
        // SAFETY: These queries do not retain pointers or modify process state.
        unsafe {
            if libc::getpid() != 1
                || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
                || libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) != 2
            {
                libc::_exit(120);
            }
        }
    }
    check
};

#[cfg(target_os = "linux")]
/// Receives only FD 3; behavior is selected by each comparison's first image byte.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        std::env::vars_os().next().is_none(),
        "inherited environment"
    );
    for fd in 0..=2 {
        assert_eq!(
            std::fs::read_link(format!("/proc/self/fd/{fd}"))?,
            std::path::Path::new("/dev/null")
        );
    }
    for fd in [4, 5, 6, 64] {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) },
            -1,
            "inherited FD {fd}"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
    // SAFETY: This executable exclusively owns inherited FD 3.
    let socket = unsafe { UnixStream::from_raw_fd(3) };
    let mut raw_reply = socket.try_clone()?;
    let mut first = true;
    serve_worker(
        socket,
        WorkerServerConfig {
            max_request_bytes: 1024,
            max_image_bytes: 100,
            first_request_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(20),
        },
        |request| {
            if first {
                std::thread::sleep(Duration::from_millis(400));
                first = false;
            }
            match request.credential_image[0] {
                200 => {
                    // SAFETY: The fixture is single-threaded and the child performs only libc calls.
                    let child = unsafe { libc::fork() };
                    assert!(child >= 0);
                    if child == 0 {
                        unsafe {
                            libc::signal(libc::SIGTERM, libc::SIG_IGN);
                            loop {
                                libc::pause();
                            }
                        }
                    }
                }
                201 => assert_eq!(std::thread::spawn(|| 42).join().unwrap(), 42),
                202 => {
                    // SAFETY: The fixture policy forbids socket creation.
                    unsafe {
                        libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                    }
                    panic!("forbidden socket syscall returned");
                }
                203 => {
                    raw_reply.write_all(&[0, 0, 0, 1, 0xff])?;
                    std::process::exit(0);
                }
                204 => {
                    return Ok(WorkerResult::Compared(ComparisonScores {
                        live_similarity: f32::NAN,
                        challenge_similarity: 0.9,
                    }));
                }
                250 => return Ok(WorkerResult::AnalysisFailed),
                252 => unsafe {
                    libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    loop {
                        libc::pause();
                    }
                },
                253 => std::process::exit(42),
                254 => return Err(Box::new(io::Error::other("fixture initialization failed"))),
                _ => {}
            }
            Ok(WorkerResult::Compared(ComparisonScores {
                live_similarity: 0.8,
                challenge_similarity: 0.9,
            }))
        },
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// This fixture cannot exercise Minijail on other operating systems.
fn main() {
    panic!("worker-process fixture requires Linux");
}
