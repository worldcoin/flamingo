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
                || libc::getuid() != flamingo_verifier_worker_process::WORKER_UID
                || libc::getgid() != flamingo_verifier_worker_process::WORKER_UID
                || libc::getgroups(0, std::ptr::null_mut()) != 0
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
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
        let stat = unsafe { stat.assume_init() };
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFCHR);
        assert_eq!(stat.st_rdev, libc::makedev(1, 3), "stdio must be /dev/null");
    }
    for fd in [4, 5, 6, 64] {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) },
            -1,
            "inherited FD {fd}"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
    for path in [
        "/proc/self/mem",
        "/proc/1/mem",
        "/dev/nsm",
        "/sys",
        "/etc/passwd",
        "../../broker-secret",
    ] {
        assert_eq!(
            std::fs::File::open(path).unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "visible host path: {path}"
        );
    }
    assert_eq!(std::fs::read("/fixture-data")?, b"approved model data");
    assert_eq!(std::env::current_dir()?, std::path::Path::new("/"));
    let mut filesystem = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    assert_eq!(
        unsafe { libc::statvfs(c"/".as_ptr(), filesystem.as_mut_ptr()) },
        0
    );
    let filesystem = unsafe { filesystem.assume_init() };
    let required_flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    assert_eq!(filesystem.f_flag & required_flags, required_flags);
    for (resource, expected) in [
        (libc::RLIMIT_AS, 1 << 30),
        (libc::RLIMIT_NPROC, 8),
        (libc::RLIMIT_NOFILE, 64),
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_FSIZE, 0),
        (libc::RLIMIT_MEMLOCK, 0),
    ] {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(resource, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (expected, expected));
    }
    // SAFETY: This executable exclusively owns inherited FD 3.
    let socket = unsafe { UnixStream::from_raw_fd(3) };
    assert!(socket.local_addr()?.is_unnamed());
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
                    std::thread::spawn(|| {
                        loop {
                            std::thread::park();
                        }
                    });
                }
                201 => assert_eq!(std::thread::spawn(|| 42).join().unwrap(), 42),
                202 => {
                    // SAFETY: The production policy forbids socket creation.
                    unsafe {
                        libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                    }
                    // Returning scores makes the broker test fail if the syscall was allowed.
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
                205..=219 => {
                    // All calls must kill the whole process, even from a secondary thread.
                    unsafe {
                        match request.credential_image[0] {
                            205 => {
                                libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
                            }
                            206 => {
                                if libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) == 0 {
                                    libc::_exit(0);
                                }
                            }
                            207 => {
                                std::thread::spawn(|| {
                                    libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                                })
                                .join()
                                .unwrap();
                            }
                            208 => {
                                libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
                            }
                            209 => {
                                libc::syscall(libc::SYS_process_vm_readv, 1, 0, 0, 0, 0, 0);
                            }
                            210 => {
                                libc::setuid(0);
                            }
                            211 => {
                                libc::unshare(libc::CLONE_NEWUSER);
                            }
                            212 => {
                                libc::openat(
                                    libc::AT_FDCWD,
                                    c"/fixture-data".as_ptr(),
                                    libc::O_WRONLY,
                                );
                            }
                            213 => {
                                let limit = libc::rlimit {
                                    rlim_cur: libc::RLIM_INFINITY,
                                    rlim_max: libc::RLIM_INFINITY,
                                };
                                libc::syscall(libc::SYS_prlimit64, 0, libc::RLIMIT_AS, &limit, 0);
                            }
                            214 => {
                                libc::ioctl(3, 0);
                            }
                            215 => {
                                libc::syscall(libc::SYS_execve, c"/fixture-data".as_ptr(), 0, 0);
                            }
                            216 => {
                                libc::mmap(
                                    std::ptr::null_mut(),
                                    4096,
                                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                                    -1,
                                    0,
                                );
                            }
                            217 => {
                                libc::chroot(c"../..".as_ptr());
                            }
                            218 => {
                                libc::sethostname(c"worker".as_ptr(), 6);
                            }
                            219 => {
                                libc::syscall(libc::SYS_uname, 0);
                            }
                            _ => unreachable!(),
                        }
                    }
                    // Do not panic here: that would also look like a sandbox kill over RPC.
                    // Return valid scores so a syscall returning (even EPERM) fails the test.
                }
                220 => {
                    // A reservation over RLIMIT_AS must fail without consuming physical RAM.
                    let allocation = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            1 << 30,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        )
                    };
                    assert_eq!(allocation, libc::MAP_FAILED);
                    assert_eq!(
                        io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOMEM)
                    );
                }
                221 => {
                    let mut files = Vec::new();
                    loop {
                        let fd = unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 0) };
                        if fd < 0 {
                            assert_eq!(
                                io::Error::last_os_error().raw_os_error(),
                                Some(libc::EMFILE)
                            );
                            break;
                        }
                        assert!(fd < 64);
                        files.push(unsafe { std::fs::File::from_raw_fd(fd) });
                    }
                    assert_eq!(files.len(), 59); // stdio, RPC and raw_reply already use 0..=4.
                }
                222 => {
                    use std::sync::{
                        Arc,
                        atomic::{AtomicBool, Ordering},
                    };
                    let done = Arc::new(AtomicBool::new(false));
                    let mut threads = Vec::new();
                    loop {
                        let done = Arc::clone(&done);
                        match std::thread::Builder::new().spawn(move || {
                            while !done.load(Ordering::Acquire) {
                                std::thread::park();
                            }
                        }) {
                            Ok(thread) => threads.push(thread),
                            Err(error) => {
                                assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
                                break;
                            }
                        }
                        assert!(threads.len() < 8, "thread limit not enforced");
                    }
                    assert_eq!(threads.len(), 7);
                    done.store(true, Ordering::Release);
                    for thread in threads {
                        thread.thread().unpark();
                        thread.join().unwrap();
                    }
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
