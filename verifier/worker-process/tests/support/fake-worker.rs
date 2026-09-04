use std::{
    error::Error,
    io::{self, Read, Write},
    os::{fd::FromRawFd, unix::net::UnixStream},
    path::Path,
    time::Duration,
};

use flamingo_verifier_worker_process::{WorkerProcess, WorkerProcessConfig};
use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores, WorkerResult};
use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerServerConfig, serve_worker};

/// Bounds isolated descriptor-allocation probes.
fn config() -> WorkerProcessConfig {
    WorkerProcessConfig {
        rpc: WorkerClientConfig {
            first_request_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(3),
            max_request_bytes: 1024,
            max_image_bytes: 100,
            score_range: -1.0..=1.0,
        },
        shutdown_timeout: Duration::from_millis(100),
        reap_timeout: Duration::from_secs(3),
    }
}

/// Exercises the real executable/FD boundary with no runtime, environment or extra descriptors.
fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "normal".into());
    if mode == "closed-stdio-parent" {
        let executable = std::env::current_exe()?;
        // SAFETY: This isolated fixture process has no threads or stdio users.
        unsafe {
            libc::close(0);
            libc::close(1);
            libc::close(2);
        }
        let mut worker = WorkerProcess::spawn(Path::new(&executable), &["normal"], config())?;
        worker.compare(CompareRequest {
            credential_image: vec![1; 8],
            live_image: vec![2; 8],
            challenge_image: vec![3; 8],
        })?;
        worker.shutdown()?;
        assert!(WorkerProcess::spawn(Path::new("/"), &["normal"], config()).is_err());
        return Ok(());
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
    // SAFETY: This entry point is the sole owner of inherited FD 3.
    let mut socket = unsafe { UnixStream::from_raw_fd(3) };
    if mode == "startup-exit" {
        std::process::exit(23);
    }
    if mode == "startup-stall" {
        forever();
    }

    if mode == "malformed" || mode == "oversized" || mode == "truncated" {
        read_request(&mut socket)?;
        let bytes = match mode.as_str() {
            "malformed" => vec![0, 0, 0, 1, 0xff],
            "oversized" => u32::MAX.to_be_bytes().to_vec(),
            _ => vec![0, 0, 0, 9, 1],
        };
        socket.write_all(&bytes)?;
        socket.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(socket.read(&mut [0])?, 0);
        return Ok(());
    }

    let mut first = true;
    let result = serve_worker(
        socket,
        WorkerServerConfig {
            max_request_bytes: 1024,
            max_image_bytes: 100,
            first_request_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
        },
        |request| {
            if first && mode == "lazy-load" {
                std::thread::sleep(Duration::from_millis(200));
            }
            first = false;
            assert_eq!(request.live_image, vec![2; 8]);
            assert_eq!(request.challenge_image, vec![3; 8]);
            match request.credential_image[0] {
                250 => return Ok(WorkerResult::AnalysisFailed),
                251 => std::process::exit(42),
                252 => forever(),
                253 => std::thread::sleep(Duration::from_millis(250)),
                254 => {
                    return Err(Box::new(io::Error::other(
                        "fixture model initialization failed",
                    )));
                }
                255 => panic!("fixture model panic"),
                _ => {}
            }
            let score = if mode == "invalid-score" {
                f32::NAN
            } else {
                0.8
            };
            Ok(WorkerResult::Compared(ComparisonScores {
                live_similarity: score,
                challenge_similarity: 0.9,
            }))
        },
    );

    if mode == "ignore-shutdown" {
        forever();
    }
    result.map_err(|error| Box::new(error) as Box<dyn Error>)
}

/// Drains one bounded request before producing an intentionally invalid response.
fn read_request(socket: &mut UnixStream) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 1024);
    socket.read_exact(&mut vec![0; length])
}

/// Simulates a process that cannot cooperate with socket shutdown.
fn forever() -> ! {
    loop {
        std::thread::park();
    }
}
