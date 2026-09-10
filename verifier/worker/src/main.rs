//! Fixed-entrypoint worker. The broker supplies a connected Unix stream on FD 3.

use std::{io, os::fd::FromRawFd, os::unix::net::UnixStream, path::Path, process::ExitCode};

/// Suppresses potentially sensitive panic payloads and exits on every terminal failure.
fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| eprintln!("worker failure: panic")));
    let stream = match inherited_socket() {
        Ok(stream) => stream,
        Err(_) => {
            eprintln!("worker failure: invalid IPC descriptor");
            return ExitCode::FAILURE;
        }
    };
    match flamingo_verifier_worker::run_worker(stream, Path::new("/models")) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Only the low-cardinality class, never third-party errors or biometric data.
            let os_error = match &error {
                flamingo_verifier_worker_rpc::WorkerServerError::Transport(error) => {
                    error.raw_os_error()
                }
                _ => None,
            };
            eprintln!(
                "worker failure: {} (os_error={os_error:?})",
                error.failure_class()
            );
            ExitCode::FAILURE
        }
    }
}

/// Validates the descriptor before taking ownership; no other code owns FD 3 at startup.
fn inherited_socket() -> io::Result<UnixStream> {
    // SAFETY: fcntl validates the inherited descriptor without assuming it is open.
    if unsafe { libc::fcntl(3, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: FD 3 is valid and exclusively owned by this single-threaded entry point.
    let stream = unsafe { UnixStream::from_raw_fd(3) };
    Ok(stream)
}
