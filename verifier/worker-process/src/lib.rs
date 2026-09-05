//! Linux worker ownership through Minijail; launch before threads or broker keys exist.

#![cfg(target_os = "linux")]

use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    time::{Duration, Instant},
};

use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
use flamingo_verifier_worker_rpc::{WorkerClient, WorkerClientConfig, WorkerClientError};
use minijail::Minijail;

const REAP_TIMEOUT: Duration = Duration::from_secs(2);

// Upstream's Cargo fallback builds static Minijail but does not declare its libcap dependency.
#[link(name = "cap")]
unsafe extern "C" {}

/// Owns one blocking connection and its PID namespace. No restart or background supervisor.
pub struct Worker {
    /// Validates each comparison and permanently closes IPC after a fatal error.
    rpc: WorkerClient,
    /// Owns the sandbox configuration and reaps its child.
    jail: Minijail,
    /// Cleared after reaping so cleanup cannot signal a reused PID.
    pid: Option<libc::pid_t>,
}

impl Worker {
    /// Launches an open executable with FD 3 and a trusted, build-controlled seccomp policy.
    /// Call from a single-threaded bootstrap before generating keys. Success is not readiness.
    pub fn spawn(
        binary: &File,
        policy: &Path,
        config: WorkerClientConfig,
    ) -> Result<Self, WorkerError> {
        let (rpc, child) = UnixStream::pair()?;
        let rpc = WorkerClient::new(rpc, config)?;

        let mut jail = Minijail::new()?;
        jail.no_new_privs();
        jail.reset_signal_mask();
        jail.namespace_pids();
        jail.parse_seccomp_filters(policy)?;
        jail.use_seccomp_filter();

        let argv = [c"worker".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        // SAFETY: Minijail checks that the caller is single-threaded and remaps/closes FDs.
        // In the child, only libc calls run; failed exec exits without dropping Rust owners.
        // run_fd_remap uses LD_PRELOAD, which would let a supplied loader run before seccomp.
        let pid = unsafe { jail.fork_remap(&[(child.as_raw_fd(), 3), (binary.as_raw_fd(), 4)])? };
        if pid == 0 {
            // SAFETY: FD 4 is the executable. Close it on exec; only IPC and null stdio survive.
            unsafe {
                if libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) == 0 {
                    libc::fexecve(4, argv.as_ptr(), envp.as_ptr());
                }
                libc::_exit(127);
            }
        }

        Ok(Self {
            rpc,
            jail,
            pid: Some(pid),
        })
    }

    /// Completes one comparison; fatal RPC failures also terminate the whole PID namespace.
    #[tracing::instrument(skip_all, fields(dependency = "biometric_worker", pid = ?self.pid))]
    pub fn compare(&mut self, request: CompareRequest) -> Result<ComparisonScores, WorkerError> {
        if self.pid.is_none() {
            return Err(WorkerError::Stopped);
        }

        let result = self.rpc.compare(request);
        if self.rpc.failure().is_some() {
            self.shutdown()?;
        }

        result.map_err(WorkerError::Rpc)
    }

    /// Forcibly stops the namespace and reaps it within a fixed deadline. Safe to repeat.
    pub fn shutdown(&mut self) -> Result<(), WorkerError> {
        let Some(pid) = self.pid else {
            return Ok(());
        };
        // SAFETY: This owner has not reaped pid. Killing namespace PID 1 kills its descendants.
        // SIGTERM can be ignored by PID 1, so Minijail::kill is unsuitable for a stuck worker.
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }

        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            // SAFETY: waitid initializes the record; WNOWAIT leaves reaping to Minijail.
            let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut status,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.pid = None;
                }
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            } else if unsafe { status.si_pid() } != 0 {
                self.pid = None;
                return match self.jail.wait() {
                    Ok(()) | Err(minijail::Error::Killed(9)) => Ok(()),
                    Err(error) => Err(error.into()),
                };
            }

            if Instant::now() >= deadline {
                return Err(WorkerError::ReapTimeout);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Worker {
    /// Attempts bounded cleanup and reports failures; Minijail's own Drop only frees memory.
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            metrics::counter!("worker_process.cleanup_failures").increment(1);
            tracing::error!(dependency = "biometric_worker", %error, "worker cleanup failed");
        }
    }
}

/// Launch, comparison or cleanup failure. Worker-controlled output is never captured.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// The process has already been reaped.
    #[error("worker is shut down")]
    Stopped,
    /// Socket creation or process cleanup failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Minijail could not launch, configure or reap the worker.
    #[error(transparent)]
    Jail(#[from] minijail::Error),
    /// Comparison failed; local input and analysis errors preserve the connection.
    #[error(transparent)]
    Rpc(#[from] WorkerClientError),
    /// SIGKILL was sent, but the kernel has not completed process cleanup.
    #[error("worker was not reaped within two seconds after SIGKILL")]
    ReapTimeout,
}
