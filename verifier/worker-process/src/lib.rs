//! Linux worker ownership through Minijail; launch before threads or broker keys exist.

#![cfg(target_os = "linux")]

#[cfg(not(target_arch = "x86_64"))]
compile_error!("the worker seccomp policy is reviewed for x86_64 Linux only");

use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
use flamingo_verifier_worker_rpc::{WorkerClient, WorkerClientConfig, WorkerClientError};
use minijail::Minijail;

mod sandbox;
pub use sandbox::{SandboxConfig, WORKER_UID};

// Upstream's Cargo fallback builds static Minijail but does not declare its libcap dependency.
#[link(name = "cap")]
unsafe extern "C" {}

/// Owns one worker for the broker's lifetime. Fatal comparisons terminate the broker.
pub struct Worker {
    /// Validates each comparison and permanently closes IPC after a fatal error.
    rpc: WorkerClient,
    /// Keeps Minijail ownership on the bootstrap thread; Drop only frees its configuration.
    _jail: Minijail,
    /// Never reaped here, so it cannot be reused before the broker exits.
    pid: libc::pid_t,
    /// Broker-owned process exit policy; must not unwind or wait for worker cleanup.
    on_fatal: fn(WorkerClientError) -> !,
}

impl Worker {
    /// Launches an open executable with FD 3 inside the embedded production sandbox policy.
    /// Call from a single-threaded bootstrap before generating keys. Success is not readiness.
    /// `on_fatal` must immediately exit the broker process, not panic or stop only a task.
    /// The enclave init must terminate the guest when the broker exits.
    pub fn spawn(
        binary: &File,
        sandbox: SandboxConfig<'_>,
        config: WorkerClientConfig,
        on_fatal: fn(WorkerClientError) -> !,
    ) -> Result<Self, WorkerError> {
        let (rpc, child) = UnixStream::pair()?;
        let rpc = WorkerClient::new(rpc, config)?;

        let jail = sandbox.create_jail()?;

        let argv = [c"worker".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        // SAFETY: Minijail checks that the caller is single-threaded and remaps/closes FDs.
        // In the child, only libc calls run; failed exec exits without dropping Rust owners.
        // run_fd_remap uses LD_PRELOAD, which would let a supplied loader run before seccomp.
        let pid = unsafe { jail.fork_remap(&[(child.as_raw_fd(), 3), (binary.as_raw_fd(), 4)])? };
        if pid == 0 {
            // SAFETY: FD 4 is the executable. Close it on exec; only IPC and null stdio survive.
            unsafe {
                if libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) == 0 {
                    libc::syscall(
                        libc::SYS_execveat,
                        4,
                        c"".as_ptr(),
                        argv.as_ptr(),
                        envp.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    );
                }
                libc::_exit(127);
            }
        }

        Ok(Self {
            rpc,
            _jail: jail,
            pid,
            on_fatal,
        })
    }

    /// Returns only success or recoverable RPC errors. Fatal errors kill the worker and exit
    /// through the broker's handler; RPC telemetry already records the original failure.
    #[tracing::instrument(skip_all, fields(dependency = "biometric_worker", pid = self.pid))]
    pub fn compare(&mut self, request: CompareRequest) -> Result<ComparisonScores, WorkerError> {
        let result = self.rpc.compare(request);
        if let Some(error) = self.rpc.failure().cloned() {
            self.kill();
            (self.on_fatal)(error);
        }

        result.map_err(WorkerError::Rpc)
    }

    /// Requests namespace termination without waiting; guest teardown owns final cleanup.
    fn kill(&self) {
        // SAFETY: This owner never reaps pid. SIGKILL terminates namespace PID 1 and its
        // descendants; a failed signal must not prevent the broker's fatal exit.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                metrics::counter!("worker_process.kill_failures").increment(1);
                tracing::error!(dependency = "biometric_worker", pid = self.pid, %error, "worker kill failed");
            }
        }
    }
}

impl Drop for Worker {
    /// Requests termination on normal broker shutdown or unwinding, without reaping.
    fn drop(&mut self) {
        self.kill();
    }
}

/// Launch or recoverable comparison failure. Fatal comparisons invoke the broker's exit handler.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// Invalid trusted root or resource configuration, rejected before forking.
    #[error("invalid worker sandbox: {0}")]
    InvalidSandbox(&'static str),
    /// Required whole-process seccomp termination is unavailable or blocked.
    #[error("worker requires kernel support for seccomp KILL_PROCESS: {0}")]
    UnsupportedKernel(#[source] io::Error),
    /// Socket, runtime root or policy storage failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Minijail could not launch or configure the worker.
    #[error(transparent)]
    Jail(#[from] minijail::Error),
    /// Client setup or local input/analysis failure; comparison failures here are recoverable.
    #[error(transparent)]
    Rpc(#[from] WorkerClientError),
}
