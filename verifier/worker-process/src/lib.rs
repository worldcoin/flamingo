//! Blocking worker process ownership; no sandbox or production launch path yet.

mod launch;
mod supervisor;

use std::{
    ffi::OsStr,
    io,
    os::unix::net::UnixStream,
    path::Path,
    process::ExitStatus,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores};
use flamingo_verifier_worker_rpc::{WorkerClient, WorkerClientConfig, WorkerClientError};

/// Limits for one boot-scoped worker; no handshake or automatic restart.
#[derive(Debug, Clone)]
pub struct WorkerProcessConfig {
    /// The first comparison includes lazy model initialization.
    pub rpc: WorkerClientConfig,
    /// Grace period after closing IPC, before sending SIGKILL.
    pub shutdown_timeout: Duration,
    /// Deadline for observing/reaping the killed child.
    pub reap_timeout: Duration,
}

impl WorkerProcessConfig {
    /// Checks limits before acquiring descriptors or launching a child.
    fn validate(&self) -> Result<(), WorkerProcessError> {
        self.rpc.validate()?;
        for timeout in [self.shutdown_timeout, self.reap_timeout] {
            if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
                return Err(WorkerProcessError::InvalidConfig);
            }
        }

        Ok(())
    }
}

/// Sole process and comparison owner. Drop requests cleanup on an independent thread.
#[derive(Debug)]
pub struct WorkerProcess {
    /// Child PID for diagnostics; only the supervisor signals and reaps it.
    pid: u32,
    /// Exclusive blocking connection; never exposed for cloning or concurrent requests.
    client: WorkerClient,
    /// Shutdown request and its optional initiating failure.
    control: mpsc::Sender<Option<WorkerProcessError>>,
    /// Supervisor result, published before any background reaping after a deadline error.
    completion: mpsc::Receiver<Result<ExitStatus, WorkerProcessError>>,
    /// Cached result so polling and waiting preserve the original failure.
    result: Option<Result<ExitStatus, WorkerProcessError>>,
}

impl WorkerProcess {
    /// Launches an absolute executable with FD 3, empty environment and null stdio.
    /// Call before serving threads or broker-key creation. Success means launched, not model-ready.
    pub fn spawn(
        program: &Path,
        args: &[impl AsRef<OsStr>],
        config: WorkerProcessConfig,
    ) -> Result<Self, WorkerProcessError> {
        config.validate()?;
        if !program.is_absolute() {
            return Err(WorkerProcessError::InvalidConfig);
        }

        let (stream, worker) =
            UnixStream::pair().map_err(|e| WorkerProcessError::io("create IPC socket", e))?;
        let shutdown_socket = stream
            .try_clone()
            .map_err(|e| WorkerProcessError::io("clone IPC socket", e))?;
        let client = WorkerClient::new(stream, config.rpc.clone())?;
        let child = launch::spawn(program, args, worker)?;
        let pid = child.id();
        let (control, receiver) = mpsc::channel();
        let (completed, completion) = mpsc::channel();

        supervisor::start(child, shutdown_socket, receiver, completed, config)?;

        Ok(Self {
            pid,
            client,
            control,
            completion,
            result: None,
        })
    }

    /// PID for diagnostics only; signaling and reaping belong to the supervisor.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.pid
    }

    /// Completes one comparison, including lazy initialization on the first request.
    /// Fatal errors also await bounded process cleanup; ordinary analysis failures do not stop it.
    /// Async callers must use bounded blocking admission and retain ownership through completion.
    #[tracing::instrument(skip_all, fields(dependency = "biometric_worker", pid = self.pid))]
    pub fn compare(
        &mut self,
        request: CompareRequest,
    ) -> Result<ComparisonScores, WorkerProcessError> {
        if let Some(status) = self.try_wait()? {
            return Err(WorkerProcessError::Exited(status));
        }

        let result = self.client.compare(request);
        if let Some(error) = self.client.failure().cloned() {
            self.stop(Some(error.clone().into()));
            return Err(self.wait().err().unwrap_or_else(|| error.into()));
        }

        result.map_err(WorkerProcessError::Rpc)
    }

    /// Observes child termination without waiting; a running child is not proof of model readiness.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WorkerProcessError> {
        if self.result.is_none() {
            self.result = match self.completion.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err(WorkerProcessError::SupervisorStopped))
                }
            };
        }

        self.result.clone().transpose()
    }

    /// Waits for termination and cleanup without initiating shutdown; an idle healthy child keeps waiting.
    pub fn wait(&mut self) -> Result<ExitStatus, WorkerProcessError> {
        if self.result.is_none() {
            self.result = Some(
                self.completion
                    .recv()
                    .unwrap_or(Err(WorkerProcessError::SupervisorStopped)),
            );
        }

        self.result.clone().expect("completion result was recorded")
    }

    /// Closes IPC, waits a bounded grace period, then kills and reaps if necessary.
    /// Forced termination remains an error even after successful reaping.
    pub fn shutdown(mut self) -> Result<ExitStatus, WorkerProcessError> {
        self.stop(None);
        self.wait()
    }

    /// A disconnected control receiver means the supervisor has already stopped.
    fn stop(&self, cause: Option<WorkerProcessError>) {
        let _ = self.control.send(cause);
    }
}

impl Drop for WorkerProcess {
    /// Starts independent cleanup without blocking the dropping thread.
    fn drop(&mut self) {
        self.stop(None);
    }
}

/// Local lifecycle failures; never includes worker stdout/stderr or request images.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WorkerProcessError {
    /// Invalid limits or a non-absolute executable path.
    #[error("invalid worker process configuration or executable path")]
    InvalidConfig,
    /// Local launch, supervision or cleanup operation failed.
    #[error("could not {operation}: {source}")]
    Io {
        /// Attempted lifecycle operation.
        operation: &'static str,
        /// Underlying operating system error.
        #[source]
        source: Arc<io::Error>,
    },
    /// Comparison or connection failure.
    #[error(transparent)]
    Rpc(#[from] WorkerClientError),
    /// Unexpected process exit, including nonzero status during shutdown.
    #[error("worker exited unexpectedly: {0}")]
    Exited(ExitStatus),
    /// Shutdown exceeded its grace period, but the child was reaped.
    #[error("worker exceeded its shutdown deadline; final status: {status}; cause: {cause:?}")]
    ForcedTermination {
        /// Observed exit status after the grace period elapsed.
        status: ExitStatus,
        /// Failure that initiated shutdown or occurred during cleanup, if any.
        cause: Option<Box<Self>>,
    },
    /// The child was not reaped within the cleanup deadline.
    #[error(
        "worker {pid} was not reaped by the deadline (background reaper: {background_reaper}); cause: {cause:?}"
    )]
    ReapTimeout {
        /// Child whose reap deadline elapsed.
        pid: u32,
        /// Whether the supervisor retains the child for background reaping.
        background_reaper: bool,
        /// Failure that initiated shutdown or occurred during cleanup, if any.
        cause: Option<Box<Self>>,
    },
    /// Cleanup failed while handling an earlier result.
    #[error("worker cleanup failed: {cleanup}; original cause: {cause:?}")]
    Cleanup {
        /// Additional failure encountered during cleanup.
        cleanup: Box<Self>,
        /// Original failure, if any.
        cause: Option<Box<Self>>,
    },
    /// The supervisor disappeared without completing its lifecycle protocol.
    #[error("worker supervisor stopped unexpectedly")]
    SupervisorStopped,
}

impl WorkerProcessError {
    /// Adds the failed local operation without capturing worker output.
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            source: Arc::new(source),
        }
    }
}
