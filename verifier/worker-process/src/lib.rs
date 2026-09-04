//! Worker process ownership only; no sandbox or production launch path yet.

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

use flamingo_verifier_worker_rpc::{
    WorkerClient, WorkerClientConfig, WorkerClientError, WorkerSession,
};
use tokio::sync::{oneshot, watch};

use supervisor::Control;

/// Limits for one boot-scoped worker; no automatic restart.
#[derive(Debug, Clone, Copy)]
pub struct WorkerProcessConfig {
    /// The handshake budget starts at launch, not at `connect`.
    pub rpc: WorkerClientConfig,
    /// Grace period after closing IPC, before sending SIGKILL.
    pub shutdown_timeout: Duration,
    /// Deadline for observing/reaping the killed child.
    pub reap_timeout: Duration,
}

impl WorkerProcessConfig {
    fn validate(self) -> Result<(), WorkerProcessError> {
        self.rpc.validate()?;
        for timeout in [
            self.rpc.handshake_timeout,
            self.shutdown_timeout,
            self.reap_timeout,
        ] {
            if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
                return Err(WorkerProcessError::InvalidConfig);
            }
        }

        Ok(())
    }
}

/// Sole process owner. Drop initiates cleanup independently of the Tokio runtime.
#[derive(Debug)]
pub struct WorkerProcess {
    /// Child PID for diagnostics; the supervisor owns signaling and reaping.
    pid: u32,
    /// RPC and process lifecycle limits.
    config: WorkerProcessConfig,
    /// Startup budget origin, recorded before launch.
    started: Instant,
    /// Broker socket consumed when connecting RPC to the Tokio runtime.
    stream: Option<UnixStream>,
    /// Lifecycle commands to the independent process supervisor thread.
    control: mpsc::Sender<Control>,
    /// Terminal supervision result; a reap timeout may leave background cleanup running.
    completion: watch::Receiver<Option<Result<ExitStatus, WorkerProcessError>>>,
    /// RPC lifecycle owner, present after connection succeeds.
    session: Option<WorkerSession>,
}

impl WorkerProcess {
    /// Launches an absolute executable with FD 3, empty environment and null stdio.
    /// Call during bootstrap, before starting serving threads or generating broker keys.
    /// The OS spawn itself is synchronous; its elapsed time counts against startup.
    ///
    /// # Errors
    /// Rejects invalid configuration, relative paths, descriptor setup and launch failures.
    pub fn spawn(
        program: &Path,
        args: &[impl AsRef<OsStr>],
        config: WorkerProcessConfig,
    ) -> Result<Self, WorkerProcessError> {
        config.validate()?;
        if !program.is_absolute() {
            return Err(WorkerProcessError::InvalidConfig);
        }

        let started = Instant::now();
        let (stream, worker) =
            UnixStream::pair().map_err(|e| WorkerProcessError::io("create IPC socket", e))?;
        stream
            .set_nonblocking(true)
            .map_err(|e| WorkerProcessError::io("set IPC nonblocking", e))?;
        let shutdown_socket = stream
            .try_clone()
            .map_err(|e| WorkerProcessError::io("clone IPC socket", e))?;
        let child = launch::spawn(program, args, worker)?;
        let pid = child.id();
        let (control, receiver) = mpsc::channel();
        let (completed, completion) = watch::channel(None);

        supervisor::start(child, shutdown_socket, receiver, completed, config, started)?;

        Ok(Self {
            pid,
            config,
            started,
            stream: Some(stream),
            control,
            completion,
            session: None,
        })
    }

    /// PID for diagnostics only; signaling and reaping belong to this owner.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.pid
    }

    /// Attaches RPC after a Tokio runtime has started. Cancellation still cleans up the child.
    ///
    /// # Errors
    /// Reports startup, transport and process failures, including incomplete cleanup.
    pub async fn connect(mut self) -> Result<(Self, WorkerClient), WorkerProcessError> {
        let stream = self
            .stream
            .take()
            .ok_or(WorkerProcessError::AlreadyConnected)?;
        let mut config = self.config.rpc;
        let startup = async {
            config.handshake_timeout = self
                .config
                .rpc
                .handshake_timeout
                .checked_sub(self.started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(WorkerClientError::HandshakeTimeout)?;
            let stream = tokio::net::UnixStream::from_std(stream)
                .map_err(|e| WorkerProcessError::io("register IPC socket", e))?;

            WorkerSession::connect(stream, config)
                .await
                .map_err(WorkerProcessError::Rpc)
        };
        let result = tokio::select! {
            result = startup => result,
            result = self.wait() => return Err(result.err().unwrap_or(WorkerProcessError::SupervisorStopped)),
        };

        let (session, client) = match result {
            Ok(connected) => connected,
            Err(error) => {
                self.stop(Some(error.clone()));
                return Err(self.wait().await.err().unwrap_or(error));
            }
        };
        self.session = Some(session);
        let (acknowledge, acknowledged) = oneshot::channel();
        let sent = self
            .control
            .send(Control::Ready(client.clone(), acknowledge))
            .is_ok();
        let accepted = sent
            && tokio::select! {
                result = acknowledged => result.is_ok(),
                result = self.wait() => return Err(result.err().unwrap_or(WorkerProcessError::SupervisorStopped)),
            };
        if !accepted {
            return Err(self
                .wait()
                .await
                .err()
                .unwrap_or(WorkerProcessError::SupervisorStopped));
        }

        metrics::histogram!("worker_process.startup_seconds")
            .record(self.started.elapsed().as_secs_f64());
        Ok((self, client))
    }

    /// Waits for termination and cleanup without initiating shutdown.
    ///
    /// # Errors
    /// Preserves fatal RPC errors, exit status, forced termination and cleanup failures.
    pub async fn wait(&self) -> Result<ExitStatus, WorkerProcessError> {
        let mut completion = self.completion.clone();
        loop {
            if let Some(result) = completion.borrow().clone() {
                return result;
            }
            completion
                .changed()
                .await
                .map_err(|_| WorkerProcessError::SupervisorStopped)?;
        }
    }

    /// Closes RPC, drains for a bounded time, then kills/reaps if necessary.
    ///
    /// # Errors
    /// Forced termination is an error even if SIGKILL successfully stopped the worker.
    pub async fn shutdown(mut self) -> Result<ExitStatus, WorkerProcessError> {
        if let Some(session) = &mut self.session {
            session.close();
        }
        self.stop(None);
        let result = self.wait().await;

        if let Some(session) = self.session.take() {
            let rpc = tokio::time::timeout(self.config.reap_timeout, session.shutdown())
                .await
                .map_err(|_| {
                    WorkerProcessError::io(
                        "join RPC supervisor",
                        io::Error::new(io::ErrorKind::TimedOut, "RPC shutdown deadline exceeded"),
                    )
                })
                .and_then(|result| result.map_err(WorkerProcessError::Rpc));
            if let Err(error) = rpc {
                if result.is_ok() {
                    return Err(error);
                }
                // Preserve independent cleanup failures; ordinary RPC failures are already the cause.
                if matches!(
                    &error,
                    WorkerProcessError::Io { .. }
                        | WorkerProcessError::Rpc(WorkerClientError::Task(_))
                ) {
                    return Err(WorkerProcessError::Cleanup {
                        cleanup: Box::new(error),
                        cause: result.err().map(Box::new),
                    });
                }
            }
        }

        result
    }

    fn stop(&self, cause: Option<WorkerProcessError>) {
        // A closed receiver means cleanup already finished.
        let _ = self.control.send(Control::Stop(cause));
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        if let Some(session) = &mut self.session {
            session.close();
        }
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
    /// RPC startup or session failure.
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
    /// A second RPC connection was attempted for the same process.
    #[error("worker process is already connected")]
    AlreadyConnected,
}

impl WorkerProcessError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            source: Arc::new(source),
        }
    }
}
