use std::{num::NonZeroU16, range::RangeInclusive, sync::Arc, time::Duration};

use flamingo_verifier_worker_protocol::{
    COMPARE_PATH, CompareRequest, ComparisonScores, READY_PATH, WORKER_PROTOCOL_VERSION,
    WorkerProtocolError, WorkerReady, encode_message,
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::UnixStream,
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tracing::Instrument;

use crate::{http, session};

/// Broker-side admission, payload and deadline limits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkerClientConfig {
    /// Includes queued requests and cancelled callers whose work is still running.
    pub max_in_flight: NonZeroU16,
    /// Covers HTTP/2 setup and the startup capability response.
    pub handshake_timeout: Duration,
    /// From admission through the complete response; also bounds idle ping checks.
    pub request_timeout: Duration,
    /// Maximum encoded request body.
    pub max_request_bytes: usize,
    /// Maximum bytes in each nonempty encoded image.
    pub max_image_bytes: usize,
    /// Model-specific inclusive score domain.
    pub score_range: RangeInclusive<f32>,
}

impl WorkerClientConfig {
    fn validate(self) -> Result<(), WorkerClientError> {
        if !http::valid_limits(self.max_request_bytes, self.max_image_bytes)
            || !http::valid_timeout(self.handshake_timeout)
            || !http::valid_timeout(self.request_timeout)
            || !self.score_range.start.is_finite()
            || !self.score_range.last.is_finite()
            || self.score_range.start > self.score_range.last
        {
            return Err(WorkerClientError::InvalidConfig);
        }

        Ok(())
    }
}

/// Sole lifecycle owner. Dropping it closes the session even if request clients remain.
#[derive(Debug)]
pub struct WorkerSession {
    stop: Option<oneshot::Sender<WorkerClientError>>,
    task: Option<JoinHandle<Result<(), WorkerClientError>>>,
}

impl WorkerSession {
    /// Connects an already-open socket. The worker must have initialized its model first.
    ///
    /// # Errors
    /// Rejects invalid configuration, startup failures and incompatible capabilities.
    pub async fn connect(
        stream: UnixStream,
        config: WorkerClientConfig,
    ) -> Result<(Self, WorkerClient), WorkerClientError> {
        config.validate()?;

        let deadline = Instant::now() + config.handshake_timeout;
        let (sender, connection) = timeout_at(
            deadline,
            http::client_builder(config.max_in_flight.get(), config.request_timeout)
                .handshake(TokioIo::new(stream)),
        )
        .await
        .map_err(|_| WorkerClientError::HandshakeTimeout)?
        .map_err(WorkerClientError::transport)?;

        let (commands, receiver) = mpsc::channel(usize::from(config.max_in_flight.get()));
        let (stop, stopped) = oneshot::channel();
        let (status_sender, status) = watch::channel(None);

        let task = tokio::spawn(
            session::run(
                connection,
                sender.clone(),
                receiver,
                stopped,
                status_sender,
                config.score_range,
            )
            .in_current_span(),
        );
        let mut owner = Self {
            stop: Some(stop),
            task: Some(task),
        };

        let startup = async {
            let ready: WorkerReady =
                http::exchange(sender, http::request(READY_PATH, Vec::new())).await?;

            if ready.protocol_version != WORKER_PROTOCOL_VERSION {
                return Err(WorkerClientError::IncompatibleProtocol);
            }
            if ready.max_in_flight == 0 {
                return Err(WorkerClientError::InvalidCapacity);
            }

            Ok(ready)
        };
        let ready = match timeout_at(deadline, startup)
            .await
            .unwrap_or(Err(WorkerClientError::HandshakeTimeout))
        {
            Ok(ready) => ready,
            Err(error) => {
                owner.signal(error.clone());
                if let Err(WorkerClientError::Task(error)) = owner.join().await {
                    return Err(WorkerClientError::Task(error));
                }
                return Err(error);
            }
        };

        let limit = usize::from(config.max_in_flight.get().min(ready.max_in_flight));
        Ok((
            owner,
            WorkerClient {
                config,
                capacity: Arc::new(Semaphore::new(limit)),
                commands,
                status,
            },
        ))
    }

    fn signal(&mut self, error: WorkerClientError) {
        if let Some(stop) = self.stop.take() {
            // A closed receiver means the supervisor already terminated.
            let _ = stop.send(error);
        }
    }

    async fn join(&mut self) -> Result<(), WorkerClientError> {
        self.task
            .take()
            .expect("session is joined once")
            .await
            .map_err(|error| WorkerClientError::Task(Arc::new(error)))?
    }

    /// Closes all clients and awaits the connection supervisor.
    ///
    /// # Errors
    /// Preserves an earlier terminal failure or a supervisor panic.
    pub async fn shutdown(mut self) -> Result<(), WorkerClientError> {
        self.signal(WorkerClientError::Closed);
        self.join().await
    }
}

impl Drop for WorkerSession {
    fn drop(&mut self) {
        self.signal(WorkerClientError::Closed);
    }
}

/// Clonable request handle; cannot shut down or reconnect its session.
#[derive(Debug, Clone)]
pub struct WorkerClient {
    config: WorkerClientConfig,
    capacity: Arc<Semaphore>,
    commands: mpsc::Sender<session::Command>,
    status: watch::Receiver<Option<WorkerClientError>>,
}

impl WorkerClient {
    /// Session readiness, not a liveness probe or capacity reservation.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.status.borrow().is_none() && self.status.has_changed().is_ok()
    }

    /// Returns the permanent failure/closure reason; suitable for broker readiness.
    pub async fn wait_unavailable(&self) -> WorkerClientError {
        let mut status = self.status.clone();
        loop {
            if let Some(error) = status.borrow().clone() {
                return error;
            }

            if status.changed().await.is_err() {
                return WorkerClientError::Unavailable;
            }
        }
    }

    fn terminal_error(&self) -> WorkerClientError {
        self.status
            .borrow()
            .clone()
            .unwrap_or(WorkerClientError::Unavailable)
    }

    /// Compares three images with immediate admission rejection and no retries.
    ///
    /// Cancelling the caller does not cancel validation, free its slot or reset its deadline.
    ///
    /// # Errors
    /// Bad local inputs, overload and analysis failure affect only this request.
    /// Timeout, transport failure, invalid scores or unexpected responses are session-fatal.
    #[tracing::instrument(
        name = "worker.compare",
        skip_all,
        fields(dependency = "biometric_worker")
    )]
    pub async fn compare(
        &self,
        request: CompareRequest,
    ) -> Result<ComparisonScores, WorkerClientError> {
        let result = self.submit(request).await;
        if let Err(error) = &result
            && matches!(
                error,
                WorkerClientError::AtCapacity
                    | WorkerClientError::InvalidImages
                    | WorkerClientError::RequestEncoding(_)
            )
        {
            metrics::counter!("worker_rpc.rejections", "class" => error.failure_class())
                .increment(1);
        }

        result
    }

    async fn submit(&self, request: CompareRequest) -> Result<ComparisonScores, WorkerClientError> {
        if !self.is_available() {
            return Err(self.terminal_error());
        }
        if !request.valid_image_sizes(self.config.max_image_bytes) {
            return Err(WorkerClientError::InvalidImages);
        }

        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| WorkerClientError::AtCapacity)?;
        let admitted_at = Instant::now();
        let deadline = admitted_at + self.config.request_timeout;
        let payload = encode_message(&request, self.config.max_request_bytes)
            .map_err(WorkerClientError::RequestEncoding)?;

        let (reply, response) = oneshot::channel();
        self.commands
            .try_send(session::Command {
                request: http::request(COMPARE_PATH, payload),
                deadline,
                admitted_at,
                reply,
                _permit: permit,
                span: tracing::Span::current(),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => WorkerClientError::AtCapacity,
                mpsc::error::TrySendError::Closed(_) => self.terminal_error(),
            })?;

        tokio::select! {
            biased;
            error = self.wait_unavailable() => Err(error),
            result = response => result.unwrap_or_else(|_| Err(self.terminal_error())),
        }
    }
}

/// Explicit per-request and terminal errors; no remote error body is logged or trusted.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WorkerClientError {
    /// Request serialization failed before sending.
    #[error("worker request encoding failed: {0}")]
    RequestEncoding(#[source] WorkerProtocolError),
    /// Invalid CBOR response.
    #[error("worker response decoding failed: {0}")]
    Protocol(#[source] WorkerProtocolError),
    /// Connection/stream failure.
    #[error("worker HTTP/2 transport failed: {0}")]
    Transport(#[source] Arc<hyper::Error>),
    /// Oversized, interrupted or otherwise unreadable response.
    #[error("worker response body failed: {0}")]
    ResponseBody(#[source] Arc<dyn std::error::Error + Send + Sync>),
    /// Unexpected HTTP status, including every 5xx.
    #[error("worker returned HTTP {0}")]
    HttpStatus(hyper::StatusCode),
    /// Successful responses must contain CBOR.
    #[error("worker returned an unexpected content type")]
    UnexpectedContentType,
    /// Invalid limits, deadlines or score domain.
    #[error("invalid worker client configuration")]
    InvalidConfig,
    /// Empty or oversized encoded image.
    #[error("worker images violate byte limits")]
    InvalidImages,
    /// Startup exceeded its total deadline.
    #[error("worker startup timed out")]
    HandshakeTimeout,
    /// Unsupported protocol.
    #[error("incompatible worker protocol version")]
    IncompatibleProtocol,
    /// Worker advertised no capacity.
    #[error("worker advertised zero capacity")]
    InvalidCapacity,
    /// Local admission or remote HTTP 429; does not invalidate the session.
    #[error("worker is at capacity")]
    AtCapacity,
    /// An admitted comparison exceeded its original deadline.
    #[error("worker comparison timed out")]
    RequestTimeout,
    /// Unexpected supervisor disappearance.
    #[error("worker session is unavailable")]
    Unavailable,
    /// The lifecycle owner shut down or was dropped.
    #[error("worker session was closed")]
    Closed,
    /// Out-of-domain or nonfinite score.
    #[error("worker returned an invalid similarity score")]
    InvalidScore,
    /// Ordinary per-request analysis failure.
    #[error("worker could not analyze the supplied images")]
    AnalysisFailed,
    /// Supervisor/request task failed.
    #[error("worker task failed: {0}")]
    Task(#[source] Arc<tokio::task::JoinError>),
}

impl WorkerClientError {
    /// Stable, low-cardinality telemetry label; never includes images or remote bodies.
    #[must_use]
    pub const fn failure_class(&self) -> &'static str {
        match self {
            Self::RequestEncoding(_) | Self::InvalidImages => "invalid_input",
            Self::InvalidConfig => "invalid_config",
            Self::Protocol(_) | Self::UnexpectedContentType => "invalid_response",
            Self::Transport(_) | Self::ResponseBody(_) => "transport",
            Self::HttpStatus(_) => "http_status",
            Self::HandshakeTimeout => "startup_timeout",
            Self::RequestTimeout => "request_timeout",
            Self::IncompatibleProtocol | Self::InvalidCapacity => "incompatible_worker",
            Self::AtCapacity => "at_capacity",
            Self::Unavailable => "unavailable",
            Self::Closed => "closed",
            Self::InvalidScore => "invalid_score",
            Self::AnalysisFailed => "analysis_failed",
            Self::Task(_) => "task_failure",
        }
    }

    pub(crate) fn transport(error: hyper::Error) -> Self {
        Self::Transport(Arc::new(error))
    }
}
