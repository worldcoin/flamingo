use std::{
    io,
    ops::RangeInclusive,
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};

use flamingo_verifier_worker_protocol::{
    CompareRequest, ComparisonScores, MAX_RESPONSE_BYTES, WorkerProtocolError, WorkerResult,
    decode_message, encode_message,
};

use crate::transport;

/// Broker-enforced byte, score and whole-comparison limits.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkerClientConfig {
    /// Total budget for the first transmitted comparison, including lazy model initialization.
    pub first_request_timeout: Duration,
    /// Total budget for each subsequent comparison.
    pub request_timeout: Duration,
    /// Maximum encoded request body, excluding its four-byte length.
    pub max_request_bytes: usize,
    /// Maximum bytes per nonempty encoded image.
    pub max_image_bytes: usize,
    /// Inclusive model-specific score domain.
    pub score_range: RangeInclusive<f32>,
}

impl WorkerClientConfig {
    /// Rejects unusable limits before opening or launching a worker.
    pub fn validate(&self) -> Result<(), WorkerClientError> {
        if !transport::valid_limits(self.max_request_bytes, self.max_image_bytes)
            || !transport::valid_timeout(self.first_request_timeout)
            || !transport::valid_timeout(self.request_timeout)
            || self.first_request_timeout < self.request_timeout
            || !self.score_range.start().is_finite()
            || !self.score_range.end().is_finite()
            || self.score_range.start() > self.score_range.end()
        {
            return Err(WorkerClientError::InvalidConfig);
        }

        Ok(())
    }
}

/// Exclusive, blocking request owner. Drop closes its socket; no cloning or pipelining.
#[derive(Debug)]
pub struct WorkerClient {
    /// Removed after a fatal error so the byte stream can never be reused.
    stream: Option<UnixStream>,
    /// Broker-side input and response validation limits.
    config: WorkerClientConfig,
    /// Whether the next transmitted comparison includes the initialization budget.
    first_request: bool,
    /// First terminal error; local input and analysis failures do not populate it.
    failure: Option<WorkerClientError>,
}

impl WorkerClient {
    /// Takes a connected socket without reading, writing or verifying model readiness.
    pub fn new(stream: UnixStream, config: WorkerClientConfig) -> Result<Self, WorkerClientError> {
        config.validate()?;
        stream
            .set_nonblocking(false)
            .map_err(WorkerClientError::transport)?;

        Ok(Self {
            stream: Some(stream),
            config,
            first_request: true,
            failure: None,
        })
    }

    /// Last observed terminal failure, not a model-readiness or liveness probe.
    #[must_use]
    pub fn failure(&self) -> Option<&WorkerClientError> {
        self.failure.as_ref()
    }

    /// Sends one comparison and validates its complete reply before accepting another.
    /// The first transmitted request includes model initialization. Fatal errors close the socket.
    /// Do not call on an async executor thread; cancelling an async wrapper cannot stop this call.
    #[tracing::instrument(
        name = "worker.compare",
        skip_all,
        fields(dependency = "biometric_worker", first_request = self.first_request)
    )]
    pub fn compare(
        &mut self,
        request: CompareRequest,
    ) -> Result<ComparisonScores, WorkerClientError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }

        let started = Instant::now();
        let timeout = if self.first_request {
            self.config.first_request_timeout
        } else {
            self.config.request_timeout
        };
        let deadline = started + timeout;
        if !request.valid_image_sizes(self.config.max_image_bytes) {
            metrics::counter!("worker_rpc.rejections", "class" => "invalid_input").increment(1);
            return Err(WorkerClientError::InvalidImages);
        }
        let payload = encode_message(&request, self.config.max_request_bytes).map_err(|error| {
            metrics::counter!("worker_rpc.rejections", "class" => "invalid_input").increment(1);
            WorkerClientError::RequestEncoding(error)
        })?;
        drop(request);

        let first_request = self.first_request;
        self.first_request = false;
        let result = self.exchange(&payload, deadline);
        if first_request {
            metrics::histogram!("worker_rpc.first_comparison_seconds")
                .record(started.elapsed().as_secs_f64());
        }
        metrics::histogram!("worker_rpc.comparison_seconds")
            .record(started.elapsed().as_secs_f64());
        metrics::counter!("worker_rpc.comparisons", "result" => result.as_ref().err().map_or("success", WorkerClientError::failure_class)).increment(1);

        if let Err(error) = &result
            && !matches!(error, WorkerClientError::AnalysisFailed)
        {
            self.failure = Some(error.clone());
            self.stream.take();
            tracing::warn!(dependency = "biometric_worker", failure_class = error.failure_class(), %error, "worker connection failed");
        }

        result
    }

    /// Uses one absolute deadline across encoding, partial I/O and response validation.
    fn exchange(
        &mut self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<ComparisonScores, WorkerClientError> {
        let stream = self
            .stream
            .as_mut()
            .expect("failed clients return before exchange");
        transport::write_frame(stream, payload, deadline).map_err(WorkerClientError::transport)?;
        let payload = transport::read_frame(stream, MAX_RESPONSE_BYTES, deadline)
            .map_err(WorkerClientError::transport)?;
        let response = decode_message::<WorkerResult>(&payload, MAX_RESPONSE_BYTES)
            .map_err(WorkerClientError::Protocol)?;
        transport::remaining(deadline).map_err(WorkerClientError::transport)?;

        match response {
            WorkerResult::AnalysisFailed => Err(WorkerClientError::AnalysisFailed),
            WorkerResult::Compared(scores)
                if self.config.score_range.contains(&scores.live_similarity)
                    && self
                        .config
                        .score_range
                        .contains(&scores.challenge_similarity) =>
            {
                Ok(scores)
            }
            WorkerResult::Compared(_) => Err(WorkerClientError::InvalidScore),
        }
    }
}

/// Local validation failures or permanent connection failures; never contains response bytes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WorkerClientError {
    /// Serialization failed before touching the socket.
    #[error("worker request encoding failed: {0}")]
    RequestEncoding(#[source] WorkerProtocolError),
    /// The reply was not a valid bounded CBOR result.
    #[error("worker response decoding failed: {0}")]
    Protocol(#[source] WorkerProtocolError),
    /// Socket or length-frame failure.
    #[error("worker socket I/O failed: {0}")]
    Transport(#[source] Arc<io::Error>),
    /// Invalid limits, deadlines or score domain.
    #[error("invalid worker client configuration")]
    InvalidConfig,
    /// Empty or oversized encoded image.
    #[error("worker images violate byte limits")]
    InvalidImages,
    /// The whole comparison exceeded its deadline.
    #[error("worker comparison timed out")]
    RequestTimeout,
    /// A score was nonfinite or outside the configured domain.
    #[error("worker returned an invalid similarity score")]
    InvalidScore,
    /// Ordinary per-request image analysis failure; the connection remains usable.
    #[error("worker could not analyze the supplied images")]
    AnalysisFailed,
}

impl WorkerClientError {
    /// Stable, low-cardinality metric label.
    #[must_use]
    pub const fn failure_class(&self) -> &'static str {
        match self {
            Self::RequestEncoding(_) | Self::InvalidImages => "invalid_input",
            Self::InvalidConfig => "invalid_config",
            Self::Protocol(_) => "invalid_response",
            Self::Transport(_) => "transport",
            Self::RequestTimeout => "request_timeout",
            Self::InvalidScore => "invalid_score",
            Self::AnalysisFailed => "analysis_failed",
        }
    }

    /// Normalizes OS-specific socket timeout errors.
    fn transport(error: io::Error) -> Self {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::RequestTimeout
        } else {
            Self::Transport(Arc::new(error))
        }
    }
}
