use std::{
    error::Error,
    io,
    os::unix::net::UnixStream,
    panic::{AssertUnwindSafe, catch_unwind},
    time::{Duration, Instant},
};

use flamingo_verifier_worker_protocol::{
    CompareRequest, MAX_RESPONSE_BYTES, WorkerProtocolError, WorkerResult, decode_message,
    encode_message,
};

use crate::transport;

/// Worker-enforced limits, independent of the broker's configuration.
#[derive(Debug, Clone, Copy)]
pub struct WorkerServerConfig {
    /// Maximum encoded request body, excluding its length prefix.
    pub max_request_bytes: usize,
    /// Maximum bytes per nonempty encoded image; decoded-pixel limits belong to the model.
    pub max_image_bytes: usize,
    /// First request budget including lazy model initialization, starting at its first byte.
    pub first_request_timeout: Duration,
    /// Subsequent request budget, starting at its first byte.
    pub request_timeout: Duration,
}

/// Reads, computes and replies sequentially. The callback may initialize its model lazily.
/// Infrastructure errors and panics terminate the connection; the worker entry point must exit.
/// A stuck callback cannot be interrupted here: the broker's supervisor must kill the process.
pub fn serve_worker<F>(
    mut stream: UnixStream,
    config: WorkerServerConfig,
    mut comparator: F,
) -> Result<(), WorkerServerError>
where
    F: FnMut(CompareRequest) -> Result<WorkerResult, Box<dyn Error + Send + Sync>>,
{
    if !transport::valid_limits(config.max_request_bytes, config.max_image_bytes)
        || !transport::valid_timeout(config.first_request_timeout)
        || !transport::valid_timeout(config.request_timeout)
        || config.first_request_timeout < config.request_timeout
    {
        return Err(WorkerServerError::InvalidConfig);
    }
    stream.set_nonblocking(false)?;

    let result = run(&mut stream, config, &mut comparator);
    if let Err(error) = &result {
        metrics::counter!("worker_rpc.server_failures", "class" => error.failure_class())
            .increment(1);
        tracing::warn!(
            dependency = "biometric_model",
            failure_class = error.failure_class(),
            "worker server stopped"
        );
    }
    result
}

/// Keeps exactly one decoded request and computation alive at a time.
fn run<F>(
    stream: &mut UnixStream,
    config: WorkerServerConfig,
    comparator: &mut F,
) -> Result<(), WorkerServerError>
where
    F: FnMut(CompareRequest) -> Result<WorkerResult, Box<dyn Error + Send + Sync>>,
{
    let mut timeout = config.first_request_timeout;
    while let Some((payload, deadline)) =
        transport::read_request(stream, config.max_request_bytes, timeout)?
    {
        timeout = config.request_timeout;
        let request: CompareRequest = decode_message(&payload, config.max_request_bytes)?;
        drop(payload);
        if !request.valid_image_sizes(config.max_image_bytes) {
            return Err(WorkerServerError::InvalidImages);
        }
        transport::remaining(deadline)?;

        let span = tracing::info_span!("worker.infer", dependency = "biometric_model");
        let _entered = span.enter();
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| comparator(request)));
        metrics::histogram!("worker_rpc.inference_seconds").record(started.elapsed().as_secs_f64());
        let response = result
            .map_err(|_| WorkerServerError::ModelPanic)?
            .map_err(WorkerServerError::Model)?;
        transport::remaining(deadline)?;

        let payload = encode_message(&response, MAX_RESPONSE_BYTES)?;
        transport::write_frame(stream, &payload, deadline)?;
    }
    Ok(())
}

/// Terminal worker failures; ordinary image analysis failures use `WorkerResult::AnalysisFailed`.
#[derive(Debug, thiserror::Error)]
pub enum WorkerServerError {
    /// Invalid body or timeout limits.
    #[error("invalid worker server configuration")]
    InvalidConfig,
    /// Socket, framing or whole-request deadline failure.
    #[error("worker socket I/O failed: {0}")]
    Transport(#[from] io::Error),
    /// Malformed request or response serialization failure.
    #[error("worker CBOR failed: {0}")]
    Protocol(#[from] WorkerProtocolError),
    /// An encoded image was empty or too large.
    #[error("worker images violate byte limits")]
    InvalidImages,
    /// The callback reported an infrastructure or initialization failure.
    #[error("worker model failed: {0}")]
    Model(#[source] Box<dyn Error + Send + Sync>),
    /// The callback panicked; its potentially sensitive panic payload is not retained.
    #[error("worker model panicked")]
    ModelPanic,
}

impl WorkerServerError {
    /// Stable, low-cardinality telemetry label.
    #[must_use]
    pub fn failure_class(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::Transport(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                "request_timeout"
            }
            Self::Transport(_) => "transport",
            Self::Protocol(_) | Self::InvalidImages => "invalid_input",
            Self::Model(_) => "model",
            Self::ModelPanic => "model_panic",
        }
    }
}
