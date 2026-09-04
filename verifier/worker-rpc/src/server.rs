use std::{error::Error, num::NonZeroU16, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use flamingo_verifier_worker_protocol::{
    COMPARE_PATH, CONTENT_TYPE, CompareRequest, MAX_RESPONSE_BYTES, READY_PATH,
    WORKER_PROTOCOL_VERSION, WorkerReady, WorkerResult, decode_message, encode_message,
};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use tokio::{
    net::UnixStream,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tracing::Instrument;

use crate::http;

/// Worker-side resource limits, independent of what the broker advertises.
#[derive(Debug, Clone, Copy)]
pub struct WorkerServerConfig {
    /// Simultaneous body reads, queued jobs and actual model computations combined.
    pub max_in_flight: NonZeroU16,
    /// Maximum encoded comparison body.
    pub max_request_bytes: usize,
    /// Maximum bytes per nonempty encoded image; decoded-pixel limits are adapter-owned.
    pub max_image_bytes: usize,
    /// Total time for body read, queueing and computation.
    pub request_timeout: Duration,
    /// How long to wait for running inference after the connection closes.
    pub shutdown_timeout: Duration,
}

/// Handler state shared by requests on one worker connection.
struct ServerState {
    /// Worker-enforced limits, independent of the broker's configuration.
    config: WorkerServerConfig,
    /// Admission slots spanning body reads, queued jobs and running inference.
    capacity: Arc<Semaphore>,
    /// Bounded queue to the supervised inference dispatcher.
    work: mpsc::Sender<Work>,
}

/// Validated comparison queued for supervised inference.
struct Work {
    /// Decoded request with encoded-image byte limits already checked.
    request: CompareRequest,
    /// Absolute deadline covering body reading, queueing and inference.
    deadline: Instant,
    /// Result channel to the HTTP handler, which may have been cancelled.
    reply: oneshot::Sender<WorkerResult>,
    /// Admission slot moved into inference so HTTP cancellation cannot release it early.
    permit: OwnedSemaphorePermit,
    /// Originating handler's tracing context.
    span: tracing::Span,
}

/// Serves one connected socket with an already-initialized synchronous comparator.
///
/// The callback returns `AnalysisFailed` for ordinary input failures and `Err` for
/// infrastructure/model faults. It must bound decoded image sizes and keep embeddings private.
/// Inference runs on the blocking pool; its permit survives HTTP cancellation.
///
/// Await this future to observe cleanup. A shutdown timeout requires the process supervisor
/// to kill the worker: Rust cannot forcibly stop an already-running blocking computation.
///
/// # Errors
/// Reports invalid limits, connection errors, model faults/panics, deadlines and incomplete cleanup.
pub async fn serve_worker<F>(
    stream: UnixStream,
    config: WorkerServerConfig,
    comparator: F,
) -> Result<(), WorkerServerError>
where
    F: Fn(CompareRequest) -> Result<WorkerResult, Box<dyn Error + Send + Sync>>
        + Send
        + Sync
        + 'static,
{
    if !http::valid_limits(config.max_request_bytes, config.max_image_bytes)
        || !http::valid_timeout(config.request_timeout)
        || !http::valid_timeout(config.shutdown_timeout)
    {
        return Err(WorkerServerError::InvalidConfig);
    }

    let capacity = Arc::new(Semaphore::new(usize::from(config.max_in_flight.get())));
    let (work, mut pending) = mpsc::channel(usize::from(config.max_in_flight.get()));
    let state = Arc::new(ServerState {
        config,
        capacity: Arc::clone(&capacity),
        work,
    });
    let router = Router::new()
        .route(READY_PATH, get(ready))
        .route(COMPARE_PATH, post(compare))
        .with_state(state);

    let builder = http::server_builder(config.max_in_flight.get());
    let mut connection =
        Box::pin(builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router)));
    let comparator = Arc::new(comparator);
    let mut tasks = JoinSet::new();

    let result = loop {
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => match result {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(error))) => break Err(error),
                Some(Err(error)) => break Err(WorkerServerError::Task(error)),
                None => unreachable!("nonempty task set"),
            },
            result = &mut connection => break result.map_err(WorkerServerError::Transport),
            Some(work) = pending.recv() => {
                if Instant::now() >= work.deadline {
                    break Err(WorkerServerError::RequestTimeout);
                }

                let comparator = Arc::clone(&comparator);
                let span = work.span.clone();
                tasks.spawn(async move {
                    let computation = tokio::task::spawn_blocking(move || {
                        let _permit = work.permit;
                        let started = std::time::Instant::now();
                        let result = comparator(work.request);
                        metrics::histogram!("worker_rpc.inference_seconds").record(started.elapsed().as_secs_f64());
                        result
                    });

                    let result = timeout_at(work.deadline, computation).await
                        .map_err(|_| WorkerServerError::RequestTimeout)?
                        .map_err(WorkerServerError::Task)?
                        .map_err(WorkerServerError::Model)?;

                    // A reset stream may have dropped the receiver. Computation still finished.
                    let _ = work.reply.send(result);
                    Ok(())
                }.instrument(span));
            }
        }
    };

    // Dropping HTTP futures is not sufficient to stop spawn_blocking. Wait on the permits
    // owned inside those closures, bounded separately from the original request deadline.
    drop(connection);
    pending.close();
    while pending.try_recv().is_ok() {}
    tasks.shutdown().await;

    let drained = timeout(
        config.shutdown_timeout,
        capacity.acquire_many(u32::from(config.max_in_flight.get())),
    )
    .await;
    if drained.is_err() {
        metrics::counter!("worker_rpc.server_failures", "class" => "shutdown_timeout").increment(1);
        tracing::error!(
            dependency = "biometric_model",
            failure_class = "shutdown_timeout",
            "inference still running; worker process must be terminated"
        );
        return Err(WorkerServerError::ShutdownTimeout {
            cause: result.err().map(Box::new),
        });
    }

    if let Err(error) = &result {
        metrics::counter!("worker_rpc.server_failures", "class" => error.failure_class())
            .increment(1);
        tracing::warn!(dependency = "biometric_model", failure_class = error.failure_class(), failure = %error,
            "worker server stopped");
    }

    result
}

async fn ready(State(state): State<Arc<ServerState>>) -> Response {
    cbor_response(&WorkerReady {
        protocol_version: WORKER_PROTOCOL_VERSION,
        max_in_flight: state.config.max_in_flight.get(),
    })
}

#[tracing::instrument(
    name = "worker.infer",
    skip_all,
    fields(dependency = "biometric_model")
)]
async fn compare(State(state): State<Arc<ServerState>>, request: Request) -> Response {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.as_bytes())
        != Some(CONTENT_TYPE.as_bytes())
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    let Ok(permit) = Arc::clone(&state.capacity).try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let deadline = Instant::now() + state.config.request_timeout;
    let result = timeout_at(deadline, async {
        let body = to_bytes(request.into_body(), state.config.max_request_bytes)
            .await
            .map_err(|error| {
                if error
                    .source()
                    .is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
                {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                }
            })?;

        let request: CompareRequest = decode_message(&body, state.config.max_request_bytes)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if !request.valid_image_sizes(state.config.max_image_bytes) {
            return Err(StatusCode::BAD_REQUEST);
        }

        let (reply, result) = oneshot::channel();
        state
            .work
            .try_send(Work {
                request,
                deadline,
                reply,
                permit,
                span: tracing::Span::current(),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => StatusCode::TOO_MANY_REQUESTS,
                mpsc::error::TrySendError::Closed(_) => StatusCode::SERVICE_UNAVAILABLE,
            })?;
        result.await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    })
    .await;

    match result {
        Ok(Ok(result)) => cbor_response(&result),
        Ok(Err(status)) => status.into_response(),
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

fn cbor_response(value: &impl serde::Serialize) -> Response {
    match encode_message(value, MAX_RESPONSE_BYTES) {
        Ok(body) => ([(header::CONTENT_TYPE, CONTENT_TYPE)], Body::from(body)).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to encode worker response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Worker lifecycle failures; infrastructure errors must not masquerade as analysis failures.
#[derive(Debug, thiserror::Error)]
pub enum WorkerServerError {
    /// Invalid body, capacity or timeout settings.
    #[error("invalid worker server configuration")]
    InvalidConfig,
    /// Socket/HTTP2 failure.
    #[error("worker HTTP/2 connection failed: {0}")]
    Transport(#[source] hyper::Error),
    /// Comparator reported a model/runtime failure.
    #[error("worker model failed: {0}")]
    Model(#[source] Box<dyn Error + Send + Sync>),
    /// A model job exceeded its original deadline.
    #[error("worker inference timed out")]
    RequestTimeout,
    /// A computation or its supervisor panicked.
    #[error("worker computation task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
    /// Work remains alive; the process supervisor must terminate the worker.
    #[error("worker inference did not stop before shutdown deadline; terminate the worker process")]
    ShutdownTimeout {
        /// Failure that triggered shutdown, if any.
        #[source]
        cause: Option<Box<Self>>,
    },
}

impl WorkerServerError {
    /// Stable, low-cardinality failure label.
    #[must_use]
    pub const fn failure_class(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::Transport(_) => "transport",
            Self::Model(_) => "model",
            Self::RequestTimeout => "request_timeout",
            Self::Task(_) => "task_failure",
            Self::ShutdownTimeout { .. } => "shutdown_timeout",
        }
    }
}
