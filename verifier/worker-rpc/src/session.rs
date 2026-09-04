use std::{future::Future, range::RangeInclusive, sync::Arc};

use flamingo_verifier_worker_protocol::{CompareRequest, ComparisonScores, WorkerResult};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use tracing::Instrument;

use crate::{WorkerClientError, http::WorkerHttpClient};

pub(crate) struct Command {
    pub request: CompareRequest,
    pub deadline: Instant,
    pub admitted_at: Instant,
    pub reply: oneshot::Sender<Result<ComparisonScores, WorkerClientError>>,
    pub _permit: OwnedSemaphorePermit,
    pub span: tracing::Span,
}

pub(crate) async fn run(
    connection: impl Future<Output = Result<(), WorkerClientError>>,
    http_client: WorkerHttpClient,
    mut commands: mpsc::Receiver<Command>,
    mut stopped: oneshot::Receiver<WorkerClientError>,
    status: watch::Sender<Option<WorkerClientError>>,
    score_range: RangeInclusive<f32>,
) -> Result<(), WorkerClientError> {
    tokio::pin!(connection);
    let mut tasks = JoinSet::new();

    let error = loop {
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => match result {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(error))) => break error,
                Some(Err(error)) => break WorkerClientError::Task(Arc::new(error)),
                None => unreachable!("nonempty task set"),
            },
            result = &mut connection => break result.err().unwrap_or(WorkerClientError::Unavailable),
            result = &mut stopped => break result.unwrap_or(WorkerClientError::Closed),
            command = commands.recv() => {
                let Some(command) = command else { break WorkerClientError::Closed };

                let span = command.span.clone();
                tasks.spawn(compare(http_client.clone(), command, score_range, status.clone()).instrument(span));
            }
        }
    };

    let error = publish_failure(&status, error);
    // Publish before dropping reply senders, so every pending caller sees the same cause.
    commands.close();
    tasks.shutdown().await;

    if matches!(error, WorkerClientError::Closed) {
        Ok(())
    } else {
        Err(error)
    }
}

async fn compare(
    http_client: WorkerHttpClient,
    command: Command,
    score_range: RangeInclusive<f32>,
    status: watch::Sender<Option<WorkerClientError>>,
) -> Result<(), WorkerClientError> {
    if Instant::now() >= command.deadline {
        return Err(publish_failure(&status, WorkerClientError::RequestTimeout));
    }

    let result = http_client
        .compare(command.request, command.deadline)
        .await
        .and_then(|result| match result {
            WorkerResult::AnalysisFailed => Err(WorkerClientError::AnalysisFailed),
            WorkerResult::Compared(scores)
                if score_range.contains(&scores.live_similarity)
                    && score_range.contains(&scores.challenge_similarity) =>
            {
                Ok(scores)
            }
            WorkerResult::Compared(_) => Err(WorkerClientError::InvalidScore),
        });

    if !matches!(&result, Err(WorkerClientError::RequestEncoding(_))) {
        metrics::counter!("worker_rpc.comparisons", "result" => result.as_ref().err().map_or("success", WorkerClientError::failure_class)).increment(1);
        metrics::histogram!("worker_rpc.comparison_seconds")
            .record(command.admitted_at.elapsed().as_secs_f64());
    }

    if let Err(error) = &result
        && !matches!(
            error,
            WorkerClientError::AtCapacity
                | WorkerClientError::AnalysisFailed
                | WorkerClientError::RequestEncoding(_)
        )
    {
        return Err(publish_failure(&status, error.clone()));
    }

    // Receiver cancellation is expected; this task still validated the whole response.
    let _ = command.reply.send(result);
    Ok(())
}

fn publish_failure(
    status: &watch::Sender<Option<WorkerClientError>>,
    error: WorkerClientError,
) -> WorkerClientError {
    let first_failure = status.send_if_modified(|current| {
        if current.is_some() {
            return false;
        }
        *current = Some(error.clone());
        true
    });

    if first_failure && !matches!(error, WorkerClientError::Closed) {
        metrics::counter!("worker_rpc.session_failures", "class" => error.failure_class())
            .increment(1);
        let upstream_status = match &error {
            WorkerClientError::HttpStatus(status) => Some(status.as_u16()),
            _ => None,
        };
        tracing::warn!(dependency = "biometric_worker", failure_class = error.failure_class(),
            failure = %error, upstream_status, retry_count = 0,
            "worker session became unavailable");
    }

    status
        .borrow()
        .clone()
        .expect("terminal status was published")
}
