use std::{
    io,
    net::Shutdown,
    os::unix::net::UnixStream,
    panic::{AssertUnwindSafe, catch_unwind},
    process::{Child, ExitStatus},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use flamingo_verifier_worker_rpc::{WorkerClient, WorkerClientError};
use tokio::sync::{oneshot, watch};

use crate::{WorkerProcessConfig, WorkerProcessError};

const POLL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub(crate) enum Control {
    Ready(WorkerClient, oneshot::Sender<()>),
    Stop(Option<WorkerProcessError>),
}

pub(crate) fn start(
    mut child: Child,
    socket: UnixStream,
    control: Receiver<Control>,
    completion: watch::Sender<Option<Result<ExitStatus, WorkerProcessError>>>,
    config: WorkerProcessConfig,
    started: Instant,
) -> Result<(), WorkerProcessError> {
    // Keep ownership in the launching thread until the reaper thread exists.
    let (sender, receiver) = mpsc::sync_channel::<Child>(1);
    let span = tracing::Span::current();
    let supervisor = thread::Builder::new()
        .name("worker-process".into())
        .spawn(move || {
            let _entered = span.enter();
            let Ok(mut child) = receiver.recv() else {
                completion.send_replace(Some(Err(WorkerProcessError::SupervisorStopped)));
                return;
            };
            let pid = child.id();
            let result = catch_unwind(AssertUnwindSafe(|| {
                let cause = monitor(&mut child, &control, config, started);
                let cause = match socket.shutdown(Shutdown::Both) {
                    Ok(()) => cause,
                    Err(error) if error.kind() == io::ErrorKind::NotConnected => cause,
                    Err(error) => Some(WorkerProcessError::Cleanup {
                        cleanup: Box::new(WorkerProcessError::io("close worker IPC", error)),
                        cause: cause.map(Box::new),
                    }),
                };

                let stopping = Instant::now();
                let result = cleanup(&mut child, config, cause, true);
                metrics::histogram!("worker_process.shutdown_seconds")
                    .record(stopping.elapsed().as_secs_f64());
                result
            }))
            .unwrap_or_else(|_| {
                cleanup(
                    &mut child,
                    config,
                    Some(WorkerProcessError::SupervisorStopped),
                    true,
                )
            });

            report(pid, &result);
            let needs_reaping = matches!(&result, Err(WorkerProcessError::ReapTimeout { .. }));
            completion.send_replace(Some(result));

            // The caller has its deadline error. Retain ownership if the OS delays SIGKILL/reaping.
            if needs_reaping {
                loop {
                    match child.wait() {
                        Ok(_) => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            tracing::error!(dependency = "biometric_worker", pid, %error,
                            failure_class = "reap_failed", "background worker reaping failed");
                            break;
                        }
                    }
                }
            }
        });

    if let Err(error) = supervisor {
        let cause = WorkerProcessError::io("start worker supervisor", error);
        return cleanup(&mut child, config, Some(cause), false).map(|_| ());
    }
    if let Err(error) = sender.send(child) {
        child = error.0;
        return cleanup(
            &mut child,
            config,
            Some(WorkerProcessError::SupervisorStopped),
            false,
        )
        .map(|_| ());
    }

    Ok(())
}

fn monitor(
    child: &mut Child,
    control: &Receiver<Control>,
    config: WorkerProcessConfig,
    started: Instant,
) -> Option<WorkerProcessError> {
    let deadline = started + config.rpc.handshake_timeout;
    let mut client: Option<WorkerClient> = None;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(WorkerProcessError::Exited(status)),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Some(WorkerProcessError::io("poll worker exit", error)),
        }

        match control.recv_timeout(POLL) {
            Ok(Control::Ready(ready, acknowledged)) => {
                if Instant::now() >= deadline {
                    return Some(WorkerClientError::HandshakeTimeout.into());
                }
                client = Some(ready);
                // Cancellation drops the owner, which also requests cleanup.
                let _ = acknowledged.send(());
            }
            Ok(Control::Stop(cause)) => {
                return cause.or_else(|| client.as_ref().and_then(session_failure));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return client.as_ref().and_then(session_failure);
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        if client.is_none() && Instant::now() >= deadline {
            return Some(WorkerClientError::HandshakeTimeout.into());
        }
        if let Some(error) = client.as_ref().and_then(session_failure) {
            return Some(error);
        }
    }
}

fn session_failure(client: &WorkerClient) -> Option<WorkerProcessError> {
    client
        .failure()
        .filter(|error| !matches!(error, WorkerClientError::Closed))
        .map(WorkerProcessError::Rpc)
}

fn cleanup(
    child: &mut Child,
    config: WorkerProcessConfig,
    cause: Option<WorkerProcessError>,
    background_reaper: bool,
) -> Result<ExitStatus, WorkerProcessError> {
    let grace = if background_reaper {
        config.shutdown_timeout
    } else {
        Duration::ZERO
    };
    match reap_until(child, Instant::now() + grace) {
        Ok(Some(status)) => {
            return match cause {
                Some(WorkerProcessError::Rpc(
                    WorkerClientError::Transport(_) | WorkerClientError::Unavailable,
                )) if !status.success() => Err(WorkerProcessError::Exited(status)),
                Some(error) => Err(error),
                None if status.success() => Ok(status),
                None => Err(WorkerProcessError::Exited(status)),
            };
        }
        Ok(None) => {}
        Err(error) => {
            return Err(WorkerProcessError::Cleanup {
                cleanup: Box::new(WorkerProcessError::io("wait for worker", error)),
                cause: cause.map(Box::new),
            });
        }
    }

    let cause = match child.kill() {
        Ok(()) => cause,
        Err(error) => Some(WorkerProcessError::Cleanup {
            cleanup: Box::new(WorkerProcessError::io("kill worker", error)),
            cause: cause.map(Box::new),
        }),
    };
    let result = reap_until(child, Instant::now() + config.reap_timeout);
    match result {
        Ok(Some(status)) => {
            // The child may have exited between try_wait and kill. Its status is authoritative.
            Err(WorkerProcessError::ForcedTermination {
                status,
                cause: cause.map(Box::new),
            })
        }
        Ok(None) => Err(WorkerProcessError::ReapTimeout {
            pid: child.id(),
            background_reaper,
            cause: cause.map(Box::new),
        }),
        Err(error) => Err(WorkerProcessError::Cleanup {
            cleanup: Box::new(WorkerProcessError::io("reap worker", error)),
            cause: cause.map(Box::new),
        }),
    }
}

fn reap_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(POLL.min(remaining));
    }
}

fn report(pid: u32, result: &Result<ExitStatus, WorkerProcessError>) {
    let class = match result {
        Ok(_) => "graceful",
        Err(WorkerProcessError::Rpc(error)) => error.failure_class(),
        Err(WorkerProcessError::Exited(_)) => "unexpected_exit",
        Err(WorkerProcessError::ForcedTermination { .. }) => "forced_termination",
        Err(WorkerProcessError::ReapTimeout { .. }) => "reap_timeout",
        Err(_) => "supervisor_failure",
    };
    metrics::counter!("worker_process.exits", "class" => class).increment(1);
    if let Err(error) = result {
        tracing::warn!(dependency = "biometric_worker", pid, failure_class = class, %error,
            "worker process stopped");
    }
}
