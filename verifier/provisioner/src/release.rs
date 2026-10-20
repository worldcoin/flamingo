//! Loads this boot's release and waits for application health before readiness.

use std::{future::Future, io, time::Duration};

use anyhow::{Context, Result, bail};
use flamingo_verifier_enclave_types::{Error as EnclaveError, HealthRequest, LoadReleaseRequest};
use pontifex::client::{self, ConnectionDetails};
use tokio::time::{sleep, timeout};

const CALL_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_DELAY: Duration = Duration::from_millis(250);

type ControlResponse = std::result::Result<std::result::Result<(), EnclaveError>, client::Error>;

/// Called after worker bootstrap acknowledgement, under the caller's overall startup deadline.
/// Dropping this future cancels its current request or retry delay; it owns no detached tasks.
pub async fn initialize(connection: ConnectionDetails, manifest: String) -> Result<()> {
    let release = LoadReleaseRequest { manifest };
    let health = HealthRequest;
    initialize_with(
        || client::send(connection, &release),
        || client::send(connection, &health),
    )
    .await
}

async fn initialize_with<L, LF, H, HF>(mut load: L, mut health: H) -> Result<()>
where
    L: FnMut() -> LF,
    LF: Future<Output = ControlResponse>,
    H: FnMut() -> HF,
    HF: Future<Output = ControlResponse>,
{
    let mut release_loaded = false;
    loop {
        let (operation, response) = if release_loaded {
            (
                "enclave health check",
                timeout(CALL_TIMEOUT, health()).await,
            )
        } else {
            ("release loading", timeout(CALL_TIMEOUT, load()).await)
        };

        match response {
            Ok(Ok(Ok(()))) if release_loaded => return Ok(()),
            Ok(Ok(Ok(()))) => {
                release_loaded = true;
                continue;
            }
            Ok(Ok(Err(EnclaveError::NotReady))) if release_loaded => {}
            Ok(Ok(Err(error))) => bail!("{operation} failed: {error:?}"),
            Ok(Err(error)) if transient(&error) => {}
            Ok(Err(error)) => return Err(error).context(operation),
            Err(_) => {}
        }
        sleep(RETRY_DELAY).await;
    }
}

fn transient(error: &client::Error) -> bool {
    match error {
        client::Error::Connection(error)
        | client::Error::Writing(_, error)
        | client::Error::Reading(_, error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::TimedOut
        ),
        client::Error::Encoding(_) | client::Error::Decoding(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        future::{pending, ready},
    };

    use pontifex::client::CodingKey;
    use tokio::time::{Instant, advance};

    use super::*;

    struct RecordDrop<'a>(&'a Cell<usize>);

    impl Drop for RecordDrop<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn each_boot_loads_before_health_and_stops_after_success() {
        let events = RefCell::new(Vec::new());
        for _ in 0..2 {
            initialize_with(
                || async {
                    events.borrow_mut().push("load");
                    Ok(Ok(()))
                },
                || async {
                    assert_eq!(events.borrow().last(), Some(&"load"));
                    events.borrow_mut().push("health");
                    Ok(Ok(()))
                },
            )
            .await
            .unwrap();
            advance(Duration::from_secs(30)).await;
        }
        assert_eq!(*events.borrow(), ["load", "health", "load", "health"]);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_server_startup_then_health_without_reloading() {
        let loads = RefCell::new(VecDeque::from([
            Err(client::Error::Connection(
                io::ErrorKind::ConnectionRefused.into(),
            )),
            Err(client::Error::Reading(
                CodingKey::Payload,
                io::ErrorKind::ConnectionReset.into(),
            )),
            Err(client::Error::Writing(
                CodingKey::Length,
                io::ErrorKind::TimedOut.into(),
            )),
            Ok(Ok(())),
        ]));
        let health = RefCell::new(VecDeque::from([
            Ok(Err(EnclaveError::NotReady)),
            Ok(Ok(())),
        ]));
        let started = Instant::now();
        initialize_with(
            || ready(loads.borrow_mut().pop_front().expect("unexpected reload")),
            || {
                assert!(
                    loads.borrow().is_empty(),
                    "health ran before release loaded"
                );
                ready(health.borrow_mut().pop_front().unwrap())
            },
        )
        .await
        .unwrap();
        assert!(loads.borrow().is_empty());
        assert!(health.borrow().is_empty());
        assert_eq!(started.elapsed(), 4 * RETRY_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_domain_failures_stop_without_retrying() {
        for (load_response, health_response) in [
            (Err(EnclaveError::ReleaseRejected), Ok(())),
            (Err(EnclaveError::NotReady), Ok(())),
            (Ok(()), Err(EnclaveError::Internal)),
        ] {
            let load_count = Cell::new(0);
            let health_count = Cell::new(0);
            let started = Instant::now();
            let error = initialize_with(
                || {
                    load_count.set(load_count.get() + 1);
                    ready(Ok(load_response))
                },
                || {
                    health_count.set(health_count.get() + 1);
                    ready(Ok(health_response))
                },
            )
            .await
            .unwrap_err();
            let expected = load_response.and(health_response).unwrap_err();
            assert!(error.to_string().contains(&format!("{expected:?}")));
            assert_eq!(load_count.get(), 1);
            assert_eq!(health_count.get(), usize::from(load_response.is_ok()));
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_transport_failure_stops_before_health() {
        let count = Cell::new(0);
        let started = Instant::now();
        let error = initialize_with(
            || {
                count.set(count.get() + 1);
                ready(Err(client::Error::Connection(
                    io::ErrorKind::PermissionDenied.into(),
                )))
            },
            || async { panic!("health must not run after a failed load") },
        )
        .await
        .unwrap_err();
        assert!(error.downcast_ref::<client::Error>().is_some());
        assert_eq!(count.get(), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn per_call_timeout_cancels_the_attempt_before_retrying() {
        let attempts = Cell::new(0);
        let dropped = Cell::new(0);
        let started = Instant::now();
        initialize_with(
            || {
                let attempt = attempts.get();
                attempts.set(attempt + 1);
                let dropped = &dropped;
                async move {
                    if attempt == 0 {
                        let _drop = RecordDrop(dropped);
                        pending::<ControlResponse>().await
                    } else {
                        assert_eq!(dropped.get(), 1);
                        Ok(Ok(()))
                    }
                }
            },
            || async { Ok(Ok(())) },
        )
        .await
        .unwrap();
        assert_eq!(attempts.get(), 2);
        assert_eq!(dropped.get(), 1);
        assert_eq!(started.elapsed(), CALL_TIMEOUT + RETRY_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_spans_load_and_health_and_cancels_pending_work() {
        let health_count = Cell::new(0);
        let dropped = Cell::new(0);
        let started = Instant::now();
        let result = timeout(
            Duration::from_secs(3),
            initialize_with(
                || async {
                    sleep(Duration::from_millis(1500)).await;
                    Ok(Ok(()))
                },
                || async {
                    health_count.set(health_count.get() + 1);
                    let _drop = RecordDrop(&dropped);
                    pending::<ControlResponse>().await
                },
            ),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(started.elapsed(), Duration::from_secs(3));
        assert_eq!(dropped.get(), 1);
        advance(Duration::from_secs(30)).await;
        assert_eq!(health_count.get(), 1);
    }
}
