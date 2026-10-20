use std::{cell::Cell, future::pending, path::PathBuf, time::Duration};

use anyhow::{Result, anyhow};
use tokio::sync::oneshot;

use super::{config::Config, supervise};

fn config(ready_file: PathBuf) -> Config {
    Config {
        eif: "unused.eif".into(),
        ready_file,
        artifact_uri: "unused".into(),
        artifact_sha256: "0".repeat(64),
        executable_name: "worker".into(),
        release_manifest_path: "unused.jws".into(),
        enclave_port: 1000,
        debug_mode: false,
        cid: 16,
        cpus: 2,
        memory_mib: 6144,
        bootstrap_timeout: Duration::from_secs(10),
        io_timeout: Duration::from_secs(2),
        poll_interval: Duration::from_secs(1),
    }
}

struct OnDrop<'a>(&'a Cell<bool>);

impl Drop for OnDrop<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[tokio::test(start_paused = true)]
async fn readiness_waits_for_initialization_and_is_cleared_on_exit() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let (started_tx, started_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let cleaned = Cell::new(false);
    let lifecycle = supervise(
        &config,
        async {
            started_tx.send(()).unwrap();
            ready_rx.await.unwrap();
            Ok(())
        },
        async {
            assert_eq!(std::fs::read(&config.ready_file).unwrap(), b"ready\n");
            Ok(())
        },
        pending(),
        async {
            assert!(!config.ready_file.exists());
            cleaned.set(true);
            Ok(())
        },
    );
    let observe = async {
        started_rx.await.unwrap();
        assert!(!config.ready_file.exists());
        ready_tx.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(lifecycle, observe);
    result.unwrap();
    assert!(cleaned.get());
    assert!(!config.ready_file.exists());
}

#[tokio::test]
async fn rejected_release_never_publishes_readiness_and_still_cleans_up() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let cleaned = Cell::new(false);
    let result = supervise(
        &config,
        async { Err(anyhow!("release rejected")) },
        async { panic!("must not monitor a rejected bootstrap") },
        pending(),
        async {
            assert!(!config.ready_file.exists());
            cleaned.set(true);
            Ok(())
        },
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("release rejected"));
    assert!(cleaned.get());
}

#[tokio::test(start_paused = true)]
async fn application_initialization_shares_the_remaining_bootstrap_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let cancelled = Cell::new(false);
    let started = tokio::time::Instant::now();
    let result = supervise(
        &config,
        async {
            // Time already spent acquiring and sideloading the worker.
            tokio::time::sleep(Duration::from_secs(4)).await;
            let _guard = OnDrop(&cancelled);
            pending::<Result<()>>().await
        },
        async { panic!("must not monitor a timed-out bootstrap") },
        pending(),
        async {
            assert!(cancelled.get());
            assert!(!config.ready_file.exists());
            Ok(())
        },
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("bootstrap deadline")
    );
    assert_eq!(started.elapsed(), config.bootstrap_timeout);
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_initialization_before_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let cancelled = Cell::new(false);
    let cleaned = Cell::new(false);
    let (started_tx, started_rx) = oneshot::channel();
    supervise(
        &config,
        async {
            let _guard = OnDrop(&cancelled);
            started_tx.send(()).unwrap();
            pending::<Result<()>>().await
        },
        async { panic!("must not monitor cancelled bootstrap") },
        async { started_rx.await.unwrap() },
        async {
            assert!(cancelled.get());
            assert!(!config.ready_file.exists());
            cleaned.set(true);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(cleaned.get());
}

#[tokio::test]
async fn shutdown_after_publication_clears_readiness_before_termination() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let (published_tx, published_rx) = oneshot::channel();
    let stopped = Cell::new(false);
    supervise(
        &config,
        async { Ok(()) },
        async {
            assert!(config.ready_file.exists());
            published_tx.send(()).unwrap();
            pending::<Result<()>>().await
        },
        async { published_rx.await.unwrap() },
        async {
            assert!(!config.ready_file.exists());
            stopped.set(true);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(stopped.get());
    // No writer can outlive the publication and recreate the marker after cleanup.
    tokio::task::yield_now().await;
    assert!(!config.ready_file.exists());
}
