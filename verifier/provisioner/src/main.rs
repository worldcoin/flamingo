//! Flamingo owns the enclave lifecycle and release initialization; Kubernetes owns restarts.
mod artifact;
mod config;
mod enclave;
mod process;
mod release;

use std::future::Future;

use anyhow::{Context, Result, ensure};
use config::Config;
use enclave::{Enclave, clear_readiness};
use pontifex::client::ConnectionDetails;
use tabernaculum_provisioner::{ProvisionOptions, provision};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::timeout,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // Clear stale readiness even if configuration parsing fails.
    clear_readiness(&config::ready_file()).await?;
    let config = Config::from_env()?;
    let directory = tempfile::tempdir()?;
    let suffix = directory
        .path()
        .file_name()
        .context("missing temporary directory name")?
        .to_string_lossy();
    let enclave = Enclave::new(&config, &suffix);

    // Install handlers before launch; cancellation of any bootstrap step still cleans up.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    supervise(
        &config,
        bootstrap(&config, &enclave, directory.path()),
        enclave.monitor(),
        async {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
            }
        },
        enclave.stop(),
    )
    .await
}

async fn bootstrap(
    config: &Config,
    enclave: &Enclave<'_>,
    directory: &std::path::Path,
) -> Result<()> {
    // Snapshot this boot's manifest before launching; it is loaded once per enclave lifecycle.
    let manifest = tokio::fs::read_to_string(&config.release_manifest_path)
        .await
        .context("cannot read the release manifest")?;
    let manifest = manifest.trim().to_owned();
    ensure!(!manifest.is_empty(), "release manifest is empty");

    tracing::debug!("fetching worker artifact");
    let executable = artifact::fetch(config, directory).await?;
    tracing::debug!("launching enclave");
    enclave.launch().await?;
    tracing::debug!("sideloading worker executable");
    provision(ProvisionOptions {
        executable,
        enclave_cid: config.cid,
        io_timeout: config.io_timeout,
    })
    .await?;

    // Bootstrap acknowledgement precedes Pontifex binding. Initialization owns bounded retries
    // until that server is available, and completes only after release-aware health succeeds.
    release::initialize(
        ConnectionDetails::new(config.cid, config.enclave_port),
        manifest,
    )
    .await?;
    enclave.running().await
}

// This private seam exercises readiness, deadlines and cleanup without Nitro hardware.
async fn supervise<B, M, S, C>(
    config: &Config,
    bootstrap: B,
    monitor: M,
    shutdown: S,
    cleanup: C,
) -> Result<()>
where
    B: Future<Output = Result<()>>,
    M: Future<Output = Result<()>>,
    S: Future<Output = ()>,
    C: Future<Output = Result<()>>,
{
    let result = tokio::select! {
        result = async {
            timeout(config.bootstrap_timeout, bootstrap)
                .await
                .context("provisioner bootstrap deadline exceeded")??;
            mark_ready(&config.ready_file)?;
            tracing::info!(cid = config.cid, "enclave ready with release loaded");
            monitor.await
        } => result,
        () = shutdown => Ok(()),
    };

    if let Err(error) = &result {
        tracing::error!(error = format!("{error:#}"), "enclave provisioning failed");
    }
    // Attempt both cleanup operations, preserving the original failure in logs.
    let readiness = clear_readiness(&config.ready_file).await;
    let termination = cleanup.await;
    readiness?;
    termination.context("enclave termination failed")?;
    result
}

// Publish this tiny local marker synchronously. Cancelling tokio::fs::write would leave its
// blocking writer alive, allowing it to recreate readiness after shutdown cleanup removed it.
fn mark_ready(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"ready\n")?;
    Ok(())
}

#[cfg(test)]
mod tests;
