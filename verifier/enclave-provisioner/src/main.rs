//! Host-side enclave provisioner: Kubernetes owns restart/backoff; each container provisions one enclave.
mod artifact;
mod config;
mod enclave;
mod process;

use anyhow::{Context, Result};
use config::Config;
use enclave::{Enclave, clear_readiness};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::timeout,
};

#[tokio::main]
async fn main() -> Result<()> {
    clear_readiness(&config::ready_file()).await?;

    let config = Config::from_env()?;
    let directory = tempfile::tempdir()?;
    let suffix = directory
        .path()
        .file_name()
        .context("missing temporary directory name")?
        .to_string_lossy();
    let enclave = Enclave::new(&config, &suffix);

    // Install handlers before launch so SIGTERM during any bootstrap step is handled.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    let result = tokio::select! {
        result = run_enclave(&config, &enclave, directory.path()) => result,
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    };
    // Attempt both cleanup operations, even if either one fails. Preserve the
    // bootstrap/health error in logs if cleanup itself also fails.
    if let Err(error) = &result {
        eprintln!("enclave-provisioner: {error:#}");
    }

    let readiness = clear_readiness(&config.ready_file).await;
    let termination = enclave.stop().await;

    readiness?;
    termination.context("enclave termination failed")?;

    result
}

async fn run_enclave(
    config: &Config,
    enclave: &Enclave<'_>,
    directory: &std::path::Path,
) -> Result<()> {
    timeout(config.bootstrap_timeout, async {
        eprintln!("enclave-provisioner: fetching sandbox bundle");
        let bundle = artifact::fetch(config, directory).await?;

        eprintln!("enclave-provisioner: launching enclave");
        enclave.launch().await?;

        eprintln!("enclave-provisioner: provisioning sandbox bundle");
        bundle.provision(config.cid, config.io_timeout).await?;

        enclave.wait_ready().await?;
        anyhow::Ok(())
    })
    .await
    .context("provisioner bootstrap deadline exceeded")??;

    mark_ready(&config.ready_file).await?;
    eprintln!("enclave-provisioner: ready");

    enclave.monitor().await
}

async fn mark_ready(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(path, b"ready\n").await?;
    Ok(())
}
