//! Host-side carrier: Kubernetes owns restart/backoff; each container provisions one enclave.
mod artifact;
mod config;
mod enclave;
mod process;

use anyhow::{Context, Result};
use config::Config;
use enclave::{Enclave, clear_readiness};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::{sleep, timeout},
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
        result = serve(&config, &enclave, directory.path()) => result,
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    };
    let readiness = clear_readiness(&config.ready_file).await;
    let cleanup = enclave.cleanup().await;
    readiness?;
    cleanup.context("carrier cleanup failed")?;
    result
}

async fn serve(config: &Config, enclave: &Enclave<'_>, directory: &std::path::Path) -> Result<()> {
    timeout(config.bootstrap_timeout, async {
        eprintln!("carrier: downloading and verifying pinned S3 worker");
        let bundle = artifact::download_and_verify(config, directory).await?;
        eprintln!("carrier: launching measured enclave");
        enclave.launch().await?;
        eprintln!("carrier: provisioning worker and waiting for initialization");
        enclave.provision(&bundle).await?;
        while enclave.health().await.is_err() {
            sleep(std::time::Duration::from_millis(200)).await;
        }
        enclave.running().await?;
        anyhow::Ok(())
    })
    .await
    .context("carrier bootstrap deadline exceeded")??;

    if let Some(parent) = config.ready_file.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&config.ready_file, b"ready\n").await?;
    eprintln!("carrier: worker enclave ready");
    loop {
        enclave.running().await?;
        enclave.health().await?;
        sleep(config.poll_interval).await;
    }
}
