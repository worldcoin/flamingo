use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser as _;
use flamingo_verifier_host::{AppState, HostConfig, enclave::PontifexEnclaveClient, release};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let config = HostConfig::parse();
    tracing::info!(?config, "Starting API");

    let manifest = std::fs::read_to_string(&config.release_manifest_path)
        .with_context(|| {
            format!(
                "failed to read the release manifest at {}",
                config.release_manifest_path.display()
            )
        })?
        .trim()
        .to_owned();

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        config.enclave_cid,
        config.enclave_port,
    ));
    tokio::spawn(release::keep_loaded(enclave_client.clone(), manifest));
    let state = AppState::new(config, enclave_client);

    flamingo_verifier_host::server::start(state).await
}
