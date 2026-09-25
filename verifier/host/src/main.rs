use std::sync::Arc;

use clap::Parser as _;
use flamingo_verifier_host::{AppState, HostConfig, enclave::PontifexEnclaveClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let config = HostConfig::parse();
    tracing::info!(?config, "Starting API");

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        config.enclave_cid,
        config.enclave_port,
    ));
    let state = AppState::new(config, enclave_client);

    flamingo_verifier_host::server::start(state).await
}
