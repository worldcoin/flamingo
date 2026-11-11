use std::sync::Arc;

use anyhow::Context as _;
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
    let billing = config.billing();
    let state = AppState::new(config, enclave_client.clone());
    let server = flamingo_verifier_host::server::start(state);

    let Some(billing) = billing else {
        tracing::warn!("no billing configuration; the host supplies no billing state");
        return server.await;
    };
    // A stopped follower leaves the enclave's billing state stale, so it ends the process.
    tokio::select! {
        result = server => result,
        result = flamingo_verifier_host::billing::run(billing, enclave_client) => {
            result.context("billing state sync stopped")
        }
    }
}
