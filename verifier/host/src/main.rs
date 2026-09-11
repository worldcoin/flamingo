use std::sync::Arc;

use flamingo_verifier_host::{AppState, Environment, enclave::PontifexEnclaveClient};

/// Starts the host and its configured telemetry.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let environment = Environment::from_env();
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        environment.enclave_cid(),
        environment.enclave_port(),
    ));
    let state = AppState::new(environment, enclave_client);

    flamingo_verifier_host::server::start(state).await
}
