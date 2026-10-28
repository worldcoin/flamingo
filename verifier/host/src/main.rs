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
    let rpc_proxy = config.rpc_proxy();
    let state = AppState::new(config, enclave_client);
    let server = flamingo_verifier_host::server::start(state);

    let Some(rpc_proxy) = rpc_proxy else {
        return server.await;
    };
    tracing::info!(
        port = rpc_proxy.port,
        destination = %rpc_proxy.destination_host,
        "forwarding enclave billing RPC"
    );
    // Its own task, so proxied connections do not share the API's. Failures of individual
    // connections are logged by the proxy; only startup errors end it.
    let proxy = tokio::spawn(pontifex::proxy::serve(rpc_proxy, |_| {}));
    tokio::select! {
        result = server => result,
        result = proxy => match result {
            Ok(Err(error)) => Err(anyhow::Error::new(error).context("billing RPC proxy failed")),
            Ok(Ok(never)) => match never {},
            Err(error) => Err(anyhow::Error::new(error).context("billing RPC proxy stopped")),
        },
    }
}
