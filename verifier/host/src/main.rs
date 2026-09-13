use std::sync::Arc;

use flamingo_verifier_host::{
    AppState, Environment,
    enclave::PontifexEnclaveClient,
    payments::{InMemoryStore, PaymentLedger, RpcEscrowReader},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let environment = Environment::from_env();
    tracing::info!(?environment, "Starting API");

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        environment.enclave_cid(),
        environment.enclave_port(),
    ));
    let escrow = RpcEscrowReader::new(environment.escrow())
        .map_err(|error| anyhow::anyhow!("failed to build the fee escrow reader: {error}"))?;

    // The store is in-process only: two replicas would hand out the same counters. Swapping in a
    // persistent `PaymentStore` is the one change that makes this safe to scale out.
    let payments = Arc::new(PaymentLedger::new(
        environment.payments(),
        Arc::new(InMemoryStore::new()),
        Arc::new(escrow),
    ));
    let state = AppState::new(environment, enclave_client, payments);

    flamingo_verifier_host::server::start(state).await
}
