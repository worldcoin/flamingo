use std::sync::Arc;

use clap::{Parser, ValueEnum};
use flamingo_verifier_host::{
    AppState, Environment, PaymentGate,
    enclave::{EnclaveClient, PontifexEnclaveClient},
    payments::{InMemoryStore, PaymentLedger, RpcEscrowReader},
};

/// Selects the mock enclave. Anything else, including unset, uses the real one.
const MOCK_ENCLAVE_MODE: &str = "mock";

/// How this host meters the matches it serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PaymentMode {
    /// Serve every match unbilled. Nothing about payments is constructed or read.
    Off,
    /// Meter a match that carries a payment, and serve one that does not.
    Optional,
    /// Refuse a match that carries no payment.
    Required,
}

/// The one setting this host takes on the command line, because it is the one an operator
/// reaches for during an incident. Everything else stays in the environment.
#[derive(Debug, Parser)]
#[command(about = "HTTP host for the Flamingo Verifier")]
struct Cli {
    /// How to meter matches.
    #[arg(long, env = "PAYMENTS", value_enum, default_value_t = PaymentMode::Off)]
    payments: PaymentMode,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let environment = Environment::from_env();
    tracing::info!(?environment, payments = ?cli.payments, "Starting API");

    // Unbilled matches are a deliberate rollback position in development and a revenue hole
    // anywhere else, so the latter says so once, loudly, at boot.
    if cli.payments == PaymentMode::Off && environment != Environment::Development {
        tracing::warn!(
            ?environment,
            "payments are off: every verification is served unbilled"
        );
    }

    let enclave_client = enclave_client()?;
    let payments = payment_gate(cli.payments, &environment)?;
    let state = AppState::new(environment, enclave_client, payments);

    flamingo_verifier_host::server::start(state).await
}

/// Builds the payment gate the selected mode asks for.
///
/// `Off` reads none of the `FEE_*` variables and builds neither the escrow reader nor the store,
/// so a host rolled back to it boots with nothing but its enclave configuration.
fn payment_gate(
    mode: PaymentMode,
    environment: &Environment,
) -> anyhow::Result<Option<PaymentGate>> {
    if mode == PaymentMode::Off {
        return Ok(None);
    }

    let escrow = RpcEscrowReader::new(environment.escrow())
        .map_err(|error| anyhow::anyhow!("failed to build the fee escrow reader: {error}"))?;

    // The store is in-process only: two replicas would hand out the same counters. Swapping in a
    // persistent `PaymentStore` is the one change that makes this safe to scale out.
    let ledger = PaymentLedger::new(
        environment.payments(),
        Arc::new(InMemoryStore::new()),
        Arc::new(escrow),
    );

    Ok(Some(PaymentGate::new(
        Arc::new(ledger),
        mode == PaymentMode::Required,
    )))
}

/// Builds the enclave client `ENCLAVE_MODE` asks for.
///
/// A build without the `mock-enclave` feature refuses `ENCLAVE_MODE=mock` rather than quietly
/// starting the real client: an operator who asked for a mock and got a vsock connection would
/// spend the outage looking in the wrong place.
fn enclave_client() -> anyhow::Result<Arc<dyn EnclaveClient>> {
    let mode = std::env::var("ENCLAVE_MODE").unwrap_or_default();

    if mode.trim().eq_ignore_ascii_case(MOCK_ENCLAVE_MODE) {
        return mock_enclave_client();
    }

    let environment = Environment::from_env();

    Ok(Arc::new(PontifexEnclaveClient::new(
        environment.enclave_cid(),
        environment.enclave_port(),
    )))
}

#[cfg(feature = "mock-enclave")]
fn mock_enclave_client() -> anyhow::Result<Arc<dyn EnclaveClient>> {
    tracing::warn!(
        "ENCLAVE_MODE=mock: matches are answered by a hash and nothing is attested. Never run \
         this against real requests."
    );

    Ok(Arc::new(
        flamingo_verifier_host::enclave::mock::MockEnclaveClient::new(),
    ))
}

#[cfg(not(feature = "mock-enclave"))]
fn mock_enclave_client() -> anyhow::Result<Arc<dyn EnclaveClient>> {
    anyhow::bail!(
        "ENCLAVE_MODE=mock needs the mock-enclave feature, which this binary was not built with. \
         Rebuild with --features mock-enclave, or unset ENCLAVE_MODE to use the real enclave."
    )
}
