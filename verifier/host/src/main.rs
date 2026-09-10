use std::sync::Arc;

use flamingo_verifier_host::{AppState, Environment, enclave::PontifexEnclaveClient};
use telemetry_batteries::{MetricsBackend, TelemetryConfig, TelemetryPreset};

/// Starts the host with explicit production telemetry requirements.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let environment = Environment::from_env();
    let mut telemetry_config = TelemetryConfig::from_env()
        .map_err(|error| anyhow::anyhow!("invalid telemetry configuration: {error:?}"))?;

    if environment != Environment::Development {
        anyhow::ensure!(
            telemetry_config.preset == TelemetryPreset::Datadog
                && telemetry_config.metrics.backend == MetricsBackend::Statsd,
            "staging/production requires TELEMETRY_PRESET=datadog and TELEMETRY_METRICS_BACKEND=statsd"
        );
        anyhow::ensure!(
            matches!(
                TelemetryConfig::log_level_from_env().as_str(),
                "warn" | "error"
            ),
            "staging/production requires RUST_LOG or TELEMETRY_LOG_LEVEL set to warn or error"
        );
        anyhow::ensure!(
            telemetry_config
                .metrics
                .statsd
                .host
                .parse::<std::net::IpAddr>()
                .is_ok(),
            "TELEMETRY_STATSD_HOST must be an IP address to avoid unbounded startup DNS"
        );
    }

    // Flush each small datagram so idle hosts do not retain their latest readiness sample.
    telemetry_config.metrics.statsd.buffer_size = 0;

    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init_with_config(telemetry_config)
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        environment.enclave_cid(),
        environment.enclave_port(),
    ));
    let state = AppState::new(environment, enclave_client);

    flamingo_verifier_host::server::start(state).await
}
