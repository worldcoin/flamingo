//! Client boundary between the host and enclave.

use std::{future::Future, time::Duration};

use async_trait::async_trait;
use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{
    GetEncryptionKeyRequest, HealthRequest, KeyAttestation, MatchRequest, MatchResponse,
};
use pontifex::Request;
use pontifex::client::ConnectionDetails;
use tokio::time::{Instant, timeout};

const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
// Includes the worker's 120-second cold-start deadline and broker sealing overhead.
const MATCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(135);

/// Failures while calling an enclave operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The Pontifex connection or wire operation failed.
    Transport(String),
    /// The enclave returned a structured operation error.
    Operation(enclave_types::Error),
    /// The enclave did not answer within the API's request deadline.
    Timeout,
}

impl Error {
    /// Static labels never contain payloads, scores or transport error text.
    #[must_use]
    pub const fn failure_class(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::Timeout => "request_timeout",
            Self::Operation(operation) => match operation {
                enclave_types::Error::NotReady => "not_ready",
                enclave_types::Error::SecureModuleNotInitialized => "nsm_unavailable",
                enclave_types::Error::AttestationFailed => "attestation_failed",
                enclave_types::Error::RequestNotOpened => "request_not_opened",
                enclave_types::Error::Internal => "internal",
            },
        }
    }
}

/// Operations the host requires from the enclave.
#[async_trait]
pub trait EnclaveClient: Send + Sync {
    /// Checks whether the enclave process is reachable and ready.
    async fn health(&self) -> Result<(), Error>;

    /// Fetches this boot's encryption key and the document attesting its commitment.
    async fn encryption_key_attestation(&self) -> Result<KeyAttestation, Error>;

    /// Runs a match inside the enclave.
    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, Error>;
}

/// Pontifex-backed enclave client.
#[derive(Debug, Clone, Copy)]
pub struct PontifexEnclaveClient {
    /// Fixed enclave address; each request uses its own bounded connection.
    connection: ConnectionDetails,
}

impl PontifexEnclaveClient {
    /// Creates a client for the provided enclave CID and Pontifex port.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self {
            connection: ConnectionDetails::new(cid, port),
        }
    }

    /// Sends `request` under `deadline`, flattening the timeout, transport and operation layers.
    async fn call<R, T>(
        &self,
        operation: &'static str,
        request: R,
        deadline: Duration,
    ) -> Result<T, Error>
    where
        R: Request<Response = Result<T, enclave_types::Error>> + Sync,
    {
        Self::bounded_call(operation, deadline, async {
            pontifex::client::send(self.connection, &request)
                .await
                .map_err(|error| Error::Transport(error.to_string()))?
                .map_err(Error::Operation)
        })
        .await
    }

    /// Enforces the whole-operation deadline and exports only host-visible outcomes.
    #[tracing::instrument(
        name = "enclave.call",
        skip_all,
        fields(dependency = "enclave", operation)
    )]
    async fn bounded_call<T>(
        operation: &'static str,
        deadline: Duration,
        call: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let started = Instant::now();
        let result = timeout(deadline, call).await.unwrap_or(Err(Error::Timeout));
        let outcome = result
            .as_ref()
            .err()
            .map_or("success", Error::failure_class);

        metrics::counter!("verifier.enclave.calls", "operation" => operation, "result" => outcome)
            .increment(1);
        metrics::histogram!(
            "verifier.enclave.call_seconds",
            "operation" => operation,
            "result" => outcome,
            "histogram" => "distribution"
        )
        .record(started.elapsed().as_secs_f64());

        if operation == "health" {
            metrics::gauge!("verifier.enclave.ready").set(f64::from(result.is_ok()));
        }

        result
    }
}

#[async_trait]
impl EnclaveClient for PontifexEnclaveClient {
    async fn health(&self) -> Result<(), Error> {
        self.call("health", HealthRequest, CONTROL_REQUEST_TIMEOUT)
            .await
    }

    async fn encryption_key_attestation(&self) -> Result<KeyAttestation, Error> {
        self.call(
            "assignment",
            GetEncryptionKeyRequest,
            CONTROL_REQUEST_TIMEOUT,
        )
        .await
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, Error> {
        self.call("match", request, MATCH_REQUEST_TIMEOUT).await
    }
}

#[cfg(test)]
mod tests {
    use super::{CONTROL_REQUEST_TIMEOUT, Error, MATCH_REQUEST_TIMEOUT, PontifexEnclaveClient};
    use std::{future::pending, time::Duration};
    use tokio::time::{Instant, sleep};

    /// No worker or vsock device is needed to verify an unresponsive dependency.
    #[tokio::test(start_paused = true)]
    async fn control_calls_time_out_without_retrying() {
        let started = Instant::now();
        let result = PontifexEnclaveClient::bounded_call(
            "health",
            CONTROL_REQUEST_TIMEOUT,
            pending::<Result<(), Error>>(),
        )
        .await;

        assert_eq!(result, Err(Error::Timeout));
        assert_eq!(started.elapsed(), CONTROL_REQUEST_TIMEOUT);
    }

    /// Cold inference may use all 120 seconds without the host abandoning it early.
    #[tokio::test(start_paused = true)]
    async fn match_budget_contains_the_cold_worker_deadline() {
        let result = PontifexEnclaveClient::bounded_call("match", MATCH_REQUEST_TIMEOUT, async {
            sleep(Duration::from_secs(120)).await;
            Ok(())
        })
        .await;

        assert_eq!(result, Ok(()));
    }

    /// Host timeouts remain bounded even when an enclave fails to enforce its own deadline.
    #[tokio::test(start_paused = true)]
    async fn match_calls_time_out_without_retrying() {
        let started = Instant::now();
        let result = PontifexEnclaveClient::bounded_call(
            "match",
            MATCH_REQUEST_TIMEOUT,
            pending::<Result<(), Error>>(),
        )
        .await;

        assert_eq!(result, Err(Error::Timeout));
        assert_eq!(started.elapsed(), MATCH_REQUEST_TIMEOUT);
    }

    /// Transport details and sealed outcomes cannot become metric labels.
    #[test]
    fn failure_labels_are_static_and_redacted() {
        assert_eq!(
            Error::Transport("private detail".into()).failure_class(),
            "transport"
        );
        assert_eq!(Error::Timeout.failure_class(), "request_timeout");
        assert_eq!(
            Error::Operation(flamingo_verifier_enclave_types::Error::NotReady).failure_class(),
            "not_ready"
        );
    }

    /// Exercise the actual `DogStatsD` exporter without an agent or sensitive payloads.
    #[tokio::test]
    async fn metrics_are_exported_with_only_host_visible_labels() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = telemetry_batteries::TelemetryConfig {
            preset: telemetry_batteries::TelemetryPreset::None,
            ..Default::default()
        };
        config.metrics.backend = telemetry_batteries::MetricsBackend::Statsd;
        config.metrics.statsd.host = "127.0.0.1".into();
        config.metrics.statsd.port = receiver.local_addr().unwrap().port();
        config.metrics.statsd.buffer_size = 0;
        let _guard = telemetry_batteries::init_with_config(config).unwrap();

        let result = PontifexEnclaveClient::bounded_call("match", MATCH_REQUEST_TIMEOUT, async {
            Err::<(), _>(Error::Transport("sensitive fixture detail".into()))
        })
        .await;
        assert!(result.is_err());

        tokio::time::timeout(Duration::from_secs(2), async {
            let mut observed_count = false;
            let mut observed_duration = false;
            let mut bytes = [0_u8; 1024];
            while !observed_count || !observed_duration {
                let length = receiver.recv(&mut bytes).await.unwrap();
                let metric = std::str::from_utf8(&bytes[..length]).unwrap();
                assert!(!metric.contains("sensitive"));
                if metric.contains("operation:match") && metric.contains("result:transport") {
                    observed_count |= metric.starts_with("verifier.enclave.calls:1|c|");
                    observed_duration |= metric.starts_with("verifier.enclave.call_seconds:")
                        && metric.contains("|d|");
                }
            }
        })
        .await
        .expect("metrics must leave the bounded exporter queue promptly");
    }
}
