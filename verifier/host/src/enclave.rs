//! Client boundary between the host and enclave.

use std::time::Duration;

use async_trait::async_trait;
use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{
    GetEncryptionKeyRequest, HealthRequest, KeyAttestation, MatchRequest, MatchResponse,
};
use pontifex::Request;
use pontifex::client::ConnectionDetails;
use tokio::time::timeout;

const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
// Match requests can carry large payloads and require expensive computation.
const MATCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    async fn call<R, T>(&self, request: R, deadline: Duration) -> Result<T, Error>
    where
        R: Request<Response = Result<T, enclave_types::Error>> + Sync,
    {
        timeout(deadline, pontifex::client::send(self.connection, &request))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Transport(error.to_string()))?
            .map_err(Error::Operation)
    }
}

#[async_trait]
impl EnclaveClient for PontifexEnclaveClient {
    async fn health(&self) -> Result<(), Error> {
        self.call(HealthRequest, CONTROL_REQUEST_TIMEOUT).await
    }

    async fn encryption_key_attestation(&self) -> Result<KeyAttestation, Error> {
        self.call(GetEncryptionKeyRequest, CONTROL_REQUEST_TIMEOUT)
            .await
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, Error> {
        self.call(request, MATCH_REQUEST_TIMEOUT).await
    }
}
