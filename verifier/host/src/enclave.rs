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

/// A stand-in enclave for running the host on a laptop.
///
/// Compiled only under the `mock-enclave` feature, which the release profile refuses, so it
/// cannot reach an environment where a caller might mistake its answers for attested ones.
#[cfg(feature = "mock-enclave")]
pub mod mock {
    use async_trait::async_trait;
    use flamingo_verifier_enclave_types::{KeyAttestation, MatchRequest, MatchResponse};
    use sha2::{Digest as _, Sha256};

    use super::{EnclaveClient, Error};

    /// The document a mock assignment returns. Not an attestation, and shaped so nothing
    /// mistakes it for one.
    const MOCK_ATTESTATION: &[u8] = b"flamingo-mock-enclave-attestation";
    /// Length of the encryption key the real enclave returns, so a client sees the same shape.
    const PUBLIC_KEY_BYTES: usize = 1216;

    /// An [`EnclaveClient`] that answers from a hash instead of an enclave.
    ///
    /// Deterministic on purpose: the same sealed body always comes back as the same ciphertext,
    /// so a harness can assert a round trip without running Nitro.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct MockEnclaveClient;

    impl MockEnclaveClient {
        /// Creates the mock client.
        #[must_use]
        pub const fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl EnclaveClient for MockEnclaveClient {
        async fn health(&self) -> Result<(), Error> {
            Ok(())
        }

        async fn encryption_key_attestation(&self) -> Result<KeyAttestation, Error> {
            Ok(KeyAttestation {
                document: MOCK_ATTESTATION.to_vec(),
                public_key: vec![0xab; PUBLIC_KEY_BYTES],
            })
        }

        async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, Error> {
            Ok(MatchResponse {
                ciphertext: Sha256::digest(&request.body).to_vec(),
            })
        }
    }
}

#[cfg(all(test, feature = "mock-enclave"))]
mod mock_tests {
    use flamingo_verifier_enclave_types::MatchRequest;
    use sha2::{Digest as _, Sha256};

    use super::EnclaveClient;
    use super::mock::MockEnclaveClient;

    /// A harness asserts a round trip, so the answer has to be a function of the request and
    /// nothing else.
    #[tokio::test]
    async fn a_mock_match_is_the_hash_of_its_request() {
        let client = MockEnclaveClient::new();
        let request = || MatchRequest {
            body: b"sealed".to_vec(),
        };

        let first = client
            .run_match(request())
            .await
            .expect("the mock always answers");
        let second = client
            .run_match(request())
            .await
            .expect("the mock always answers");

        assert_eq!(first.ciphertext, second.ciphertext);
        assert_eq!(first.ciphertext, Sha256::digest(b"sealed").to_vec());

        let other = client
            .run_match(MatchRequest {
                body: b"elsewhere".to_vec(),
            })
            .await
            .expect("the mock always answers");
        assert_ne!(first.ciphertext, other.ciphertext);
    }

    #[tokio::test]
    async fn the_mock_serves_a_key_shaped_like_the_real_one() {
        let attestation = MockEnclaveClient::new()
            .encryption_key_attestation()
            .await
            .expect("the mock always answers");

        assert_eq!(attestation.public_key.len(), 1216);
        assert!(
            !attestation.document.is_empty(),
            "a client should have something to reject"
        );
    }
}
