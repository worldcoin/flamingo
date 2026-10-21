use serde::{Deserialize, Serialize};

/// Errors returned by enclave operations.
///
/// Coarse on the match path: detail worth disclosing travels sealed in the response ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// The enclave is reachable but not ready to process requests.
    NotReady,
    /// The Nitro Secure Module is unavailable.
    SecureModuleNotInitialized,
    /// The Nitro Secure Module could not produce an attestation document.
    AttestationFailed,
    /// The sealed request could not be opened.
    ///
    /// The only input failure the host may see: with no channel there is nothing to seal a reply
    /// into. Everything the enclave learns *after* opening travels sealed instead.
    RequestNotOpened,
    /// The sealed request exceeds the largest `max_request_bytes` of the loaded release; rejected
    /// before opening, as WIP-201 §3.2 requires.
    RequestTooLarge,
    /// The enclave failed while producing a response. Detail stays in the enclave log.
    Internal,
    /// The release manifest is malformed, breaks a WIP-201 rule, or names another Engine bundle.
    ReleaseRejected,
}
