use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// This boot's channel encryption key and the NSM document attesting its commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestation {
    /// Raw COSE-encoded document.
    #[serde(with = "serde_bytes")]
    pub document: Vec<u8>,
    /// Full X-Wing public key. The document's `public_key` field contains its Pontifex commitment.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// SHA-256 of each loaded Engine bundle. Unauthenticated: a wrong list only fails requests.
    pub engine_hashes: Vec<[u8; 32]>,
}

/// Requests the attestation for this boot's encryption key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetEncryptionKeyRequest;

impl Request for GetEncryptionKeyRequest {
    const ROUTE_ID: &'static str = "/v1/encryption-key";
    type Response = Result<KeyAttestation, Error>;
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::GetEncryptionKeyRequest;

    #[test]
    fn the_encryption_key_route_id_is_versioned_and_stable() {
        assert_eq!(GetEncryptionKeyRequest::ROUTE_ID, "/v1/encryption-key");
    }
}
