use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// This boot's channel encryption key, the NSM document attesting its commitment with the loaded
/// `release_hash` as `user_data`, and that release's manifest (WIP-201 §4.4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestation {
    /// Raw COSE-encoded document.
    #[serde(with = "serde_bytes")]
    pub document: Vec<u8>,
    /// Full X-Wing public key. The document's `public_key` field contains its Pontifex commitment.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// The loaded release manifest as a compact JWS, as the provisioner loaded it. The document's
    /// `user_data` is its `release_hash`.
    pub release_manifest: String,
    /// Latest response slot across the loaded release's pipelines, in milliseconds.
    /// Not attested; used only by the untrusted host for its transport deadline.
    pub max_response_slot_millis: u64,
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
