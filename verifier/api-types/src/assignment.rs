use serde::{Deserialize, Serialize};

/// The enclave's encryption key and attestation, returned as the assignment in a `/v1/matches` session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveAssignmentResponse {
    /// COSE attestation committing to the encryption key, standard padded base64.
    pub attestation: String,
    /// Full X-Wing encryption public key, standard padded base64.
    pub public_key: String,
    /// `release_hash` of each loaded release, lowercase hex. Not attested: a wrong list only makes
    /// requests fail, since the enclave rejects a request for a release it did not load.
    pub release_hashes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::EnclaveAssignmentResponse;

    #[test]
    fn the_response_keeps_its_wire_name() {
        let body = EnclaveAssignmentResponse {
            attestation: "Y29zZQ==".to_owned(),
            public_key: "a2V5".to_owned(),
            release_hashes: vec!["2a".repeat(32)],
        };
        let json = serde_json::json!({
            "attestation": "Y29zZQ==",
            "public_key": "a2V5",
            "release_hashes": ["2a".repeat(32)],
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<EnclaveAssignmentResponse>(json).expect("should deserialize"),
            body
        );
    }
}
