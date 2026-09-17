use serde::{Deserialize, Serialize};

/// `POST /v1/enclave-assignment` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveAssignmentResponse {
    /// COSE attestation committing to the encryption key, standard padded base64.
    pub attestation: String,
    /// Full X-Wing encryption public key, standard padded base64.
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::EnclaveAssignmentResponse;

    #[test]
    fn the_response_keeps_its_wire_name() {
        let body = EnclaveAssignmentResponse {
            attestation: "Y29zZQ==".to_owned(),
            public_key: "a2V5".to_owned(),
        };
        let json = serde_json::json!({ "attestation": "Y29zZQ==", "public_key": "a2V5" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<EnclaveAssignmentResponse>(json).expect("should deserialize"),
            body
        );
    }
}
