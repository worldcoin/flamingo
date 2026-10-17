use serde::{Deserialize, Serialize};

/// The enclave's encryption key and attestation, returned as the assignment in a `/v1/matches` session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveAssignmentResponse {
    /// COSE attestation committing to the encryption key, standard padded base64.
    pub attestation: String,
    /// Full X-Wing encryption public key, standard padded base64.
    pub public_key: String,
    /// `release_hash` of each loaded release, hex on the wire. Not attested: a wrong list only makes
    /// requests fail, since the enclave rejects a request for a release it did not load. An
    /// enclave loads one Engine for now, so the list is empty or has one entry.
    #[serde(with = "hex_hashes")]
    pub release_hashes: Vec<[u8; 32]>,
}

/// Encodes 32-byte hashes as lowercase hex strings and accepts either case.
mod hex_hashes {
    use hex::FromHex as _;
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(hashes: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(hashes.iter().map(hex::encode))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<[u8; 32]>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|hash| <[u8; 32]>::from_hex(hash).map_err(D::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::EnclaveAssignmentResponse;

    #[test]
    fn the_response_keeps_its_wire_name() {
        let body = EnclaveAssignmentResponse {
            attestation: "Y29zZQ==".to_owned(),
            public_key: "a2V5".to_owned(),
            release_hashes: vec![[0x2a; 32]],
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

    #[test]
    fn release_hashes_are_32_bytes_of_hex_in_either_case() {
        let parse = |hash: String| {
            serde_json::from_value::<EnclaveAssignmentResponse>(serde_json::json!({
                "attestation": "",
                "public_key": "",
                "release_hashes": [hash],
            }))
            .map(|body| body.release_hashes)
        };
        assert_eq!(parse("2A".repeat(32)).unwrap(), vec![[0x2a; 32]]);
        for invalid in ["2a".repeat(31), "2a".repeat(33), "zz".repeat(32)] {
            assert!(parse(invalid).is_err());
        }
    }
}
