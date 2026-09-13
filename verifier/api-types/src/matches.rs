use serde::{Deserialize, Serialize};

use crate::Payment;

/// `POST /v1/matches` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRequestBody {
    /// The sealed match request, base64.
    pub ciphertext: String,
    /// The channel nonce this verification spends, when the verifier meters the caller.
    ///
    /// Omitted rather than null when absent, so a client that predates metering still sends the
    /// body it always sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<Payment>,
}

/// `POST /v1/matches` response.
///
/// No cleartext outcome: whether a match held is itself a fact about the request. The
/// signing-key attestation travels sealed inside, beside the statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponseBody {
    /// The sealed outcome, base64.
    pub response_ciphertext: String,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{FixedBytes, b256};

    use super::{MatchRequestBody, MatchResponseBody};
    use crate::{ChannelNonce, Payment};

    /// Pins the wire names. A round trip alone would not: a rename moves both ends together.
    ///
    /// An unpaid request carries no `payment` key at all, so adding the field did not change
    /// what an existing client sends.
    #[test]
    fn the_request_keeps_its_wire_names() {
        let body = MatchRequestBody {
            ciphertext: "c2VhbGVk".to_owned(),
            payment: None,
        };
        let json = serde_json::json!({ "ciphertext": "c2VhbGVk" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<MatchRequestBody>(json).expect("should deserialize"),
            body
        );
    }

    #[test]
    fn a_paid_request_carries_the_payment_beside_the_ciphertext() {
        let signature = FixedBytes::<65>::repeat_byte(0x33);
        let body = MatchRequestBody {
            ciphertext: "c2VhbGVk".to_owned(),
            payment: Some(Payment {
                channel_id: b256!(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                ),
                epoch: 7,
                channel_nonce: ChannelNonce::new(3, 42),
                signature,
            }),
        };
        let json = serde_json::json!({
            "ciphertext": "c2VhbGVk",
            "payment": {
                "channel_id": format!("0x{}", "11".repeat(32)),
                "epoch": 7,
                "channel_nonce": "0x3000000000000002a",
                "signature": format!("0x{}", "33".repeat(65)),
            },
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<MatchRequestBody>(json).expect("should deserialize"),
            body
        );
    }

    #[test]
    fn the_response_keeps_its_wire_names() {
        let body = MatchResponseBody {
            response_ciphertext: "c2VhbGVk".to_owned(),
        };
        let json = serde_json::json!({ "response_ciphertext": "c2VhbGVk" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<MatchResponseBody>(json).expect("should deserialize"),
            body
        );
    }
}
