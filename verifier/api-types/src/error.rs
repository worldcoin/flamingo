use serde::{Deserialize, Serialize};

use crate::LaneAuthorizationBody;

/// Error envelope returned to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    /// Whether the client should retry the request.
    pub allow_retry: bool,
    /// Error details.
    pub error: ErrorBody,
}

/// Machine-readable code and human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable identifier a client can branch on.
    pub code: String,
    /// Description for a human reading logs or a response.
    pub message: String,
    /// Evidence for the refusal, when the code carries any. Absent rather than null, so a client
    /// that predates it sees the envelope it always saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

/// What a refusal can prove about itself.
///
/// Only `capacity_exhausted` carries one: a relying party told its channel is spent can check
/// every signature listed here and add up the counters, rather than take the count on trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Epoch the counts belong to.
    pub epoch: u64,
    /// Verifications already served against this channel in that epoch.
    pub admitted_units: u64,
    /// Units the channel may spend in that epoch, as the escrow reports them.
    pub capacity: u64,
    /// Unix seconds at which the earliest outstanding reservation frees its lane. Present only
    /// when waiting is what would help.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// The highest authorization on each lane, lowest lane first.
    pub authorizations: Vec<LaneAuthorizationBody>,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{FixedBytes, fixed_bytes};

    use super::{ApiErrorResponse, ErrorBody, ErrorDetails};
    use crate::{ChannelNonce, LaneAuthorizationBody};

    /// `allowRetry` is the one camelCase key, and clients branch on `error.code`.
    #[test]
    fn the_envelope_keeps_its_wire_names() {
        let body = ApiErrorResponse {
            allow_retry: true,
            error: ErrorBody {
                code: "reassign_required".to_owned(),
                message: "stub".to_owned(),
                details: None,
            },
        };
        let json = serde_json::json!({
            "allowRetry": true,
            "error": { "code": "reassign_required", "message": "stub" },
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<ApiErrorResponse>(json).expect("should deserialize"),
            body
        );
    }

    /// The proof a capacity refusal carries, in the envelope rather than behind another route.
    #[test]
    fn a_refusal_can_carry_the_authorizations_behind_it() {
        const SIGNATURE: FixedBytes<65> = fixed_bytes!(
            "0x3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
        );

        let body = ApiErrorResponse {
            allow_retry: false,
            error: ErrorBody {
                code: "capacity_exhausted".to_owned(),
                message: "stub".to_owned(),
                details: Some(ErrorDetails {
                    epoch: 7,
                    admitted_units: 2,
                    capacity: 2,
                    retry_after: None,
                    authorizations: vec![LaneAuthorizationBody {
                        lane: 0,
                        channel_nonce: ChannelNonce::new(0, 1),
                        signature: SIGNATURE,
                    }],
                }),
            },
        };
        let json = serde_json::json!({
            "allowRetry": false,
            "error": {
                "code": "capacity_exhausted",
                "message": "stub",
                "details": {
                    "epoch": 7,
                    "admitted_units": 2,
                    "capacity": 2,
                    "authorizations": [{
                        "lane": 0,
                        "channel_nonce": "0x1",
                        "signature": format!("0x{}", "33".repeat(65)),
                    }],
                },
            },
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<ApiErrorResponse>(json).expect("should deserialize"),
            body
        );
    }
}
