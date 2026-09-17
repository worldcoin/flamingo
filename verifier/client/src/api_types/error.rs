use serde::{Deserialize, Serialize};

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
}

#[cfg(test)]
mod tests {
    use super::{ApiErrorResponse, ErrorBody};

    /// `allowRetry` is the one camelCase key, and clients branch on `error.code`.
    #[test]
    fn the_envelope_keeps_its_wire_names() {
        let body = ApiErrorResponse {
            allow_retry: true,
            error: ErrorBody {
                code: "reassign_required".to_owned(),
                message: "stub".to_owned(),
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
}
