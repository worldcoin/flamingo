//! JSON text frames for the `/matches` WebSocket.
//!
//! A session exchanges exactly one assignment request and one assignment response as text frames,
//! then one sealed match request and one sealed match response as binary frames. The `type` tag
//! discriminates the messages, so an implementation that does not recognise a tag rejects it
//! rather than guessing.

use serde::{Deserialize, Serialize};

use crate::EnclaveAssignmentResponse;

/// A text frame sent by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Asks the host to return this enclave's assignment.
    AssignmentRequest,
}

/// A text frame sent by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    /// The enclave's encryption key and attestation.
    Assignment(EnclaveAssignmentResponse),
}

#[cfg(test)]
mod tests {
    use super::{ClientMessage, HostMessage};
    use crate::EnclaveAssignmentResponse;

    /// The request is the whole message: no fields beyond the discriminator.
    #[test]
    fn an_assignment_request_serializes_to_its_tag_alone() {
        let json = serde_json::json!({ "type": "assignment_request" });

        assert_eq!(
            serde_json::to_value(ClientMessage::AssignmentRequest).expect("should serialize"),
            json
        );
        assert_eq!(
            serde_json::from_value::<ClientMessage>(json).expect("should deserialize"),
            ClientMessage::AssignmentRequest
        );
    }

    /// The host's assignment keeps the v1 response fields, flattened next to the tag.
    #[test]
    fn an_assignment_response_flattens_next_to_its_tag() {
        let message = HostMessage::Assignment(EnclaveAssignmentResponse {
            attestation: "Y29zZQ==".to_owned(),
            public_key: "a2V5".to_owned(),
        });
        let json = serde_json::json!({
            "type": "assignment",
            "attestation": "Y29zZQ==",
            "public_key": "a2V5",
        });

        assert_eq!(
            serde_json::to_value(&message).expect("should serialize"),
            json
        );
        assert_eq!(
            serde_json::from_value::<HostMessage>(json).expect("should deserialize"),
            message
        );
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        assert!(
            serde_json::from_value::<ClientMessage>(serde_json::json!({ "type": "nope" })).is_err()
        );
        assert!(
            serde_json::from_value::<HostMessage>(serde_json::json!({ "type": "nope" })).is_err()
        );
    }
}
