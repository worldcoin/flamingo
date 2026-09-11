use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Three 8 MiB images, 64 KiB metadata and bounded CBOR field overhead.
pub const MAX_MATCH_PLAINTEXT_BYTES: usize = 24 * 1024 * 1024 + 64 * 1024 + 1024;
/// Pontifex 2 adds a 1216-byte response key, 7-byte header, 1120-byte KEM and 16-byte tag.
pub const MAX_MATCH_CIPHERTEXT_BYTES: usize = MAX_MATCH_PLAINTEXT_BYTES + 2359;

/// Requests a 3-way face match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// The sealed request, relayed verbatim.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

impl Request for MatchRequest {
    const ROUTE_ID: &'static str = "/v1/matches";
    type Response = Result<MatchResponse, Error>;
}

/// The sealed outcome of a match.
///
/// Ciphertext and nothing else. There is deliberately no cleartext class: whether a match held is
/// itself a fact about the request, so the host learns only that the enclave answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponse {
    /// The sealed response, readable only by the requester.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::MatchRequest;

    #[test]
    fn matches_route_id_is_versioned_and_stable() {
        assert_eq!(MatchRequest::ROUTE_ID, "/v1/matches");
    }
}
