use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Requests a 3-way face match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// The sealed request, relayed verbatim.
    pub body: bytes::Bytes,
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
