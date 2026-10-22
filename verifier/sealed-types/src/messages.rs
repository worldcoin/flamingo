//! The attested statement a passing request produces, and the claims it must carry.
//!
//! The request itself is `world_id_flamingo::Request`; this module does not interpret its
//! payload here; the enclave validates it and its interim adapter maps pipeline roles and metadata.

use serde::{Deserialize, Serialize};
use world_id_flamingo::{FlamingoClaims, Payload, Request, RequestError, engine_config_hash};

use crate::{DebugReport, FailureReason};

/// The claims a Flamingo Token for `request` with the decoded `payload` must carry, after
/// verifying its AAT.
///
/// # Errors
/// Fails when the AAT does not verify.
pub fn expected_claims(
    request: &Request,
    payload: &Payload,
) -> Result<FlamingoClaims, RequestError> {
    Ok(FlamingoClaims {
        compared_entry_hashes: payload.compared_entry_hashes(),
        aud: request.aud,
        nonce: request.nonce,
        aat: request.verify_aat()?,
        engine_config_hash: engine_config_hash(
            &payload.release_hash,
            payload.pipeline,
            payload.match_strictness,
        ),
    })
}

/// A Flamingo Token with the attestation of the key that signed it, carried together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedStatement {
    /// The signed Flamingo Token, as its CWT encoding.
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
    /// NSM document attesting the token's signing key.
    #[serde(with = "serde_bytes")]
    pub signing_key_attestation: Vec<u8>,
}

/// The sealed response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MatchResult {
    /// The Engine passed and the Verifier signed a Flamingo Token.
    Success {
        /// Token and signing-key attestation.
        statement: AttestedStatement,
        /// Engine diagnostics outside the token.
        debug_report: DebugReport,
    },
    /// No token was issued.
    Failed {
        /// Why the request failed.
        reason: FailureReason,
        /// Engine diagnostics, if produced.
        debug_report: DebugReport,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_flamingo::{Entry, MAX_COMPARED};
    use world_id_primitives::FieldElement;

    fn request() -> Request {
        let entry = |data: &[u8]| Entry {
            data: data.to_vec(),
            meta: Vec::new(),
        };
        let payload = Payload {
            pipeline: 1,
            match_strictness: 2,
            hints: Vec::new(),
            entries: vec![entry(b"a"), entry(b"b"), entry(b"c")],
            compare: vec![2, 0],
            release_hash: [0x2a; 32],
        };
        Request::new(7u64.into(), 42u64.into(), &payload, None).unwrap()
    }

    #[test]
    fn claims_hash_the_compared_entries_in_compare_order() {
        let request = request();
        let payload = request.payload().unwrap();
        let claims = expected_claims(&request, &payload).unwrap();
        assert_eq!(
            claims.compared_entry_hashes,
            payload.compared_entry_hashes()
        );
        assert_ne!(
            claims.compared_entry_hashes[0],
            claims.compared_entry_hashes[1]
        );
        assert_eq!(
            claims.compared_entry_hashes[2..],
            [FieldElement::ZERO; MAX_COMPARED - 2]
        );
        assert_eq!(claims.aud, request.aud);
        assert_eq!(claims.nonce, request.nonce);
        assert_eq!(claims.aat, None);
        assert_eq!(
            claims.engine_config_hash,
            engine_config_hash(&[0x2a; 32], 1, 2)
        );
    }

    #[test]
    fn every_outcome_has_identical_envelope_size() {
        use crate::MATCH_RESPONSE_ENVELOPE_LEN;
        let success = MatchResult::Success {
            statement: AttestedStatement {
                token: vec![1; 512],
                signing_key_attestation: vec![2; 5000],
            },
            debug_report: DebugReport::NotProduced,
        };
        let failure = MatchResult::Failed {
            reason: FailureReason::MalformedInputs,
            debug_report: DebugReport::NotProduced,
        };
        for result in [success, failure] {
            let encoded = result.to_padded_cbor().unwrap();
            assert_eq!(encoded.len(), MATCH_RESPONSE_ENVELOPE_LEN);
            assert_eq!(MatchResult::from_padded_cbor(&encoded), Ok(result));
        }
    }
}
