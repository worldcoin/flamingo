//! The attested statement a passing request produces, and the claims it must carry.
//!
//! The request itself is `world_id_flamingo::Request`; this module does not interpret its
//! payload; the enclave validates it and its interim adapter maps pipeline inputs and metadata.

use serde::{Deserialize, Serialize};
use world_id_flamingo::{FlamingoClaims, Payload, ReleaseManifest, Request, engine_config_hash};
use world_id_primitives::FieldElement;

use crate::{DebugReport, FailureReason};

/// The claims a Flamingo Token for `request` with the decoded `payload` must carry when `release`
/// ran it at the Verifier's time `now`, in Unix seconds (WIP-201 §4.5). Verifies the AAT at `now`.
///
/// `billing_nullifier` is `0`: this Verifier bills no RP yet (WIP-107 §4.7).
///
/// # Errors
/// [`FailureReason::UnsupportedPipeline`] if `release` does not define the payload's pipeline or
/// `pipeline_inputs` does not fit it, and [`FailureReason::AatRejected`] if the AAT does not verify.
pub fn expected_claims(
    request: &Request,
    payload: &Payload,
    release: &ReleaseManifest,
    now: u32,
) -> Result<FlamingoClaims, FailureReason> {
    let pipeline = release
        .pipeline(payload.pipeline_id)
        .ok_or(FailureReason::UnsupportedPipeline)?;
    let compare_sources = payload
        .compare_sources(pipeline)
        .map_err(|_| FailureReason::UnsupportedPipeline)?;
    Ok(FlamingoClaims {
        now,
        compared_entry_hashes: payload.compared_entry_hashes(),
        aud: request.aud,
        nonce: request.nonce,
        aat: request.verify_aat(now)?,
        compare_sources,
        engine_config_hash: engine_config_hash(
            &release.release_hash(),
            payload.pipeline_id,
            payload.match_strictness,
        ),
        billing_nullifier: FieldElement::ZERO,
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
    use crate::testing;
    use world_id_flamingo::{Entry, MAX_COMPARED};

    const NOW: u32 = 1_783_446_000;

    fn release() -> ReleaseManifest {
        ReleaseManifest::from_jws(&testing::manifest(testing::TEST_ENGINE_HASH, 1)).unwrap()
    }

    fn request() -> Request {
        let entry = |data: &[u8]| Entry {
            data: data.to_vec(),
            meta: Vec::new(),
        };
        let payload = Payload {
            pipeline_id: 1,
            match_strictness: 2,
            hints: Vec::new(),
            entries: vec![entry(b"a"), entry(b"b"), entry(b"c")],
            pipeline_inputs: vec![0],
            compare: vec![2, 0, 1],
        };
        Request::new(
            7u64.into(),
            42u64.into(),
            u64::from(NOW) + 300,
            FieldElement::ZERO,
            &payload,
            None,
        )
        .unwrap()
    }

    #[test]
    fn claims_hash_the_compared_entries_in_compare_order() {
        let request = request();
        let payload = request.payload().unwrap();
        let release = release();
        let claims = expected_claims(&request, &payload, &release, NOW).unwrap();
        assert_eq!(
            claims.compared_entry_hashes,
            payload.compared_entry_hashes()
        );
        assert_ne!(
            claims.compared_entry_hashes[0],
            claims.compared_entry_hashes[1]
        );
        assert_eq!(
            claims.compared_entry_hashes[3..],
            [FieldElement::ZERO; MAX_COMPARED - 3]
        );
        assert_eq!(claims.now, NOW);
        assert_eq!(claims.aud, request.aud);
        assert_eq!(claims.nonce, request.nonce);
        assert_eq!(claims.aat, None);
        // `compare[1]` is pipeline input 0.
        assert_eq!(claims.compare_sources, 256);
        assert_eq!(claims.billing_nullifier, FieldElement::ZERO);
        assert_eq!(
            claims.engine_config_hash,
            engine_config_hash(&release.release_hash(), 1, 2)
        );
    }

    #[test]
    fn a_pipeline_the_release_lacks_or_does_not_fit_is_unsupported() {
        let request = request();
        let release = release();
        let mut payload = request.payload().unwrap();
        payload.pipeline_id = 9;
        assert_eq!(
            expected_claims(&request, &payload, &release, NOW),
            Err(FailureReason::UnsupportedPipeline)
        );
        // Pipeline 2 checks two inputs.
        payload.pipeline_id = 2;
        assert_eq!(
            expected_claims(&request, &payload, &release, NOW),
            Err(FailureReason::UnsupportedPipeline)
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
