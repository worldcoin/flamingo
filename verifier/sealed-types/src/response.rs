//! Versioned response metadata and fixed-size framing.
use crate::{Error, MatchInputs, MatchResult, valid_similarity};
use serde::{Deserialize, Serialize};

pub use flamingo_verifier_api_types::{MATCH_RESPONSE_ENVELOPE_LEN, MAX_DEBUG_REPORT_BYTES};
const LENGTH_LEN: usize = 4;

/// Complete normalized comparisons. These observations are not signed token claims.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchObservations {
    /// Three pairwise scores, each in [0, 1] with f32 normalization precision.
    DeepFace {
        /// Credential versus live.
        credential_live: f64,
        /// Credential versus challenge.
        credential_challenge: f64,
        /// Live versus challenge.
        live_challenge: f64,
    },
    /// One comparison across two images.
    GrayBadge {
        /// Live versus challenge.
        live_challenge: f64,
    },
}

impl MatchObservations {
    /// Checks score ranges and that the observations belong to this request's operation.
    #[must_use]
    pub fn matches_inputs(&self, inputs: &MatchInputs) -> bool {
        matches!(
            (self, inputs),
            (Self::DeepFace { .. }, MatchInputs::DeepFace(_))
                | (Self::GrayBadge { .. }, MatchInputs::GrayBadge(_))
        ) && self.valid()
    }

    /// Checks every completed comparison against the request's normalized threshold.
    #[must_use]
    pub fn meets_threshold(&self, threshold: f64) -> bool {
        match *self {
            Self::DeepFace {
                credential_live,
                credential_challenge,
                live_challenge,
            } => [credential_live, credential_challenge, live_challenge]
                .into_iter()
                .all(|score| score >= threshold),
            Self::GrayBadge { live_challenge } => live_challenge >= threshold,
        }
    }

    /// The score also carried in the operation's signed token.
    #[must_use]
    pub const fn token_score(&self) -> f64 {
        match *self {
            Self::DeepFace {
                credential_live, ..
            } => credential_live,
            Self::GrayBadge { live_challenge } => live_challenge,
        }
    }

    fn valid(&self) -> bool {
        match *self {
            Self::DeepFace {
                credential_live,
                credential_challenge,
                live_challenge,
            } => [credential_live, credential_challenge, live_challenge]
                .into_iter()
                .all(valid_similarity),
            Self::GrayBadge { live_challenge } => valid_similarity(live_challenge),
        }
    }
}

/// Delivery status of the original worker JSON. Report content is never included in Debug.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DebugReport {
    /// Original JSON without parsing or reserialization.
    Available {
        /// Worker-provided UTF-8 JSON.
        json: String,
    },
    /// The worker did not produce a report, or inference did not run.
    NotProduced,
    /// The entire report was omitted to preserve a valid outcome.
    OmittedTooLarge {
        /// Original UTF-8 byte count.
        original_size_bytes: u64,
    },
}

impl std::fmt::Debug for DebugReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available { json } => f
                .debug_struct("Available")
                .field("bytes", &json.len())
                .finish(),
            Self::NotProduced => f.write_str("NotProduced"),
            Self::OmittedTooLarge {
                original_size_bytes,
            } => f
                .debug_struct("OmittedTooLarge")
                .field("original_size_bytes", original_size_bytes)
                .finish(),
        }
    }
}

impl From<Option<String>> for DebugReport {
    fn from(report: Option<String>) -> Self {
        match report {
            Some(json) if json.len() > MAX_DEBUG_REPORT_BYTES => Self::OmittedTooLarge {
                original_size_bytes: json.len() as u64,
            },
            Some(json) => Self::Available { json },
            None => Self::NotProduced,
        }
    }
}

/// Encrypted response; the host cannot read its outcome, observations or diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchResponse {
    /// Signed statement or rejection.
    pub outcome: MatchResult,
    /// All comparisons after completed inference, including below-threshold rejection.
    pub observations: Option<MatchObservations>,
    /// Original bounded worker report or explicit absence status.
    pub debug_report: DebugReport,
}

impl From<MatchResult> for MatchResponse {
    fn from(outcome: MatchResult) -> Self {
        Self {
            outcome,
            observations: None,
            debug_report: DebugReport::NotProduced,
        }
    }
}

impl MatchResponse {
    /// Encodes a response in the version 3 fixed padded envelope with a four-byte length.
    /// # Errors
    /// Rejects malformed metadata or a response that exceeds the total envelope budget.
    pub fn to_padded_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;
        if encoded.len() > MATCH_RESPONSE_ENVELOPE_LEN - LENGTH_LEN {
            if let DebugReport::Available { json } = &self.debug_report {
                let mut without_report = self.clone();
                without_report.debug_report = DebugReport::OmittedTooLarge {
                    original_size_bytes: json.len() as u64,
                };
                // A report can fit its own cap but not the total response budget.
                encoded.clear();
                ciborium::into_writer(&without_report, &mut encoded)
                    .map_err(|_| Error::Encoding)?;
            }
            if encoded.len() > MATCH_RESPONSE_ENVELOPE_LEN - LENGTH_LEN {
                return Err(Error::ResponseTooLarge);
            }
        }
        let length = u32::try_from(encoded.len()).map_err(|_| Error::ResponseTooLarge)?;
        let mut envelope = vec![0; MATCH_RESPONSE_ENVELOPE_LEN];
        envelope[..LENGTH_LEN].copy_from_slice(&length.to_be_bytes());
        envelope[LENGTH_LEN..LENGTH_LEN + encoded.len()].copy_from_slice(&encoded);
        Ok(envelope)
    }

    /// Decodes exactly one response, rejecting nonzero padding and trailing CBOR.
    /// # Errors
    /// Returns Malformed for invalid framing or metadata.
    pub fn from_padded_cbor(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != MATCH_RESPONSE_ENVELOPE_LEN {
            return Err(Error::Malformed);
        }
        let length = u32::from_be_bytes(
            bytes[..LENGTH_LEN]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        ) as usize;
        let end = LENGTH_LEN
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::Malformed)?;
        if bytes[end..].iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed);
        }
        let mut reader = &bytes[LENGTH_LEN..end];
        let response: Self = ciborium::from_reader(&mut reader).map_err(|_| Error::Malformed)?;
        if !reader.is_empty() {
            return Err(Error::Malformed);
        }
        response.validate()?;
        Ok(response)
    }

    fn validate(&self) -> Result<(), Error> {
        let valid_report = match &self.debug_report {
            DebugReport::Available { json } => json.len() <= MAX_DEBUG_REPORT_BYTES,
            DebugReport::OmittedTooLarge {
                original_size_bytes,
            } => *original_size_bytes > 0,
            DebugReport::NotProduced => true,
        };
        if !valid_report || self.observations.is_some_and(|scores| !scores.valid()) {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FailureReason;

    #[test]
    fn report_delivery_uses_utf8_bytes_and_preserves_json() {
        for len in [41_739, MAX_DEBUG_REPORT_BYTES] {
            let json = format!("\"{}\"", "x".repeat(len - 2));
            let mut response =
                MatchResponse::from(MatchResult::Failed(FailureReason::MalformedInputs));
            response.debug_report = Some(json.clone()).into();
            let encoded = response.to_padded_cbor().unwrap();
            assert_eq!(encoded.len(), MATCH_RESPONSE_ENVELOPE_LEN);
            assert_eq!(MatchResponse::from_padded_cbor(&encoded).unwrap(), response);
            assert!(!format!("{:?}", response.debug_report).contains(&json));
        }
        let json = "é".repeat(MAX_DEBUG_REPORT_BYTES / 2 + 1);
        assert_eq!(
            DebugReport::from(Some(json)),
            DebugReport::OmittedTooLarge {
                original_size_bytes: MAX_DEBUG_REPORT_BYTES as u64 + 2
            }
        );
    }

    #[test]
    fn framing_rejects_legacy_lengths_trailing_cbor_and_nonzero_padding() {
        let response = MatchResponse::from(MatchResult::Failed(FailureReason::MalformedInputs));
        let mut bytes = response.to_padded_cbor().unwrap();
        assert!(MatchResponse::from_padded_cbor(&bytes[..16 * 1024]).is_err());
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        // A CBOR value inside the declared payload must not be silently ignored.
        bytes[..4].copy_from_slice(&(length + 1).to_be_bytes());
        assert!(MatchResponse::from_padded_cbor(&bytes).is_err());
        bytes[..4].copy_from_slice(&length.to_be_bytes());
        *bytes.last_mut().unwrap() = 1;
        assert!(MatchResponse::from_padded_cbor(&bytes).is_err());
        bytes[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(MatchResponse::from_padded_cbor(&bytes).is_err());
    }
    #[test]
    fn version_three_framing_has_frozen_bytes() {
        let response = MatchResponse::from(MatchResult::Failed(FailureReason::MalformedInputs));
        let bytes = response.to_padded_cbor().unwrap();
        let payload = b"\xa3\x67outcome\xa1\x66Failed\x70malformed_inputs\x6cobservations\xf6\x6cdebug_report\x6cnot_produced";
        assert_eq!(&bytes[..4], &[0, 0, 0, 74]);
        assert_eq!(&bytes[4..78], payload);
        assert!(bytes[78..].iter().all(|byte| *byte == 0));
        assert_eq!(crate::MATCH_CHANNEL_DOMAIN, "flamingo-verifier/matches/v3");
    }

    #[test]
    fn total_budget_omits_report_without_erasing_a_signed_outcome() {
        use crate::AttestedStatement;
        use flamingo_verifier_protocol::match_token::MatchToken;
        let outcome = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(vec![1; 170 * 1024]),
            signing_key_attestation: vec![2; 5000],
        });
        let response = MatchResponse {
            outcome: outcome.clone(),
            observations: None,
            debug_report: Some("x".repeat(100 * 1024)).into(),
        };
        let decoded = MatchResponse::from_padded_cbor(&response.to_padded_cbor().unwrap()).unwrap();
        assert_eq!(decoded.outcome, outcome);
        assert_eq!(
            decoded.debug_report,
            DebugReport::OmittedTooLarge {
                original_size_bytes: 100 * 1024
            }
        );
        let response = MatchResponse {
            outcome: MatchResult::Success(AttestedStatement {
                token: MatchToken::from_bytes(vec![1; MATCH_RESPONSE_ENVELOPE_LEN]),
                signing_key_attestation: vec![],
            }),
            observations: None,
            debug_report: DebugReport::NotProduced,
        };
        assert_eq!(response.to_padded_cbor(), Err(Error::ResponseTooLarge));
    }
}
