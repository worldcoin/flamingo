//! Versioned response metadata and fixed-size framing.
use crate::{Error, MatchResult};
use serde::{Deserialize, Serialize};

pub use flamingo_verifier_api_types::{MATCH_RESPONSE_ENVELOPE_LEN, MAX_DEBUG_REPORT_BYTES};
const LENGTH_LEN: usize = 4;

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

impl MatchResult {
    /// Encodes a response in the version 3 fixed padded envelope with a four-byte length.
    /// # Errors
    /// Rejects malformed metadata or a response that exceeds the total envelope budget.
    pub fn to_padded_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;
        if encoded.len() > MATCH_RESPONSE_ENVELOPE_LEN - LENGTH_LEN {
            if let DebugReport::Available { json } = self.debug_report() {
                let mut without_report = self.clone();
                *without_report.debug_report_mut() = DebugReport::OmittedTooLarge {
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

    const fn debug_report(&self) -> &DebugReport {
        match self {
            Self::Success { debug_report, .. } | Self::Failed { debug_report, .. } => debug_report,
        }
    }

    const fn debug_report_mut(&mut self) -> &mut DebugReport {
        match self {
            Self::Success { debug_report, .. } | Self::Failed { debug_report, .. } => debug_report,
        }
    }

    const fn validate(&self) -> Result<(), Error> {
        let valid_report = match self.debug_report() {
            DebugReport::Available { json } => json.len() <= MAX_DEBUG_REPORT_BYTES,
            DebugReport::OmittedTooLarge {
                original_size_bytes,
            } => *original_size_bytes > 0,
            DebugReport::NotProduced => true,
        };
        if !valid_report {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestedStatement, FailureReason};
    use flamingo_verifier_protocol::match_token::MatchToken;

    fn rejection(debug_report: DebugReport) -> MatchResult {
        MatchResult::Failed {
            reason: FailureReason::MalformedInputs,
            debug_report,
        }
    }

    #[test]
    fn report_delivery_uses_utf8_bytes_and_preserves_json() {
        for success in [false, true] {
            for len in [41_739, MAX_DEBUG_REPORT_BYTES] {
                let json = format!("\"{}\"", "x".repeat(len - 2));
                let debug_report = Some(json.clone()).into();
                let response = if success {
                    MatchResult::Success {
                        statement: AttestedStatement {
                            token: MatchToken::from_bytes(vec![1; 512]),
                            signing_key_attestation: vec![2; 5000],
                        },
                        debug_report,
                    }
                } else {
                    rejection(debug_report)
                };
                let encoded = response.to_padded_cbor().unwrap();
                assert_eq!(encoded.len(), MATCH_RESPONSE_ENVELOPE_LEN);
                assert_eq!(MatchResult::from_padded_cbor(&encoded).unwrap(), response);
                assert!(!format!("{response:?}").contains(&json));
            }
        }
        let json = "é".repeat(MAX_DEBUG_REPORT_BYTES / 2 + 1);
        assert_eq!(
            DebugReport::from(Some(json)),
            DebugReport::OmittedTooLarge {
                original_size_bytes: MAX_DEBUG_REPORT_BYTES as u64 + 2
            }
        );
        for report in [
            DebugReport::NotProduced,
            DebugReport::OmittedTooLarge {
                original_size_bytes: 200_000,
            },
        ] {
            let response = rejection(report);
            assert_eq!(
                MatchResult::from_padded_cbor(&response.to_padded_cbor().unwrap()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn framing_rejects_legacy_lengths_trailing_cbor_and_nonzero_padding() {
        let mut bytes = rejection(DebugReport::NotProduced)
            .to_padded_cbor()
            .unwrap();
        assert!(MatchResult::from_padded_cbor(&bytes[..16 * 1024]).is_err());
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        bytes[..4].copy_from_slice(&(length + 1).to_be_bytes());
        assert!(MatchResult::from_padded_cbor(&bytes).is_err());
        bytes[..4].copy_from_slice(&length.to_be_bytes());
        *bytes.last_mut().unwrap() = 1;
        assert!(MatchResult::from_padded_cbor(&bytes).is_err());
        bytes[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(MatchResult::from_padded_cbor(&bytes).is_err());
    }

    #[test]
    fn version_three_framing_has_frozen_bytes() {
        let bytes = rejection(DebugReport::NotProduced)
            .to_padded_cbor()
            .unwrap();
        let payload =
            b"\xa1\x66Failed\xa2\x66reason\x70malformed_inputs\x6cdebug_report\x6cnot_produced";
        assert_eq!(&bytes[..4], &[0, 0, 0, 59]);
        assert_eq!(&bytes[4..63], payload);
        assert!(bytes[63..].iter().all(|byte| *byte == 0));
        assert_eq!(crate::MATCH_CHANNEL_DOMAIN, "flamingo-verifier/matches/v3");
    }

    #[test]
    fn total_budget_omits_report_without_erasing_a_signed_outcome() {
        let statement = AttestedStatement {
            token: MatchToken::from_bytes(vec![1; 170 * 1024]),
            signing_key_attestation: vec![2; 5000],
        };
        let response = MatchResult::Success {
            statement: statement.clone(),
            debug_report: Some("x".repeat(100 * 1024)).into(),
        };
        let decoded = MatchResult::from_padded_cbor(&response.to_padded_cbor().unwrap()).unwrap();
        assert_eq!(
            decoded,
            MatchResult::Success {
                statement,
                debug_report: DebugReport::OmittedTooLarge {
                    original_size_bytes: 100 * 1024
                }
            }
        );
        let response = MatchResult::Success {
            statement: AttestedStatement {
                token: MatchToken::from_bytes(vec![1; MATCH_RESPONSE_ENVELOPE_LEN]),
                signing_key_attestation: vec![],
            },
            debug_report: DebugReport::NotProduced,
        };
        assert_eq!(response.to_padded_cbor(), Err(Error::ResponseTooLarge));
    }
}
