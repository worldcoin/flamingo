//! Typed CBOR payloads. Image ownership moves across inference adapters without cloning.
use super::{Error, FailureReason};
use crate::api_types::{
    MAX_HASHES_JSON_BYTES, MAX_IMAGE_BYTES, MAX_MATCH_PLAINTEXT_BYTES, MAX_TOTAL_IMAGE_BYTES,
};
use crate::protocol::match_token::{MatchClaims, MatchToken};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// One supported face operation.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchInputs {
    /// Orb/live/challenge comparisons with PCP binding.
    DeepFace(DeepFaceInputs),
    /// Live/challenge comparison without PCP.
    GrayBadge(GrayBadgeInputs),
}
/// `DeepFace` fields mirror the engine operation plus broker-owned PCP and policy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeepFaceInputs {
    /// Encoded Orb thumbnail.
    pub orb_credential: ByteBuf,
    /// Explicit capture variant.
    pub live: LiveCapture,
    /// Encoded relying-party challenge.
    pub rtms_challenge: ByteBuf,
    /// Exact original PCP hashes.json bytes.
    pub hashes_json: ByteBuf,
    /// Minimum normalized cosine score for all three comparisons.
    pub match_threshold: f64,
}
/// `GrayBadge` has no credential or PCP fields.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrayBadgeInputs {
    /// Explicit capture variant.
    pub live: LiveCapture,
    /// Encoded relying-party challenge.
    pub rtms_challenge: ByteBuf,
    /// Minimum normalized cosine score.
    pub match_threshold: f64,
}

/// Which `LightGuard` frame supplies the matching embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightGuardMatchingFrame {
    /// Illuminated frame.
    Illuminated,
    /// Unilluminated frame.
    Unilluminated,
}

/// Whether a normalized cosine value is finite and within [0, 1].
#[must_use]
pub fn valid_similarity(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

/// Capture bytes are deliberately not Debug or Clone.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LiveCapture {
    /// Single vanilla image.
    Vanilla(ByteBuf),
    /// Explicit challenge-response pair.
    LightGuard {
        /// Illuminated frame.
        illuminated: ByteBuf,
        /// Unilluminated frame.
        unilluminated: ByteBuf,
        /// Frame selected for matching.
        matching_frame: LightGuardMatchingFrame,
    },
}

impl LiveCapture {
    fn images(&self) -> impl Iterator<Item = &ByteBuf> {
        let (first, second) = match self {
            Self::Vanilla(image) => (image, None),
            Self::LightGuard {
                illuminated,
                unilluminated,
                ..
            } => (illuminated, Some(unilluminated)),
        };
        std::iter::once(first).chain(second)
    }
}
impl MatchInputs {
    /// Encode a validated request, borrowing image bytes directly.
    /// # Errors
    /// Rejects invalid fields or encoding failures.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate().map_err(|_| Error::Malformed)?;
        let payload_len = match self {
            Self::DeepFace(i) => {
                i.live.images().map(|b| b.len()).sum::<usize>()
                    + i.orb_credential.len()
                    + i.rtms_challenge.len()
                    + i.hashes_json.len()
            }
            Self::GrayBadge(i) => {
                i.live.images().map(|b| b.len()).sum::<usize>() + i.rtms_challenge.len()
            }
        };
        let mut encoded = Zeroizing::new(Vec::with_capacity(payload_len + 1024));
        ciborium::into_writer(self, &mut *encoded).map_err(|_| Error::Encoding)?;
        if encoded.len() > MAX_MATCH_PLAINTEXT_BYTES {
            return Err(Error::Malformed);
        }
        Ok(encoded)
    }
    /// Decode one complete bounded CBOR request. Semantic validation is broker-owned.
    /// # Errors
    /// Returns [`FailureReason::MalformedInputs`] for oversized, malformed or trailing data.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, FailureReason> {
        if bytes.len() > MAX_MATCH_PLAINTEXT_BYTES {
            return Err(FailureReason::MalformedInputs);
        }
        let mut reader = bytes;
        let result =
            ciborium::from_reader(&mut reader).map_err(|_| FailureReason::MalformedInputs)?;
        if !reader.is_empty() {
            return Err(FailureReason::MalformedInputs);
        }
        Ok(result)
    }
    /// Validate fields and shared byte budgets before hashing or inference.
    /// # Errors
    /// Returns a sealed input failure.
    pub fn validate(&self) -> Result<(), FailureReason> {
        let (live, challenge, credential, hashes, threshold) = match self {
            Self::DeepFace(i) => (
                &i.live,
                &i.rtms_challenge,
                Some(&i.orb_credential),
                Some(&i.hashes_json),
                i.match_threshold,
            ),
            Self::GrayBadge(i) => (&i.live, &i.rtms_challenge, None, None, i.match_threshold),
        };
        if !valid_similarity(threshold) {
            return Err(FailureReason::InvalidThreshold);
        }
        if hashes.is_some_and(|b| b.is_empty() || b.len() > MAX_HASHES_JSON_BYTES) {
            return Err(FailureReason::InvalidHashesJson);
        }
        let mut total = 0usize;
        for image in live
            .images()
            .chain(std::iter::once(challenge))
            .chain(credential)
        {
            if image.is_empty() {
                return Err(FailureReason::EmptyImage);
            }
            if image.len() > MAX_IMAGE_BYTES {
                return Err(FailureReason::InputTooLarge);
            }
            total += image.len();
        }
        if total > MAX_TOTAL_IMAGE_BYTES {
            return Err(FailureReason::InputTooLarge);
        }
        Ok(())
    }
    /// Check the legacy statement's input hashes and live score against a `DeepFace` request.
    /// Other operations and capture modes have no agreed token contract yet.
    #[must_use]
    pub fn matches_claims(&self, claims: &MatchClaims) -> bool {
        let Self::DeepFace(inputs) = self else {
            return false;
        };
        let LiveCapture::Vanilla(live) = &inputs.live else {
            return false;
        };
        let score = f64::from(claims.match_coefficient);
        claims.live_image_hash == <[u8; 32]>::from(Sha256::digest(live))
            && claims.challenger_image_hash
                == <[u8; 32]>::from(Sha256::digest(&inputs.rtms_challenge))
            && claims.credential_claim == <[u8; 32]>::from(Sha256::digest(&inputs.hashes_json))
            && valid_similarity(score)
            && score >= inputs.match_threshold
    }
}

/// A held match: the signed statement, and the document attesting the key that signed it.
///
/// The two travel together because nothing else binds them. The token's `kid` names a key; only
/// this document says an enclave running a measured image generated it.
///
/// Separate from the encryption key's attestation on purpose. This one outlives the exchange and
/// is carried into the `Verifier` proof; that one is transport setup, discarded with the channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedStatement {
    /// The signed statement.
    pub token: MatchToken,
    /// Raw COSE attestation document for the key that signed [`Self::token`].
    #[serde(with = "serde_bytes")]
    pub signing_key_attestation: Vec<u8>,
}

/// The authoritative result of a match.
///
/// Everything the enclave learns after opening the request travels in here rather than in the error
/// it returns to the host. Once a request has been opened there is a channel to answer on, so
/// surfacing any of it in the clear would tell the host about a plaintext it cannot read.
///
/// [`Self::Failed`] spans both a correct negative answer and unusable input: a match that scored
/// below the threshold failed in the same sense that a malformed payload did — no statement was
/// issued. It is *not* a transport error, and a client must not treat it as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchResult {
    /// The match held; carries the signed statement and the attestation for its key.
    Success(AttestedStatement),
    /// No statement was issued; carries why. No attestation: nothing to verify.
    Failed(FailureReason),
}

/// Fixed plaintext size of every sealed match response.
pub const MATCH_RESULT_ENVELOPE_LEN: usize = 16 * 1024;
const MATCH_RESULT_LENGTH_LEN: usize = 2;

impl MatchResult {
    /// Encodes the result as CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(encoded)
    }

    /// Encodes this result in the fixed-size sealed-response envelope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ResponseTooLarge`] when the result exceeds the envelope.
    pub fn to_padded_cbor(&self) -> Result<Vec<u8>, Error> {
        let encoded = self.to_cbor()?;
        let max_result_len = MATCH_RESULT_ENVELOPE_LEN - MATCH_RESULT_LENGTH_LEN;
        let length: u16 = encoded
            .len()
            .try_into()
            .map_err(|_| Error::ResponseTooLarge)?;
        if encoded.len() > max_result_len {
            return Err(Error::ResponseTooLarge);
        }

        let mut envelope = vec![0; MATCH_RESULT_ENVELOPE_LEN];
        envelope[..MATCH_RESULT_LENGTH_LEN].copy_from_slice(&length.to_be_bytes());
        envelope[MATCH_RESULT_LENGTH_LEN..MATCH_RESULT_LENGTH_LEN + encoded.len()]
            .copy_from_slice(&encoded);
        Ok(envelope)
    }

    /// Decodes a result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the bytes are not this framing.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|_| Error::Malformed)
    }

    /// Decodes a result from the fixed-size sealed-response envelope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for an invalid envelope or result.
    pub fn from_padded_cbor(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != MATCH_RESULT_ENVELOPE_LEN {
            return Err(Error::Malformed);
        }
        let length = u16::from_be_bytes(
            bytes[..MATCH_RESULT_LENGTH_LEN]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        ) as usize;
        let result_end = MATCH_RESULT_LENGTH_LEN
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::Malformed)?;
        if bytes[result_end..].iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed);
        }

        Self::from_cbor(&bytes[MATCH_RESULT_LENGTH_LEN..result_end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_claims_bind_input_hashes_and_enforce_the_live_threshold() {
        let inputs = MatchInputs::DeepFace(DeepFaceInputs {
            orb_credential: b"orb".to_vec().into(),
            live: LiveCapture::Vanilla(b"live".to_vec().into()),
            rtms_challenge: b"challenge".to_vec().into(),
            hashes_json: b"hashes".to_vec().into(),
            match_threshold: 0.5,
        });
        let claims = MatchClaims {
            live_image_hash: Sha256::digest(b"live").into(),
            credential_claim: Sha256::digest(b"hashes").into(),
            challenger_image_hash: Sha256::digest(b"challenge").into(),
            match_coefficient: 0.75,
        };
        assert!(inputs.matches_claims(&claims));
        for changed in [
            MatchClaims {
                live_image_hash: [0; 32],
                ..claims
            },
            MatchClaims {
                credential_claim: [0; 32],
                ..claims
            },
            MatchClaims {
                challenger_image_hash: [0; 32],
                ..claims
            },
        ] {
            assert!(!inputs.matches_claims(&changed));
        }
        for score in [0.25, -0.1, 1.1, f32::NAN, f32::INFINITY] {
            assert!(!inputs.matches_claims(&MatchClaims {
                match_coefficient: score,
                ..claims
            }));
        }
        // Neither unsupported mode may accept a legacy token as its result.
        assert!(!request().matches_claims(&claims));
        let MatchInputs::DeepFace(mut inputs) = inputs else {
            unreachable!()
        };
        inputs.live = LiveCapture::LightGuard {
            illuminated: b"live".to_vec().into(),
            unilluminated: b"other".to_vec().into(),
            matching_frame: LightGuardMatchingFrame::Illuminated,
        };
        assert!(!MatchInputs::DeepFace(inputs).matches_claims(&claims));
    }

    fn request() -> MatchInputs {
        MatchInputs::GrayBadge(GrayBadgeInputs {
            live: LiveCapture::Vanilla(vec![1, 2, 3].into()),
            rtms_challenge: vec![4, 5].into(),
            match_threshold: 0.5,
        })
    }
    #[test]
    fn wire_uses_byte_strings_and_explicit_operations() {
        let encoded = request().to_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(map[0].0.as_text(), Some("gray_badge"));
        let fields = map[0].1.as_map().unwrap();
        assert!(fields.iter().any(
            |(k, v)| k.as_text() == Some("rtms_challenge") && v.as_bytes() == Some(&vec![4, 5])
        ));
        assert!(matches!(
            MatchInputs::from_cbor(&encoded),
            Ok(MatchInputs::GrayBadge(_))
        ));
    }
    #[test]
    fn trailing_data_and_old_requests_are_rejected() {
        let mut encoded = request().to_cbor().unwrap();
        encoded.push(0);
        assert!(MatchInputs::from_cbor(&encoded).is_err());
        assert!(MatchInputs::from_cbor(b"invalid").is_err());
    }
    #[test]
    fn nonfinite_threshold_and_oversized_images_fail_before_encoding() {
        for value in [f64::NAN, f64::INFINITY, 1.01, -0.01] {
            let MatchInputs::GrayBadge(mut inputs) = request() else {
                unreachable!()
            };
            inputs.match_threshold = value;
            assert!(MatchInputs::GrayBadge(inputs).to_cbor().is_err());
        }
        let MatchInputs::GrayBadge(mut inputs) = request() else {
            unreachable!()
        };
        inputs.rtms_challenge = vec![0; MAX_IMAGE_BYTES + 1].into();
        let inputs = MatchInputs::GrayBadge(inputs);
        assert_eq!(inputs.validate(), Err(FailureReason::InputTooLarge));
        // A caller can bypass our encoder; the enclave must validate decoded fields too.
        let mut encoded = Vec::new();
        ciborium::into_writer(&inputs, &mut encoded).unwrap();
        let decoded = MatchInputs::from_cbor(&encoded).unwrap();
        assert_eq!(decoded.validate(), Err(FailureReason::InputTooLarge));
    }
    #[test]
    fn every_outcome_has_identical_envelope_size() {
        let success = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(vec![1; 512]),
            signing_key_attestation: vec![2; 5000],
        });
        let failure = MatchResult::Failed(FailureReason::UnsupportedCapture);
        let image_failure = MatchResult::Failed(FailureReason::ImageRejected {
            image: crate::sealed_types::ImageRole::LiveSelfie,
            reason: crate::sealed_types::ImageFailureReason::EyesClosed,
        });
        for result in [success, failure, image_failure] {
            let encoded = result.to_padded_cbor().unwrap();
            assert_eq!(encoded.len(), MATCH_RESULT_ENVELOPE_LEN);
            assert_eq!(MatchResult::from_padded_cbor(&encoded), Ok(result));
        }
    }
    #[test]
    fn ownership_conversion_keeps_the_image_allocation() {
        let image = vec![1u8; 1024];
        let pointer = image.as_ptr();
        let capture = LiveCapture::Vanilla(image.into());
        let LiveCapture::Vanilla(image) = capture else {
            unreachable!()
        };
        let image = image.into_vec();
        assert_eq!(image.as_ptr(), pointer);
    }
}
