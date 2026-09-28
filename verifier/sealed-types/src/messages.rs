//! Typed CBOR payloads. Image ownership moves across inference adapters without cloning.
use crate::{Error, FailureReason};
use flamingo_verifier_api_types::{
    MAX_HASHES_JSON_BYTES, MAX_IMAGE_BYTES, MAX_MATCH_PLAINTEXT_BYTES, MAX_TOTAL_IMAGE_BYTES,
};
use flamingo_verifier_protocol::match_token::{MatchClaims, MatchOperation, MatchToken};
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

/// Whether a normalized cosine value is finite and within [0, 1].
#[must_use]
pub fn valid_similarity(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

/// Maximum frames in one live capture.
pub const MAX_LIVE_FRAMES: usize = 8;
/// Maximum UTF-8 bytes in a capture profile name.
pub const MAX_CAPTURE_PROFILE_BYTES: usize = 32;

/// A live capture: ordered frames whose meaning the sandboxed engine derives from `profile`.
///
/// The profile is opaque here; which profiles exist is up to the engine adapter.
///
/// Capture bytes are deliberately not Debug or Clone.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCapture {
    /// Names how the engine reads `frames`, e.g. `light_guard`.
    pub profile: String,
    /// Encoded frames, in the order the profile defines.
    pub frames: Vec<ByteBuf>,
    /// Index into `frames` of the frame that supplies the matching embedding.
    pub matching_frame: u32,
}

impl LiveCapture {
    /// Commits to the profile, every frame in order and the matching-frame index.
    /// The profile is length-prefixed and frame hashes have fixed width, so no boundary can shift.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"flamingo/live-capture/v1");
        hash.update(len_prefix(self.profile.len()));
        hash.update(self.profile.as_bytes());
        hash.update(len_prefix(self.frames.len()));
        for frame in &self.frames {
            hash.update(Sha256::digest(frame));
        }
        hash.update(self.matching_frame.to_be_bytes());

        hash.finalize().into()
    }

    /// Profile-independent shape checks; the engine adapter checks the profile itself.
    fn validate(&self) -> Result<(), FailureReason> {
        let matching_frame = usize::try_from(self.matching_frame).unwrap_or(usize::MAX);
        if self.profile.is_empty()
            || self.profile.len() > MAX_CAPTURE_PROFILE_BYTES
            || self.frames.is_empty()
            || self.frames.len() > MAX_LIVE_FRAMES
            || matching_frame >= self.frames.len()
        {
            return Err(FailureReason::MalformedInputs);
        }

        Ok(())
    }

    fn images(&self) -> impl Iterator<Item = &ByteBuf> {
        self.frames.iter()
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "callers pass lengths bounded by validation"
)]
const fn len_prefix(len: usize) -> [u8; 4] {
    (len as u32).to_be_bytes()
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

        live.validate()?;

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

    /// Checks the signed operation, input commitments and score against this request.
    #[must_use]
    pub fn matches_claims(&self, claims: &MatchClaims) -> bool {
        let (live, challenge, threshold, operation) = match self {
            Self::DeepFace(inputs) => (
                &inputs.live,
                &inputs.rtms_challenge,
                inputs.match_threshold,
                MatchOperation::DeepFace {
                    credential_claim: Sha256::digest(&inputs.hashes_json).into(),
                },
            ),
            Self::GrayBadge(inputs) => (
                &inputs.live,
                &inputs.rtms_challenge,
                inputs.match_threshold,
                MatchOperation::GrayBadge,
            ),
        };
        let score = f64::from(claims.match_coefficient);

        self.validate().is_ok()
            && claims.operation == operation
            && claims.live_capture_hash == live.commitment()
            && claims.challenger_image_hash == <[u8; 32]>::from(Sha256::digest(challenge))
            && valid_similarity(score)
            && score >= threshold
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
    fn claims_bind_operation_input_hashes_and_enforce_the_threshold() {
        let inputs = MatchInputs::DeepFace(DeepFaceInputs {
            orb_credential: b"orb".to_vec().into(),
            live: capture("vanilla", &[b"live"], 0),
            rtms_challenge: b"challenge".to_vec().into(),
            hashes_json: b"hashes".to_vec().into(),
            match_threshold: 0.5,
        });
        let claims = MatchClaims {
            live_capture_hash: capture("vanilla", &[b"live"], 0).commitment(),
            operation: MatchOperation::DeepFace {
                credential_claim: Sha256::digest(b"hashes").into(),
            },
            challenger_image_hash: Sha256::digest(b"challenge").into(),
            match_coefficient: 0.75,
        };
        assert!(inputs.matches_claims(&claims));
        for changed in [
            MatchClaims {
                live_capture_hash: [0; 32],
                ..claims
            },
            MatchClaims {
                operation: MatchOperation::DeepFace {
                    credential_claim: [0; 32],
                },
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
        // Another operation or capture cannot accept this token as its result.
        assert!(!request().matches_claims(&claims));
        let MatchInputs::DeepFace(mut inputs) = inputs else {
            unreachable!()
        };
        inputs.live = capture("light_guard", &[b"live", b"other"], 0);
        assert!(!MatchInputs::DeepFace(inputs).matches_claims(&claims));
    }

    fn capture(profile: &str, frames: &[&[u8]], matching_frame: u32) -> LiveCapture {
        LiveCapture {
            profile: profile.to_owned(),
            frames: frames.iter().map(|frame| frame.to_vec().into()).collect(),
            matching_frame,
        }
    }

    #[test]
    fn commitment_binds_profile_every_frame_order_and_selection() {
        let light_guard =
            |frames: &[&[u8]], matching_frame| capture("light_guard", frames, matching_frame);
        let live = light_guard(&[b"lit", b"dark"], 0);
        let claims = MatchClaims {
            live_capture_hash: live.commitment(),
            operation: MatchOperation::GrayBadge,
            challenger_image_hash: Sha256::digest(b"challenge").into(),
            match_coefficient: 0.75,
        };
        let inputs = |live| {
            MatchInputs::GrayBadge(GrayBadgeInputs {
                live,
                rtms_challenge: b"challenge".to_vec().into(),
                match_threshold: 0.5,
            })
        };
        assert!(inputs(live).matches_claims(&claims));

        for changed in [
            light_guard(&[b"changed", b"dark"], 0),
            light_guard(&[b"lit", b"changed"], 0),
            light_guard(&[b"lit", b"dark"], 1),
            light_guard(&[b"dark", b"lit"], 0),
            light_guard(&[b"lit", b"dark", b"extra"], 0),
            capture("other", &[b"lit", b"dark"], 0),
            // Moving bytes between the profile and a frame must not collide.
            capture("light_guar", &[b"lit", b"dark"], 0),
            capture("vanilla", &[b"lit"], 0),
        ] {
            assert!(!inputs(changed).matches_claims(&claims));
        }
    }

    fn request() -> MatchInputs {
        MatchInputs::GrayBadge(GrayBadgeInputs {
            live: capture("vanilla", &[&[1, 2, 3]], 0),
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
        let failure = MatchResult::Failed(FailureReason::MalformedInputs);
        let image_failure = MatchResult::Failed(FailureReason::ImageRejected {
            image: crate::ImageRole::LiveSelfie,
            reason: crate::ImageFailureReason::EyesClosed,
        });
        for result in [success, failure, image_failure] {
            let encoded = result.to_padded_cbor().unwrap();
            assert_eq!(encoded.len(), MATCH_RESULT_ENVELOPE_LEN);
            assert_eq!(MatchResult::from_padded_cbor(&encoded), Ok(result));
        }
    }

    #[test]
    fn malformed_capture_shapes_are_rejected() {
        let long_profile = "p".repeat(MAX_CAPTURE_PROFILE_BYTES + 1);
        let too_many: Vec<&[u8]> = vec![b"frame"; MAX_LIVE_FRAMES + 1];
        for live in [
            capture("", &[b"frame"], 0),
            capture(&long_profile, &[b"frame"], 0),
            capture("vanilla", &[], 0),
            capture("vanilla", &too_many, 0),
            capture("light_guard", &[b"lit", b"dark"], 2),
            capture("light_guard", &[b"lit", b"dark"], u32::MAX),
        ] {
            let inputs = MatchInputs::GrayBadge(GrayBadgeInputs {
                live,
                rtms_challenge: b"challenge".to_vec().into(),
                match_threshold: 0.5,
            });
            assert_eq!(inputs.validate(), Err(FailureReason::MalformedInputs));
        }
        // The profile is opaque here; only the engine adapter knows which profiles exist.
        let unknown = MatchInputs::GrayBadge(GrayBadgeInputs {
            live: capture("future_pad", &[b"a", b"b", b"c"], 2),
            rtms_challenge: b"challenge".to_vec().into(),
            match_threshold: 0.5,
        });
        assert_eq!(unknown.validate(), Ok(()));
    }

    #[test]
    fn ownership_conversion_keeps_the_image_allocation() {
        let image = vec![1u8; 1024];
        let pointer = image.as_ptr();
        let capture = LiveCapture {
            profile: "vanilla".to_owned(),
            frames: vec![image.into()],
            matching_frame: 0,
        };
        let image = capture.frames.into_iter().next().unwrap().into_vec();
        assert_eq!(image.as_ptr(), pointer);
    }
}
