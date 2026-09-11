//! The two ends of one match exchange: what the requester seals in, and what the enclave seals
//! back. The host relays both ciphertexts and holds no key for either.

use flamingo_verifier_protocol::match_token::MatchToken;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;

/// The sealed inputs to one match.
///
/// All three frames travel here; the requester downloads the challenge image from the RP itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInputs {
    /// Raw liveness image bytes.
    #[serde(with = "serde_bytes")]
    pub live_image: Vec<u8>,
    /// Raw credential image bytes (the Orb PCP thumbnail).
    #[serde(with = "serde_bytes")]
    pub credential_image: Vec<u8>,
    /// The second liveness frame `LightGuard` analyses, if the requester captured one.
    ///
    /// Absent selects vanilla mode — the credential-against-live-and-challenge flow. Present
    /// selects the `LightGuard` flow, which the enclave does not implement yet.
    #[serde(default, with = "serde_bytes")]
    pub light_guard_image: Option<Vec<u8>>,
    /// Raw `hashes.json` bytes from the PCP.
    #[serde(with = "serde_bytes")]
    pub hashes_json: Vec<u8>,
    /// The RP's challenge frame, as the requester downloaded it.
    #[serde(with = "serde_bytes")]
    pub challenge_image: Vec<u8>,
    /// Minimum similarity the RP requires, finite and in [0, 1] for nonnegative match claims.
    pub match_threshold: f32,
}

impl MatchInputs {
    /// Encodes the inputs as CBOR. [`Zeroizing`] because it holds biometric images.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(Zeroizing::new(encoded))
    }

    /// Decodes the inputs from CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the bytes are not this framing.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut remaining = bytes;
        let inputs: Self = ciborium::from_reader(&mut remaining).map_err(|_| Error::Malformed)?;
        if !remaining.is_empty() {
            return Err(Error::Malformed);
        }

        Ok(inputs)
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
        let mut remaining = bytes;
        let result = ciborium::from_reader(&mut remaining).map_err(|_| Error::Malformed)?;
        if !remaining.is_empty() {
            return Err(Error::Malformed);
        }

        Ok(result)
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

/// Why no statement was issued.
///
/// Each of these is a fact about the sealed plaintext — either what it contained or what the
/// analysis made of it — so naming any of them in the clear would describe content the host cannot
/// read. They travel sealed without exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    /// The plaintext was not the CBOR framing [`MatchInputs`] writes.
    MalformedInputs,
    /// `hashes.json` was absent, not JSON, or missing a usable `thumbnail.png` entry.
    InvalidHashesJson,
    /// The credential image did not match the `thumbnail.png` hash committed in `hashes.json`.
    ThumbnailHashMismatch,
    /// A comparison scored below the RP-supplied `match_threshold`.
    MatchBelowThreshold,
    /// The enclave could not get from the images to a score. Covers a decode failure, a quality
    /// rejection, an unusable frame, and a matcher that failed on well-formed embeddings.
    /// These outcomes must not appear in enclave logs or metrics.
    ImageAnalysisFailed,
}

#[cfg(test)]
mod tests {
    use flamingo_verifier_protocol::match_token::MatchToken;

    use super::{
        AttestedStatement, Error, FailureReason, MATCH_RESULT_ENVELOPE_LEN, MatchInputs,
        MatchResult,
    };

    fn inputs() -> MatchInputs {
        MatchInputs {
            live_image: b"liveness-frame".to_vec(),
            credential_image: b"credential-thumbnail".to_vec(),
            light_guard_image: None,
            hashes_json: br#"{"thumbnail.png":"aa"}"#.to_vec(),
            challenge_image: b"challenge-frame".to_vec(),
            match_threshold: 0.5,
        }
    }

    #[test]
    fn inputs_round_trip() {
        let encoded = inputs().to_cbor().expect("encoding should succeed");

        let decoded = MatchInputs::from_cbor(&encoded).expect("decoding should succeed");

        assert_eq!(decoded.live_image, inputs().live_image);
        assert_eq!(decoded.credential_image, inputs().credential_image);
        assert_eq!(decoded.light_guard_image, inputs().light_guard_image);
        assert_eq!(decoded.hashes_json, inputs().hashes_json);
        assert_eq!(decoded.challenge_image, inputs().challenge_image);
        assert_eq!(
            decoded.match_threshold.to_bits(),
            inputs().match_threshold.to_bits()
        );
    }

    #[test]
    fn a_light_guard_image_round_trips() {
        let mut inputs = inputs();
        inputs.light_guard_image = Some(b"second-liveness-frame".to_vec());
        let encoded = inputs.to_cbor().expect("encoding should succeed");

        let decoded = MatchInputs::from_cbor(&encoded).expect("decoding should succeed");

        assert_eq!(
            decoded.light_guard_image.as_deref(),
            Some(&b"second-liveness-frame"[..])
        );
    }

    /// A payload with no challenge frame must be refused rather than defaulted to empty, which
    /// would compare a face against nothing.
    #[test]
    fn inputs_without_a_challenge_image_do_not_decode() {
        #[derive(serde::Serialize)]
        struct WithoutChallenge {
            #[serde(with = "serde_bytes")]
            live_image: Vec<u8>,
            #[serde(with = "serde_bytes")]
            credential_image: Vec<u8>,
            #[serde(default, with = "serde_bytes")]
            light_guard_image: Option<Vec<u8>>,
            #[serde(with = "serde_bytes")]
            hashes_json: Vec<u8>,
            match_threshold: f32,
        }

        let old = WithoutChallenge {
            live_image: b"liveness-frame".to_vec(),
            credential_image: b"credential-thumbnail".to_vec(),
            light_guard_image: None,
            hashes_json: br#"{"thumbnail.png":"aa"}"#.to_vec(),
            match_threshold: 0.5,
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&old, &mut encoded).expect("encoding should succeed");

        assert_eq!(
            MatchInputs::from_cbor(&encoded).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn rejects_non_cbor_inputs() {
        assert_eq!(
            MatchInputs::from_cbor(b"not cbor framing").err(),
            Some(Error::Malformed)
        );
    }

    /// A valid value cannot hide a second payload or nonzero envelope data.
    #[test]
    fn rejects_trailing_bytes_on_inputs_and_results() {
        let mut input = inputs().to_cbor().unwrap().to_vec();
        input.push(0);
        assert_eq!(MatchInputs::from_cbor(&input).err(), Some(Error::Malformed));

        let mut result = MatchResult::Failed(FailureReason::MalformedInputs)
            .to_cbor()
            .unwrap();
        result.push(0);
        assert_eq!(MatchResult::from_cbor(&result), Err(Error::Malformed));
    }

    #[test]
    fn results_round_trip_every_variant() {
        let success = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
            signing_key_attestation: b"cose-attestation-document".to_vec(),
        });
        let below = MatchResult::Failed(FailureReason::MatchBelowThreshold);
        let malformed = MatchResult::Failed(FailureReason::MalformedInputs);

        for result in [success, below, malformed] {
            let encoded = result.to_cbor().expect("encoding should succeed");

            assert_eq!(
                MatchResult::from_cbor(&encoded).expect("decoding should succeed"),
                result
            );
        }
    }

    #[test]
    fn result_envelopes_have_the_same_length_for_every_outcome() {
        let success = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
            signing_key_attestation: vec![7; 5_000],
        });
        let failures = [
            FailureReason::MalformedInputs,
            FailureReason::InvalidHashesJson,
            FailureReason::ThumbnailHashMismatch,
            FailureReason::MatchBelowThreshold,
            FailureReason::ImageAnalysisFailed,
        ];

        let success_envelope = success.to_padded_cbor().expect("success should fit");

        assert_eq!(success_envelope.len(), MATCH_RESULT_ENVELOPE_LEN);
        assert_eq!(
            MatchResult::from_padded_cbor(&success_envelope),
            Ok(success)
        );
        for failure in failures {
            let envelope = MatchResult::Failed(failure)
                .to_padded_cbor()
                .expect("failure should fit");
            assert_eq!(envelope.len(), MATCH_RESULT_ENVELOPE_LEN);
            assert_eq!(
                MatchResult::from_padded_cbor(&envelope),
                Ok(MatchResult::Failed(failure))
            );
        }
    }

    #[test]
    fn rejects_a_result_that_does_not_fit_the_envelope() {
        let result = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
            signing_key_attestation: vec![0; MATCH_RESULT_ENVELOPE_LEN],
        });

        assert_eq!(result.to_padded_cbor(), Err(Error::ResponseTooLarge));
    }

    /// A round trip that dropped the document would leave a token nothing can verify.
    #[test]
    fn a_statement_carries_its_attestation_through_cbor() {
        let document: Vec<u8> = (0..=255u8).cycle().take(5_000).collect();
        let result = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
            signing_key_attestation: document.clone(),
        });

        let encoded = result.to_cbor().expect("encoding should succeed");
        let MatchResult::Success(decoded) =
            MatchResult::from_cbor(&encoded).expect("decoding should succeed")
        else {
            panic!("a held match decodes as a statement");
        };

        assert_eq!(decoded.signing_key_attestation, document);
        assert_eq!(decoded.token.as_bytes(), b"cose-sign1");
    }

    /// A rejection has no statement, so there is nothing for a document to attest.
    #[test]
    fn a_rejection_carries_no_attestation() {
        let encoded = MatchResult::Failed(FailureReason::MatchBelowThreshold)
            .to_cbor()
            .expect("encoding should succeed");

        assert!(encoded.len() < 64, "a rejection stays small: {encoded:?}");
    }

    #[test]
    fn rejects_non_cbor_results() {
        assert_eq!(
            MatchResult::from_cbor(b"not cbor framing").err(),
            Some(Error::Malformed)
        );
    }
}
