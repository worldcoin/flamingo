use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de::Visitor};

/// Inputs required for one three-way face comparison.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareRequest {
    /// Raw credential image bytes from the user's Personal Custody Package.
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "image_bytes"
    )]
    pub credential_image: Vec<u8>,
    /// Raw live image bytes captured by the authenticator.
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "image_bytes"
    )]
    pub live_image: Vec<u8>,
    /// Raw challenge image bytes supplied by the relying party.
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "image_bytes"
    )]
    pub challenge_image: Vec<u8>,
}

/// The only worker replies; infrastructure failures terminate the connection.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum WorkerResult {
    /// The worker produced both required similarity scores.
    Compared(ComparisonScores),
    /// The worker could not decode, analyze, or compare at least one image.
    AnalysisFailed,
}

/// Similarity scores for one credential image against the live and challenge images.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonScores {
    /// Credential-to-live similarity.
    pub live_similarity: f32,
    /// Credential-to-challenge similarity.
    pub challenge_similarity: f32,
}

impl CompareRequest {
    /// Checks encoded-image byte limits; decoded-pixel limits belong to the model adapter.
    #[must_use]
    pub fn valid_image_sizes(&self, max_bytes: usize) -> bool {
        [
            &self.credential_image,
            &self.live_image,
            &self.challenge_image,
        ]
        .iter()
        .all(|image| !image.is_empty() && image.len() <= max_bytes)
    }
}

impl fmt::Debug for CompareRequest {
    /// Redacts image contents.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompareRequest")
            .field("credential_image_bytes", &self.credential_image.len())
            .field("live_image_bytes", &self.live_image.len())
            .field("challenge_image_bytes", &self.challenge_image.len())
            .finish()
    }
}

/// Rejects arrays with attacker-controlled allocation hints.
fn image_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    /// Accepts byte buffers while rejecting sequence-based image encodings.
    struct Bytes;
    impl Visitor<'_> for Bytes {
        type Value = Vec<u8>;

        /// Describes the accepted CBOR type without exposing image data.
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an encoded image byte string")
        }

        /// Takes ownership of the bounded decoder's byte buffer.
        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(bytes)
        }
    }
    deserializer.deserialize_byte_buf(Bytes)
}
