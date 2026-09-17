//! Operation-specific match statements. See `docs/matches-api.md` for the signed encoding.
use crate::error::Error;
use ark_babyjubjub::Fq;
use ark_ff::PrimeField;
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, Header, RegisteredLabelWithPrivate};
pub use eddsa_babyjubjub::EdDSAPublicKey;
use eddsa_babyjubjub::EdDSASignature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// COSE identifier for `BabyJubJub` `EdDSA` Poseidon2.
pub const COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2: i64 = -65537;
/// Breaking operation-specific claim encoding.
pub const TOKEN_VERSION: u64 = 2;
/// Compressed signing key size.
pub const SIGNING_KEY_LEN: usize = 32;
const DOMAIN_SEPARATOR: &[u8] = b"WORLD_ID_FM_V2";

/// Which `LightGuard` frame supplies the matching embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightGuardMatchingFrame {
    /// Illuminated frame.
    Illuminated,
    /// Unilluminated frame.
    Unilluminated,
}

/// SHA-256 commitments to the exact encoded capture bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureCommitment {
    /// One vanilla image.
    Vanilla([u8; 32]),
    /// Both `LightGuard` images and the selection used for matching.
    LightGuard {
        /// Illuminated image hash.
        illuminated: [u8; 32],
        /// Unilluminated image hash.
        unilluminated: [u8; 32],
        /// Selected matching frame.
        matching_frame: LightGuardMatchingFrame,
    },
}

/// Scores use Tobi's names and raw cosine scale, [-1, 1].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeepFaceScores {
    /// Orb credential versus live selfie.
    pub similarity_orb_selfie: f64,
    /// Orb credential versus RTMS challenge.
    pub similarity_orb_challenge: f64,
    /// Live selfie versus RTMS challenge.
    pub similarity_selfie_challenge: f64,
}

/// `GrayBadge`'s single comparison.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrayBadgeScores {
    /// Live selfie versus RTMS challenge.
    pub similarity_selfie_challenge: f64,
}

/// Request context authenticated alongside scores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchContext {
    /// Capture hashes and capture mode.
    pub live: CaptureCommitment,
    /// SHA-256 of the RTMS challenge bytes.
    pub rtms_challenge: [u8; 32],
    /// Minimum raw cosine similarity applied to every comparison.
    pub match_threshold: f64,
}

/// Authenticated operation-specific results. No dummy credential fields for `GrayBadge`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchClaims {
    /// Three comparisons and the PCP binding.
    DeepFace {
        /// Common request context.
        context: MatchContext,
        /// SHA-256 of the exact Orb thumbnail bytes.
        orb_credential: [u8; 32],
        /// SHA-256 of the exact PCP hashes.json bytes (not proof of issuance).
        credential_claim: [u8; 32],
        /// All three raw cosine scores.
        scores: DeepFaceScores,
    },
    /// Live/challenge comparison without a credential.
    GrayBadge {
        /// Common request context.
        context: MatchContext,
        /// Raw cosine score.
        scores: GrayBadgeScores,
    },
}

impl MatchClaims {
    /// Common context bound to either operation.
    #[must_use]
    pub const fn context(&self) -> &MatchContext {
        match self {
            Self::DeepFace { context, .. } | Self::GrayBadge { context, .. } => context,
        }
    }

    /// Validate score range and successful-threshold semantics before signing or accepting.
    /// # Errors
    /// Rejects nonfinite, out-of-range or below-threshold scores.
    pub fn validate(&self) -> Result<(), Error> {
        let threshold = self.context().match_threshold;
        if !valid_similarity(threshold) {
            return Err(Error::UnrepresentableCoefficient);
        }
        let check = |score| valid_similarity(score) && score >= threshold;
        let valid = match self {
            Self::DeepFace { scores, .. } => {
                check(scores.similarity_orb_selfie)
                    && check(scores.similarity_orb_challenge)
                    && check(scores.similarity_selfie_challenge)
            }
            Self::GrayBadge { scores, .. } => check(scores.similarity_selfie_challenge),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::UnrepresentableCoefficient)
        }
    }

    // A deterministic, versioned CBOR array, encoded from typed fields in declaration order.
    fn claims(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut encoded = Vec::new();
        coset::cbor::into_writer(&(TOKEN_VERSION, self), &mut encoded)
            .map_err(|_| Error::Encoding)?;
        Ok(encoded)
    }

    /// Domain-separated Poseidon2 digest of the SHA-256 commitment to the canonical payload.
    /// # Errors
    /// Rejects invalid claims. This is the V2 proof-consumer contract, incompatible with V1.
    pub fn message_hash(&self) -> Result<Fq, Error> {
        let hash: [u8; 32] = Sha256::digest(self.claims()?).into();
        let limbs = hash_limbs(&hash);
        let mut state = [Fq::from(0u64); 8];
        state[0] = Fq::from_be_bytes_mod_order(DOMAIN_SEPARATOR);
        state[1] = limbs[0];
        state[2] = limbs[1];
        poseidon2::bn254::t8::permutation_in_place(&mut state);
        Ok(state[1])
    }
}

/// Whether a raw cosine value is finite and within [-1, 1].
#[must_use]
pub fn valid_similarity(value: f64) -> bool {
    value.is_finite() && (-1.0..=1.0).contains(&value)
}

/// A signed match token: an untagged `COSE_Sign1` over [`MatchClaims`].
///
/// A newtype so the bytes cannot be confused with any other buffer between [`build_token`] and
/// [`verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchToken(#[serde(with = "serde_bytes")] Vec<u8>);

impl MatchToken {
    /// Wraps already-encoded token bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the encoded token.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Borrows the encoded token.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Assembles a signed match token as an untagged `COSE_Sign1`.
///
/// The signature must cover [`MatchClaims::message_hash`] for the same claims. Key material stays
/// with the caller — the enclave owns it — so this only encodes what it is handed.
///
/// The protected header carries [`COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2`] and a `kid` holding the
/// compressed public key.
///
/// # Errors
///
/// Returns [`Error`] if a score or threshold is invalid, or if the claims,
/// signature, or public key cannot be serialized.
pub fn build_token(
    claims: &MatchClaims,
    signature: &EdDSASignature,
    signing_public_key: &EdDSAPublicKey,
) -> Result<MatchToken, Error> {
    let signature = signature
        .to_compressed_bytes()
        .map_err(|_| Error::KeyEncoding)?;
    let key_id = signing_public_key
        .to_compressed_bytes()
        .map_err(|_| Error::KeyEncoding)?;

    let protected = Header {
        alg: Some(RegisteredLabelWithPrivate::PrivateUse(
            COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
        )),
        key_id: key_id.to_vec(),
        ..Header::default()
    };

    CoseSign1Builder::new()
        .protected(protected)
        .payload(claims.claims()?)
        .signature(signature.to_vec())
        .build()
        .to_vec()
        .map(MatchToken::from_bytes)
        .map_err(|_| Error::Encoding)
}

/// Splits a 32-byte hash into two 128-bit big-endian limbs.
fn hash_limbs(hash: &[u8; 32]) -> [Fq; 2] {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&hash[..16]);
    lo.copy_from_slice(&hash[16..]);

    [
        Fq::from(u128::from_be_bytes(hi)),
        Fq::from(u128::from_be_bytes(lo)),
    ]
}

/// Verifies a serialized match token and returns the claims it commits to.
///
/// Note: Signature verification is performend in the circuit. This function is still provided for convenience.
///
/// # Errors
///
/// Returns [`Error`] if the token is not a well-formed `COSE_Sign1`, names another
/// algorithm, carries claims of an unexpected shape, or fails signature verification.
pub fn verify(
    token: &MatchToken,
    signing_public_key: &EdDSAPublicKey,
) -> Result<MatchClaims, Error> {
    let sign1 = CoseSign1::from_slice(token.as_bytes()).map_err(|_| Error::Malformed)?;

    match sign1.protected.header.alg {
        Some(RegisteredLabelWithPrivate::PrivateUse(COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2)) => {}
        _ => return Err(Error::UnexpectedAlgorithm),
    }

    let payload = sign1.payload.as_deref().ok_or(Error::Malformed)?;
    let claims = decode_claims(payload)?;

    let signature = <[u8; 64]>::try_from(sign1.signature.as_slice())
        .map_err(|_| Error::Malformed)
        .and_then(|bytes| {
            eddsa_babyjubjub::EdDSASignature::from_compressed_bytes(bytes)
                .map_err(|_| Error::Malformed)
        })?;

    if signing_public_key.verify(claims.message_hash()?, &signature) {
        Ok(claims)
    } else {
        Err(Error::SignatureInvalid)
    }
}

fn decode_claims(payload: &[u8]) -> Result<MatchClaims, Error> {
    let (version, claims): (u64, MatchClaims) =
        coset::cbor::from_reader(payload).map_err(|_| Error::Malformed)?;
    if version != TOKEN_VERSION {
        return Err(Error::UnsupportedTokenVersion);
    }
    if claims.claims()? != payload {
        return Err(Error::Malformed);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eddsa_babyjubjub::EdDSAPrivateKey;
    fn claims() -> MatchClaims {
        MatchClaims::GrayBadge {
            context: MatchContext {
                live: CaptureCommitment::Vanilla([1; 32]),
                rtms_challenge: [2; 32],
                match_threshold: -0.5,
            },
            scores: GrayBadgeScores {
                similarity_selfie_challenge: -0.25,
            },
        }
    }
    #[test]
    fn signed_negative_score_round_trips() {
        let key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let claims = claims();
        let token = build_token(
            &claims,
            &key.sign(claims.message_hash().unwrap()),
            &key.public(),
        )
        .unwrap();
        assert_eq!(verify(&token, &key.public()), Ok(claims));
    }
    #[test]
    fn every_context_and_score_is_bound() {
        let original = claims();
        let mut variants = Vec::new();
        for field in 0..4 {
            let mut changed = original.clone();
            let MatchClaims::GrayBadge { context, scores } = &mut changed else {
                unreachable!()
            };
            match field {
                0 => context.live = CaptureCommitment::Vanilla([3; 32]),
                1 => context.rtms_challenge = [3; 32],
                2 => context.match_threshold = -0.75,
                _ => scores.similarity_selfie_challenge = 0.5,
            }
            variants.push(changed);
        }
        for changed in variants {
            assert_ne!(original.message_hash(), changed.message_hash());
        }
    }
    #[test]
    fn invalid_scores_cannot_be_signed() {
        for value in [f64::NAN, f64::INFINITY, -1.1, 1.1, -0.75] {
            let mut c = claims();
            let MatchClaims::GrayBadge { scores, .. } = &mut c else {
                unreachable!()
            };
            scores.similarity_selfie_challenge = value;
            assert!(c.message_hash().is_err());
        }
    }
    #[test]
    fn mutations_fail_signature_verification() {
        let key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let c = claims();
        let token = build_token(&c, &key.sign(c.message_hash().unwrap()), &key.public()).unwrap();
        let mut sign1 = CoseSign1::from_slice(token.as_bytes()).unwrap();
        let mut changed = c;
        let MatchClaims::GrayBadge { scores, .. } = &mut changed else {
            unreachable!()
        };
        scores.similarity_selfie_challenge = 0.75;
        sign1.payload = Some(changed.claims().unwrap());
        assert_eq!(
            verify(
                &MatchToken::from_bytes(sign1.to_vec().unwrap()),
                &key.public()
            ),
            Err(Error::SignatureInvalid)
        );
    }
    #[test]
    fn frozen_claim_encoding() {
        let gray = claims();
        let deep = MatchClaims::DeepFace {
            context: gray.context().clone(),
            orb_credential: [3; 32],
            credential_claim: [4; 32],
            scores: DeepFaceScores {
                similarity_orb_selfie: 0.75,
                similarity_orb_challenge: 0.875,
                similarity_selfie_challenge: 0.9375,
            },
        };
        let vectors = [
            (
                gray,
                "4d92c1e2ccd876ae8938949db3e92560928eebfb2dc6d02a1b238e0240abc57e",
                "14491240167894508522494218986162224629619844214970339047621988342487863332047",
            ),
            (
                deep,
                "54bf24073aaeaa91814cda0545fc98e0913dd062bb973b371051fa76ec741245",
                "19811348251815745611443440052035379723738992838256880595205668972482548281469",
            ),
        ];
        for (claim, expected_payload_hash, expected_field) in vectors {
            assert_eq!(
                format!("{:x}", Sha256::digest(claim.claims().unwrap())),
                expected_payload_hash
            );
            assert_eq!(claim.message_hash().unwrap().to_string(), expected_field);
        }
    }
    #[test]
    fn deep_face_and_light_guard_bind_every_field() {
        let original = MatchClaims::DeepFace {
            context: MatchContext {
                live: CaptureCommitment::LightGuard {
                    illuminated: [1; 32],
                    unilluminated: [2; 32],
                    matching_frame: LightGuardMatchingFrame::Illuminated,
                },
                rtms_challenge: [3; 32],
                match_threshold: 0.5,
            },
            orb_credential: [4; 32],
            credential_claim: [5; 32],
            scores: DeepFaceScores {
                similarity_orb_selfie: 0.75,
                similarity_orb_challenge: 0.8,
                similarity_selfie_challenge: 0.9,
            },
        };
        for field in 0..8 {
            let mut changed = original.clone();
            let MatchClaims::DeepFace {
                context,
                orb_credential,
                credential_claim,
                scores,
            } = &mut changed
            else {
                unreachable!()
            };
            let CaptureCommitment::LightGuard {
                illuminated,
                unilluminated,
                matching_frame,
            } = &mut context.live
            else {
                unreachable!()
            };
            match field {
                0 => *illuminated = [9; 32],
                1 => *unilluminated = [9; 32],
                2 => *matching_frame = LightGuardMatchingFrame::Unilluminated,
                3 => *orb_credential = [9; 32],
                4 => *credential_claim = [9; 32],
                5 => scores.similarity_orb_selfie = 1.0,
                6 => scores.similarity_orb_challenge = 1.0,
                _ => scores.similarity_selfie_challenge = 1.0,
            }
            assert_ne!(original.message_hash(), changed.message_hash());
        }
    }
    #[test]
    fn rejects_another_version_key_and_noncanonical_payload() {
        let claims = claims();
        let key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let token = build_token(
            &claims,
            &key.sign(claims.message_hash().unwrap()),
            &key.public(),
        )
        .unwrap();
        let other = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        assert_eq!(
            verify(&token, &other.public()),
            Err(Error::SignatureInvalid)
        );
        let mut bytes = claims.claims().unwrap();
        bytes[1] = 1; // first tuple element is the token version
        assert_eq!(decode_claims(&bytes), Err(Error::UnsupportedTokenVersion));
        let mut bytes = claims.claims().unwrap();
        bytes.push(0);
        assert_eq!(decode_claims(&bytes), Err(Error::Malformed));
    }
}
