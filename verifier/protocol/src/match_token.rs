//! Match-result tokens: CWTs (RFC 8392) carrying private claims.
//! Note: This is a WIP module and will probably move to the `world-id-protocol` repo.
//!
//! The enclave signs operation-specific match claims. They are not yet aligned with the
//! WIP-110/WIP-111 token consumed by the proposed embedding-similarity circuit.
//!

use ark_babyjubjub::Fq;
use ark_ff::PrimeField;
use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, Header, RegisteredLabelWithPrivate,
    cbor::value::Value,
};
use eddsa_babyjubjub::EdDSASignature;
use serde::{Deserialize, Serialize};

use crate::error::Error;
// Re-exported so consumers holding attested bytes can build the key `verify` takes, without
// depending on eddsa-babyjubjub directly.
pub use eddsa_babyjubjub::EdDSAPublicKey;

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2`, as defined in WIP-106.
pub const COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2: i64 = -65537;

/// Version of this token's encoding.
pub const TOKEN_VERSION: u64 = 2;

// The `-81_00x` block is unallocated: WIP-106's own private claims sit at `-80_000`, `-80_001`, and
// `-70_000`, so these claims keep clear of those while staying in the same negative range. Nothing
// reserves the block for us, which is what makes the keys provisional — ratification is pending.

/// Private CWT claim key for [`TOKEN_VERSION`]. Frozen across versions; never renumber.
pub const CLAIM_VERSION: i64 = -81_004;

/// Private CWT claim key for `live_capture_hash`. Provisional.
pub const CLAIM_LIVE_CAPTURE_HASH: i64 = -81_000;
/// Private CWT claim key for `credential_claim`. Provisional.
pub const CLAIM_CREDENTIAL_CLAIM: i64 = -81_001;
/// Private CWT claim key for `challenger_image_hash`. Provisional.
pub const CLAIM_CHALLENGER_IMAGE_HASH: i64 = -81_002;
/// Private CWT claim key for `match_coefficient`. Provisional.
pub const CLAIM_MATCH_COEFFICIENT: i64 = -81_003;

/// Private CWT claim key for the operation (1 = `DeepFace`, 2 = `GrayBadge`).
pub const CLAIM_OPERATION: i64 = -81_005;

/// The operation and its operation-specific commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOperation {
    /// Three-way matching bound to a PCP commitment.
    DeepFace {
        /// SHA-256 of the exact PCP hashes.json bytes.
        credential_claim: [u8; 32],
    },
    /// Live/challenge matching without a credential.
    GrayBadge,
}

impl MatchOperation {
    const fn id(self) -> u64 {
        match self {
            Self::DeepFace { .. } => 1,
            Self::GrayBadge => 2,
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::DeepFace { .. } => b"WORLD_ID_DFVT_V2",
            Self::GrayBadge => b"WORLD_ID_GBVT_V2",
        }
    }
}

/// Fixed-point scale applied to `match_coefficient` before it becomes a field element.
///
/// A power of two so unscaling is a shift. `f32` carries ~24 mantissa bits, so the low six are
/// noise. Provisional.
pub const MATCH_COEFFICIENT_SCALE: u32 = 1 << 30;

/// Width of the Poseidon2 permutation the digest uses.
const POSEIDON2_WIDTH: usize = 8;

/// Number of field elements the claims lower to: two limbs per hash plus the coefficient.
const CLAIM_ELEMENTS: usize = 7;

// The domain separator occupies slot 0 and the claims fill the rest exactly. Checked at compile
// time so adding a claim cannot silently overflow the permutation.
const _: () = assert!(CLAIM_ELEMENTS + 1 == POSEIDON2_WIDTH);

/// Length of a compressed `BabyJubJub` public key.
pub const SIGNING_KEY_LEN: usize = 32;

/// The claims a match token commits to.
///
/// The operation is signed through its own domain; `GrayBadge` carries no credential claim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchClaims {
    /// Commitment to the capture variant, all live frames and the matching-frame selection.
    pub live_capture_hash: [u8; 32],
    /// Matching operation and its credential commitment, when applicable.
    pub operation: MatchOperation,
    /// SHA-256 of the challenge image.
    pub challenger_image_hash: [u8; 32],
    /// Credential/live similarity for `DeepFace`; live/challenge similarity for `GrayBadge`.
    pub match_coefficient: f32,
}

impl MatchClaims {
    /// Builds the CWT claims set as a deterministic CBOR map.
    fn claims(&self) -> Result<Vec<u8>, Error> {
        let mut entries = vec![
            (
                Value::Integer(CLAIM_LIVE_CAPTURE_HASH.into()),
                Value::Bytes(self.live_capture_hash.to_vec()),
            ),
            (
                Value::Integer(CLAIM_CHALLENGER_IMAGE_HASH.into()),
                Value::Bytes(self.challenger_image_hash.to_vec()),
            ),
            (
                Value::Integer(CLAIM_MATCH_COEFFICIENT.into()),
                Value::Integer(self.scaled_coefficient()?.into()),
            ),
            (
                Value::Integer(CLAIM_VERSION.into()),
                Value::Integer(TOKEN_VERSION.into()),
            ),
            (
                Value::Integer(CLAIM_OPERATION.into()),
                Value::Integer(self.operation.id().into()),
            ),
        ];
        if let MatchOperation::DeepFace { credential_claim } = self.operation {
            entries.insert(
                1,
                (
                    Value::Integer(CLAIM_CREDENTIAL_CLAIM.into()),
                    Value::Bytes(credential_claim.to_vec()),
                ),
            );
        }

        let claims = Value::Map(entries);
        let mut encoded = Vec::new();
        coset::cbor::into_writer(&claims, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(encoded)
    }

    /// Scales `match_coefficient` into a non-negative fixed-point integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnrepresentableCoefficient`] if the score is not finite, is
    /// negative, or does not fit the fixed-point integer. Claims that cannot commit to their own
    /// score are not signed at all.
    fn scaled_coefficient(&self) -> Result<u32, Error> {
        // NaN and infinity have no field-element representation, and the target is unsigned.
        if !self.match_coefficient.is_finite() || self.match_coefficient < 0.0 {
            return Err(Error::UnrepresentableCoefficient);
        }

        // Both operands widen losslessly.
        let scaled =
            (f64::from(self.match_coefficient) * f64::from(MATCH_COEFFICIENT_SCALE)).round();

        // `u32::MAX` converts to `f64` exactly, so this bounds by what the encoding holds.
        if scaled > f64::from(u32::MAX) {
            return Err(Error::UnrepresentableCoefficient);
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "non-negative and bounded by the checks above"
        )]
        Ok(scaled as u32)
    }

    /// Lowers the claims into the Poseidon2 state and returns the digest.
    ///
    /// Slot 0 holds the domain separator, the remaining seven hold the claim elements. The digest
    /// is element 1 of the permuted state, matching the Trust Anchor Key Token.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `match_coefficient` cannot be represented.
    pub fn message_hash(&self) -> Result<Fq, Error> {
        let coefficient = self.scaled_coefficient()?;

        let mut state = [Fq::from(0u64); POSEIDON2_WIDTH];
        // 16 bytes, so `mod_order` cannot reduce it; the call is the lowering WIP-106 specifies.
        state[0] = Fq::from_be_bytes_mod_order(self.operation.domain());

        // GrayBadge reserves zero limbs here; the distinct operation domain prevents aliasing
        // it with a DeepFace claim whose credential commitment happens to be all zeros.
        let credential_claim = match self.operation {
            MatchOperation::DeepFace { credential_claim } => credential_claim,
            MatchOperation::GrayBadge => [0; 32],
        };
        let mut slot = 1;
        for hash in [
            &self.live_capture_hash,
            &credential_claim,
            &self.challenger_image_hash,
        ] {
            for limb in hash_limbs(hash) {
                state[slot] = limb;
                slot += 1;
            }
        }
        state[slot] = Fq::from(coefficient);

        poseidon2::bn254::t8::permutation_in_place(&mut state);

        Ok(state[1])
    }
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
/// Returns [`Error`] if the coefficient cannot be represented, or if the claims,
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

/// Rebuilds [`MatchClaims`] from an encoded claims set.
///
/// Note: This function is not needed for the proof, but it is provided for convenience.
fn decode_claims(payload: &[u8]) -> Result<MatchClaims, Error> {
    let claims: Value = coset::cbor::from_reader(payload).map_err(|_| Error::Malformed)?;
    let entries = claims.as_map().ok_or(Error::Malformed)?;

    // Reject duplicate or unknown keys instead of silently accepting ambiguous statements.
    let mut keys = std::collections::BTreeSet::new();
    for (key, _) in entries {
        let key = key
            .as_integer()
            .and_then(|key| i64::try_from(i128::from(key)).ok())
            .ok_or(Error::Malformed)?;
        if !matches!(
            key,
            CLAIM_LIVE_CAPTURE_HASH
                | CLAIM_CREDENTIAL_CLAIM
                | CLAIM_CHALLENGER_IMAGE_HASH
                | CLAIM_MATCH_COEFFICIENT
                | CLAIM_VERSION
                | CLAIM_OPERATION
        ) || !keys.insert(key)
        {
            return Err(Error::Malformed);
        }
    }

    let lookup = |key: i64| {
        entries
            .iter()
            .find(|(k, _)| k.as_integer() == Some(key.into()))
            .map(|(_, v)| v)
            .ok_or(Error::Malformed)
    };

    let hash = |key: i64| -> Result<[u8; 32], Error> {
        lookup(key)?
            .as_bytes()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or(Error::Malformed)
    };

    let version = lookup(CLAIM_VERSION)?
        .as_integer()
        .and_then(|value| u64::try_from(i128::from(value)).ok())
        .ok_or(Error::Malformed)?;
    if version != TOKEN_VERSION {
        return Err(Error::UnsupportedTokenVersion);
    }

    // Bounded to `u32`, which is all `scaled_coefficient` produces, so the widening is lossless.
    let scaled = lookup(CLAIM_MATCH_COEFFICIENT)?
        .as_integer()
        .and_then(|value| u32::try_from(i128::from(value)).ok())
        .ok_or(Error::Malformed)?;

    let unscaled = f64::from(scaled) / f64::from(MATCH_COEFFICIENT_SCALE);

    #[expect(
        clippy::cast_possible_truncation,
        reason = "narrowing back to the f32 the claims were built from is the intent"
    )]
    let match_coefficient = unscaled as f32;

    let operation = match lookup(CLAIM_OPERATION)?.as_integer().map(i128::from) {
        Some(1) if entries.len() == 6 => MatchOperation::DeepFace {
            credential_claim: hash(CLAIM_CREDENTIAL_CLAIM)?,
        },
        Some(2) if entries.len() == 5 && !keys.contains(&CLAIM_CREDENTIAL_CLAIM) => {
            MatchOperation::GrayBadge
        }
        _ => return Err(Error::Malformed),
    };

    Ok(MatchClaims {
        live_capture_hash: hash(CLAIM_LIVE_CAPTURE_HASH)?,
        operation,
        challenger_image_hash: hash(CLAIM_CHALLENGER_IMAGE_HASH)?,
        match_coefficient,
    })
}

#[cfg(test)]
mod tests {
    use ark_babyjubjub::Fq;
    use coset::{CborSerializable as _, CoseSign1, CoseSign1Builder, cbor::value::Value};

    use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};

    use super::{
        CLAIM_OPERATION, CLAIM_VERSION, COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2, Error, MatchClaims,
        MatchOperation, MatchToken, TOKEN_VERSION, build_token, hash_limbs, verify,
    };

    /// Stands in for the enclave, which owns the real key material.
    struct TestSigner {
        private_key: EdDSAPrivateKey,
        public_key: EdDSAPublicKey,
    }

    impl TestSigner {
        fn sign(&self, claims: &MatchClaims) -> Result<MatchToken, Error> {
            let signature = self.private_key.sign(claims.message_hash()?);
            build_token(claims, &signature, &self.public_key)
        }

        const fn public_key(&self) -> &EdDSAPublicKey {
            &self.public_key
        }
    }

    fn signer() -> TestSigner {
        let private_key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let public_key = private_key.public();

        TestSigner {
            private_key,
            public_key,
        }
    }

    fn claims() -> MatchClaims {
        MatchClaims {
            live_capture_hash: [1u8; 32],
            operation: MatchOperation::DeepFace {
                credential_claim: [2u8; 32],
            },
            challenger_image_hash: [3u8; 32],
            match_coefficient: 0.9375,
        }
    }

    #[test]
    fn round_trips_through_sign_and_verify() {
        let signing_key = signer();
        let original = claims();

        let token = signing_key.sign(&original).expect("signing should succeed");
        let verified = verify(&token, signing_key.public_key())
            .expect("the token should verify under its key");

        assert_eq!(verified.live_capture_hash, original.live_capture_hash);
        assert_eq!(verified.operation, original.operation);
        assert_eq!(
            verified.challenger_image_hash,
            original.challenger_image_hash
        );
        // 0.9375 is exactly representable at this scale, so the round trip is lossless.
        assert_eq!(
            verified.match_coefficient.to_bits(),
            original.match_coefficient.to_bits()
        );
    }

    #[test]
    fn gray_badge_round_trips_without_a_credential() {
        let signer = signer();
        let claims = MatchClaims {
            operation: MatchOperation::GrayBadge,
            ..claims()
        };
        let token = signer.sign(&claims).unwrap();
        assert_eq!(verify(&token, signer.public_key()).unwrap(), claims);

        let sign1 = CoseSign1::from_slice(token.as_bytes()).unwrap();
        let payload: Value = coset::cbor::from_reader(sign1.payload.unwrap().as_slice()).unwrap();
        assert!(
            !payload
                .as_map()
                .unwrap()
                .iter()
                .any(|(key, _)| key.as_integer() == Some(super::CLAIM_CREDENTIAL_CLAIM.into()))
        );
        assert_ne!(
            claims.message_hash().unwrap(),
            MatchClaims {
                operation: MatchOperation::DeepFace {
                    credential_claim: [0; 32]
                },
                ..claims
            }
            .message_hash()
            .unwrap()
        );
    }

    #[test]
    fn operation_cannot_be_changed_to_reuse_a_signature() {
        let signer = signer();
        let original = MatchClaims {
            operation: MatchOperation::DeepFace {
                credential_claim: [0; 32],
            },
            ..claims()
        };
        let signature = signer.private_key.sign(original.message_hash().unwrap());
        let forged = build_token(
            &MatchClaims {
                operation: MatchOperation::GrayBadge,
                ..original
            },
            &signature,
            signer.public_key(),
        )
        .unwrap();
        assert_eq!(
            verify(&forged, signer.public_key()),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_a_token_signed_by_another_key() {
        let token = signer().sign(&claims()).expect("signing should succeed");

        assert_eq!(
            verify(&token, signer().public_key()).err(),
            Some(Error::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_a_mutated_claim() {
        let signing_key = signer();
        let token = signing_key.sign(&claims()).expect("signing should succeed");

        // The digest is recomputed from the parsed claims, so a flipped byte breaks the match.
        let mut bytes = token.into_bytes();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        let token = MatchToken::from_bytes(bytes);

        assert!(matches!(
            verify(&token, signing_key.public_key()),
            Err(Error::SignatureInvalid | Error::Malformed)
        ));
    }

    #[test]
    fn every_claim_is_committed_by_the_digest() {
        let base = claims().message_hash().expect("hashing should succeed");

        for mutated in [
            MatchClaims {
                live_capture_hash: [9u8; 32],
                ..claims()
            },
            MatchClaims {
                operation: MatchOperation::DeepFace {
                    credential_claim: [9u8; 32],
                },
                ..claims()
            },
            MatchClaims {
                challenger_image_hash: [9u8; 32],
                ..claims()
            },
            MatchClaims {
                match_coefficient: 0.875,
                ..claims()
            },
        ] {
            assert_ne!(
                base,
                mutated.message_hash().expect("hashing should succeed"),
                "digest must change when a claim changes"
            );
        }
    }

    #[test]
    fn hash_limbs_split_big_endian() {
        let mut hash = [0u8; 32];
        hash[15] = 1;
        hash[31] = 2;

        assert_eq!(hash_limbs(&hash), [Fq::from(1u64), Fq::from(2u64)]);
    }

    #[test]
    fn hash_limbs_distinguish_halves() {
        let mut swapped = [0u8; 32];
        swapped[0] = 1;
        let mut other = [0u8; 32];
        other[16] = 1;

        assert_ne!(hash_limbs(&swapped), hash_limbs(&other));
    }

    #[test]
    fn rejects_a_token_declaring_another_version() {
        // The version is not in the digest, so a bumped version keeps a valid signature. Only
        // the explicit check catches this.
        let signing_key = signer();
        let token = signing_key.sign(&claims()).expect("signing should succeed");
        let sign1 = CoseSign1::from_slice(token.as_bytes()).expect("token should parse");

        let payload = sign1.payload.as_deref().expect("payload should be present");
        let mut entries = coset::cbor::from_reader::<Value, _>(payload)
            .expect("payload should decode")
            .into_map()
            .expect("claims are a map");
        for (key, value) in &mut entries {
            if key.as_integer() == Some(CLAIM_VERSION.into()) {
                *value = Value::Integer((TOKEN_VERSION + 1).into());
            }
        }

        let mut repacked = Vec::new();
        coset::cbor::into_writer(&Value::Map(entries), &mut repacked).expect("should re-encode");

        let forged = CoseSign1Builder::new()
            .protected(sign1.protected.header.clone())
            .payload(repacked)
            .signature(sign1.signature.clone())
            .build()
            .to_vec()
            .map(MatchToken::from_bytes)
            .expect("should serialize");

        // Not SignatureInvalid: the signature genuinely still verifies.
        assert_eq!(
            verify(&forged, signing_key.public_key()).err(),
            Some(Error::UnsupportedTokenVersion)
        );
    }

    #[test]
    fn rejects_a_coefficient_the_encoding_cannot_hold() {
        // Far beyond any similarity; bounded by the integer, not by policy.
        let claims = MatchClaims {
            match_coefficient: 8.0e9,
            ..claims()
        };

        assert_eq!(
            claims.message_hash().err(),
            Some(Error::UnrepresentableCoefficient)
        );
    }

    #[test]
    fn rejects_a_negative_coefficient() {
        // Unreachable in the enclave, but fail closed anyway.
        let claims = MatchClaims {
            match_coefficient: -0.5,
            ..claims()
        };

        assert_eq!(
            claims.message_hash().err(),
            Some(Error::UnrepresentableCoefficient)
        );
    }

    #[test]
    fn rejects_a_non_finite_coefficient() {
        for coefficient in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let claims = MatchClaims {
                match_coefficient: coefficient,
                ..claims()
            };

            assert_eq!(
                signer().sign(&claims).err(),
                Some(Error::UnrepresentableCoefficient),
                "{coefficient} must not be signed"
            );
        }
    }

    #[test]
    fn coefficient_scaling_is_order_preserving() {
        // The property the circuit's threshold comparison depends on.
        let scaled = |coefficient: f32| {
            MatchClaims {
                match_coefficient: coefficient,
                ..claims()
            }
            .scaled_coefficient()
            .expect("in-range coefficient")
        };

        let mut previous = scaled(0.0);
        for step in 1..=20u8 {
            let current = scaled(f32::from(step) / 20.0);
            assert!(current > previous, "scaling must be strictly increasing");
            previous = current;
        }
    }

    #[test]
    fn protected_header_names_the_wip_106_algorithm() {
        let signing_key = signer();
        let token = signing_key.sign(&claims()).expect("signing should succeed");

        let sign1 =
            coset::CoseSign1::from_slice(token.as_bytes()).expect("token should be a COSE_Sign1");
        assert_eq!(
            sign1.protected.header.alg,
            Some(coset::RegisteredLabelWithPrivate::PrivateUse(
                COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2
            ))
        );
        // `kid` lets a verifier find the key; it is not trusted in place of one.
        assert_eq!(
            sign1.protected.header.key_id,
            signing_key
                .public_key()
                .to_compressed_bytes()
                .expect("the public key serializes")
                .to_vec()
        );
    }

    #[test]
    fn claims_are_in_deterministic_cbor_order() {
        // Keep the legacy deterministic CWT map encoding stable.
        let payload = claims().claims().expect("claims should encode");
        let claims: coset::cbor::value::Value =
            coset::cbor::from_reader(payload.as_slice()).expect("claims should decode");
        let keys: Vec<i128> = claims
            .as_map()
            .expect("claims are a map")
            .iter()
            .map(|(key, _)| i128::from(key.as_integer().expect("integer key")))
            .collect();

        let mut expected = keys.clone();
        // RFC 8949 §4.2.1: equal-width negatives, so ascending by magnitude.
        expected.sort_by_key(|key| (i32::from(*key < 0), key.abs()));

        assert_eq!(keys, expected);
        // The operation sorts last, so lookup cannot rely on position.
        assert_eq!(keys.last(), Some(&i128::from(CLAIM_OPERATION)));
        assert_eq!(keys.len(), 6);
    }
}
