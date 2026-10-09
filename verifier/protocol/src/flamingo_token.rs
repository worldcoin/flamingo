//! The WIP-201 Flamingo Token: a CWT in an untagged `COSE_Sign1` over a Poseidon2 digest.
//!
//! The signature covers [`FlamingoClaims::digest`], not the COSE `Sig_structure`, so a circuit
//! verifies the token without parsing CBOR.

use ark_babyjubjub::Fq;
use ark_ff::{BigInteger, PrimeField};
use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, Header, RegisteredLabelWithPrivate,
    cbor::value::Value,
};
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use serde::{Deserialize, Serialize};

use crate::{error::Error, match_token::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2};

/// Domain separator of the signed digest.
pub const DS_SIGN: &[u8] = b"WORLD-ID/WIP-201/SIGN";
/// Domain separator of [`engine_config_hash`].
pub const DS_ENGINE: &[u8] = b"WORLD-ID/WIP-201/ENGINE";
/// The `eat_profile` claim of every Flamingo Token.
pub const EAT_PROFILE: &str = "https://world.org/eat/flamingo/v1";
/// Compared entries a token carries.
pub const MAX_COMPARED: usize = 4;

/// RFC 9711 `eat_profile`.
pub const CLAIM_EAT_PROFILE: i64 = 265;
/// `compared_entry_hash_k` is `CLAIM_COMPARED_ENTRY_HASH - k`.
pub const CLAIM_COMPARED_ENTRY_HASH: i64 = -90_000;
/// The request's `aud`.
pub const CLAIM_AUD: i64 = -90_004;
/// The request's `nonce`.
pub const CLAIM_NONCE: i64 = -90_005;
/// WIP-106 hash of the Authenticator Provider key that verified the AAT.
pub const CLAIM_AUTHENTICATOR_PROVIDER_KEY_HASH: i64 = -90_006;
/// Public AAT flags.
pub const CLAIM_AAT_FLAGS: i64 = -90_007;
/// Whether the Verifier verified an AAT.
pub const CLAIM_HAS_AAT: i64 = -90_008;
/// `now` of the verified AAT.
pub const CLAIM_NOW: i64 = -90_009;
/// The Engine configuration that ran.
pub const CLAIM_ENGINE_CONFIG_HASH: i64 = -90_010;

/// Claims in the signed digest; the remaining four rate slots of the `t=16` state stay zero.
const DIGEST_CLAIMS: usize = 11;

/// The public values of a verified AAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AatClaims {
    /// WIP-106 hash of the `authenticator_provider_key`.
    pub authenticator_provider_key_hash: Fq,
    /// `sec_flags` layout with `min_build_version` in place of `build_version`.
    pub aat_flags: u64,
    /// The AAT's `now`, in seconds since the Unix epoch.
    pub now: u32,
}

impl AatClaims {
    /// The values a token carries without an AAT.
    fn zero() -> Self {
        Self {
            authenticator_provider_key_hash: Fq::from(0u64),
            aat_flags: 0,
            now: 0,
        }
    }
}

/// The claims a Flamingo Token signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlamingoClaims {
    /// `R(SHA-256(data))` per compared entry, `0` past the last one.
    pub compared_entry_hashes: [Fq; MAX_COMPARED],
    /// The request's `aud`.
    pub aud: Fq,
    /// The request's `nonce`.
    pub nonce: Fq,
    /// `None` encodes `has_aat = 0` with every AAT claim zero.
    pub aat: Option<AatClaims>,
    /// See [`engine_config_hash`].
    pub engine_config_hash: Fq,
}

impl FlamingoClaims {
    /// The signed digest, `H_16(DS_SIGN; now, compared_entry_hash_0..3, aud, nonce,
    /// authenticator_provider_key_hash, aat_flags, has_aat, engine_config_hash)`.
    #[must_use]
    pub fn digest(&self) -> Fq {
        let aat = self.aat.unwrap_or_else(AatClaims::zero);
        let [c0, c1, c2, c3] = self.compared_entry_hashes;
        let claims: [Fq; DIGEST_CLAIMS] = [
            Fq::from(aat.now),
            c0,
            c1,
            c2,
            c3,
            self.aud,
            self.nonce,
            aat.authenticator_provider_key_hash,
            Fq::from(aat.aat_flags),
            Fq::from(u64::from(self.aat.is_some())),
            self.engine_config_hash,
        ];

        let mut state = [Fq::from(0u64); 16];
        state[0] = Fq::from_be_bytes_mod_order(DS_SIGN);
        state[1..=DIGEST_CLAIMS].copy_from_slice(&claims);
        poseidon2::bn254::t16::permutation_in_place(&mut state);
        state[1]
    }

    fn payload(&self) -> Result<Vec<u8>, Error> {
        let field = |key: i64, value: Fq| (Value::Integer(key.into()), field_bytes(value));
        let uint =
            |key: i64, value: u64| (Value::Integer(key.into()), Value::Integer(value.into()));
        let aat = self.aat.unwrap_or_else(AatClaims::zero);

        // Bytewise order of the encoded keys: 265 first, then the negatives by magnitude.
        let mut entries = vec![(
            Value::Integer(CLAIM_EAT_PROFILE.into()),
            Value::Text(EAT_PROFILE.into()),
        )];
        entries.extend(
            (0i64..)
                .zip(self.compared_entry_hashes)
                .map(|(k, hash)| field(CLAIM_COMPARED_ENTRY_HASH - k, hash)),
        );
        entries.extend([
            field(CLAIM_AUD, self.aud),
            field(CLAIM_NONCE, self.nonce),
            field(
                CLAIM_AUTHENTICATOR_PROVIDER_KEY_HASH,
                aat.authenticator_provider_key_hash,
            ),
            uint(CLAIM_AAT_FLAGS, aat.aat_flags),
            uint(CLAIM_HAS_AAT, u64::from(self.aat.is_some())),
            uint(CLAIM_NOW, u64::from(aat.now)),
            field(CLAIM_ENGINE_CONFIG_HASH, self.engine_config_hash),
        ]);

        let mut encoded = Vec::new();
        coset::cbor::into_writer(&Value::Map(entries), &mut encoded)
            .map_err(|_| Error::Encoding)?;
        Ok(encoded)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        let value: Value = coset::cbor::from_reader(payload).map_err(|_| Error::Malformed)?;
        let entries = value.as_map().ok_or(Error::Malformed)?;
        let claim = |key: i64| {
            entries
                .iter()
                .find(|(k, _)| k.as_integer() == Some(key.into()))
                .map(|(_, v)| v)
                .ok_or(Error::Malformed)
        };
        let field = |key: i64| claim(key).and_then(parse_field);
        let uint = |key: i64| {
            claim(key)?
                .as_integer()
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(Error::Malformed)
        };

        let mut compared_entry_hashes = [Fq::from(0u64); MAX_COMPARED];
        for (k, hash) in (0i64..).zip(&mut compared_entry_hashes) {
            *hash = field(CLAIM_COMPARED_ENTRY_HASH - k)?;
        }
        let aat = AatClaims {
            authenticator_provider_key_hash: field(CLAIM_AUTHENTICATOR_PROVIDER_KEY_HASH)?,
            aat_flags: uint(CLAIM_AAT_FLAGS)?,
            now: u32::try_from(uint(CLAIM_NOW)?).map_err(|_| Error::Malformed)?,
        };
        let aat = match uint(CLAIM_HAS_AAT)? {
            1 => Some(aat),
            0 if aat == AatClaims::zero() => None,
            _ => return Err(Error::Malformed),
        };
        let claims = Self {
            compared_entry_hashes,
            aud: field(CLAIM_AUD)?,
            nonce: field(CLAIM_NONCE)?,
            aat,
            engine_config_hash: field(CLAIM_ENGINE_CONFIG_HASH)?,
        };

        // Re-encoding pins the exact claim set, the profile and deterministic CBOR.
        if claims.payload()? != payload {
            return Err(Error::Malformed);
        }
        Ok(claims)
    }
}

/// `R(d)`: a 256-bit digest read as a big-endian integer modulo p.
#[must_use]
pub fn digest_to_field(digest: &[u8; 32]) -> Fq {
    Fq::from_be_bytes_mod_order(digest)
}

/// `H_4(DS_ENGINE; R(engine_hash), pipeline, match_strictness)`.
#[must_use]
pub fn engine_config_hash(engine_hash: &[u8; 32], pipeline: u32, match_strictness: u8) -> Fq {
    let mut state = [
        Fq::from_be_bytes_mod_order(DS_ENGINE),
        digest_to_field(engine_hash),
        Fq::from(pipeline),
        Fq::from(match_strictness),
    ];
    poseidon2::bn254::t4::permutation_in_place(&mut state);
    state[1]
}

/// The encoded `COSE_Sign1` of a Flamingo Token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamingoToken(#[serde(with = "serde_bytes")] Vec<u8>);

impl FlamingoToken {
    /// Wraps encoded token bytes without checking them.
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

/// Encodes a token from claims and a signature over their [`FlamingoClaims::digest`].
///
/// # Errors
/// Fails when a key, signature or the CBOR cannot be encoded.
pub fn build_token(
    claims: &FlamingoClaims,
    signature: &EdDSASignature,
    signing_public_key: &EdDSAPublicKey,
) -> Result<FlamingoToken, Error> {
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
        .payload(claims.payload()?)
        .signature(signature.to_vec())
        .build()
        .to_vec()
        .map(FlamingoToken::from_bytes)
        .map_err(|_| Error::Encoding)
}

/// Decodes a token and verifies its signature under `signing_public_key`; `kid` is ignored.
///
/// # Errors
/// Fails on any framing, claim or algorithm mismatch, or an invalid signature.
pub fn verify(
    token: &FlamingoToken,
    signing_public_key: &EdDSAPublicKey,
) -> Result<FlamingoClaims, Error> {
    let sign1 = CoseSign1::from_slice(token.as_bytes()).map_err(|_| Error::Malformed)?;
    match sign1.protected.header.alg {
        Some(RegisteredLabelWithPrivate::PrivateUse(COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2)) => {}
        _ => return Err(Error::UnexpectedAlgorithm),
    }

    let claims = FlamingoClaims::from_payload(sign1.payload.as_deref().ok_or(Error::Malformed)?)?;
    let signature = <[u8; 64]>::try_from(sign1.signature.as_slice())
        .ok()
        .and_then(|bytes| EdDSASignature::from_compressed_bytes(bytes).ok())
        .ok_or(Error::Malformed)?;

    if signing_public_key.verify(claims.digest(), &signature) {
        Ok(claims)
    } else {
        Err(Error::SignatureInvalid)
    }
}

fn field_bytes(value: Fq) -> Value {
    let bytes = value.into_bigint().to_bytes_be();
    let mut padded = vec![0u8; 32 - bytes.len()];
    padded.extend(bytes);
    Value::Bytes(padded)
}

/// Accepts only the canonical 32-byte big-endian encoding of a field element.
fn parse_field(value: &Value) -> Result<Fq, Error> {
    let bytes: &[u8; 32] = value
        .as_bytes()
        .and_then(|bytes| bytes.as_slice().try_into().ok())
        .ok_or(Error::Malformed)?;
    let element = Fq::from_be_bytes_mod_order(bytes);
    if field_bytes(element).as_bytes().map(Vec::as_slice) == Some(bytes.as_slice()) {
        Ok(element)
    } else {
        Err(Error::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eddsa_babyjubjub::EdDSAPrivateKey;

    // WIP-201 Appendix A1.
    const ENGINE_CONFIG_HASH: &str =
        "2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d";
    const PROVIDER_KEY_HASH: &str =
        "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
    const DIGEST_WITH_AAT: &str =
        "229f44f2caa18f609df2c1819223d778ef8b08a30ce9de589dbe754275e123bd";
    const DIGEST_WITHOUT_AAT: &str =
        "046b836383d9d9fd350fbed1197e1c1c17f2b187fb6ef1571e5f9b42ec6fc8fc";
    const KID: &str = "f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12";
    const CWT_WITH_AAT: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a059017dac190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582014b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d83a00015f961b0013000007d601023a00015f97013a00015f981a6a4d39f03a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d5840cbf2231e80118d266870d7277931546a19bca6ee1d7bbe8c9a8df15659b175908eb3bcbd8c10258173e6130d02539bb720f85db7479c17ad224ca11e66741903";
    const CWT_WITHOUT_AAT: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a0590171ac190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582000000000000000000000000000000000000000000000000000000000000000003a00015f96003a00015f97003a00015f98003a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d5840a2c1883fd414440ca4df81723869407caa35ef840b0438ec1fb9280757b572abe2ebb272225105813188bff8dd3d5d236636ad7c9aa002413121164697265705";

    fn hex_field(hex: &str) -> Fq {
        Fq::from_be_bytes_mod_order(&hex::decode(hex).unwrap())
    }

    fn sha256_field(bytes: &[u8]) -> Fq {
        use sha2::{Digest, Sha256};
        digest_to_field(&Sha256::digest(bytes).into())
    }

    fn signing_key() -> EdDSAPrivateKey {
        EdDSAPrivateKey::from_bytes([0x15; 32])
    }

    fn claims(aat: Option<AatClaims>) -> FlamingoClaims {
        FlamingoClaims {
            compared_entry_hashes: [
                sha256_field(b"credential image"),
                sha256_field(b"live image"),
                sha256_field(b"challenge image"),
                Fq::from(0u64),
            ],
            aud: Fq::from(1_928_118u64),
            nonce: Fq::from(42u64),
            aat,
            engine_config_hash: hex_field(ENGINE_CONFIG_HASH),
        }
    }

    fn with_aat() -> FlamingoClaims {
        claims(Some(AatClaims {
            authenticator_provider_key_hash: hex_field(PROVIDER_KEY_HASH),
            aat_flags: 0x0013_0000_07d6_0102,
            now: 1_783_446_000,
        }))
    }

    fn sign(claims: &FlamingoClaims) -> FlamingoToken {
        let key = signing_key();
        build_token(claims, &key.sign(claims.digest()), &key.public()).unwrap()
    }

    #[test]
    fn domain_separators_match_the_spec() {
        assert_eq!(
            Fq::from_be_bytes_mod_order(DS_SIGN).to_string(),
            "127603488023523044162070750169730750022280897185614"
        );
        assert_eq!(
            Fq::from_be_bytes_mod_order(DS_ENGINE).to_string(),
            "8362622191109606222205468683123474433460185506268139077"
        );
    }

    #[test]
    fn engine_config_hash_matches_the_vector() {
        assert_eq!(
            engine_config_hash(&[0x2a; 32], 1, 2),
            hex_field(ENGINE_CONFIG_HASH)
        );
    }

    #[test]
    fn tokens_match_the_vectors() {
        assert_eq!(
            hex::encode(signing_key().public().to_compressed_bytes().unwrap()),
            KID
        );
        for (claims, digest, cwt) in [
            (with_aat(), DIGEST_WITH_AAT, CWT_WITH_AAT),
            (claims(None), DIGEST_WITHOUT_AAT, CWT_WITHOUT_AAT),
        ] {
            assert_eq!(claims.digest(), hex_field(digest));
            let token = sign(&claims);
            assert_eq!(hex::encode(token.as_bytes()), cwt);
            assert_eq!(verify(&token, &signing_key().public()), Ok(claims));
        }
    }

    #[test]
    fn rejects_another_key() {
        let other = EdDSAPrivateKey::from_bytes([0x16; 32]).public();
        assert_eq!(
            verify(&sign(&with_aat()), &other),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn every_claim_is_in_the_digest() {
        let base = with_aat();
        let one = Fq::from(1u64);
        let aat = base.aat.unwrap();
        let mut changed = vec![
            FlamingoClaims { aud: one, ..base },
            FlamingoClaims { nonce: one, ..base },
            FlamingoClaims {
                engine_config_hash: one,
                ..base
            },
            FlamingoClaims { aat: None, ..base },
        ];
        for k in 0..MAX_COMPARED {
            let mut claims = base;
            claims.compared_entry_hashes[k] = one;
            changed.push(claims);
        }
        for aat in [
            AatClaims {
                authenticator_provider_key_hash: one,
                ..aat
            },
            AatClaims {
                aat_flags: 1,
                ..aat
            },
            AatClaims { now: 1, ..aat },
        ] {
            changed.push(FlamingoClaims {
                aat: Some(aat),
                ..base
            });
        }
        for claims in changed {
            assert_ne!(claims.digest(), base.digest());
        }
    }

    fn resign(payload: Vec<(Value, Value)>) -> FlamingoToken {
        let token = sign(&with_aat());
        let sign1 = CoseSign1::from_slice(token.as_bytes()).unwrap();
        let mut encoded = Vec::new();
        coset::cbor::into_writer(&Value::Map(payload), &mut encoded).unwrap();
        CoseSign1Builder::new()
            .protected(sign1.protected.header)
            .payload(encoded)
            .signature(sign1.signature)
            .build()
            .to_vec()
            .map(FlamingoToken::from_bytes)
            .unwrap()
    }

    fn payload(claims: &FlamingoClaims) -> Vec<(Value, Value)> {
        let encoded = claims.payload().unwrap();
        coset::cbor::from_reader::<Value, _>(encoded.as_slice())
            .unwrap()
            .into_map()
            .unwrap()
    }

    #[test]
    fn rejects_payloads_that_are_not_the_exact_claim_set() {
        let key = signing_key().public();
        let mut extra = payload(&with_aat());
        extra.push((Value::Integer(1.into()), Value::Integer(1.into())));
        let mut reordered = payload(&with_aat());
        reordered.swap(1, 2);
        let mut profile = payload(&with_aat());
        profile[0].1 = Value::Text("https://example.org".into());
        let mut missing = payload(&with_aat());
        missing.pop();
        let mut has_aat = payload(&with_aat());
        has_aat[9].1 = Value::Integer(2.into());
        let mut stray_aat = payload(&claims(None));
        stray_aat[10].1 = Value::Integer(1.into());
        let mut non_canonical = payload(&with_aat());
        non_canonical[5].1 = Value::Bytes(vec![0xff; 32]);

        for payload in [
            extra,
            reordered,
            profile,
            missing,
            has_aat,
            stray_aat,
            non_canonical,
        ] {
            assert_eq!(verify(&resign(payload), &key), Err(Error::Malformed));
        }
    }

    #[test]
    fn rejects_another_algorithm() {
        let token = sign(&with_aat());
        let mut sign1 = CoseSign1::from_slice(token.as_bytes()).unwrap();
        sign1.protected.header.alg = Some(RegisteredLabelWithPrivate::PrivateUse(-65538));
        sign1.protected.original_data = None;
        let token = FlamingoToken::from_bytes(sign1.to_vec().unwrap());
        assert_eq!(
            verify(&token, &signing_key().public()),
            Err(Error::UnexpectedAlgorithm)
        );
    }
}
