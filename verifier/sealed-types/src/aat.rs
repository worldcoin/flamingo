//! WIP-201 §3.3: the optional Authenticator Assertion, verified per WIP-106 §3.7.

use flamingo_verifier_protocol::{
    Fq,
    flamingo_token::{AatClaims, canonical_field, digest_to_field},
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use sha2::{Digest, Sha256};
use world_id_primitives::{
    EdDSAPublicKey, EdDSASignature, FieldElement,
    authenticator_assertion::{
        AuthenticatorAssertionPrivateInputs, AuthenticatorAssertionPublicInputs,
        authenticator_provider_key_hash, verify_aat,
    },
};

use crate::{Error, FailureReason};

/// The AAT and the RP's minimum build, as the Authenticator sends them.
///
/// Field order follows deterministic CBOR (RFC 8949 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatInputs {
    /// Expiration, in seconds since the Unix epoch.
    pub exp: u32,
    /// Current time, in seconds since the Unix epoch; the RP checks it against its own clock.
    pub now: u32,
    /// Compressed signature by `authenticator_provider_key`.
    pub sig: ByteArray<64>,
    /// Blinding factor of the AAT's request commitment, a canonical field element.
    pub blind: ByteArray<32>,
    /// Packed WIP-106 security flags.
    pub sec_flags: u64,
    /// The RP's minimum `build_version`; `0` sets no minimum.
    pub min_build_version: u32,
    /// Compressed Authenticator Provider key.
    pub authenticator_provider_key: ByteArray<32>,
}

impl AatInputs {
    /// Verifies the AAT for this request and returns the public values the token carries.
    ///
    /// `cdh` is `R(SHA-256(payload))` over the exact payload bytes, so the AAT vouches for every
    /// entry, compared or not.
    ///
    /// # Errors
    /// Returns [`FailureReason::AatRejected`] if any WIP-106 §3.7 check fails.
    pub fn verify(&self, aud: Fq, nonce: Fq, payload: &[u8]) -> Result<AatClaims, FailureReason> {
        let private = self
            .private_inputs(payload)
            .map_err(|_| FailureReason::AatRejected)?;
        let public = private
            .public_inputs(
                self.now,
                FieldElement::from(aud),
                FieldElement::from(nonce),
                self.min_build_version,
            )
            .map_err(|_| FailureReason::AatRejected)?;
        verify_aat(&public, &private).map_err(|_| FailureReason::AatRejected)?;
        Ok(claims(&public))
    }

    /// The public values a token over this AAT carries, without verifying it.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for an undecodable key or reserved `sec_flags`.
    pub fn claims(&self) -> Result<AatClaims, Error> {
        let private = self.private_inputs(&[])?;
        let public = private
            .public_inputs(
                self.now,
                FieldElement::ZERO,
                FieldElement::ZERO,
                self.min_build_version,
            )
            .map_err(|_| Error::Malformed)?;
        Ok(claims(&public))
    }

    fn private_inputs(&self, payload: &[u8]) -> Result<AuthenticatorAssertionPrivateInputs, Error> {
        Ok(AuthenticatorAssertionPrivateInputs {
            authenticator_provider_key: EdDSAPublicKey::from_compressed_bytes(
                *self.authenticator_provider_key,
            )
            .map_err(|_| Error::Malformed)?,
            exp: self.exp,
            sec_flags: self.sec_flags,
            sig: EdDSASignature::from_compressed_bytes(*self.sig).map_err(|_| Error::Malformed)?,
            cdh: FieldElement::from(digest_to_field(&Sha256::digest(payload).into())),
            blind: FieldElement::from(canonical_field(&self.blind).map_err(|_| Error::Malformed)?),
        })
    }
}

/// `aat_flags`: the `sec_flags` layout with the public `min_build_version` in place of
/// `build_version`.
fn claims(public: &AuthenticatorAssertionPublicInputs) -> AatClaims {
    AatClaims {
        authenticator_provider_key_hash: *public.authenticator_provider_key_hash,
        aat_flags: u64::from(public.platform)
            | (u64::from(public.sec_level) << 8)
            | (u64::from(public.min_build_version) << 16)
            | (u64::from(public.sec_meta) << 48)
            | (u64::from(u8::from(public.user_presence)) << 51),
        now: public.now,
    }
}

/// Hash of a compressed Authenticator Provider key, as RPs allowlist it.
///
/// # Errors
/// Returns [`Error::Malformed`] for an undecodable key.
pub fn provider_key_hash(key: [u8; 32]) -> Result<Fq, Error> {
    EdDSAPublicKey::from_compressed_bytes(key)
        .map(|key| *authenticator_provider_key_hash(&key))
        .map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flamingo_verifier_protocol::flamingo_token::field_to_bytes;
    use world_id_primitives::EdDSAPrivateKey;

    // WIP-201 Appendix A1, "With an AAT".
    const PAYLOAD: &str = "a6646d6574614067636f6d706172658300010267656e747269657383a264646174615063726564656e7469616c20696d616765646d65746140a264646174614a6c69766520696d616765646d65746140a264646174614f6368616c6c656e676520696d616765646d6574614068706970656c696e65016b656e67696e655f6861736858202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a706d617463685f7374726963746e65737302";
    const SIG: &str = "bc46a4a4a6193df70abe0cff4cbd083dee0f5172a3137f68687d55fb82160a23bc4bc8c90187f692513c48da819c8ecd329598f3a6eeca5ca2ba4dd0e4f99700";

    fn inputs() -> AatInputs {
        let key = EdDSAPrivateKey::from_bytes([0x07; 32]).public();
        let mut blind = [0; 32];
        blind[31] = 7;
        AatInputs {
            exp: 1_783_446_925,
            now: 1_783_446_000,
            sig: <[u8; 64]>::try_from(hex::decode(SIG).unwrap())
                .unwrap()
                .into(),
            blind: blind.into(),
            sec_flags: 0x0013_0000_07d6_0102,
            min_build_version: 2006,
            authenticator_provider_key: key.to_compressed_bytes().unwrap().into(),
        }
    }

    fn verify(inputs: &AatInputs, payload: &[u8]) -> Result<AatClaims, FailureReason> {
        inputs.verify(Fq::from(1_928_118u64), Fq::from(42u64), payload)
    }

    #[test]
    fn verifies_the_wip_201_vector() {
        let payload = hex::decode(PAYLOAD).unwrap();
        let claims = verify(&inputs(), &payload).unwrap();
        assert_eq!(
            hex::encode(field_to_bytes(claims.authenticator_provider_key_hash)),
            "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8"
        );
        assert_eq!(claims.aat_flags, 0x0013_0000_07d6_0102);
        assert_eq!(claims.now, 1_783_446_000);
        assert_eq!(inputs().claims().unwrap(), claims);
        assert_eq!(
            provider_key_hash(*inputs().authenticator_provider_key).unwrap(),
            claims.authenticator_provider_key_hash
        );
    }

    #[test]
    fn rejects_an_aat_for_another_payload_request_or_policy() {
        let payload = hex::decode(PAYLOAD).unwrap();
        let mut other_payload = payload.clone();
        other_payload.push(0);
        assert_eq!(
            verify(&inputs(), &other_payload),
            Err(FailureReason::AatRejected)
        );
        assert_eq!(
            inputs().verify(Fq::from(1u64), Fq::from(42u64), &payload),
            Err(FailureReason::AatRejected)
        );
        let changes: [fn(&mut AatInputs); 5] = [
            |i| i.now = i.exp,
            |i| i.now = i.exp - 1801,
            |i| i.min_build_version = 2007,
            |i| i.sec_flags ^= 1,
            |i| i.blind = [0xff; 32].into(),
        ];
        for change in changes {
            let mut inputs = inputs();
            change(&mut inputs);
            assert_eq!(verify(&inputs, &payload), Err(FailureReason::AatRejected));
        }
    }

    #[test]
    fn a_lower_minimum_is_reported_in_the_flags() {
        let payload = hex::decode(PAYLOAD).unwrap();
        let mut inputs = inputs();
        inputs.min_build_version = 0;
        assert_eq!(
            verify(&inputs, &payload).unwrap().aat_flags,
            0x0013_0000_0000_0102
        );
    }
}
