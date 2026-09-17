//! Boot-scoped signing key material.
//!
//! The keypair is generated in memory at boot and never persisted, sealed, or shared across
//! enclaves. There is deliberately no KMS-, disk-, or leader-derived key path. The sealed
//! channel endpoint lives in [`pontifex::ChannelEnclave`] and is owned by
//! [`crate::state::EnclaveState`].

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use flamingo_verifier_protocol::match_token::{MatchClaims, MatchToken, build_token};

/// The field element a `BabyJubJub` `EdDSA` signature commits to.
type SigningMessage = ark_babyjubjub::Fq;

/// The `BabyJubJub` `EdDSA` keypair that signs match statements.
pub struct SigningKey {
    private_key: EdDSAPrivateKey,
    public_key: EdDSAPublicKey,
}

impl SigningKey {
    /// Generates a fresh `BabyJubJub` `EdDSA` keypair.
    #[must_use]
    pub fn generate() -> Self {
        let private_key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let public_key = private_key.public();

        Self {
            private_key,
            public_key,
        }
    }

    /// Returns the public key that verifies this boot's statements.
    #[must_use]
    pub const fn public_key(&self) -> &EdDSAPublicKey {
        &self.public_key
    }

    /// Signs `claims` and returns the finished token.
    ///
    /// # Errors
    ///
    /// Propagates [`flamingo_verifier_protocol::Error`] if the claims cannot be lowered to a digest or the
    /// token cannot be encoded.
    pub fn sign_claims(
        &self,
        claims: &MatchClaims,
    ) -> Result<MatchToken, flamingo_verifier_protocol::Error> {
        let signature = self.sign(claims.message_hash()?);

        build_token(claims, &signature, &self.public_key)
    }

    /// Signs one field element. Private on purpose — see [`Self::sign_claims`].
    fn sign(&self, message: SigningMessage) -> eddsa_babyjubjub::EdDSASignature {
        self.private_key.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use ark_babyjubjub::Fq;

    use super::SigningKey;

    #[test]
    fn separate_signing_keys_are_distinct() {
        let first = SigningKey::generate();
        let second = SigningKey::generate();

        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn signatures_verify_under_the_attested_public_key() {
        let key = SigningKey::generate();
        let message = Fq::from(42u64);

        let signature = key.sign(message);

        assert!(key.public_key().verify(message, &signature));
        assert!(!key.public_key().verify(Fq::from(43u64), &signature));
    }
}
