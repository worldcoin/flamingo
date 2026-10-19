//! Boot-scoped signing key material.
//!
//! The keypair is generated in memory at boot and never persisted, sealed, or shared across
//! enclaves. There is deliberately no KMS-, disk-, or leader-derived key path. The sealed
//! channel endpoint lives in [`pontifex::ChannelEnclave`] and is owned by
//! [`crate::state::EnclaveState`].

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use world_id_flamingo::{FlamingoClaims, FlamingoToken, TokenError};

/// The `BabyJubJub` `EdDSA` keypair that signs Flamingo Tokens.
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
    /// Propagates [`TokenError`] if the token cannot be encoded.
    pub fn sign_claims(&self, claims: &FlamingoClaims) -> Result<FlamingoToken, TokenError> {
        claims.sign(&self.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::SigningKey;

    #[test]
    fn separate_signing_keys_are_distinct() {
        let first = SigningKey::generate();
        let second = SigningKey::generate();

        assert_ne!(first.public_key(), second.public_key());
    }
}
