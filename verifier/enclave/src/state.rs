//! Boot-scoped state owned by the enclave.

use std::sync::Arc;

use eddsa_babyjubjub::EdDSAPublicKey;
use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_sealed_types::MATCH_CHANNEL_DOMAIN;
use pontifex::{ChannelDomain, ChannelEnclave};
use tokio::task::JoinHandle;

use crate::{
    attestation::{AttestedKey, Attestor, MAX_CACHED_AGE},
    face_engine::FaceComparator,
    keys::SigningKey,
};

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    channel: ChannelEnclave,
    signing_key: SigningKey,
    attested_encryption_key: AttestedKey,
    attested_signing_key: AttestedKey,
    face_engine: Arc<dyn FaceComparator>,
}

impl EnclaveState {
    /// Generates fresh boot-scoped keys and attests both.
    ///
    /// Attesting here rather than per request fails the boot on a broken NSM, and leaves both
    /// caches populated before the server accepts anything.
    ///
    /// # Errors
    ///
    /// Returns [`enclave_types::Error`] if channel generation fails, the signing public key cannot
    /// be serialized, or either key cannot be attested.
    pub fn generate(
        attestor: Arc<dyn Attestor>,
        face_engine: Arc<dyn FaceComparator>,
    ) -> Result<Self, enclave_types::Error> {
        let channel = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN)).map_err(
            |error| {
                tracing::error!(?error, "failed to generate channel key");
                enclave_types::Error::Internal
            },
        )?;
        let signing_key = SigningKey::generate();
        tracing::info!("generated boot-scoped sealed channel and signing keys");

        // Serialized once here rather than on every attestation.
        let signing_public_key =
            signing_key
                .public_key()
                .to_compressed_bytes()
                .map_err(|error| {
                    tracing::error!(%error, "failed to serialize the signing public key");
                    enclave_types::Error::AttestationFailed
                })?;

        let attested_encryption_key = AttestedKey::new(
            Arc::clone(&attestor),
            channel.public_key_commitment().to_vec(),
            MAX_CACHED_AGE,
        )?;
        let attested_signing_key =
            AttestedKey::new(attestor, signing_public_key.to_vec(), MAX_CACHED_AGE)?;

        Ok(Self {
            channel,
            signing_key,
            attested_encryption_key,
            attested_signing_key,
            face_engine,
        })
    }

    /// Returns the channel that opens sealed requests for this boot.
    #[must_use]
    pub const fn channel(&self) -> &ChannelEnclave {
        &self.channel
    }

    /// Returns the full X-Wing public key whose commitment is attested for this boot.
    #[must_use]
    pub fn encryption_public_key(&self) -> Vec<u8> {
        self.channel.public_key()
    }

    /// Returns the signing key for this boot.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns the `BabyJubJub` public key that verifies this boot's statements.
    #[must_use]
    pub const fn signing_public_key(&self) -> &EdDSAPublicKey {
        self.signing_key.public_key()
    }

    /// Returns the Face Engine used for enclave match operations.
    #[must_use]
    pub fn face_engine(&self) -> &dyn FaceComparator {
        self.face_engine.as_ref()
    }

    /// Starts background attestation refresh for both boot keys.
    ///
    /// Supervise both handles in `main`: if either completes, exit the process.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn start_attestation_refresh(&mut self) -> (JoinHandle<()>, JoinHandle<()>) {
        (
            self.attested_encryption_key.start_refresh(),
            self.attested_signing_key.start_refresh(),
        )
    }

    /// The attestation document for the encryption public key (last successful cache entry).
    pub async fn encryption_key_attestation(&self) -> Vec<u8> {
        self.attested_encryption_key.document().await
    }

    /// The attestation document for the signing public key (last successful cache entry).
    pub async fn signing_key_attestation(&self) -> Vec<u8> {
        self.attested_signing_key.document().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use flamingo_verifier_enclave_types as enclave_types;

    use super::EnclaveState;
    use crate::test_support::{EchoAttestor, FailingAttestor, UnusedFaceEngine, state_with};

    fn state() -> Arc<EnclaveState> {
        state_with(Arc::new(EchoAttestor))
    }

    #[test]
    fn keys_are_stable_for_one_state() {
        let state = state();

        assert_eq!(state.encryption_public_key(), state.encryption_public_key());
        assert_eq!(state.signing_public_key(), state.signing_public_key());
    }

    #[test]
    fn separate_states_receive_separate_keys() {
        let first = state();
        let second = state();

        assert_ne!(
            first.encryption_public_key(),
            second.encryption_public_key()
        );
        assert_ne!(first.signing_public_key(), second.signing_public_key());
    }

    #[tokio::test]
    async fn each_key_is_attested_in_its_own_document() {
        let state = state();

        assert_eq!(
            state.encryption_key_attestation().await,
            pontifex::channel::public_key_commitment(&state.encryption_public_key()).to_vec()
        );
        assert_eq!(
            state.signing_key_attestation().await,
            state
                .signing_public_key()
                .to_compressed_bytes()
                .expect("generated BabyJubJub public key serializes")
                .to_vec()
        );
    }

    /// An enclave that cannot prove its own identity must not reach the point of serving.
    #[test]
    fn an_attestor_that_fails_fails_the_boot() {
        let error =
            EnclaveState::generate(Arc::new(FailingAttestor), Arc::new(UnusedFaceEngine)).err();

        assert_eq!(error, Some(enclave_types::Error::AttestationFailed));
    }
}
