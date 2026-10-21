//! Boot-scoped state owned by the enclave.

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use eddsa_babyjubjub::EdDSAPublicKey;
use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_sealed_types::CHANNEL_DOMAIN;
use pontifex::ChannelEnclave;
use tokio::task::JoinHandle;
use world_id_flamingo::ReleaseManifest;

use crate::{
    attestation::{AttestedKey, Attestor, MAX_CACHED_AGE},
    biometric_engine::BiometricEngine,
    keys::SigningKey,
    replay::ReplayGuard,
};

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    /// Opens requests sealed to this boot.
    channel: ChannelEnclave,
    /// Signs accepted match claims.
    signing_key: SigningKey,
    /// Cached attestation of the sealed-channel key.
    attested_encryption_key: AttestedKey,
    /// Cached attestation of the statement key.
    attested_signing_key: AttestedKey,
    engine: Box<dyn BiometricEngine>,
    /// `SHA-256` of the Engine bundle this boot runs.
    engine_hash: [u8; 32],
    /// The release manifest of that bundle, once the host has loaded it.
    release: OnceLock<ReleaseManifest>,
    /// (`aud`, `nonce`) pairs processed under this boot's channel key.
    replay: ReplayGuard,
    /// Set once the Engine overran a pipeline's last response slot.
    engine_overran: AtomicBool,
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
        engine: Box<dyn BiometricEngine>,
        engine_hash: [u8; 32],
    ) -> Result<Self, enclave_types::Error> {
        let channel = ChannelEnclave::generate(CHANNEL_DOMAIN).map_err(|error| {
            tracing::error!(?error, "failed to generate channel key");
            enclave_types::Error::Internal
        })?;
        let signing_key = SigningKey::generate();

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
            engine,
            engine_hash,
            release: OnceLock::new(),
            replay: ReplayGuard::default(),
            engine_overran: AtomicBool::new(false),
        })
    }

    /// Loads the release manifest of this boot's Engine bundle (WIP-201 §3.5.2).
    ///
    /// Loading the manifest already loaded succeeds again; any other manifest is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`enclave_types::Error::ReleaseRejected`] for a manifest that is malformed, breaks a
    /// WIP-201 rule, names another bundle, or differs from the one already loaded.
    pub fn load_release(&self, compact: &str) -> Result<(), enclave_types::Error> {
        let manifest = ReleaseManifest::parse(compact).map_err(|error| {
            tracing::warn!(%error, "release manifest rejected");
            enclave_types::Error::ReleaseRejected
        })?;
        if manifest.payload().engine_hash() != Some(self.engine_hash) {
            tracing::warn!(
                engine_hash = %hex::encode(self.engine_hash),
                "release manifest names another Engine bundle"
            );
            return Err(enclave_types::Error::ReleaseRejected);
        }
        let loaded = self.release.get_or_init(|| manifest.clone());
        if loaded.release_hash() == manifest.release_hash() {
            Ok(())
        } else {
            tracing::warn!("a different release manifest is already loaded");
            Err(enclave_types::Error::ReleaseRejected)
        }
    }

    /// The loaded release manifest, if any.
    #[must_use]
    pub fn release(&self) -> Option<&ReleaseManifest> {
        self.release.get()
    }

    /// `release_hash` of each loaded release.
    #[must_use]
    pub fn release_hashes(&self) -> Vec<[u8; 32]> {
        self.release()
            .map(ReleaseManifest::release_hash)
            .into_iter()
            .collect()
    }

    /// Rejects requests this boot already processed.
    #[must_use]
    pub const fn replay(&self) -> &ReplayGuard {
        &self.replay
    }

    /// Whether the Engine overran a last response slot; the enclave then serves nothing more.
    #[must_use]
    pub fn engine_overran(&self) -> bool {
        self.engine_overran.load(Ordering::Relaxed)
    }

    /// WIP-201 §3.5.4: an Engine that overran the last slot is terminated and reset.
    pub fn reset_overrunning_engine(&self) {
        if !self.engine_overran.swap(true, Ordering::Relaxed) {
            tracing::error!(
                dependency = "biometric_worker",
                "engine overran the last response slot; terminating it"
            );
            self.engine.terminate();
        }
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

    /// Checks an idle worker without waiting for an in-flight comparison.
    pub fn check_worker_health(&self) {
        self.engine.check_health();
    }

    pub(crate) fn engine(&self) -> &dyn BiometricEngine {
        self.engine.as_ref()
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
    use crate::test_support::{
        EchoAttestor, FailingAttestor, TEST_ENGINE_HASH, UnusedBiometricEngine, manifest,
        state_with,
    };

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
            flamingo_verifier_sealed_types::CHANNEL_DOMAIN
                .public_key_commitment(&state.encryption_public_key())
                .to_vec()
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
        let error = EnclaveState::generate(
            Arc::new(FailingAttestor),
            Box::new(UnusedBiometricEngine),
            TEST_ENGINE_HASH,
        )
        .err();

        assert_eq!(error, Some(enclave_types::Error::AttestationFailed));
    }

    #[test]
    fn loads_the_manifest_of_its_bundle_once() {
        let state = state();
        assert!(state.release_hashes().is_empty());

        let current = manifest(TEST_ENGINE_HASH, "1.0.0");
        assert_eq!(state.load_release(&current), Ok(()));
        assert_eq!(state.load_release(&current), Ok(()));
        let release_hash = state.release().expect("loaded").release_hash();
        assert_eq!(state.release_hashes(), vec![release_hash]);

        assert_eq!(
            state.load_release(&manifest(TEST_ENGINE_HASH, "1.0.1")),
            Err(enclave_types::Error::ReleaseRejected)
        );
        assert_eq!(state.release_hashes(), vec![release_hash]);
    }

    #[test]
    fn rejects_a_manifest_for_another_bundle_or_a_malformed_one() {
        let state = state();
        for rejected in [manifest([0x2b; 32], "1.0.0"), "not.a.jws".to_owned()] {
            assert_eq!(
                state.load_release(&rejected),
                Err(enclave_types::Error::ReleaseRejected)
            );
        }
        assert!(state.release().is_none());
    }
}
