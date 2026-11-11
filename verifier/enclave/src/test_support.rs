//! Test doubles shared across the enclave's unit tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use flamingo_verifier_enclave_types as enclave_types;

use crate::{
    attestation::{Attestation, Attestor},
    biometric_engine::{BiometricEngine, BiometricError, DeepFaceScores, GrayBadgeScores},
    state::EnclaveState,
};

/// The Verifier time test attestations state, in Unix seconds.
pub const TEST_NOW: u32 = 1_783_446_000;

fn attestation(document: Vec<u8>) -> Attestation {
    Attestation {
        document,
        timestamp_millis: u64::from(TEST_NOW) * 1000,
    }
}

/// Returns the attested key, then `|` and the `user_data` if any, as its own "document", so tests
/// can tell documents apart.
pub struct EchoAttestor;

impl Attestor for EchoAttestor {
    fn attest(
        &self,
        public_key: &[u8],
        user_data: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error> {
        Ok(attestation(echo(public_key, user_data)))
    }
}

/// The document [`EchoAttestor`] returns.
pub fn echo(public_key: &[u8], user_data: Option<&[u8]>) -> Vec<u8> {
    let mut document = public_key.to_vec();
    if let Some(user_data) = user_data {
        document.push(b'|');
        document.extend_from_slice(user_data);
    }
    document
}

pub struct FailingAttestor;

impl Attestor for FailingAttestor {
    fn attest(&self, _: &[u8], _: Option<&[u8]>) -> Result<Attestation, enclave_types::Error> {
        Err(enclave_types::Error::AttestationFailed)
    }
}

/// Counts attestations and makes every document distinct, so a cached document is distinguishable
/// from a re-attested one.
#[derive(Default)]
pub struct CountingAttestor {
    calls: AtomicUsize,
}

impl CountingAttestor {
    pub const fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Attestor for CountingAttestor {
    fn attest(
        &self,
        public_key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);

        let mut document = public_key.to_vec();
        document.push(u8::try_from(call % 256).unwrap_or_default());

        Ok(attestation(document))
    }
}

/// Succeeds for the configured number of calls, then returns
/// [`enclave_types::Error::AttestationFailed`].
pub struct FailsAfterSuccessesAttestor {
    calls: AtomicUsize,
    successful_calls: usize,
}

impl FailsAfterSuccessesAttestor {
    pub const fn new(successful_calls: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            successful_calls,
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Attestor for FailsAfterSuccessesAttestor {
    fn attest(
        &self,
        public_key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        if call < self.successful_calls {
            Ok(attestation(public_key.to_vec()))
        } else {
            Err(enclave_types::Error::AttestationFailed)
        }
    }
}

/// Panics if a test reaches it, for paths that must reject before comparing faces.
pub struct UnusedBiometricEngine;

#[async_trait::async_trait]
impl BiometricEngine for UnusedBiometricEngine {
    async fn deepface(
        &self,
        _: Vec<u8>,
        _: crate::biometric_engine::LiveCapture,
        _: Vec<u8>,
        _: tokio::time::Instant,
    ) -> Result<DeepFaceScores, BiometricError> {
        panic!("biometric engine was called unexpectedly")
    }

    async fn graybadge(
        &self,
        _: crate::biometric_engine::LiveCapture,
        _: Vec<u8>,
        _: tokio::time::Instant,
    ) -> Result<GrayBadgeScores, BiometricError> {
        panic!("biometric engine was called unexpectedly")
    }

    fn terminate(&self) {
        panic!("biometric engine was terminated unexpectedly")
    }
}

pub use flamingo_verifier_sealed_types::testing::{
    TEST_ENGINE_HASH, TEST_SLOTS, manifest, manifest_with_slots, with_payload,
};

/// Builds state whose biometric engine must not be called.
pub fn state_with(attestor: Arc<dyn Attestor>) -> Arc<EnclaveState> {
    Arc::new(
        EnclaveState::generate(
            attestor,
            Box::new(UnusedBiometricEngine),
            TEST_ENGINE_HASH,
            None,
        )
        .expect("boot state should generate"),
    )
}

/// Builds state for `engine` with the [`manifest`] of [`TEST_ENGINE_HASH`] loaded.
pub fn loaded_state(engine: impl BiometricEngine + 'static) -> Arc<EnclaveState> {
    loaded_state_with_slots(engine, TEST_SLOTS)
}

/// [`loaded_state`] with every pipeline's response slots set to `slots`.
pub fn loaded_state_with_slots(
    engine: impl BiometricEngine + 'static,
    slots: &[u64],
) -> Arc<EnclaveState> {
    let state = EnclaveState::generate(
        Arc::new(EchoAttestor),
        Box::new(engine),
        TEST_ENGINE_HASH,
        None,
    )
    .expect("boot state should generate");
    state
        .load_release(&manifest_with_slots(TEST_ENGINE_HASH, 1, slots))
        .expect("the test manifest should load");
    Arc::new(state)
}

/// A loaded state that bills on `target`, with an Engine that must not be called.
pub fn loaded_billing_state(target: crate::billing::BillingTarget) -> Arc<EnclaveState> {
    let state = EnclaveState::generate(
        Arc::new(EchoAttestor),
        Box::new(UnusedBiometricEngine),
        TEST_ENGINE_HASH,
        Some(target),
    )
    .expect("boot state should generate");
    state
        .load_release(&manifest(TEST_ENGINE_HASH, 1))
        .expect("the test manifest should load");
    Arc::new(state)
}
