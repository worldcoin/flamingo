//! Test doubles shared across the enclave's unit tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use flamingo_verifier_enclave_types as enclave_types;

use crate::{
    attestation::Attestor,
    biometric_engine::{BiometricEngine, BiometricError, DeepFaceScores, GrayBadgeScores},
    state::EnclaveState,
};

/// Returns the attested key as its own "document", so tests can tell the two apart.
pub struct EchoAttestor;

impl Attestor for EchoAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
        Ok(public_key.to_vec())
    }
}

pub struct FailingAttestor;

impl Attestor for FailingAttestor {
    fn attest_public_key(&self, _: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
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
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);

        let mut document = public_key.to_vec();
        document.push(u8::try_from(call % 256).unwrap_or_default());

        Ok(document)
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
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        if call < self.successful_calls {
            Ok(public_key.to_vec())
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
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<DeepFaceScores, BiometricError> {
        panic!("biometric engine was called unexpectedly")
    }

    async fn graybadge(&self, _: Vec<u8>, _: Vec<u8>) -> Result<GrayBadgeScores, BiometricError> {
        panic!("biometric engine was called unexpectedly")
    }
}

/// Builds state whose biometric engine must not be called.
pub fn state_with(attestor: Arc<dyn Attestor>) -> Arc<EnclaveState> {
    Arc::new(
        EnclaveState::generate(attestor, Box::new(UnusedBiometricEngine))
            .expect("boot state should generate"),
    )
}
