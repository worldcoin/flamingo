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
        _: crate::biometric_engine::LiveCapture,
        _: Vec<u8>,
    ) -> Result<DeepFaceScores, BiometricError> {
        panic!("biometric engine was called unexpectedly")
    }

    async fn graybadge(
        &self,
        _: crate::biometric_engine::LiveCapture,
        _: Vec<u8>,
    ) -> Result<GrayBadgeScores, BiometricError> {
        panic!("biometric engine was called unexpectedly")
    }
}

/// `engine_hash` of the bundle test states claim to run.
pub const TEST_ENGINE_HASH: [u8; 32] = [0x2a; 32];

/// Builds state whose biometric engine must not be called.
pub fn state_with(attestor: Arc<dyn Attestor>) -> Arc<EnclaveState> {
    Arc::new(
        EnclaveState::generate(attestor, Box::new(UnusedBiometricEngine), TEST_ENGINE_HASH)
            .expect("boot state should generate"),
    )
}

/// `max_request_bytes` of pipeline 1 in [`manifest`]; pipeline 2 allows half.
pub const TEST_MAX_REQUEST_BYTES: u64 = 1 << 20;

/// Builds state for `engine` with the [`manifest`] of [`TEST_ENGINE_HASH`] loaded.
pub fn loaded_state(engine: impl BiometricEngine + 'static) -> Arc<EnclaveState> {
    let state = EnclaveState::generate(Arc::new(EchoAttestor), Box::new(engine), TEST_ENGINE_HASH)
        .expect("boot state should generate");
    state
        .load_release(&manifest(TEST_ENGINE_HASH, "1.0.0"))
        .expect("the test manifest should load");
    Arc::new(state)
}

/// A release manifest for `engine_hash`; the enclave does not check its signature.
pub fn manifest(engine_hash: [u8; 32], version: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let payload = serde_json::json!({
        "engine_hash": hex::encode(engine_hash),
        "version": version,
        "pipelines": [
            {
                "pipeline": 1,
                "description": "credential image, live capture, challenge",
                "response_slots": { "min": 500, "max": 4000, "count": 4 },
                "max_request_bytes": TEST_MAX_REQUEST_BYTES,
            },
            {
                "pipeline": 2,
                "description": "live capture, challenge",
                "response_slots": { "min": 500, "max": 4000, "count": 4 },
                "max_request_bytes": TEST_MAX_REQUEST_BYTES / 2,
            },
        ],
        "match_strictness_levels": [
            { "match_strictness": 1, "description": "lenient" },
            { "match_strictness": 2, "description": "strict" },
            { "match_strictness": 3, "description": "strictest" },
        ],
    });
    let header = r#"{"alg":"ES256","kid":"test","typ":"world-id-engine-manifest"}"#;
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        URL_SAFE_NO_PAD.encode([0u8; 64])
    )
}
