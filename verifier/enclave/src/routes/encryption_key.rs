use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the cached encryption-key attestation, the full key it commits to and the loaded
/// Engines.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, enclave_types::Error> {
    Ok(KeyAttestation {
        document: state.encryption_key_attestation().await,
        public_key: state.encryption_public_key(),
        engine_hashes: state.engine_hashes(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{GetEncryptionKeyRequest, handler};
    use crate::test_support::{EchoAttestor, state_with};

    #[tokio::test]
    async fn returns_the_full_key_and_attests_its_commitment() {
        let state = state_with(Arc::new(EchoAttestor));
        let response = handler(Arc::clone(&state), GetEncryptionKeyRequest)
            .await
            .unwrap();

        assert_eq!(response.public_key.len(), 1216);
        assert_eq!(
            response.engine_hashes,
            vec![crate::test_support::TEST_ENGINE_HASH]
        );
        assert_eq!(response.public_key, state.channel().public_key());
        // EchoAttestor records the bytes submitted to the NSM public_key field.
        assert_eq!(
            response.document,
            flamingo_verifier_sealed_types::CHANNEL_DOMAIN
                .public_key_commitment(&response.public_key)
        );
    }
}
