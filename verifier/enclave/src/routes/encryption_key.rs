use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the cached encryption-key attestation and the full key it commits to.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, enclave_types::Error> {
    Ok(KeyAttestation {
        document: state.encryption_key_attestation().await,
        public_key: state.encryption_public_key(),
        release_hashes: state.release_hashes(),
        max_response_slot_millis: state.release().and_then(|release| {
            release
                .payload()
                .pipelines
                .iter()
                .filter_map(|pipeline| pipeline.response_slots.last())
                .max()
        }),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{GetEncryptionKeyRequest, handler};
    use crate::test_support::{EchoAttestor, state_with};

    #[tokio::test]
    async fn deadline_metadata_tracks_the_provisioned_release() {
        use crate::test_support::{TEST_ENGINE_HASH, manifest};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let state = state_with(Arc::new(EchoAttestor));
        assert_eq!(
            handler(Arc::clone(&state), GetEncryptionKeyRequest)
                .await
                .unwrap()
                .max_response_slot_millis,
            None
        );
        let manifest = manifest(TEST_ENGINE_HASH, "1.0.0");
        let parts: Vec<_> = manifest.split('.').collect();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        payload["pipelines"][1]["response_slots"] = serde_json::json!([1, 9000]);
        let manifest = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(payload.to_string()),
            parts[2]
        );
        state.load_release(&manifest).unwrap();
        assert_eq!(
            handler(state, GetEncryptionKeyRequest)
                .await
                .unwrap()
                .max_response_slot_millis,
            Some(9000)
        );
    }

    #[tokio::test]
    async fn returns_the_full_key_and_attests_its_commitment() {
        let state = state_with(Arc::new(EchoAttestor));
        let response = handler(Arc::clone(&state), GetEncryptionKeyRequest)
            .await
            .unwrap();

        assert_eq!(response.public_key.len(), 1216);
        assert_eq!(response.public_key, state.channel().public_key());
        // EchoAttestor records the bytes submitted to the NSM public_key field.
        assert_eq!(
            response.document,
            flamingo_verifier_sealed_types::CHANNEL_DOMAIN
                .public_key_commitment(&response.public_key)
        );
    }
}
