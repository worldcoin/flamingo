use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the cached encryption-key attestation, the full key it commits to and the release
/// manifest it attests.
///
/// # Errors
/// [`enclave_types::Error::NotReady`] until a release is loaded: before then the channel key is
/// not attested with a `release_hash`.
#[allow(clippy::unused_async, reason = "uniform async route interface")]
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, enclave_types::Error> {
    let release = state.release().ok_or(enclave_types::Error::NotReady)?;
    Ok(KeyAttestation {
        document: state.encryption_key_attestation(),
        public_key: state.encryption_public_key(),
        release_manifest: release.as_jws().to_owned(),
        max_response_slot_millis: release
            .payload()
            .pipelines
            .iter()
            .filter_map(|pipeline| pipeline.response_slots.last())
            .max()
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use flamingo_verifier_enclave_types as enclave_types;

    use super::{GetEncryptionKeyRequest, handler};
    use crate::test_support::{
        EchoAttestor, TEST_ENGINE_HASH, echo, manifest, state_with, with_payload,
    };

    #[tokio::test]
    async fn is_not_ready_until_a_release_is_loaded() {
        let state = state_with(Arc::new(EchoAttestor));
        assert_eq!(
            handler(state, GetEncryptionKeyRequest).await,
            Err(enclave_types::Error::NotReady)
        );
    }

    #[tokio::test]
    async fn deadline_metadata_tracks_the_provisioned_release() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let state = state_with(Arc::new(EchoAttestor));
        let manifest = manifest(TEST_ENGINE_HASH, 1);
        let encoded = manifest.split('.').nth(1).unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        payload["pipelines"][1]["response_slots"] = serde_json::json!([1, 9000]);
        state.load_release(&with_payload(&payload)).unwrap();
        assert_eq!(
            handler(state, GetEncryptionKeyRequest)
                .await
                .unwrap()
                .max_response_slot_millis,
            9000
        );
    }

    #[tokio::test]
    async fn returns_the_full_key_and_attests_its_commitment_with_the_release() {
        let state = state_with(Arc::new(EchoAttestor));
        let manifest = manifest(TEST_ENGINE_HASH, 1);
        state.load_release(&manifest).unwrap();
        let response = handler(Arc::clone(&state), GetEncryptionKeyRequest)
            .await
            .unwrap();

        assert_eq!(response.public_key.len(), 1216);
        assert_eq!(response.public_key, state.channel().public_key());
        assert_eq!(response.release_manifest, manifest);
        // EchoAttestor records the bytes submitted to the NSM public_key and user_data fields.
        let commitment = flamingo_verifier_sealed_types::CHANNEL_DOMAIN
            .public_key_commitment(&response.public_key);
        let release_hash = state.release().unwrap().release_hash();
        assert_eq!(response.document, echo(&commitment, Some(&release_hash)));
    }
}
