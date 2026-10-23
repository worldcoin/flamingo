use std::{env, fs::File, io::Read};

use anyhow::{Context, Result, ensure};
use flamingo_verifier_client::Config;
use world_id_flamingo::{
    EngineProviderMetadata, ReleaseManifest,
    engine_provider::ReleaseStatus,
    release_manifest::{ReleaseKeyJwk, verifying_key},
};

const MAX_METADATA_BYTES: u64 = 1024 * 1024;

pub fn load_release() -> Result<ReleaseManifest> {
    let metadata = read_input("PROVIDER_METADATA")?;
    // This is an independently enrolled trust anchor, never a key accepted from metadata alone.
    let trusted_key = read_input("PROVIDER_KEY")?;
    let expected_hash = env::var("EXPECTED_RELEASE_HASH")
        .context("EXPECTED_RELEASE_HASH must select the reviewed engine release")?;
    verify_release(&metadata, &trusted_key, &expected_hash)
}

fn read_input(name: &str) -> Result<Vec<u8>> {
    let path = env::var(name).with_context(|| format!("{name} must name a JSON file"))?;
    let mut bytes = Vec::new();
    File::open(&path)
        .with_context(|| format!("open {name} file"))?
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {name} file"))?;
    ensure!(
        bytes.len() as u64 <= MAX_METADATA_BYTES,
        "{name} exceeds 1 MiB"
    );
    Ok(bytes)
}

fn verify_release(
    metadata: &[u8],
    trusted_key: &[u8],
    expected_hash: &str,
) -> Result<ReleaseManifest> {
    let expected_hash: [u8; 32] = hex::decode(expected_hash)
        .context("EXPECTED_RELEASE_HASH must be hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("EXPECTED_RELEASE_HASH must be exactly 32 bytes"))?;
    let trusted_key: ReleaseKeyJwk =
        serde_json::from_slice(trusted_key).context("invalid trusted provider JWK")?;
    verifying_key(&trusted_key).context("invalid trusted provider key")?;
    let metadata = EngineProviderMetadata::parse(metadata).context("invalid provider metadata")?;
    let keys: Vec<_> = metadata
        .release_keys
        .iter()
        .filter(|key| key.jwk.prm.kid == trusted_key.prm.kid)
        .collect();
    ensure!(
        keys.len() == 1 && keys[0].status == ReleaseStatus::Active && keys[0].jwk == trusted_key,
        "provider metadata must contain exactly the pinned, active release key"
    );
    let mut selected = None;
    for jws in metadata.manifests {
        let manifest =
            ReleaseManifest::from_jws(&jws).context("malformed manifest in provider metadata")?;
        if manifest.release_hash() == expected_hash {
            ensure!(
                selected.is_none(),
                "duplicate selected release in provider metadata"
            );
            manifest
                .verify(&trusted_key)
                .context("selected release does not verify under the trusted provider key")?;
            selected = Some(manifest);
        }
    }
    selected.context("selected release is absent from provider metadata")
}

pub fn require_offered(expected: &[u8; 32], offered: &[[u8; 32]]) -> Result<()> {
    ensure!(
        offered.contains(expected),
        "host does not offer the reviewed provider release"
    );
    Ok(())
}

pub fn measured_config(json: &str) -> Result<Config> {
    let config = Config::from_json(json).context("invalid client config")?;
    // Reuse the client's strict PCR0–2 parsing, while disallowing its optional development bypass.
    let config_json = serde_json::to_value(&config)?;
    ensure!(
        config_json["dangerously_skip_measurements"] == false,
        "E2E qualification requires trusted nonzero PCR0, PCR1 and PCR2; measurement bypass is forbidden"
    );
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use serde_json::{Value, json};

    fn fixture() -> (Value, Value, String) {
        let signing = SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let jwk = json!({"kty":"EC", "crv":"P-256", "kid":"test-key", "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())});
        let payload = json!({"engine_hash": "a".repeat(64), "version": "test", "pipelines":[{"pipeline":1, "description":"test", "response_slots":[16000],"max_request_bytes":7352320}],"match_strictness_levels":[{"match_strictness":2,"description":"test"}]});
        let header = json!({"alg":"ES256", "kid":"test-key", "typ":"world-id-engine-manifest"});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let signature: Signature = signing.sign(input.as_bytes());
        let compact = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let hash = hex::encode(ReleaseManifest::from_jws(&compact).unwrap().release_hash());
        let metadata = json!({"version":1,"provider_id":"test","release_keys":[{"jwk":jwk,"status":"active"}],"manifests":[compact]});
        (metadata, jwk, hash)
    }

    fn verify(metadata: &Value, key: &Value, hash: &str) -> Result<ReleaseManifest> {
        verify_release(
            &serde_json::to_vec(metadata).unwrap(),
            &serde_json::to_vec(key).unwrap(),
            hash,
        )
    }

    #[test]
    fn accepts_only_the_selected_signed_release_and_offered_hash() {
        let (metadata, key, hash) = fixture();
        let release = verify(&metadata, &key, &hash).unwrap();
        assert!(
            require_offered(&release.release_hash(), &[[9; 32], release.release_hash()]).is_ok()
        );
        assert!(require_offered(&release.release_hash(), &[[9; 32]]).is_err());
        assert!(verify(&metadata, &key, &"0".repeat(64)).is_err());
        assert!(verify(&metadata, &key, "bad-hash").is_err());
    }

    #[test]
    fn metadata_cannot_replace_the_trusted_key_or_bypass_bad_signatures() {
        let (mut metadata, mut key, hash) = fixture();
        key["kid"] = json!("untrusted-key");
        assert!(verify(&metadata, &key, &hash).is_err());
        let (_, key, _) = fixture();
        metadata["release_keys"][0]["jwk"]["x"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 32]));
        assert!(verify(&metadata, &key, &hash).is_err());
        let (mut metadata, key, hash) = fixture();
        let compact = metadata["manifests"][0].as_str().unwrap();
        let input = compact.rsplit_once('.').unwrap().0;
        metadata["manifests"][0] = json!(format!("{input}.{}", URL_SAFE_NO_PAD.encode([0_u8; 64])));
        assert!(verify(&metadata, &key, &hash).is_err());
    }

    #[test]
    fn rejects_inactive_keys_and_ambiguous_releases_or_keys() {
        for status in ["retired", "revoked"] {
            let (mut metadata, key, hash) = fixture();
            metadata["release_keys"][0]["status"] = json!(status);
            assert!(verify(&metadata, &key, &hash).is_err());
        }
        for member in ["release_keys", "manifests"] {
            let (mut metadata, key, hash) = fixture();
            let duplicate = metadata[member][0].clone();
            metadata[member].as_array_mut().unwrap().push(duplicate);
            assert!(verify(&metadata, &key, &hash).is_err());
        }
    }

    #[test]
    fn requires_real_pcr_pins_and_rejects_debug_bypass() {
        let config = json!({"host_url":"http://localhost:8000","allowed_pcr_configs":[[{"index":0,"value":"11".repeat(48)},{"index":1,"value":"22".repeat(48)},{"index":2,"value":"33".repeat(48)}]]});
        assert!(measured_config(&config.to_string()).is_ok());
        let mut debug = config.clone();
        debug["dangerously_skip_measurements"] = json!(true);
        assert!(measured_config(&debug.to_string()).is_err());
        let mut zero = config;
        zero["allowed_pcr_configs"][0][0]["value"] = json!("00".repeat(48));
        assert!(measured_config(&zero.to_string()).is_err());
    }
}
