//! Validated public Engine Provider discovery metadata.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::Serialize;
use world_id_flamingo::{EngineMetadata, ReleaseManifest};

pub use world_id_flamingo::metadata::METADATA_PATH as ENGINE_METADATA_PATH;

/// Maximum encoded provider document accepted from configuration.
pub const MAX_ENGINE_METADATA_BYTES: usize = 64 * 1024;

/// WIP-201 discovery document, validated before the host publishes it.
///
/// Uses the protocol's wire types and retains inactive keys and manifests so consumers can
/// discover revocations. This document does not establish a client's trust in its provider.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EngineProviderMetadata(EngineMetadata);

impl fmt::Debug for EngineProviderMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineProviderMetadata")
            .field("provider_id", &self.0.provider_id)
            .field("release_keys", &self.0.release_keys.len())
            .field("manifests", &self.0.manifests.len())
            .finish()
    }
}

/// A configuration error that never echoes the supplied document or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EngineProviderMetadataError {
    /// Document exceeds the configuration limit.
    #[error("Engine Provider metadata exceeds 64 KiB")]
    TooLarge,
    /// JSON or the document shape is invalid.
    #[error("invalid Engine Provider metadata JSON")]
    Malformed,
    /// The schema version is not supported.
    #[error("Engine Provider metadata version must be 1")]
    Version,
    /// The provider identifier is empty.
    #[error("Engine Provider metadata needs a nonempty provider_id")]
    ProviderId,
    /// A public key or its identifier is invalid.
    #[error("release keys must be valid public P-256 JWKs with nonempty kid values")]
    Key,
    /// Key identifiers are ambiguous.
    #[error("release key kid values must be unique")]
    DuplicateKey,
    /// A manifest is listed more than once, possibly with conflicting statuses.
    #[error("release manifest entries must be unique")]
    DuplicateManifest,
    /// A private key was supplied instead of its public part.
    #[error("Engine Provider metadata must not contain private JWK material")]
    PrivateKey,
    /// A manifest does not parse or names an unconfigured key.
    #[error("each release manifest must be valid and name a configured release key")]
    Manifest,
    /// A manifest's signature does not verify.
    #[error("release manifest signature does not verify under its configured key")]
    Signature,
}

impl FromStr for EngineProviderMetadata {
    type Err = EngineProviderMetadataError;

    fn from_str(json: &str) -> Result<Self, Self::Err> {
        use EngineProviderMetadataError as Error;
        if json.len() > MAX_ENGINE_METADATA_BYTES {
            return Err(Error::TooLarge);
        }
        let value: serde_json::Value = serde_json::from_str(json).map_err(|_| Error::Malformed)?;
        if value["release_keys"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|key| key["jwk"].get("d").is_some()))
        {
            return Err(Error::PrivateKey);
        }
        let metadata: EngineMetadata =
            serde_json::from_value(value).map_err(|_| Error::Malformed)?;
        if metadata.version != 1 {
            return Err(Error::Version);
        }
        if metadata.provider_id.trim().is_empty() {
            return Err(Error::ProviderId);
        }
        let mut kids = BTreeSet::new();
        for key in &metadata.release_keys {
            if key.jwk.kid.trim().is_empty() || key.jwk.verifying_key().is_err() {
                return Err(Error::Key);
            }
            if !kids.insert(&key.jwk.kid) {
                return Err(Error::DuplicateKey);
            }
        }
        let mut manifests = BTreeSet::new();
        for entry in &metadata.manifests {
            if !manifests.insert(&entry.manifest) {
                return Err(Error::DuplicateManifest);
            }
            let manifest =
                ReleaseManifest::from_jws(&entry.manifest).map_err(|_| Error::Manifest)?;
            let key = metadata
                .release_keys
                .iter()
                .find(|key| key.jwk.kid == manifest.kid())
                .ok_or(Error::Manifest)?;
            // Verify consistency regardless of status: revocation must not prevent publication.
            manifest.verify(&key.jwk).map_err(|_| Error::Signature)?;
        }
        Ok(Self(metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const FIXTURE: &str = include_str!("../tests/fixtures/engine-provider.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    #[test]
    fn public_document_preserves_exact_manifests_and_all_statuses() {
        for status in ["active", "retired", "revoked"] {
            let mut value = fixture();
            value["release_keys"][0]["status"] = status.into();
            value["manifests"][0]["status"] = status.into();
            let metadata: EngineProviderMetadata = value.to_string().parse().unwrap();
            assert_eq!(serde_json::to_value(&metadata).unwrap(), value);
            assert_eq!(
                metadata.0.active_manifests().len(),
                usize::from(status == "active")
            );
        }
    }

    #[test]
    fn revocation_and_key_first_bootstrap_do_not_require_active_releases() {
        let mut value = fixture();
        value["release_keys"][0]["status"] = "revoked".into();
        let metadata: EngineProviderMetadata = value.to_string().parse().unwrap();
        assert!(metadata.0.active_manifests().is_empty());
        value["manifests"] = json!([]);
        assert!(value.to_string().parse::<EngineProviderMetadata>().is_ok());
        value["release_keys"] = json!([]);
        assert!(value.to_string().parse::<EngineProviderMetadata>().is_ok());
    }

    #[test]
    fn rejects_invalid_configuration_and_ambiguous_key_statuses() {
        use EngineProviderMetadataError as Error;
        for (pointer, replacement, error) in [
            ("/version", json!(2), Error::Version),
            ("/provider_id", json!(" "), Error::ProviderId),
            ("/release_keys/0/jwk/kid", json!(""), Error::Key),
            ("/release_keys/0/jwk/crv", json!("P-384"), Error::Key),
            ("/release_keys/0/jwk/x", json!("invalid"), Error::Key),
            ("/manifests/0/manifest", json!("invalid"), Error::Manifest),
        ] {
            let mut value = fixture();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert_eq!(
                value.to_string().parse::<EngineProviderMetadata>(),
                Err(error)
            );
        }
        let mut value = fixture();
        let mut revoked = value["release_keys"][0].clone();
        revoked["status"] = "revoked".into();
        value["release_keys"].as_array_mut().unwrap().push(revoked);
        assert_eq!(
            value.to_string().parse::<EngineProviderMetadata>(),
            Err(Error::DuplicateKey)
        );
        let mut value = fixture();
        let mut revoked = value["manifests"][0].clone();
        revoked["status"] = "revoked".into();
        value["manifests"].as_array_mut().unwrap().push(revoked);
        assert_eq!(
            value.to_string().parse::<EngineProviderMetadata>(),
            Err(Error::DuplicateManifest)
        );
        assert_eq!(
            "{}".parse::<EngineProviderMetadata>(),
            Err(Error::Malformed)
        );
        assert_eq!(
            " ".repeat(MAX_ENGINE_METADATA_BYTES + 1)
                .parse::<EngineProviderMetadata>(),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn rejects_private_keys_unknown_signers_and_invalid_signatures() {
        use EngineProviderMetadataError as Error;
        let mut value = fixture();
        value["release_keys"][0]["jwk"]["d"] = "PRIVATE-KEY-MUST-NOT-BE-ECHOED".into();
        assert_eq!(
            value.to_string().parse::<EngineProviderMetadata>(),
            Err(Error::PrivateKey)
        );
        let mut value = fixture();
        value["release_keys"][0]["jwk"]["kid"] = "another-key".into();
        assert_eq!(
            value.to_string().parse::<EngineProviderMetadata>(),
            Err(Error::Manifest)
        );
        let mut value = fixture();
        let mut manifest = value["manifests"][0]["manifest"]
            .as_str()
            .unwrap()
            .to_owned();
        let start = manifest.rfind('.').unwrap() + 1;
        let replacement = if &manifest[start..=start] == "A" {
            "B"
        } else {
            "A"
        };
        manifest.replace_range(start..=start, replacement);
        value["manifests"][0]["manifest"] = manifest.into();
        assert_eq!(
            value.to_string().parse::<EngineProviderMetadata>(),
            Err(Error::Signature)
        );
    }
}
