//! One policy parser shared by release validation and measured enclave startup.

use std::{fs::File, io::Read, path::Path};

use p384::ecdsa::VerifyingKey;
use serde::Deserialize;

use crate::{Error, MAX_BUNDLE_BYTES};

/// Public publisher trust and resource configuration included in the measured image.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// SEC1-encoded P-384 publisher public keys in hex; no default trust anchor.
    pub publisher_keys: Vec<String>,
    /// Aggregate artifact budget, selected for the provisioned enclave's RAM.
    pub max_bundle_bytes: u64,
    /// Worker virtual-memory ceiling, leaving room for the broker and kernel.
    pub address_space_bytes: u64,
    /// Reserved worker UID's process/thread ceiling.
    pub max_threads: u32,
    /// Whole startup transfer budget, including waiting for the provisioner and acknowledgement.
    pub bootstrap_timeout_seconds: u64,
}

impl BootstrapConfig {
    /// Rejects missing release decisions rather than trusting host-provided defaults.
    ///
    /// # Errors
    /// Returns an error for missing budgets, invalid limits, or unusable publisher keys.
    pub fn validate(&self) -> Result<Vec<VerifyingKey>, Error> {
        if self.publisher_keys.is_empty()
            || self.publisher_keys.len() > 8
            || !(1..=MAX_BUNDLE_BYTES).contains(&self.max_bundle_bytes)
            || !(1..=i64::MAX as u64).contains(&self.address_space_bytes)
            || !(1..=256).contains(&self.max_threads)
            || !(1..=900).contains(&self.bootstrap_timeout_seconds)
        {
            return Err(Error::InvalidConfig);
        }

        self.publisher_keys
            .iter()
            .map(|value| {
                if ![98, 194].contains(&value.len()) {
                    return Err(Error::InvalidConfig);
                }
                let bytes = hex::decode(value).map_err(|_| Error::InvalidConfig)?;
                VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| Error::InvalidConfig)
            })
            .collect()
    }

    /// Reads the exact bounded JSON file; callers select a fixed measured path at startup.
    ///
    /// # Errors
    /// Returns an error when configuration cannot be read, exceeds 64 KiB, or fails decoding.
    pub fn load_from(path: &Path) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err(Error::InvalidConfig);
        }

        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidConfig)
    }
}

#[cfg(test)]
mod tests {
    use super::BootstrapConfig as Config;

    /// Public CI images build without trusted keys, but cannot provision a worker.
    #[test]
    fn unconfigured_release_cannot_boot() {
        let config: Config = serde_json::from_str(r#"{"publisher_keys":[],"max_bundle_bytes":0,"address_space_bytes":0,"max_threads":0,"bootstrap_timeout_seconds":0}"#).unwrap();
        assert!(config.validate().is_err());
    }

    /// Trust and every deployment budget must be valid together; no setting is defaulted.
    #[test]
    fn validates_configured_trust_and_each_budget() {
        let key = p384::ecdsa::SigningKey::from_slice(&[1; 48]).unwrap();
        let public = hex::encode(key.verifying_key().to_encoded_point(true).as_bytes());
        let valid = serde_json::json!({
            "publisher_keys": [public],
            "max_bundle_bytes": 1024,
            "address_space_bytes": 1024,
            "max_threads": 1,
            "bootstrap_timeout_seconds": 1
        });
        let config: Config = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(config.validate().unwrap().len(), 1);

        for (field, value) in [
            ("publisher_keys", serde_json::json!([])),
            ("publisher_keys", serde_json::json!(["00"])),
            ("publisher_keys", serde_json::json!(["00".repeat(49)])),
            ("max_bundle_bytes", serde_json::json!(0)),
            ("max_bundle_bytes", serde_json::json!(u64::MAX)),
            ("address_space_bytes", serde_json::json!(0)),
            ("address_space_bytes", serde_json::json!(u64::MAX)),
            ("max_threads", serde_json::json!(0)),
            ("max_threads", serde_json::json!(257)),
            ("bootstrap_timeout_seconds", serde_json::json!(0)),
            ("bootstrap_timeout_seconds", serde_json::json!(901)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            let config: Config = serde_json::from_value(invalid).unwrap();
            assert!(config.validate().is_err(), "{field} must be validated");
        }
    }
}
