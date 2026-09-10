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
    pub max_bundle_bytes: Option<u64>,
    /// Worker virtual-memory ceiling, leaving room for the broker and kernel.
    pub address_space_bytes: Option<u64>,
    /// Reserved worker UID's process/thread ceiling.
    pub max_threads: Option<u32>,
    /// Whole startup transfer budget, including waiting for the provisioner and acknowledgement.
    pub bootstrap_timeout_seconds: Option<u64>,
}

impl BootstrapConfig {
    /// Rejects missing release decisions rather than trusting host-provided defaults.
    ///
    /// # Errors
    /// Returns an error for missing budgets, invalid limits, or unusable publisher keys.
    pub fn validate(&self) -> Result<Vec<VerifyingKey>, Error> {
        if self.publisher_keys.is_empty()
            || self.publisher_keys.len() > 8
            || !self
                .max_bundle_bytes
                .is_some_and(|value| (1..=MAX_BUNDLE_BYTES).contains(&value))
            || !self
                .address_space_bytes
                .is_some_and(|value| (1..=i64::MAX as u64).contains(&value))
            || !self
                .max_threads
                .is_some_and(|value| (1..=256).contains(&value))
            || !self
                .bootstrap_timeout_seconds
                .is_some_and(|value| (1..=900).contains(&value))
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
