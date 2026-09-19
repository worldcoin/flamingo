//! One policy parser shared by release validation and measured enclave startup.

use std::{fs::File, io::Read, path::Path};

use serde::Deserialize;

use crate::{Error, MAX_BUNDLE_BYTES};

/// Public resource configuration included in the measured image.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Executable byte budget, selected for the provisioned enclave's RAM.
    pub max_bundle_bytes: u64,
    /// Worker virtual-memory ceiling, leaving room for the broker and kernel.
    pub address_space_bytes: u64,
    /// Reserved worker UID's process/thread ceiling.
    pub max_threads: u32,
    /// Timeout for each blocking read/write on the accepted provisioning socket (1..=900 seconds).
    /// Configure both directions before receiving; progress can extend the total transfer.
    /// The bootstrap supervisor separately bounds total startup and owns enclave cleanup.
    pub provisioning_io_timeout_seconds: u64,
}

impl BootstrapConfig {
    /// Rejects missing release decisions rather than trusting host-provided defaults.
    ///
    /// # Errors
    /// Returns an error for missing budgets or invalid limits.
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=MAX_BUNDLE_BYTES).contains(&self.max_bundle_bytes)
            || !(1..=i64::MAX as u64).contains(&self.address_space_bytes)
            || !(1..=256).contains(&self.max_threads)
            || !(1..=900).contains(&self.provisioning_io_timeout_seconds)
        {
            return Err(Error::InvalidConfig);
        }

        Ok(())
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

    /// A release without configured resource budgets cannot provision a worker.
    #[test]
    fn unconfigured_release_cannot_boot() {
        let config: Config = serde_json::from_str(r#"{"max_bundle_bytes":0,"address_space_bytes":0,"max_threads":0,"provisioning_io_timeout_seconds":0}"#).unwrap();
        assert!(config.validate().is_err());
    }

    /// Every deployment budget must be valid; no setting is defaulted.
    #[test]
    fn validates_each_configured_budget() {
        let valid = serde_json::json!({
            "max_bundle_bytes": 1024,
            "address_space_bytes": 1024,
            "max_threads": 1,
            "provisioning_io_timeout_seconds": 1
        });
        let config: Config = serde_json::from_value(valid.clone()).unwrap();
        config.validate().unwrap();

        for (field, value) in [
            ("max_bundle_bytes", serde_json::json!(0)),
            ("max_bundle_bytes", serde_json::json!(u64::MAX)),
            ("address_space_bytes", serde_json::json!(0)),
            ("address_space_bytes", serde_json::json!(u64::MAX)),
            ("max_threads", serde_json::json!(0)),
            ("max_threads", serde_json::json!(257)),
            ("provisioning_io_timeout_seconds", serde_json::json!(0)),
            ("provisioning_io_timeout_seconds", serde_json::json!(901)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            let config: Config = serde_json::from_value(invalid).unwrap();
            assert!(config.validate().is_err(), "{field} must be validated");
        }
    }
}
