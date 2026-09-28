//! Resource budgets compiled into the measured enclave binary.

use crate::{Error, MAX_BUNDLE_BYTES};

/// Bootstrap limits; production uses the defaults, tests can override individual budgets.
#[derive(Clone, Copy, Debug)]
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

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            max_bundle_bytes: 1024 * 1024 * 1024,
            address_space_bytes: 3 * 1024 * 1024 * 1024,
            max_threads: 32,
            provisioning_io_timeout_seconds: 120,
        }
    }
}

impl BootstrapConfig {
    /// Checks the limits, including explicit overrides used by tests.
    ///
    /// # Errors
    /// Returns an error for zero budgets or limits exceeding the supported bounds.
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
}

#[cfg(test)]
mod tests {
    use super::BootstrapConfig as Config;

    #[test]
    fn measured_defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn validates_explicit_budget_overrides() {
        let valid = Config::default();

        for invalid in [
            Config {
                max_bundle_bytes: 0,
                ..valid
            },
            Config {
                max_bundle_bytes: u64::MAX,
                ..valid
            },
            Config {
                address_space_bytes: 0,
                ..valid
            },
            Config {
                address_space_bytes: u64::MAX,
                ..valid
            },
            Config {
                max_threads: 0,
                ..valid
            },
            Config {
                max_threads: 257,
                ..valid
            },
            Config {
                provisioning_io_timeout_seconds: 0,
                ..valid
            },
            Config {
                provisioning_io_timeout_seconds: 901,
                ..valid
            },
        ] {
            assert!(invalid.validate().is_err(), "invalid limits: {invalid:?}");
        }
    }
}
