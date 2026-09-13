//! Runtime environment configuration.

use std::env;

use std::time::Duration;

use alloy_primitives::{Address, U256};

use crate::payments::PaymentConfig;
use crate::payments::escrow::rpc::EscrowConfig;

/// World Chain Sepolia, where the fee escrow is deployed for development.
const DEFAULT_FEE_ESCROW_CHAIN_ID: u64 = 4801;
/// Deadline for one fee escrow call, retry included.
const DEFAULT_ESCROW_TIMEOUT_MS: u64 = 2_000;
/// How long a capacity read stays good.
const DEFAULT_CAPACITY_TTL_MS: u64 = 5_000;

/// Runtime environment for the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Production environment.
    Production,
    /// Staging environment.
    Staging,
    /// Local development environment.
    Development,
}

impl Environment {
    /// Resolves the runtime environment from `APP_ENV`.
    ///
    /// Defaults to development when `APP_ENV` is unset.
    ///
    /// # Panics
    ///
    /// Panics when `APP_ENV` is not `development`, `staging`, or `production`.
    #[must_use]
    pub fn from_env() -> Self {
        let environment = env::var("APP_ENV")
            .unwrap_or_else(|_| "development".to_owned())
            .trim()
            .to_lowercase();

        match environment.as_str() {
            "production" => Self::Production,
            "staging" => Self::Staging,
            "development" => Self::Development,
            _ => panic!("invalid APP_ENV: {environment}"),
        }
    }

    /// Returns the configured Nitro enclave CID.
    ///
    /// # Panics
    ///
    /// Panics when `ENCLAVE_CID` is unset or is not a valid `u32`.
    #[must_use]
    pub fn enclave_cid(&self) -> u32 {
        Self::required_u32("ENCLAVE_CID")
    }

    /// Returns the configured enclave Pontifex port.
    ///
    /// # Panics
    ///
    /// Panics when `ENCLAVE_PORT` is unset or is not a valid `u32`.
    #[must_use]
    pub fn enclave_port(&self) -> u32 {
        Self::required_u32("ENCLAVE_PORT")
    }

    /// Resolves the payment settings from the environment.
    ///
    /// # Panics
    ///
    /// Panics when `FEE_COLLECTOR_ADDRESS`, `FEE_TOKEN_ADDRESS` or `FEE_MIN_PRICE_PER_UNIT` is
    /// unset, or any payment variable is set but cannot be parsed. Failing at boot beats
    /// discovering a wrong escrow, or a price of one wei, at the first payment.
    #[must_use]
    pub fn payments(&self) -> PaymentConfig {
        PaymentConfig::new(
            Self::optional("FEE_ESCROW_CHAIN_ID", DEFAULT_FEE_ESCROW_CHAIN_ID),
            Self::optional("FEE_ESCROW_ADDRESS", Address::ZERO),
            Self::required_address("FEE_COLLECTOR_ADDRESS"),
            Self::required_address("FEE_TOKEN_ADDRESS"),
            Self::required_u256("FEE_MIN_PRICE_PER_UNIT"),
            Self::optional("PAYMENT_REQUIRED", false),
        )
    }

    /// Resolves how this host reads the fee escrow.
    ///
    /// # Panics
    ///
    /// Panics when `FEE_ESCROW_RPC_URL` is unset, or a timeout is set but unparseable.
    #[must_use]
    pub fn escrow(&self) -> EscrowConfig {
        EscrowConfig {
            rpc_url: Self::required("FEE_ESCROW_RPC_URL"),
            address: Self::optional("FEE_ESCROW_ADDRESS", Address::ZERO),
            chain_id: Self::optional("FEE_ESCROW_CHAIN_ID", DEFAULT_FEE_ESCROW_CHAIN_ID),
            timeout: Duration::from_millis(Self::optional(
                "FEE_ESCROW_RPC_TIMEOUT_MS",
                DEFAULT_ESCROW_TIMEOUT_MS,
            )),
            capacity_ttl: Duration::from_millis(Self::optional(
                "FEE_ESCROW_CAPACITY_TTL_MS",
                DEFAULT_CAPACITY_TTL_MS,
            )),
        }
    }

    fn required(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("{name} environment variable is not set"))
    }

    fn required_u32(name: &str) -> u32 {
        Self::required(name)
            .parse()
            .unwrap_or_else(|_| panic!("{name} environment variable is not a valid u32"))
    }

    /// Parses `name`, falling back to `default` when it is unset.
    ///
    /// A set but unparseable value panics rather than falling back: silently running on a
    /// default the operator did not choose is how a misconfigured escrow reaches production.
    fn optional<T: std::str::FromStr>(name: &str, default: T) -> T {
        let Ok(value) = env::var(name) else {
            return default;
        };

        value.trim().parse().unwrap_or_else(|_| {
            panic!(
                "{name} environment variable is not a valid {}",
                std::any::type_name::<T>()
            )
        })
    }

    fn required_address(name: &str) -> Address {
        Self::required(name)
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{name} environment variable is not a hex address"))
    }

    fn required_u256(name: &str) -> U256 {
        Self::required(name)
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{name} environment variable is not a uint256"))
    }
}
