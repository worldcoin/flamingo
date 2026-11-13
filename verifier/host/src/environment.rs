//! Host configuration parsed from environment variables and CLI flags.

use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
};

use alloy::primitives::Address;

use crate::{PublishedMetadata, billing::BillingConfig};

use clap::{Parser, ValueEnum};
use flamingo_verifier_billing_follower::RpcUrl;

const DEFAULT_PORT: u16 = 8000;
const DEFAULT_WS_IDLE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_WS_MAX_CONNECTIONS: usize = 100;

/// Runtime environment for the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Environment {
    /// Production environment.
    Production,
    /// Staging environment.
    Staging,
    /// Local development environment.
    Development,
}

/// Host configuration.
///
/// Every setting has both an environment variable and an equivalent CLI flag; a flag overrides its
/// environment variable. `PORT`, `WS_IDLE_TIMEOUT_SECS` and `WS_MAX_CONNECTIONS` reject zero.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "flamingo-verifier-host",
    about = "Host for the Flamingo verifier"
)]
pub struct HostConfig {
    /// Runtime environment.
    #[arg(
        long = "app-env",
        env = "APP_ENV",
        value_enum,
        ignore_case = true,
        default_value = "development"
    )]
    pub environment: Environment,

    /// Public WIP-201 provider metadata JSON. Omit to disable discovery during rollout.
    #[arg(long = "engine-provider-metadata", env = "ENGINE_PROVIDER_METADATA", value_parser = PublishedMetadataParser, hide_env_values = true)]
    pub engine_provider_metadata: Option<Arc<PublishedMetadata>>,

    /// Nitro enclave CID.
    #[arg(long, env = "ENCLAVE_CID")]
    pub enclave_cid: u32,

    /// Enclave Pontifex port.
    #[arg(long, env = "ENCLAVE_PORT")]
    pub enclave_port: u32,

    /// API listen port.
    #[arg(long, env = "PORT", default_value_t = default_port())]
    pub port: NonZeroU16,

    /// WebSocket idle timeout, in seconds. The deadline runs from the upgrade, restarts after a
    /// valid assignment exchange, and ends when the match frame arrives.
    #[arg(long = "ws-idle-timeout-secs", env = "WS_IDLE_TIMEOUT_SECS", default_value_t = default_ws_idle_timeout())]
    pub ws_idle_timeout: NonZeroU64,

    /// Maximum WebSocket sessions served at once, per host process.
    #[arg(long = "ws-max-connections", env = "WS_MAX_CONNECTIONS", default_value_t = default_ws_max_connections())]
    pub ws_max_connections: NonZeroUsize,

    /// The JSON-RPC endpoint of the chain hosting the WIP-107 Billing Contract. Unset turns
    /// billing off, which an enclave image that bills never becomes ready under.
    #[arg(
        long = "billing-rpc-url",
        env = "BILLING_RPC_URL",
        value_parser = RpcUrlParser,
        hide_env_values = true,
        requires_all = ["billing_chain_id", "billing_contract", "billing_deploy_block"],
    )]
    pub billing_rpc_url: Option<RpcUrl>,

    /// The chain hosting the Billing Contract. Must match the enclave image's.
    #[arg(
        long = "billing-chain-id",
        env = "BILLING_CHAIN_ID",
        requires = "billing_rpc_url"
    )]
    pub billing_chain_id: Option<u64>,

    /// The Billing Contract's address. Must match the enclave image's.
    #[arg(
        long = "billing-contract",
        env = "BILLING_CONTRACT",
        requires = "billing_rpc_url"
    )]
    pub billing_contract: Option<Address>,

    /// The block the Billing Contract was deployed in.
    #[arg(
        long = "billing-deploy-block",
        env = "BILLING_DEPLOY_BLOCK",
        requires = "billing_rpc_url"
    )]
    pub billing_deploy_block: Option<u64>,

    /// Bound on the registrations the host follows. The enclave image's should not be smaller.
    #[arg(long = "billing-max-registrations", env = "BILLING_MAX_REGISTRATIONS", default_value_t = default_max_registrations())]
    pub billing_max_registrations: NonZeroUsize,
}

impl HostConfig {
    /// The billing configuration, or `None` if billing is off. Parsing sets all of it or none.
    #[must_use]
    pub fn billing(&self) -> Option<BillingConfig> {
        Some(BillingConfig {
            rpc_url: self.billing_rpc_url.clone()?,
            chain_id: self.billing_chain_id?,
            contract: self.billing_contract?,
            deploy_block: self.billing_deploy_block?,
            max_registrations: self.billing_max_registrations.get(),
        })
    }
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            engine_provider_metadata: None,
            enclave_cid: 0,
            enclave_port: 0,
            port: default_port(),
            ws_idle_timeout: default_ws_idle_timeout(),
            ws_max_connections: default_ws_max_connections(),
            billing_rpc_url: None,
            billing_chain_id: None,
            billing_contract: None,
            billing_deploy_block: None,
            billing_max_registrations: default_max_registrations(),
        }
    }
}

#[derive(Clone)]
struct RpcUrlParser;

impl clap::builder::TypedValueParser for RpcUrlParser {
    type Value = RpcUrl;

    fn parse_ref(
        &self,
        _: &clap::Command,
        _: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        // Clap's default error echoes the input, which carries the provider's API key.
        let url = value
            .to_str()
            .and_then(|value| value.parse::<url::Url>().ok())
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .ok_or_else(|| {
                clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    "BILLING_RPC_URL must be an HTTP or HTTPS URL",
                )
            })?;
        Ok(RpcUrl(url))
    }
}

#[derive(Clone)]
struct PublishedMetadataParser;

impl clap::builder::TypedValueParser for PublishedMetadataParser {
    type Value = Arc<PublishedMetadata>;

    fn parse_ref(
        &self,
        _: &clap::Command,
        _: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidUtf8,
                "Engine Provider metadata must be UTF-8",
            )
        })?;
        // Clap's default error echoes the input, which could accidentally include a private JWK.
        value
            .parse::<PublishedMetadata>()
            .map(Arc::new)
            .map_err(|error| {
                clap::Error::raw(clap::error::ErrorKind::ValueValidation, error.to_string())
            })
    }
}

const fn default_port() -> NonZeroU16 {
    NonZeroU16::new(DEFAULT_PORT).expect("default port is nonzero")
}

const fn default_ws_idle_timeout() -> NonZeroU64 {
    NonZeroU64::new(DEFAULT_WS_IDLE_TIMEOUT_SECS).expect("default idle timeout is nonzero")
}

const fn default_max_registrations() -> NonZeroUsize {
    NonZeroUsize::new(crate::billing::DEFAULT_MAX_REGISTRATIONS)
        .expect("the default bound is nonzero")
}

const fn default_ws_max_connections() -> NonZeroUsize {
    NonZeroUsize::new(DEFAULT_WS_MAX_CONNECTIONS).expect("default connection limit is nonzero")
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Environment, HostConfig};

    const BILLING: [&str; 8] = [
        "--billing-rpc-url",
        "https://one.example.com/v2/key-one",
        "--billing-chain-id",
        "480",
        "--billing-contract",
        "0x1111111111111111111111111111111111111111",
        "--billing-deploy-block",
        "42",
    ];

    #[test]
    fn billing_is_set_in_full_or_not_at_all() {
        let base = ["host", "--enclave-cid", "16", "--enclave-port", "1000"];
        assert!(parse(&base).unwrap().billing().is_none());

        let billing = parse(&[base.as_slice(), &BILLING].concat())
            .unwrap()
            .billing()
            .expect("billing is configured");
        assert_eq!(billing.rpc_url.0.host_str(), Some("one.example.com"));
        assert_eq!(billing.chain_id, 480);
        assert_eq!(billing.deploy_block, 42);
        assert_eq!(billing.max_registrations, 1 << 22);

        for missing in [0, 2, 4, 6] {
            let mut partial = BILLING.to_vec();
            partial.drain(missing..missing + 2);
            assert!(parse(&[base.as_slice(), &partial].concat()).is_err());
        }
    }

    #[test]
    fn billing_urls_are_never_echoed() {
        let base = ["host", "--enclave-cid", "16", "--enclave-port", "1000"];
        let config = parse(&[base.as_slice(), &BILLING].concat()).unwrap();
        assert!(!format!("{config:?}").contains("key-one"));

        let mut invalid = BILLING.to_vec();
        invalid[1] = "ftp://secret-key@example.com";
        let error = parse(&[base.as_slice(), &invalid].concat()).unwrap_err();
        assert!(!error.to_string().contains("secret-key"));
    }

    fn parse(args: &[&str]) -> Result<HostConfig, clap::Error> {
        HostConfig::try_parse_from(args)
    }

    #[test]
    fn defaults_are_applied_when_only_the_required_fields_are_given() {
        let config = parse(&["host", "--enclave-cid", "16", "--enclave-port", "1000"])
            .expect("required fields should parse");

        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.enclave_cid, 16);
        assert_eq!(config.enclave_port, 1000);
        assert_eq!(config.port.get(), 8000);
        assert_eq!(config.ws_idle_timeout.get(), 30);
        assert_eq!(config.ws_max_connections.get(), 100);
    }

    #[test]
    fn flags_override_defaults() {
        let config = parse(&[
            "host",
            "--enclave-cid",
            "16",
            "--enclave-port",
            "1000",
            "--app-env",
            "production",
            "--port",
            "9000",
            "--ws-idle-timeout-secs",
            "5",
            "--ws-max-connections",
            "7",
        ])
        .expect("all provided fields should parse");

        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.port.get(), 9000);
        assert_eq!(config.ws_idle_timeout.get(), 5);
        assert_eq!(config.ws_max_connections.get(), 7);
    }

    #[test]
    fn provider_metadata_is_validated_without_echoing_input() {
        let json = include_str!("../tests/fixtures/engine-provider.json");
        let config = parse(&[
            "host",
            "--enclave-cid",
            "16",
            "--enclave-port",
            "1000",
            "--engine-provider-metadata",
            json,
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(config.engine_provider_metadata.unwrap().as_ref()).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
        for invalid in ["", "{}", r#"{"secret":"PRIVATE-KEY-MUST-NOT-BE-ECHOED"}"#] {
            let error = parse(&[
                "host",
                "--enclave-cid",
                "16",
                "--enclave-port",
                "1000",
                "--engine-provider-metadata",
                invalid,
            ])
            .unwrap_err();
            assert!(!error.to_string().contains("PRIVATE-KEY-MUST-NOT-BE-ECHOED"));
        }
    }

    #[test]
    fn zero_is_rejected() {
        for args in [
            vec![
                "host",
                "--enclave-cid",
                "16",
                "--enclave-port",
                "1000",
                "--port",
                "0",
            ],
            vec![
                "host",
                "--enclave-cid",
                "16",
                "--enclave-port",
                "1000",
                "--ws-idle-timeout-secs",
                "0",
            ],
            vec![
                "host",
                "--enclave-cid",
                "16",
                "--enclave-port",
                "1000",
                "--ws-max-connections",
                "0",
            ],
        ] {
            assert!(parse(&args).is_err(), "{args:?} should reject zero");
        }
    }

    #[test]
    fn invalid_values_are_rejected() {
        assert!(
            parse(&["host", "--enclave-cid", "16"]).is_err(),
            "missing port"
        );
        assert!(parse(&["host", "--enclave-cid", "abc", "--enclave-port", "1000"]).is_err());
        assert!(
            parse(&[
                "host",
                "--enclave-cid",
                "16",
                "--enclave-port",
                "1000",
                "--app-env",
                "nope"
            ])
            .is_err()
        );
    }
}
