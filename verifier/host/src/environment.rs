//! Host configuration parsed from environment variables and CLI flags.

use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
};

use crate::PublishedMetadata;

use clap::{Parser, ValueEnum};

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

    /// vsock port on which the enclave dials its billing RPC provider (WIP-107 §4.8). Set with
    /// `RPC_UPSTREAM_HOST` to forward it; it must match the image's `BILLING_RPC_PROXY_PORT`.
    #[arg(
        long = "rpc-proxy-port",
        env = "RPC_PROXY_PORT",
        requires = "rpc_upstream_host"
    )]
    pub rpc_proxy_port: Option<u32>,

    /// Host the RPC proxy forwards to. TLS terminates in the enclave, so this only routes bytes.
    #[arg(
        long = "rpc-upstream-host",
        env = "RPC_UPSTREAM_HOST",
        requires = "rpc_proxy_port"
    )]
    pub rpc_upstream_host: Option<String>,

    /// TCP port the RPC proxy forwards to.
    #[arg(long = "rpc-upstream-port", env = "RPC_UPSTREAM_PORT", default_value_t = default_rpc_upstream_port())]
    pub rpc_upstream_port: NonZeroU16,
}

impl HostConfig {
    /// The outbound proxy for the enclave's billing RPC reads, admitting only the enclave.
    #[must_use]
    pub fn rpc_proxy(&self) -> Option<pontifex::proxy::Config> {
        let (port, host) = (self.rpc_proxy_port?, self.rpc_upstream_host.clone()?);
        let mut config = pontifex::proxy::Config::new(port, host, self.rpc_upstream_port.get());
        config.allowed_cid = Some(self.enclave_cid);
        Some(config)
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
            rpc_proxy_port: None,
            rpc_upstream_host: None,
            rpc_upstream_port: default_rpc_upstream_port(),
        }
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

const fn default_rpc_upstream_port() -> NonZeroU16 {
    NonZeroU16::new(443).expect("default RPC port is nonzero")
}

const fn default_port() -> NonZeroU16 {
    NonZeroU16::new(DEFAULT_PORT).expect("default port is nonzero")
}

const fn default_ws_idle_timeout() -> NonZeroU64 {
    NonZeroU64::new(DEFAULT_WS_IDLE_TIMEOUT_SECS).expect("default idle timeout is nonzero")
}

const fn default_ws_max_connections() -> NonZeroUsize {
    NonZeroUsize::new(DEFAULT_WS_MAX_CONNECTIONS).expect("default connection limit is nonzero")
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Environment, HostConfig};

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
