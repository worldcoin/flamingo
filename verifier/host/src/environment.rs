//! Host configuration parsed from environment variables and CLI flags.

use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

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
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            enclave_cid: 0,
            enclave_port: 0,
            port: default_port(),
            ws_idle_timeout: default_ws_idle_timeout(),
            ws_max_connections: default_ws_max_connections(),
        }
    }
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
