use std::{env, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};

pub struct Config {
    pub eif: PathBuf,
    pub tool: String,
    pub ready_file: PathBuf,
    pub artifact_uri: String,
    pub artifact_sha256: String,
    pub release_id: String,
    pub cid: u32,
    pub cpus: u32,
    pub memory_mib: u32,
    pub bootstrap_timeout: Duration,
    pub io_timeout: u64,
    pub poll_interval: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let environment = env::var("WORKER_ENVIRONMENT").context("missing WORKER_ENVIRONMENT")?;
        let release_id = env::var("WORKER_RELEASE_ID").context("missing WORKER_RELEASE_ID")?;
        let artifact_uri =
            env::var("WORKER_ARTIFACT_URI").context("missing WORKER_ARTIFACT_URI")?;
        let artifact_sha256 =
            env::var("WORKER_ARTIFACT_SHA256").context("missing WORKER_ARTIFACT_SHA256")?;
        validate_pin(&environment, &release_id, &artifact_uri, &artifact_sha256)?;
        let cid = number("ENCLAVE_CID", 16)?;
        ensure!(cid > 3, "enclave CID must be greater than 3");
        let io_timeout = u64::from(number("PROVISIONING_IO_TIMEOUT_SECONDS", 120)?);
        ensure!(
            io_timeout <= 900,
            "provisioning I/O timeout exceeds 900 seconds"
        );
        Ok(Self {
            eif: setting("EIF_PATH", "/home/enclave.eif").into(),
            tool: setting("WORKER_TOOL", "/home/sandbox-bundle"),
            ready_file: ready_file(),
            artifact_uri,
            artifact_sha256,
            release_id,
            cid,
            cpus: number("ENCLAVE_CPU_COUNT", 2)?,
            memory_mib: number("ENCLAVE_MEMORY_SIZE", 4096)?,
            bootstrap_timeout: Duration::from_secs(
                number("BOOTSTRAP_TIMEOUT_SECONDS", 300)?.into(),
            ),
            io_timeout,
            poll_interval: Duration::from_secs(number("POLL_SECONDS", 2)?.into()),
        })
    }
}

pub fn ready_file() -> PathBuf {
    setting("WORKER_READY_FILE", "/run/flamingo/ready").into()
}

fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn number(name: &str, default: u32) -> Result<u32> {
    let value = setting(name, &default.to_string())
        .parse::<u32>()
        .with_context(|| format!("invalid {name}"))?;
    ensure!(value > 0, "{name} must be positive");
    Ok(value)
}

fn validate_pin(environment: &str, release: &str, uri: &str, digest: &str) -> Result<()> {
    ensure!(
        ["dev", "stage", "prod"].contains(&environment),
        "invalid worker environment"
    );
    let version = release
        .strip_prefix("biometric-engines-worker-v")
        .context("invalid worker release id")?;
    ensure!(
        version.starts_with(|c: char| c.is_ascii_digit())
            && release.len() <= 128
            && version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c)),
        "invalid worker release version"
    );
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && digest.bytes().any(|c| c != b'0'),
        "invalid archive SHA256 pin"
    );
    ensure!(
        uri == format!(
            "s3://biometric-engines-worker-{environment}-eu-central-1/worker/v{version}/{release}-x86_64-unknown-linux-gnu.tar.gz"
        ),
        "artifact URI does not match environment and release"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pins_bind_environment_version_and_archive() {
        let release = "biometric-engines-worker-v0.1.0-devtest";
        let uri = format!(
            "s3://biometric-engines-worker-dev-eu-central-1/worker/v0.1.0-devtest/{release}-x86_64-unknown-linux-gnu.tar.gz"
        );
        let digest = "a".repeat(64);
        validate_pin("dev", release, &uri, &digest).unwrap();
        assert!(validate_pin("stage", release, &uri, &digest).is_err());
        assert!(validate_pin("dev", release, &uri, &"0".repeat(64)).is_err());
        assert!(validate_pin("dev", release, &uri, "placeholder").is_err());
        assert!(validate_pin("dev", "biometric-engines-worker-v../bad", &uri, &digest).is_err());
    }
}
