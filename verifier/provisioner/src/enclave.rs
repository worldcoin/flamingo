use crate::{config::Config, process};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{path::Path, time::Duration};
use tokio::time::sleep;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Description {
    #[serde(rename = "EnclaveID")]
    id: String,
    #[serde(rename = "EnclaveName")]
    name: String,
    state: String,
    flags: String,
}

impl Description {
    fn is_running(&self, name: &str, debug_mode: bool) -> bool {
        let expected_flags = if debug_mode { "DEBUG_MODE" } else { "NONE" };
        self.name == name && self.state == "RUNNING" && self.flags == expected_flags
    }
}

pub struct Enclave<'a> {
    pub name: String,
    config: &'a Config,
}

impl<'a> Enclave<'a> {
    pub fn new(config: &'a Config, suffix: &str) -> Self {
        Self {
            name: format!(
                "flamingo-{}-{}",
                std::process::id(),
                suffix.trim_start_matches('.')
            ),
            config,
        }
    }

    pub async fn launch(&self) -> Result<()> {
        let config = self.config;
        let cpus = config.cpus.to_string();
        let memory = config.memory_mib.to_string();
        let cid = config.cid.to_string();
        let mut args = vec![
            "run-enclave".as_ref(),
            "--eif-path".as_ref(),
            config.eif.as_os_str(),
            "--cpu-count".as_ref(),
            cpus.as_ref(),
            "--memory".as_ref(),
            memory.as_ref(),
            "--enclave-cid".as_ref(),
            cid.as_ref(),
            "--enclave-name".as_ref(),
            self.name.as_ref(),
        ];
        if config.debug_mode {
            args.push("--debug-mode".as_ref());
        }
        let response = process::output("nitro-cli", &args, config.bootstrap_timeout).await?;

        let launch: serde_json::Value = serde_json::from_slice(&response)?;
        ensure!(
            launch["EnclaveCID"].as_u64() == Some(u64::from(config.cid)),
            "unexpected launched CID"
        );

        Ok(())
    }

    /// Bootstrap has already checked the worker, release manifest and application health.
    /// Worker death exits the enclave; Kubernetes restarts this provisioner for a new boot.
    pub async fn monitor(&self) -> Result<()> {
        loop {
            self.running().await?;

            sleep(self.config.poll_interval).await;
        }
    }

    pub async fn running(&self) -> Result<()> {
        ensure!(
            self.describe()
                .await?
                .iter()
                .any(|e| e.is_running(&self.name, self.config.debug_mode)),
            "owned enclave is not running in the configured mode"
        );
        Ok(())
    }

    async fn describe(&self) -> Result<Vec<Description>> {
        Ok(serde_json::from_slice(
            &process::output(
                "nitro-cli",
                &["describe-enclaves".as_ref()],
                Duration::from_secs(10),
            )
            .await?,
        )?)
    }

    pub async fn stop(&self) -> Result<()> {
        // Name lookup also covers a cancelled launch that never returned its enclave ID.
        let owned: Vec<_> = self
            .describe()
            .await?
            .into_iter()
            .filter(|e| e.name == self.name)
            .collect();
        ensure!(owned.len() <= 1, "duplicate owned enclave name");

        if let Some(enclave) = owned.first() {
            let terminated = process::output(
                "nitro-cli",
                &[
                    "terminate-enclave".as_ref(),
                    "--enclave-id".as_ref(),
                    enclave.id.as_ref(),
                ],
                Duration::from_secs(15),
            )
            .await;

            if terminated.is_err() {
                ensure!(
                    !self.describe().await?.iter().any(|e| e.id == enclave.id),
                    "owned enclave cleanup failed"
                );
            }
        }

        Ok(())
    }
}

pub async fn clear_readiness(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("cannot clear readiness"),
    }
}

#[cfg(test)]
mod tests {
    use super::Description;

    #[test]
    fn running_requires_the_owned_enclave_and_exact_configured_mode() {
        let mut enclave = Description {
            id: "owned".into(),
            name: "test-enclave".into(),
            state: "RUNNING".into(),
            flags: "NONE".into(),
        };
        assert!(enclave.is_running("test-enclave", false));
        assert!(!enclave.is_running("test-enclave", true));
        enclave.flags = "DEBUG_MODE".into();
        assert!(enclave.is_running("test-enclave", true));
        assert!(!enclave.is_running("test-enclave", false));
        assert!(!enclave.is_running("another-enclave", true));
        enclave.state = "TERMINATING".into();
        assert!(!enclave.is_running("test-enclave", true));
    }
}
