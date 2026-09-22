use crate::{config::Config, process};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{path::Path, time::Duration};

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
        let c = self.config;
        let response = process::output(
            "nitro-cli",
            &[
                "run-enclave".as_ref(),
                "--eif-path".as_ref(),
                c.eif.as_os_str(),
                "--cpu-count".as_ref(),
                c.cpus.to_string().as_ref(),
                "--memory".as_ref(),
                c.memory_mib.to_string().as_ref(),
                "--enclave-cid".as_ref(),
                c.cid.to_string().as_ref(),
                "--enclave-name".as_ref(),
                self.name.as_ref(),
            ],
            c.bootstrap_timeout,
        )
        .await?;
        let launch: serde_json::Value = serde_json::from_slice(&response)?;
        ensure!(
            launch["EnclaveCID"].as_u64() == Some(u64::from(c.cid)),
            "unexpected launched CID"
        );
        Ok(())
    }

    pub async fn provision(&self, bundle: &Path) -> Result<()> {
        let c = self.config;
        process::output(
            &c.tool,
            &[
                "send".as_ref(),
                c.cid.to_string().as_ref(),
                bundle.as_os_str(),
                c.io_timeout.to_string().as_ref(),
            ],
            c.bootstrap_timeout,
        )
        .await?;
        Ok(())
    }

    pub async fn health(&self) -> Result<()> {
        process::output(
            &self.config.tool,
            &["health".as_ref(), self.config.cid.to_string().as_ref()],
            Duration::from_secs(5),
        )
        .await?;
        Ok(())
    }

    pub async fn running(&self) -> Result<()> {
        ensure!(
            self.describe()
                .await?
                .iter()
                .any(|e| e.name == self.name && e.state == "RUNNING" && e.flags == "NONE"),
            "owned measured enclave is not running"
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

    pub async fn cleanup(&self) -> Result<()> {
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
