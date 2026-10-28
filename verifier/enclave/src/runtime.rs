//! Provisioned worker startup and enclave serving on Linux.

use std::{
    fs::File,
    io,
    os::unix::fs::FileExt as _,
    path::Path,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, anyhow};
use flamingo_verifier_enclave::{
    attestation::{self, NsmAttestor},
    billing_chain::{BillingChain, BillingChainConfig, BillingReader as _},
    biometric_engine::{MAX_IMAGE_BYTES, MAX_REQUEST_BYTES, SandboxBiometricEngine},
    rng, server,
    state::EnclaveState,
};
use flamingo_verifier_sandbox_client::{FaceLimits, SandboxClient};
use pontifex::SecureModule;
use sha2::{Digest as _, Sha256};
use tabernaculum::{
    ConnectionError, Limits, Policy, SandboxConfig, Worker,
    bundle::{
        BootstrapConfig,
        enclave::{self, Bootstrap, STAGING_DIR},
    },
};
use tracing::error;
use tracing_subscriber::EnvFilter;

const PONTIFEX_PORT: u32 = 1000;

/// The reviewed default worker policy, unchanged.
static POLICY: LazyLock<Policy> = LazyLock::new(Policy::default_worker);

/// Provisions and forks the worker while no executor threads or broker keys exist.
pub(super) fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| {
        error!("enclave panicked");
    }));

    rng::verify_nsm_hwrng_current().context("Nitro hardware RNG is not configured")?;
    // Measured EIF environment, so the host cannot pick the chain, contract or provider.
    let billing = BillingChainConfig::from_env()?;
    let boot = enclave::accept(&BootstrapConfig::default(), Path::new(STAGING_DIR))
        .context("worker artifact provisioning failed")?;
    let runtime = boot.runtime();
    // WIP-201 names the bundle by SHA-256; tabernaculum's SHA-384 only checks the transfer.
    let engine_hash = sha256(&runtime.binary).context("failed to hash the worker executable")?;
    tracing::info!(
        worker_sha384 = %runtime.sha384,
        engine_hash = %hex::encode(engine_hash),
        "worker executable provisioned"
    );
    let limits = FaceLimits {
        max_request_bytes: MAX_REQUEST_BYTES,
        max_image_bytes: MAX_IMAGE_BYTES,
    };
    let (worker, ready) = Worker::spawn(
        &runtime.binary,
        SandboxConfig {
            root: runtime.root.path(),
            limits: Limits::default(),
            policy: &POLICY,
        },
        limits.connection().context("invalid worker limits")?,
        worker_failed,
    )
    .context("sandboxed worker launch failed")?;
    let worker =
        SandboxClient::new(worker, &ready, limits).context("sandboxed worker launch failed")?;
    worker.check_alive();

    // The verified runtime root must outlive the worker and every blocking comparison.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start enclave executor")?
        .block_on(serve(boot, worker, engine_hash, billing))
}

/// Connects the Billing Contract reader and checks the provider serves the configured chain.
///
/// A provider on another chain is a misconfiguration and stops the boot. An unreachable one does
/// not: WIP-107 §4.8 keeps provider failures out of process liveness.
async fn billing_chain(config: BillingChainConfig) -> anyhow::Result<BillingChain> {
    let chain = BillingChain::new(config);
    let expected = chain.config().chain_id;
    match chain.chain_id().await {
        Ok(chain_id) if chain_id == expected => {
            tracing::info!(chain_id, "billing chain reachable");
        }
        Ok(chain_id) => {
            anyhow::bail!("billing RPC serves chain {chain_id}, configured for {expected}")
        }
        Err(error) => tracing::warn!(%error, "billing chain unreachable at boot"),
    }
    Ok(chain)
}

/// `SHA-256` of a file, read without moving its offset.
fn sha256(file: &File) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    let mut offset = 0;
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
        offset += read as u64;
    }
}

/// A terminal worker cannot be replaced within an enclave boot; init tears down the guest.
fn worker_failed(error: ConnectionError) -> ! {
    error!(
        dependency = "biometric_worker",
        %error,
        "terminal worker failure; exiting enclave"
    );
    std::process::exit(1)
}

/// Attests boot keys after isolation and model initialization, then accepts requests.
async fn serve(
    boot: Bootstrap,
    worker: SandboxClient,
    engine_hash: [u8; 32],
    billing: Option<BillingChainConfig>,
) -> anyhow::Result<()> {
    worker.check_alive();
    let engine = Box::new(SandboxBiometricEngine::new(worker));
    // Attests both boot keys, so a broken NSM stops the boot and both caches start populated.
    attestation::connect()
        .await
        .context("Nitro Secure Module is unavailable")?;
    let mut state = EnclaveState::generate(Arc::new(NsmAttestor), engine, engine_hash)
        .map_err(|error| anyhow!("failed to generate and attest the boot keys: {error:?}"))?;
    if let Some(config) = billing {
        state.set_billing_chain(Box::new(billing_chain(config).await?));
    }
    let (encryption_refresh, signing_refresh) = state.start_attestation_refresh();
    let state = Arc::new(state);

    let document = SecureModule::global()
        .attest(None::<Vec<u8>>, None::<Vec<u8>>, None::<Vec<u8>>)
        .context("failed to read boot measurements")?;
    attestation::log_boot_measurements(&document);

    state.check_worker_health();
    // The verified runtime root must outlive the worker, so hold it while serving.
    let _runtime = boot
        .acknowledge()
        .context("failed to acknowledge worker startup")?;

    tokio::select! {
        result = server::start(state, PONTIFEX_PORT) => {
            result.map_err(|error| {
                error!(%error, "enclave Pontifex server stopped");
                error
            })
        }
        result = encryption_refresh => {
            Err(anyhow!(
                "encryption key attestation refresh stopped: {result:?}"
            ))
        }
        result = signing_refresh => {
            Err(anyhow!(
                "signing key attestation refresh stopped: {result:?}"
            ))
        }
    }
}
