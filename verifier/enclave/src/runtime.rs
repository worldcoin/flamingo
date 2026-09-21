//! Provisioned worker startup and enclave serving on Linux.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use flamingo_verifier_enclave::{
    attestation::{self, NsmAttestor},
    biometric_engine::{MAX_IMAGE_BYTES, MAX_REQUEST_BYTES, SandboxBiometricEngine},
    bootstrap::{self, BootWorker},
    rng, server,
    state::EnclaveState,
};
use flamingo_verifier_sandbox_client::{SandboxClientConfig, SandboxClientError};
use flamingo_verifier_sandbox_client::{SandboxConfig, Worker};
use pontifex::SecureModule;
use tracing::error;
use tracing_subscriber::EnvFilter;

const PONTIFEX_PORT: u32 = 1000;

/// Provisions and forks the worker while no executor threads or broker keys exist.
pub(super) fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| {
        error!("enclave panicked");
    }));

    rng::verify_nsm_hwrng_current().context("Nitro hardware RNG is not configured")?;
    let mut boot = bootstrap::receive().context("worker artifact provisioning failed")?;
    let worker = Worker::spawn(
        &boot.runtime.binary,
        SandboxConfig {
            root: boot.runtime.root.path(),
            address_space_bytes: boot.address_space_bytes,
            max_threads: boot.max_threads,
        },
        SandboxClientConfig {
            max_request_bytes: MAX_REQUEST_BYTES,
            max_image_bytes: MAX_IMAGE_BYTES,
            ..SandboxClientConfig::default()
        },
        worker_failed,
    )
    .context("sandboxed worker launch failed")?;
    worker.check_alive();

    // The verified runtime root must outlive the worker and every blocking comparison.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start enclave executor")?
        .block_on(serve(&mut boot, worker))
}

/// A terminal worker cannot be replaced within an enclave boot; init tears down the guest.
fn worker_failed(error: SandboxClientError) -> ! {
    error!(
        dependency = "biometric_worker",
        %error,
        "terminal worker failure; exiting enclave"
    );
    std::process::exit(1)
}

/// Attests boot keys after isolation and model initialization, then accepts requests.
async fn serve(boot: &mut BootWorker, worker: Worker) -> anyhow::Result<()> {
    worker.check_alive();
    let engine = Box::new(SandboxBiometricEngine::new(worker));
    // Attests both boot keys, so a broken NSM stops the boot and both caches start populated.
    attestation::connect()
        .await
        .context("Nitro Secure Module is unavailable")?;
    let mut state = EnclaveState::generate(Arc::new(NsmAttestor), engine)
        .map_err(|error| anyhow!("failed to generate and attest the boot keys: {error:?}"))?;
    let (encryption_refresh, signing_refresh) = state.start_attestation_refresh();
    let state = Arc::new(state);

    let document = SecureModule::global()
        .attest(None::<Vec<u8>>, None::<Vec<u8>>, None::<Vec<u8>>)
        .context("failed to read boot measurements")?;
    attestation::log_boot_measurements(&document);

    state.check_worker_health();
    boot.acknowledge()
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
