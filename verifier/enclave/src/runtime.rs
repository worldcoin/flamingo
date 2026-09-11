//! Authenticated worker startup and enclave serving on Linux.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use flamingo_verifier_enclave::{
    attestation::{self, NsmAttestor},
    bootstrap::{self, BootWorker},
    face_engine::{FaceEngine, MAX_IMAGE_BYTES, MAX_REQUEST_BYTES},
    rng, server,
    state::EnclaveState,
};
use flamingo_verifier_worker_process::{SandboxConfig, Worker};
use flamingo_verifier_worker_rpc::{WorkerClientConfig, WorkerClientError};
use pontifex::SecureModule;
use tracing::error;
use tracing_subscriber::EnvFilter;

const PONTIFEX_PORT: u32 = 1000;

/// Authenticates and forks the worker while no executor threads or broker keys exist.
pub(super) fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| {
        error!(failure_class = "panic", "enclave panicked");
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
        WorkerClientConfig {
            first_request_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(10),
            max_request_bytes: MAX_REQUEST_BYTES,
            max_image_bytes: MAX_IMAGE_BYTES,
            score_range: -1.0..=1.0,
        },
        worker_failed,
    )
    .context("sandboxed worker launch failed")?;
    worker.check_alive();

    // The authenticated runtime root must outlive the worker and every blocking comparison.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start enclave executor")?
        .block_on(serve(&mut boot, worker))
}

/// A terminal worker cannot be replaced within an enclave boot; init tears down the guest.
fn worker_failed(error: WorkerClientError) -> ! {
    metrics::counter!("enclave_match.failures", "class" => "worker_terminal").increment(1);
    error!(
        dependency = "biometric_worker",
        failure_class = error.failure_class(),
        "terminal worker failure; exiting enclave"
    );
    std::process::exit(1)
}

/// Attests boot keys only after isolation, then accepts requests without an inference handshake.
async fn serve(boot: &mut BootWorker, worker: Worker) -> anyhow::Result<()> {
    worker.check_alive();
    let face_engine = Arc::new(FaceEngine::new(worker));
    // Attests both boot keys, so a broken NSM stops the boot and both caches start populated.
    attestation::connect()
        .await
        .context("Nitro Secure Module is unavailable")?;
    let mut state = EnclaveState::generate(Arc::new(NsmAttestor), face_engine)
        .map_err(|error| anyhow!("failed to generate and attest the boot keys: {error:?}"))?;
    let (encryption_refresh, signing_refresh) = state.start_attestation_refresh();
    let state = Arc::new(state);

    let document = SecureModule::global()
        .attest(None::<Vec<u8>>, None::<Vec<u8>>, None::<Vec<u8>>)
        .context("failed to read boot measurements")?;
    attestation::log_boot_measurements(&document);

    state.face_engine().check_health();
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
