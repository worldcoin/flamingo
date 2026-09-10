//! Nitro Secure Module attestation.

use std::sync::Arc;
use std::time::Duration;

use flamingo_verifier_enclave_types as enclave_types;
use pontifex::{AttestationDoc, SecureModule};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long after an attest before the background task refreshes the document.
pub const MAX_CACHED_AGE: Duration = Duration::from_mins(10);

/// After a failed refresh, if the last successful attest is at least this old, the
/// refresh task exits so `main` takes down the enclave. Aligned with the client
/// default `max_attestation_age_millis` (1h).
pub const MAX_SERVABLE_AGE: Duration = Duration::from_hours(1);

/// Bounds each refresh and the initial NSM connection plus boot-key attestations.
pub const NSM_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs an NSM operation off the executor; a hung or panicking device call is terminal.
/// Returning would leave a detached blocking task that can prevent runtime shutdown.
pub async fn run_bounded<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    let result = tokio::time::timeout(
        NSM_OPERATION_TIMEOUT,
        tokio::task::spawn_blocking(operation),
    )
    .await;
    let failure_class = match result {
        Ok(Ok(value)) => return value,
        Ok(Err(_)) => "panic",
        Err(_) => "request_timeout",
    };
    metrics::counter!("enclave_attestation.failures", "class" => failure_class).increment(1);
    tracing::error!(
        dependency = "nitro_nsm",
        failure_class,
        "terminal NSM operation failure"
    );
    std::process::exit(1)
}

/// Produces documents attesting a raw signing key or a channel-key commitment.
pub trait Attestor: Send + Sync {
    /// Attests `public_key` in the document's `public_key` field.
    /// # Errors
    ///
    /// Returns [`enclave_types::Error::AttestationFailed`] when the module rejects the request.
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error>;
}

/// [`Attestor`] backed by the real Nitro Secure Module.
#[derive(Debug, Clone, Copy)]
pub struct NsmAttestor;

impl Attestor for NsmAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
        let secure_module =
            SecureModule::try_global().ok_or(enclave_types::Error::SecureModuleNotInitialized)?;

        secure_module
            .raw_attest(None::<Vec<u8>>, None::<Vec<u8>>, Some(public_key.to_vec()))
            .map_err(|error| {
                tracing::error!(?error, "failed to attest public key");
                enclave_types::Error::AttestationFailed
            })
    }
}

/// A cached document and when it was produced.
struct CachedAttestation {
    document: Vec<u8>,
    attested_at: Instant,
}

/// A boot-scoped key binding (raw key or commitment) and its latest attestation document.
///
/// Call [`Self::start_refresh`] once; the returned handle must be supervised (see `main`).
/// Until then the construction-time document is served. Readers always get the last
/// successful document immediately.
pub struct AttestedKey {
    attestor: Arc<dyn Attestor>,
    public_key: Vec<u8>,
    max_age: Duration,
    cached_attestation: Arc<Mutex<CachedAttestation>>,
    refresh_started: bool,
}

impl AttestedKey {
    /// Constructs a new `AttestedKey` for `public_key` using the given `attestor`.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn new(
        attestor: Arc<dyn Attestor>,
        public_key: Vec<u8>,
        max_age: Duration,
    ) -> Result<Self, enclave_types::Error> {
        let document = attestor.attest_public_key(&public_key)?;

        Ok(Self {
            attestor,
            public_key,
            max_age,
            cached_attestation: Arc::new(Mutex::new(CachedAttestation {
                document,
                attested_at: Instant::now(),
            })),
            refresh_started: false,
        })
    }

    /// Starts the background refresh task.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn start_refresh(&mut self) -> JoinHandle<()> {
        assert!(!self.refresh_started, "attestation refresh already started");
        self.refresh_started = true;

        let attestor = Arc::clone(&self.attestor);
        let public_key = self.public_key.clone();
        let max_age = self.max_age;
        let cache = Arc::clone(&self.cached_attestation);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(max_age).await;

                let attestor = Arc::clone(&attestor);
                let key = public_key.clone();
                let result = run_bounded(move || attestor.attest_public_key(&key)).await;

                match result {
                    Ok(document) => {
                        let mut cached = cache.lock().await;
                        cached.document = document;
                        cached.attested_at = Instant::now();
                    }
                    Err(error) => {
                        tracing::error!(?error, "background attestation refresh failed");
                        let age = cache.lock().await.attested_at.elapsed();
                        if age >= MAX_SERVABLE_AGE {
                            tracing::error!(
                                ?age,
                                max = ?MAX_SERVABLE_AGE,
                                "attestation document exceeded max servable age; exiting refresh task"
                            );
                            return;
                        }
                    }
                }
            }
        })
    }

    /// Cached attestations remain usable during brief NSM failures, never beyond the client limit.
    pub async fn is_fresh(&self) -> bool {
        self.cached_attestation.lock().await.attested_at.elapsed() < MAX_SERVABLE_AGE
    }

    /// Returns the cached attestation document (may be older than `max_age` while a refresh runs).
    pub async fn document(&self) -> Vec<u8> {
        let cached = self.cached_attestation.lock().await;
        if cached.attested_at.elapsed() >= MAX_SERVABLE_AGE {
            metrics::counter!("enclave_attestation.failures", "class" => "stale_cache")
                .increment(1);
            tracing::error!(
                dependency = "nitro_nsm",
                failure_class = "stale_cache",
                "cached attestation expired"
            );
            std::process::exit(1);
        }
        cached.document.clone()
    }
}

/// Connects to the Nitro Secure Module. Called before serving so a missing or broken device fails the boot.
///
/// # Errors
///
/// Returns an error when the NSM device cannot be opened.
pub async fn connect() -> anyhow::Result<&'static SecureModule> {
    Ok(SecureModule::try_init_global().await?)
}

/// Whether every PCR in a document is zeroed.
///
/// True for a `--debug-mode` enclave, whose measurements say nothing about the image
/// that produced them.
#[must_use]
pub fn has_zeroed_measurements(document: &AttestationDoc) -> bool {
    !document.pcrs.is_empty()
        && document
            .pcrs
            .values()
            .all(|pcr| pcr.iter().all(|&b| b == 0))
}

/// Logs the measurements a client will pin this enclave against.
///
/// Emitted once at boot so the running image is identifiable from logs alone, without
/// an attestation fetch.
///
/// Clients pin `pcr0`, which is a hash of the whole image. `pcr1` (kernel and boot ramfs) and
/// `pcr2` (application) are logged for introspection.
pub fn log_boot_measurements(document: &AttestationDoc) {
    if has_zeroed_measurements(document) {
        tracing::warn!(
            module_id = %document.module_id,
            "enclave is running in debug mode: measurements are zeroed and attestations \
             are not verifiable against a released image"
        );
        return;
    }

    let measurement = |index: usize| {
        document
            .pcrs
            .get(&index)
            .map(hex::encode)
            .unwrap_or_default()
    };

    tracing::info!(
        module_id = %document.module_id,
        pcr0 = %measurement(0),
        pcr1 = %measurement(1),
        pcr2 = %measurement(2),
        "attested enclave measurements"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Duration;

    use flamingo_verifier_enclave_types as enclave_types;
    use tokio::sync::Notify;

    use super::{AttestedKey, Attestor, MAX_SERVABLE_AGE, NSM_OPERATION_TIMEOUT, run_bounded};
    use crate::test_support::{CountingAttestor, FailsAfterSuccessesAttestor};

    fn key(attestor: Arc<dyn Attestor>, max_age: Duration) -> AttestedKey {
        AttestedKey::new(attestor, b"a-public-key".to_vec(), max_age).expect("should attest")
    }

    #[tokio::test]
    async fn reads_inside_the_window_do_not_reach_the_attestor() {
        let attestor = Arc::new(CountingAttestor::new());
        let cached = key(attestor.clone(), Duration::from_hours(1));

        assert_eq!(cached.document().await, cached.document().await);
        assert_eq!(attestor.calls(), 1, "only the one at construction");
    }

    #[tokio::test]
    async fn background_task_refreshes_after_max_age() {
        let attestor = Arc::new(CountingAttestor::new());
        let mut cached = key(attestor.clone(), Duration::from_millis(20));
        let _refresh = cached.start_refresh();
        let before = cached.document().await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let after = cached.document().await;
        assert_ne!(before, after);
        assert!(attestor.calls() >= 2);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_serving_the_last_document() {
        let attestor = Arc::new(FailsAfterSuccessesAttestor::new(1));
        let mut cached = key(attestor.clone(), Duration::from_millis(20));
        let refresh = cached.start_refresh();
        let before = cached.document().await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            attestor.calls() >= 2,
            "failed refresh should have been attempted"
        );
        assert_eq!(cached.document().await, before);
        assert!(!refresh.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_task_exits_when_document_exceeds_max_servable_age() {
        let attestor = Arc::new(FailsAfterSuccessesAttestor::new(1));
        let mut cached = key(attestor.clone(), Duration::from_secs(1));
        let refresh = cached.start_refresh();

        tokio::task::yield_now().await;
        tokio::time::advance(MAX_SERVABLE_AGE).await;
        // Do not auto-advance the new hard timeout before the blocking pool gets CPU time.
        tokio::time::resume();

        // Awaiting the handle lets the runtime go idle, which is what drives the refresh loop's
        // blocking attest to completion. Spinning on `is_finished` instead kept the runtime busy
        // and failed whenever the blocking pool needed longer than the spin.
        refresh.await.expect("refresh task should not panic");

        assert!(attestor.calls() >= 2);
    }

    /// Successful calls and ordinary NSM rejection preserve their result under the deadline.
    #[tokio::test]
    async fn bounded_operation_preserves_results() {
        assert_eq!(
            run_bounded(|| Ok::<_, enclave_types::Error>(42)).await,
            Ok(42)
        );
        assert_eq!(
            run_bounded(|| Err::<(), _>(enclave_types::Error::AttestationFailed)).await,
            Err(enclave_types::Error::AttestationFailed)
        );
    }

    /// Boots successfully, then blocks the background device operation without consuming CPU.
    struct BlockingAttestor {
        /// Only the construction-time attestation succeeds.
        calls: AtomicUsize,
        /// Signals that the blocking operation really started.
        entered: Arc<Notify>,
        /// Held closed until the subprocess exits at the device deadline.
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Attestor for BlockingAttestor {
        /// The fixture is used only to verify terminal timeout behavior, never inference.
        fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
            if self.calls.fetch_add(1, Ordering::Relaxed) != 0 {
                self.entered.notify_one();
                self.release.lock().unwrap().recv().unwrap();
            }
            Ok(public_key.to_vec())
        }
    }

    /// A hung refresh exits the process instead of waiting forever while dropping the runtime.
    #[test]
    fn hung_refresh_is_terminal_without_waiting_for_device() {
        const CHILD_ENV: &str = "FLAMINGO_TEST_NSM_TIMEOUT";
        if std::env::var_os(CHILD_ENV).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                tokio::time::pause();
                let entered = Arc::new(Notify::new());
                let (_release, receiver) = mpsc::channel();
                let attestor = Arc::new(BlockingAttestor {
                    calls: AtomicUsize::new(0),
                    entered: Arc::clone(&entered),
                    release: Mutex::new(receiver),
                });
                let mut cached = key(attestor, Duration::from_secs(1));
                let refresh = cached.start_refresh();
                tokio::task::yield_now().await;
                tokio::time::advance(Duration::from_secs(1)).await;
                entered.notified().await;
                tokio::time::advance(NSM_OPERATION_TIMEOUT + Duration::from_millis(1)).await;
                refresh.await.unwrap();
            });
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "attestation::tests::hung_refresh_is_terminal_without_waiting_for_device",
            ])
            .env(CHILD_ENV, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(1));
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("hung NSM operation survived its hard deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
