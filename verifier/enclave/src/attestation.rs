//! Nitro Secure Module attestation, and the Verifier clock synced to it (WIP-201 §4.4.2).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use flamingo_verifier_enclave_types as enclave_types;
use pontifex::{AttestationDoc, SecureModule};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long after an attest before the background task refreshes the document.
pub const MAX_CACHED_AGE: Duration = Duration::from_mins(10);

/// After a failed refresh, if the last successful attest is at least this old, the
/// refresh task exits so `main` takes down the enclave. Aligned with the client
/// default `max_attestation_age_millis` (1h).
pub const MAX_SERVABLE_AGE: Duration = Duration::from_hours(1);

/// A document and the time it states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// The attestation document: `COSE_Sign1` from Nitro.
    pub document: Vec<u8>,
    /// The document's `timestamp`, in milliseconds since the Unix epoch.
    pub timestamp_millis: u64,
}

/// Produces documents attesting a raw signing key or a channel-key commitment.
pub trait Attestor: Send + Sync {
    /// Attests `public_key` in the document's `public_key` field and `user_data` in its
    /// `user_data` field.
    ///
    /// # Errors
    ///
    /// Returns [`enclave_types::Error::AttestationFailed`] when the module rejects the request.
    fn attest(
        &self,
        public_key: &[u8],
        user_data: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error>;
}

/// [`Attestor`] backed by the real Nitro Secure Module.
#[derive(Debug, Clone, Copy)]
pub struct NsmAttestor;

impl Attestor for NsmAttestor {
    fn attest(
        &self,
        public_key: &[u8],
        user_data: Option<&[u8]>,
    ) -> Result<Attestation, enclave_types::Error> {
        let secure_module =
            SecureModule::try_global().ok_or(enclave_types::Error::SecureModuleNotInitialized)?;

        let document = secure_module
            .raw_attest(
                user_data.map(<[u8]>::to_vec),
                None::<Vec<u8>>,
                Some(public_key.to_vec()),
            )
            .map_err(|error| {
                tracing::error!(?error, "failed to attest public key");
                enclave_types::Error::AttestationFailed
            })?;
        let timestamp_millis = document_timestamp(&document).ok_or_else(|| {
            tracing::error!("the Nitro Secure Module returned an unreadable document");
            enclave_types::Error::AttestationFailed
        })?;
        Ok(Attestation {
            document,
            timestamp_millis,
        })
    }
}

/// The `timestamp` of a `COSE_Sign1` attestation document, without verifying its signature.
fn document_timestamp(document: &[u8]) -> Option<u64> {
    use coset::CborSerializable as _;
    let envelope = coset::CoseSign1::from_slice(document).ok()?;
    let payload = envelope.payload?;
    ciborium::from_reader::<AttestationDoc, _>(payload.as_slice())
        .ok()
        .map(|document| document.timestamp)
}

/// The Verifier's time: the `timestamp` of its latest attestation, advanced on the monotonic
/// clock since (WIP-201 §4.4.2 item 6). No other time source is used.
#[derive(Debug)]
pub struct VerifierClock {
    anchor: Mutex<(u64, Instant)>,
}

impl VerifierClock {
    /// A clock set to `timestamp_millis` now.
    #[must_use]
    pub fn new(timestamp_millis: u64) -> Self {
        Self {
            anchor: Mutex::new((timestamp_millis, Instant::now())),
        }
    }

    /// Syncs the clock to the `timestamp` of a new attestation. Never moves it backwards:
    /// concurrent refreshes of the two keys may sync out of order.
    pub fn sync(&self, timestamp_millis: u64) {
        let mut anchor = self.anchor.lock().unwrap_or_else(PoisonError::into_inner);
        if timestamp_millis >= Self::millis(*anchor) {
            *anchor = (timestamp_millis, Instant::now());
        }
    }

    /// The Verifier's time, in Unix seconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        Self::millis(*self.anchor.lock().unwrap_or_else(PoisonError::into_inner)) / 1000
    }

    fn millis((timestamp_millis, at): (u64, Instant)) -> u64 {
        let elapsed = u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX);
        timestamp_millis.saturating_add(elapsed)
    }
}

/// A cached document and when it was produced.
struct CachedAttestation {
    document: Vec<u8>,
    attested_at: Instant,
}

/// A boot-scoped key binding (raw key or commitment), the `user_data` attested with it, and its
/// latest attestation document. Every successful attestation syncs the [`VerifierClock`].
///
/// Call [`Self::start_refresh`] once; the returned handle must be supervised (see `main`).
/// Until then the construction-time document is served. Readers always get the last
/// successful document immediately.
pub struct AttestedKey {
    binding: Arc<Binding>,
    max_age: Duration,
    refresh_started: bool,
}

/// What [`AttestedKey`] shares with its refresh task.
struct Binding {
    attestor: Arc<dyn Attestor>,
    clock: Arc<VerifierClock>,
    public_key: Vec<u8>,
    /// Held across every attestation, so documents are cached in the order their `user_data`
    /// was set: a refresh that started earlier never overwrites a newer document.
    user_data: Mutex<Option<Vec<u8>>>,
    cached: Mutex<CachedAttestation>,
}

impl Binding {
    /// Attests the binding with its current `user_data` and caches the document.
    fn attest(&self) -> Result<(), enclave_types::Error> {
        let user_data = self
            .user_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.attest_with(user_data.as_deref())
    }

    /// Attests with `user_data` and caches the document. Call with the `user_data` lock held.
    fn attest_with(&self, user_data: Option<&[u8]>) -> Result<(), enclave_types::Error> {
        let attestation = self.attestor.attest(&self.public_key, user_data)?;
        self.clock.sync(attestation.timestamp_millis);
        *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = CachedAttestation {
            document: attestation.document,
            attested_at: Instant::now(),
        };
        Ok(())
    }

    fn attested_at(&self) -> Instant {
        self.cached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .attested_at
    }
}

impl AttestedKey {
    /// Attests `public_key` without `user_data`, and returns it with the clock its document set.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn first(
        attestor: Arc<dyn Attestor>,
        public_key: Vec<u8>,
        max_age: Duration,
    ) -> Result<(Self, Arc<VerifierClock>), enclave_types::Error> {
        let attestation = attestor.attest(&public_key, None)?;
        let clock = Arc::new(VerifierClock::new(attestation.timestamp_millis));
        let key = Self::with_document(
            attestor,
            Arc::clone(&clock),
            public_key,
            max_age,
            attestation,
        );
        Ok((key, clock))
    }

    /// Attests `public_key` without `user_data`, syncing `clock`.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn new(
        attestor: Arc<dyn Attestor>,
        clock: Arc<VerifierClock>,
        public_key: Vec<u8>,
        max_age: Duration,
    ) -> Result<Self, enclave_types::Error> {
        let attestation = attestor.attest(&public_key, None)?;
        clock.sync(attestation.timestamp_millis);
        Ok(Self::with_document(
            attestor,
            clock,
            public_key,
            max_age,
            attestation,
        ))
    }

    fn with_document(
        attestor: Arc<dyn Attestor>,
        clock: Arc<VerifierClock>,
        public_key: Vec<u8>,
        max_age: Duration,
        attestation: Attestation,
    ) -> Self {
        Self {
            binding: Arc::new(Binding {
                attestor,
                clock,
                public_key,
                user_data: Mutex::new(None),
                cached: Mutex::new(CachedAttestation {
                    document: attestation.document,
                    attested_at: Instant::now(),
                }),
            }),
            max_age,
            refresh_started: false,
        }
    }

    /// Attests the key again with `user_data`, which every later refresh keeps.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure; the previous `user_data` and document then stay.
    pub fn set_user_data(&self, user_data: Vec<u8>) -> Result<(), enclave_types::Error> {
        let mut current = self
            .binding
            .user_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.binding.attest_with(Some(&user_data))?;
        *current = Some(user_data);
        drop(current);
        Ok(())
    }

    /// Starts the background refresh task.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn start_refresh(&mut self) -> JoinHandle<()> {
        assert!(!self.refresh_started, "attestation refresh already started");
        self.refresh_started = true;

        let binding = Arc::clone(&self.binding);
        let max_age = self.max_age;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(max_age).await;

                let attesting = Arc::clone(&binding);
                match tokio::task::spawn_blocking(move || attesting.attest()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(?error, "background attestation refresh failed");
                        let age = binding.attested_at().elapsed();
                        if age >= MAX_SERVABLE_AGE {
                            tracing::error!(
                                ?age,
                                max = ?MAX_SERVABLE_AGE,
                                "attestation document exceeded max servable age; exiting refresh task"
                            );
                            return;
                        }
                    }
                    Err(error) => {
                        // spawn_blocking task panicked
                        tracing::error!(
                            ?error,
                            "background attestation spawn_blocking join failed"
                        );
                        return;
                    }
                }
            }
        })
    }

    /// Returns the cached attestation document (may be older than `max_age` while a refresh runs).
    #[must_use]
    pub fn document(&self) -> Vec<u8> {
        self.binding
            .cached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .document
            .clone()
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
    use std::sync::Arc;
    use std::time::Duration;

    use super::{AttestationDoc, AttestedKey, Attestor, MAX_SERVABLE_AGE, VerifierClock};
    use crate::test_support::{
        CountingAttestor, EchoAttestor, FailsAfterSuccessesAttestor, TEST_NOW,
    };

    fn key(attestor: Arc<dyn Attestor>, max_age: Duration) -> AttestedKey {
        AttestedKey::first(attestor, b"a-public-key".to_vec(), max_age)
            .expect("should attest")
            .0
    }

    #[tokio::test]
    async fn reads_inside_the_window_do_not_reach_the_attestor() {
        let attestor = Arc::new(CountingAttestor::new());
        let cached = key(attestor.clone(), Duration::from_hours(1));

        assert_eq!(cached.document(), cached.document());
        assert_eq!(attestor.calls(), 1, "only the one at construction");
    }

    #[tokio::test]
    async fn background_task_refreshes_after_max_age() {
        let attestor = Arc::new(CountingAttestor::new());
        let mut cached = key(attestor.clone(), Duration::from_millis(20));
        let _refresh = cached.start_refresh();
        let before = cached.document();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let after = cached.document();
        assert_ne!(before, after);
        assert!(attestor.calls() >= 2);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_serving_the_last_document() {
        let attestor = Arc::new(FailsAfterSuccessesAttestor::new(1));
        let mut cached = key(attestor.clone(), Duration::from_millis(20));
        let refresh = cached.start_refresh();
        let before = cached.document();

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            attestor.calls() >= 2,
            "failed refresh should have been attempted"
        );
        assert_eq!(cached.document(), before);
        assert!(!refresh.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_task_exits_when_document_exceeds_max_servable_age() {
        let attestor = Arc::new(FailsAfterSuccessesAttestor::new(1));
        let mut cached = key(attestor.clone(), Duration::from_secs(1));
        let refresh = cached.start_refresh();

        tokio::task::yield_now().await;
        tokio::time::advance(MAX_SERVABLE_AGE).await;

        // Awaiting the handle lets the runtime go idle, which is what drives the refresh loop's
        // blocking attest to completion. Spinning on `is_finished` instead kept the runtime busy
        // and failed whenever the blocking pool needed longer than the spin.
        refresh.await.expect("refresh task should not panic");

        assert!(attestor.calls() >= 2);
    }

    #[tokio::test]
    async fn user_data_is_attested_and_kept() {
        let cached = key(Arc::new(EchoAttestor), Duration::from_hours(1));
        assert_eq!(cached.document(), b"a-public-key");
        cached.set_user_data(b"release".to_vec()).unwrap();
        assert_eq!(cached.document(), b"a-public-key|release");
    }

    /// Blocks its first refresh (the second call) until released, so a test can set `user_data`
    /// while that refresh is in flight.
    struct GatedAttestor {
        calls: std::sync::atomic::AtomicUsize,
        refresh_started: std::sync::Barrier,
        release_refresh: std::sync::Barrier,
    }

    impl Attestor for GatedAttestor {
        fn attest(
            &self,
            public_key: &[u8],
            user_data: Option<&[u8]>,
        ) -> Result<super::Attestation, flamingo_verifier_enclave_types::Error> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 1 {
                self.refresh_started.wait();
                self.release_refresh.wait();
            }
            EchoAttestor.attest(public_key, user_data)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refresh_in_flight_never_overwrites_newer_user_data() {
        let attestor = Arc::new(GatedAttestor {
            calls: std::sync::atomic::AtomicUsize::new(0),
            refresh_started: std::sync::Barrier::new(2),
            release_refresh: std::sync::Barrier::new(2),
        });
        let mut cached = key(attestor.clone(), Duration::from_millis(10));
        let _refresh = cached.start_refresh();
        let cached = Arc::new(cached);

        let waiting = Arc::clone(&attestor);
        tokio::task::spawn_blocking(move || waiting.refresh_started.wait())
            .await
            .unwrap();
        // The refresh holds the lock, so this waits for it and attests after it.
        let setting = Arc::clone(&cached);
        let set = tokio::task::spawn_blocking(move || setting.set_user_data(b"release".to_vec()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let releasing = Arc::clone(&attestor);
        tokio::task::spawn_blocking(move || releasing.release_refresh.wait())
            .await
            .unwrap();
        set.await.unwrap().unwrap();
        assert_eq!(cached.document(), b"a-public-key|release");
    }

    #[test]
    fn reads_the_timestamp_of_a_cose_document() {
        use coset::CborSerializable as _;
        let document = AttestationDoc {
            module_id: "i-test".to_owned(),
            digest: pontifex::nsm::Digest::SHA384,
            timestamp: 1_783_446_000_123,
            pcrs: std::collections::BTreeMap::new(),
            certificate: flamingo_verifier_sealed_types::ByteBuf::new(),
            cabundle: Vec::new(),
            public_key: None,
            user_data: None,
            nonce: None,
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&document, &mut payload).unwrap();
        let envelope = coset::CoseSign1Builder::new().payload(payload).build();
        assert_eq!(
            super::document_timestamp(&envelope.to_vec().unwrap()),
            Some(1_783_446_000_123)
        );
        assert_eq!(super::document_timestamp(b"not cose"), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_clock_advances_from_the_latest_attestation() {
        let clock = VerifierClock::new(u64::from(TEST_NOW) * 1000);
        assert_eq!(clock.now(), u64::from(TEST_NOW));
        tokio::time::advance(Duration::from_secs(90)).await;
        assert_eq!(clock.now(), u64::from(TEST_NOW) + 90);
        clock.sync(u64::from(TEST_NOW) * 1000 + 120_000);
        assert_eq!(clock.now(), u64::from(TEST_NOW) + 120);
    }

    #[tokio::test(start_paused = true)]
    async fn an_older_attestation_never_moves_the_clock_back() {
        let clock = VerifierClock::new(u64::from(TEST_NOW) * 1000);
        tokio::time::advance(Duration::from_secs(90)).await;
        clock.sync(u64::from(TEST_NOW) * 1000 + 30_000);
        assert_eq!(clock.now(), u64::from(TEST_NOW) + 90);
    }
}
