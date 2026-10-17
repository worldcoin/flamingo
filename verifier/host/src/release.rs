//! Keeps the enclave's WIP-201 release manifest loaded.

use std::{sync::Arc, time::Duration};

use flamingo_verifier_enclave_types as enclave_types;
use rand::Rng as _;

use crate::enclave::{self, EnclaveClient};

/// How often a loaded manifest is sent again, so a restarted enclave gets it back.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);
const MIN_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Loads `manifest` into the enclave and keeps it loaded; never returns.
///
/// Loading is idempotent, so the manifest is resent every [`RELOAD_INTERVAL`]. Failures retry with
/// capped exponential backoff and full jitter. Until a load succeeds the enclave reports itself not
/// ready, so readiness reflects a missing release.
pub async fn keep_loaded(client: Arc<dyn EnclaveClient>, manifest: String) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let delay = match client.load_release(manifest.clone()).await {
            Ok(()) => {
                backoff = MIN_BACKOFF;
                RELOAD_INTERVAL
            }
            Err(error) => {
                let delay = jittered(backoff);
                log_failure(&error, delay);
                backoff = (backoff * 2).min(MAX_BACKOFF);
                delay
            }
        };
        tokio::time::sleep(delay).await;
    }
}

fn log_failure(error: &enclave::Error, retry_in: Duration) {
    let retry_in_ms = u64::try_from(retry_in.as_millis()).unwrap_or(u64::MAX);
    if *error == enclave::Error::Operation(enclave_types::Error::ReleaseRejected) {
        // A rejected manifest does not fix itself: it is malformed or names another bundle.
        tracing::error!(
            dependency = "enclave",
            ?error,
            retry_in_ms,
            "enclave rejected the release manifest"
        );
    } else {
        tracing::warn!(
            dependency = "enclave",
            ?error,
            retry_in_ms,
            "loading the release manifest failed"
        );
    }
}

fn jittered(backoff: Duration) -> Duration {
    backoff.mul_f64(rand::thread_rng().gen_range(0.0..=1.0))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use flamingo_verifier_enclave_types::{KeyAttestation, MatchRequest, MatchResponse};

    use super::keep_loaded;
    use crate::enclave::{self, EnclaveClient};

    /// Fails the first `failures` loads, then succeeds; counts every attempt.
    struct FlakyEnclave {
        failures: usize,
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl EnclaveClient for FlakyEnclave {
        async fn health(&self) -> Result<(), enclave::Error> {
            unreachable!()
        }

        async fn encryption_key_attestation(&self) -> Result<KeyAttestation, enclave::Error> {
            unreachable!()
        }

        async fn run_match(&self, _: MatchRequest) -> Result<MatchResponse, enclave::Error> {
            unreachable!()
        }

        async fn load_release(&self, manifest: String) -> Result<(), enclave::Error> {
            assert_eq!(manifest, "manifest");
            if self.attempts.fetch_add(1, Ordering::SeqCst) < self.failures {
                Err(enclave::Error::Timeout)
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retries_until_loaded_then_resends() {
        let enclave = Arc::new(FlakyEnclave {
            failures: 3,
            attempts: AtomicUsize::new(0),
        });
        let task = tokio::spawn(keep_loaded(
            Arc::clone(&enclave) as Arc<dyn EnclaveClient>,
            "manifest".to_owned(),
        ));

        // Three failures back off by at most 250 ms, 500 ms and 1 s before the fourth attempt.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(enclave.attempts.load(Ordering::SeqCst), 4);

        // A loaded manifest is sent again after the reload interval.
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(enclave.attempts.load(Ordering::SeqCst), 5);
        task.abort();
    }
}
