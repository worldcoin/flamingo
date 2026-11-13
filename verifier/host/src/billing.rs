//! Follows the WIP-107 Billing Contract and keeps the enclave's billing state current
//! (WIP-107 §4.8).
//!
//! The enclave holds the billing state. The pusher passes each follower update on as the next
//! update of a numbered stream, and retries an update whose answer it lost. When the enclave
//! loses the stream, e.g. after it restarted, the host follows the chain again from the Billing
//! Contract's deployment, which rebuilds the enclave's state from a new stream.

use std::{fmt, sync::Arc, time::Duration};

use alloy::primitives::Address;
use anyhow::Context as _;
use flamingo_verifier_billing_follower::{
    BillingFollower, BillingUpdate, FollowerConfig, FollowerError,
};
use flamingo_verifier_billing_state::BillingOp;
use flamingo_verifier_enclave_types::{
    self as enclave_types, BillingStatus, BillingUpdateRequest, MAX_BILLING_OPS,
};
use rand::Rng as _;
use url::Url;

use crate::enclave::{self, EnclaveClient};

const PUSHES: &str = "flamingo.billing.pushes";
const RESTARTS: &str = "flamingo.billing.restarts";
const PUSHED_BLOCK: &str = "flamingo.billing.pushed_block";
const ENCLAVE_REGISTRATIONS: &str = "flamingo.billing.enclave_registrations";
const ENCLAVE_READY: &str = "flamingo.billing.enclave_ready";
const ENCLAVE_MAX_REGISTRATIONS: &str = "flamingo.billing.enclave_max_registrations";

/// Default bound on the registrations the host follows; the enclave image's should match.
pub const DEFAULT_MAX_REGISTRATIONS: usize = 1 << 22;

/// A JSON-RPC endpoint. `Debug` shows only its host: provider URLs often carry API keys.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcUrl(pub Url);

impl fmt::Debug for RpcUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.host_str().unwrap_or("?"))
    }
}

/// What the host follows and where it reads it.
#[derive(Debug, Clone)]
pub struct BillingConfig {
    /// The endpoint the follower reads the chain from.
    pub rpc_url: RpcUrl,
    /// The chain hosting the Billing Contract. The follower fails on another chain.
    pub chain_id: u64,
    /// The Billing Contract.
    pub contract: Address,
    /// The block the Billing Contract was deployed in.
    pub deploy_block: u64,
    /// Bound on the registrations the follower holds. Above the enclave's, the enclave fills up
    /// and stops serving first.
    pub max_registrations: usize,
}

/// Follows the Billing Contract and pushes its changes to the enclave until the follower fails.
///
/// Chain reads and pushes are retried without end, so this returns only when the billing state
/// itself is broken: the endpoints serve another chain, or the logs register a nullifier twice.
///
/// # Errors
/// When the follower stops: the endpoints serve another chain, or the billing state rejects an op.
pub async fn run(config: BillingConfig, enclave: Arc<dyn EnclaveClient>) -> anyhow::Result<()> {
    let follower_config = FollowerConfig {
        max_registrations: config.max_registrations,
        ..FollowerConfig::new(config.chain_id, config.contract, config.deploy_block)
    };
    let mut pusher = Pusher::new(enclave, config.max_registrations);
    // Restarts since a stream last caught up, which back off so an enclave that keeps rejecting
    // the state does not turn into back-to-back backfills.
    let mut restarts: u32 = 0;
    loop {
        let mut follower = connect(&config, follower_config.clone()).await?;
        let error = loop {
            let update = follower
                .next()
                .await
                .context("the billing follower stopped")?;
            match pusher.push(&update).await {
                Ok(status) => {
                    if update.backfill_done && status.ready {
                        restarts = 0;
                    }
                }
                Err(error) => break error,
            }
        };
        restarts += 1;
        metrics::counter!(RESTARTS).increment(1);
        let delay = restart_delay(restarts);
        tracing::warn!(
            error = ?error,
            dependency = "enclave",
            restarts,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "the enclave lost the billing stream; following the chain again from the deployment"
        );
        tokio::time::sleep(delay).await;
    }
}

async fn connect(
    config: &BillingConfig,
    follower_config: FollowerConfig,
) -> anyhow::Result<BillingFollower> {
    let mut failures: u32 = 0;
    loop {
        match BillingFollower::connect(config.rpc_url.0.clone(), follower_config.clone()).await {
            Ok(follower) => return Ok(follower),
            Err(FollowerError::Source(error)) => {
                failures += 1;
                tracing::warn!(%error, dependency = "billing_rpc", failures, "billing follower cannot read the chain ID; retrying");
                tokio::time::sleep(retry_delay(failures)).await;
            }
            Err(error) => return Err(error).context("the billing follower cannot start"),
        }
    }
}

/// Passes the follower's updates to the enclave as one numbered stream.
pub struct Pusher {
    client: Arc<dyn EnclaveClient>,
    /// The `seq` of the next update; `0` starts a new stream.
    next_seq: u64,
    max_registrations: usize,
    warned_capacity: bool,
}

impl Pusher {
    /// A pusher whose first push starts a new stream.
    #[must_use]
    pub const fn new(client: Arc<dyn EnclaveClient>, max_registrations: usize) -> Self {
        Self {
            client,
            next_seq: 0,
            max_registrations,
            warned_capacity: false,
        }
    }

    /// Sends `update` to the enclave, retrying a lost answer until it is applied.
    ///
    /// # Errors
    /// When the enclave refuses the update, e.g. it restarted or rejected the state. The stream is
    /// then lost: the next push starts a new one, which must carry the whole state.
    pub async fn push(&mut self, update: &BillingUpdate) -> Result<BillingStatus, enclave::Error> {
        if update.reset {
            self.next_seq = 0;
        }
        let parts = chunk_count(&update.ops);
        let mut status = self.send(update, 0, parts).await?;
        for index in 1..parts {
            status = self.send(update, index, parts).await?;
        }
        metrics::gauge!(PUSHED_BLOCK).set(gauge_value(update.head));
        Ok(status)
    }

    /// Sends part `index` of `parts` of `update` as the next update of the stream.
    async fn send(
        &mut self,
        update: &BillingUpdate,
        index: usize,
        parts: usize,
    ) -> Result<BillingStatus, enclave::Error> {
        let request = BillingUpdateRequest {
            seq: self.next_seq,
            ops: chunk(&update.ops, index).to_vec(),
            // An update split in parts is complete only after its last part.
            backfill_done: update.backfill_done && index + 1 == parts,
        };
        let mut failures: u32 = 0;
        loop {
            match self.client.update_billing(request.clone()).await {
                Ok(status) => {
                    metrics::counter!(PUSHES, "result" => "ok").increment(1);
                    self.record(status);
                    self.next_seq += 1;
                    return Ok(status);
                }
                // A lost answer is retried as is; the enclave applies a repeated `seq` once.
                Err(error @ (enclave::Error::Timeout | enclave::Error::Transport(_))) => {
                    failures += 1;
                    metrics::counter!(PUSHES, "result" => result_label(&error)).increment(1);
                    if failures.is_power_of_two() {
                        tracing::warn!(
                            error = ?error,
                            dependency = "enclave",
                            failures,
                            head = update.head,
                            "billing push failed; retrying"
                        );
                    }
                    tokio::time::sleep(retry_delay(failures)).await;
                }
                Err(error) => {
                    metrics::counter!(PUSHES, "result" => result_label(&error)).increment(1);
                    self.next_seq = 0;
                    return Err(error);
                }
            }
        }
    }
}

impl Pusher {
    fn record(&mut self, status: BillingStatus) {
        metrics::gauge!(ENCLAVE_REGISTRATIONS).set(gauge_value(status.registrations));
        metrics::gauge!(ENCLAVE_MAX_REGISTRATIONS).set(gauge_value(status.max_registrations));
        metrics::gauge!(ENCLAVE_READY).set(if status.ready { 1.0 } else { 0.0 });
        let own = u64::try_from(self.max_registrations).unwrap_or(u64::MAX);
        if own > status.max_registrations && !self.warned_capacity {
            self.warned_capacity = true;
            tracing::warn!(
                host_max_registrations = own,
                enclave_max_registrations = status.max_registrations,
                "the enclave holds fewer registrations than the host follows; it stops serving once full"
            );
        }
    }
}

/// Updates needed for `ops`: one per [`MAX_BILLING_OPS`], and one even without ops, so an
/// enclave that lost the stream answers `BillingOutOfOrder` within a block.
const fn chunk_count(ops: &[BillingOp]) -> usize {
    if ops.is_empty() {
        1
    } else {
        ops.len().div_ceil(MAX_BILLING_OPS)
    }
}

fn chunk(ops: &[BillingOp], index: usize) -> &[BillingOp] {
    ops.chunks(MAX_BILLING_OPS).nth(index).unwrap_or_default()
}

const fn result_label(error: &enclave::Error) -> &'static str {
    match error {
        enclave::Error::Timeout => "timeout",
        enclave::Error::Transport(_) => "transport",
        enclave::Error::Operation(enclave_types::Error::BillingOutOfOrder) => "out_of_order",
        enclave::Error::Operation(enclave_types::Error::BillingRejected) => "rejected",
        enclave::Error::Operation(_) => "error",
    }
}

/// Exponential backoff with equal jitter, from 200 ms to 5 s.
fn retry_delay(failures: u32) -> Duration {
    jittered(Duration::from_millis(200), failures, Duration::from_secs(5))
}

/// Exponential backoff with equal jitter between restarts, from 1 s to 5 min.
fn restart_delay(restarts: u32) -> Duration {
    jittered(Duration::from_secs(1), restarts, Duration::from_secs(300))
}

fn jittered(base: Duration, attempts: u32, max: Duration) -> Duration {
    let ceiling = base.saturating_mul(1 << attempts.min(10)).min(max);
    let half = ceiling / 2;
    half + half.mul_f64(rand::thread_rng().gen_range(0.0..=1.0))
}

#[expect(
    clippy::cast_precision_loss,
    reason = "block numbers and counts stay below 2^53"
)]
const fn gauge_value(value: u64) -> f64 {
    value as f64
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Mutex, PoisonError},
    };

    use async_trait::async_trait;
    use flamingo_verifier_billing_state::Registration;
    use flamingo_verifier_enclave_types::{KeyAttestation, MatchRequest, MatchResponse};
    use world_id_primitives::{FieldElement, rp::RpId};

    use super::*;

    /// Records billing pushes and answers them from a script, then with `ready`.
    #[derive(Default)]
    struct Recorder {
        pushes: Mutex<Vec<BillingUpdateRequest>>,
        answers: Mutex<VecDeque<Result<BillingStatus, enclave::Error>>>,
    }

    impl Recorder {
        fn pushes(&self) -> Vec<BillingUpdateRequest> {
            self.pushes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn answer(&self, answer: Result<BillingStatus, enclave::Error>) {
            self.answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(answer);
        }
    }

    #[async_trait]
    impl EnclaveClient for Recorder {
        async fn health(&self) -> Result<(), enclave::Error> {
            unimplemented!()
        }

        async fn encryption_key_attestation(&self) -> Result<KeyAttestation, enclave::Error> {
            unimplemented!()
        }

        async fn run_match(&self, _: MatchRequest) -> Result<MatchResponse, enclave::Error> {
            unimplemented!()
        }

        async fn update_billing(
            &self,
            request: BillingUpdateRequest,
        ) -> Result<BillingStatus, enclave::Error> {
            self.pushes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request);
            self.answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .unwrap_or(Ok(BillingStatus {
                    registrations: 0,
                    max_registrations: 1 << 22,
                    ready: true,
                }))
        }
    }

    fn registration(nullifier: u64) -> BillingOp {
        BillingOp::AddRegistration {
            nullifier: FieldElement::from(nullifier),
            registration: Registration {
                rp_id: RpId::new(7),
                period_start: 1_793_534_400,
            },
        }
    }

    fn update(ops: Vec<BillingOp>, head: u64) -> BillingUpdate {
        BillingUpdate {
            reset: false,
            ops,
            head,
            backfill_done: true,
        }
    }

    fn pusher(recorder: &Arc<Recorder>) -> Pusher {
        Pusher::new(
            Arc::clone(recorder) as Arc<dyn EnclaveClient>,
            DEFAULT_MAX_REGISTRATIONS,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn updates_pass_through_as_one_stream() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);

        sync.push(&update(vec![registration(1)], 10)).await.unwrap();
        sync.push(&update(Vec::new(), 11)).await.unwrap();

        let pushes = recorder.pushes();
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].seq, 0);
        assert_eq!(pushes[0].ops, vec![registration(1)]);
        assert_eq!(pushes[1].seq, 1);
        assert!(
            pushes[1].ops.is_empty(),
            "an update without ops still goes out"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn large_updates_are_split_and_only_the_last_part_completes_them() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        let ops = (0..=u64::try_from(MAX_BILLING_OPS).unwrap() * 2)
            .map(registration)
            .collect();
        sync.push(&update(ops, 10)).await.unwrap();

        let pushes = recorder.pushes();
        assert_eq!(pushes.len(), 3);
        assert!(pushes.iter().all(|push| push.ops.len() <= MAX_BILLING_OPS));
        assert_eq!(
            pushes.iter().map(|push| push.seq).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(
            pushes
                .iter()
                .map(|push| push.backfill_done)
                .collect::<Vec<_>>(),
            [false, false, true]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_update_ends_the_stream() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        sync.push(&update(vec![registration(1)], 10)).await.unwrap();

        // The enclave restarted.
        recorder.answer(Err(enclave::Error::Operation(
            enclave_types::Error::BillingOutOfOrder,
        )));
        let refused = sync.push(&update(vec![registration(2)], 11)).await;
        assert!(matches!(
            refused,
            Err(enclave::Error::Operation(
                enclave_types::Error::BillingOutOfOrder
            ))
        ));

        sync.push(&update(vec![registration(3)], 0)).await.unwrap();
        let seqs: Vec<_> = recorder.pushes().iter().map(|push| push.seq).collect();
        assert_eq!(seqs, [0, 1, 0], "the next push starts a new stream");
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_answer_is_retried_with_the_same_seq() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        sync.push(&update(vec![registration(1)], 10)).await.unwrap();

        recorder.answer(Err(enclave::Error::Timeout));
        recorder.answer(Err(enclave::Error::Transport("reset".to_owned())));
        sync.push(&update(vec![registration(2)], 11)).await.unwrap();

        let pushes = recorder.pushes();
        let seqs: Vec<_> = pushes.iter().map(|push| push.seq).collect();
        assert_eq!(seqs, [0, 1, 1, 1]);
        assert!(
            pushes[1..]
                .iter()
                .all(|push| push.ops == vec![registration(2)])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_smaller_enclave_bound_is_flagged() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        sync.push(&update(Vec::new(), 10)).await.unwrap();
        assert!(!sync.warned_capacity);

        recorder.answer(Ok(BillingStatus {
            registrations: 0,
            max_registrations: 1,
            ready: true,
        }));
        sync.push(&update(Vec::new(), 11)).await.unwrap();
        assert!(sync.warned_capacity);
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_reset_starts_a_new_stream() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        sync.push(&update(vec![registration(1)], 10)).await.unwrap();

        let mut reset = update(vec![registration(2)], 12);
        reset.reset = true;
        sync.push(&reset).await.unwrap();

        let last = recorder.pushes().pop().unwrap();
        assert_eq!(last.seq, 0);
        assert_eq!(last.ops, vec![registration(2)]);
    }

    #[test]
    fn the_rpc_url_debug_shows_only_its_host() {
        let url = RpcUrl(
            "https://worldchain.example.com/v2/secret-key"
                .parse()
                .unwrap(),
        );
        assert_eq!(format!("{url:?}"), "worldchain.example.com");
    }

    #[test]
    fn retries_back_off_up_to_five_seconds() {
        assert!(retry_delay(1) <= Duration::from_millis(400));
        assert!(retry_delay(40) >= Duration::from_millis(2500));
        assert!(retry_delay(40) <= Duration::from_secs(5));
    }

    #[test]
    fn restarts_back_off_up_to_five_minutes() {
        assert!(restart_delay(1) <= Duration::from_secs(2));
        assert!(restart_delay(40) >= Duration::from_secs(150));
        assert!(restart_delay(40) <= Duration::from_secs(300));
    }
}
