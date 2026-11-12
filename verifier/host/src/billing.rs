//! Follows the WIP-107 Billing Contract and keeps the enclave's billing state current
//! (WIP-107 §4.8).
//!
//! The follower's state is the source of truth. The pusher sends each change to the enclave as
//! the next update of a numbered stream. It retries an update whose answer it lost, and starts a
//! new stream from the follower's full state when the enclave rebooted or rejected an update, so
//! neither costs chain reads.

use std::{fmt, sync::Arc, time::Duration};

use alloy::primitives::Address;
use anyhow::Context as _;
use flamingo_verifier_billing_follower::{
    BillingFollower, BillingUpdate, FollowerConfig, FollowerError,
};
use flamingo_verifier_billing_state::{BillingOp, BillingState};
use flamingo_verifier_enclave_types::{
    self as enclave_types, BillingStatus, BillingUpdateRequest, MAX_BILLING_OPS,
};
use rand::Rng as _;
use url::Url;

use crate::enclave::{self, EnclaveClient};

const PUSHES: &str = "flamingo.billing.pushes";
const RESYNCS: &str = "flamingo.billing.resyncs";
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
    /// The chain hosting the Billing Contract. The enclave rejects state of another chain.
    pub chain_id: u64,
    /// The Billing Contract. The enclave rejects state of another contract.
    pub contract: Address,
    /// The block the Billing Contract was deployed in.
    pub deploy_block: u64,
    /// Bound on the registrations the follower holds. Above the enclave's, the enclave fills up
    /// and stops serving first.
    pub max_registrations: usize,
}

/// Follows the Billing Contract and pushes its state to the enclave until the follower fails.
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
    let mut follower = connect(&config, follower_config).await?;
    let mut pusher = Pusher::new(
        enclave,
        config.chain_id,
        config.contract.into_array(),
        config.max_registrations,
    );
    loop {
        let update = follower
            .next()
            .await
            .context("the billing follower stopped")?;
        // Pushing a partial state would replace the enclave's complete one, so a restarted host
        // first catches up. The first push after that sends the whole state; a rebuild after a
        // deep fork arrives complete in one update.
        if update.backfill_done {
            pusher.push(&update, follower.state()).await;
        }
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

/// Sends the follower's changes to the enclave as one numbered stream.
pub struct Pusher {
    client: Arc<dyn EnclaveClient>,
    chain_id: u64,
    contract: [u8; 20],
    /// The `seq` of the next update, or `None` if the next push starts a new stream.
    next_seq: Option<u64>,
    max_registrations: usize,
    warned_capacity: bool,
}

impl Pusher {
    /// A pusher whose first push starts a new stream.
    #[must_use]
    pub const fn new(
        client: Arc<dyn EnclaveClient>,
        chain_id: u64,
        contract: [u8; 20],
        max_registrations: usize,
    ) -> Self {
        Self {
            client,
            chain_id,
            contract,
            next_seq: None,
            max_registrations,
            warned_capacity: false,
        }
    }

    /// Sends `update` to the enclave, retrying until it is applied. `state` is the follower's state
    /// after `update`, which a new stream is built from.
    pub async fn push(&mut self, update: &BillingUpdate, state: &BillingState) {
        if update.reset {
            self.next_seq = None;
        }
        let (mut first_seq, mut ops) = self
            .next_seq
            .map_or_else(|| new_stream(state), |seq| (seq, update.ops.clone()));
        let mut sent = 0;
        let mut failures: u32 = 0;
        while sent < chunk_count(&ops) {
            let last = sent + 1 == chunk_count(&ops);
            let request = BillingUpdateRequest {
                chain_id: self.chain_id,
                contract: self.contract,
                seq: first_seq + u64::try_from(sent).unwrap_or(u64::MAX),
                ops: chunk(&ops, sent).to_vec(),
                // A new stream serves once complete, so only its last part may say so.
                backfill_done: update.backfill_done && last,
            };
            match self.client.update_billing(request).await {
                Ok(status) => {
                    metrics::counter!(PUSHES, "result" => "ok").increment(1);
                    self.record(status);
                    sent += 1;
                }
                Err(error) => {
                    failures += 1;
                    metrics::counter!(PUSHES, "result" => result_label(&error)).increment(1);
                    // A lost answer is retried as is; the enclave applies a repeated `seq` once.
                    // Anything else, e.g. a rebooted enclave, needs a new stream.
                    let retry = matches!(
                        error,
                        enclave::Error::Timeout | enclave::Error::Transport(_)
                    );
                    if failures == 1 || failures.is_power_of_two() {
                        tracing::warn!(
                            error = ?error,
                            dependency = "enclave",
                            failures,
                            head = update.head,
                            new_stream = !retry,
                            "billing push failed"
                        );
                    }
                    if !retry {
                        (first_seq, ops) = new_stream(state);
                        sent = 0;
                    }
                    tokio::time::sleep(retry_delay(failures)).await;
                }
            }
        }
        self.next_seq = Some(first_seq + u64::try_from(sent).unwrap_or(u64::MAX));
        metrics::gauge!(PUSHED_BLOCK).set(gauge_value(update.head));
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

/// The first `seq` and the ops of a new stream: the whole state.
fn new_stream(state: &BillingState) -> (u64, Vec<BillingOp>) {
    metrics::counter!(RESYNCS).increment(1);
    (0, state.snapshot().collect())
}

/// Updates needed for `ops`: one per [`MAX_BILLING_OPS`], and one even without ops, so a
/// rebooted enclave answers `BillingOutOfOrder` within a block and gets its state back.
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
    let ceiling = Duration::from_millis(200)
        .saturating_mul(1 << failures.min(5))
        .min(Duration::from_secs(5));
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

    const CHAIN_ID: u64 = 480;
    const CONTRACT: [u8; 20] = [0x11; 20];

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

    /// The follower's state after `ops`, and the update that carried them.
    fn follow(state: &mut BillingState, ops: Vec<BillingOp>, head: u64) -> BillingUpdate {
        for op in &ops {
            state.apply(*op).unwrap();
        }
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
            CHAIN_ID,
            CONTRACT,
            DEFAULT_MAX_REGISTRATIONS,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_push_starts_a_stream_from_the_full_state() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        let mut state = BillingState::default();
        state.apply(registration(1)).unwrap();

        let update = follow(&mut state, vec![registration(2)], 10);
        sync.push(&update, &state).await;
        let heartbeat = follow(&mut state, Vec::new(), 11);
        sync.push(&heartbeat, &state).await;

        let pushes = recorder.pushes();
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].seq, 0);
        assert_eq!(
            pushes[0].ops.len(),
            2,
            "the snapshot holds both registrations"
        );
        assert_eq!(
            (pushes[0].chain_id, pushes[0].contract),
            (CHAIN_ID, CONTRACT)
        );
        assert_eq!(pushes[1].seq, 1);
        assert!(pushes[1].ops.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn large_changes_are_split_and_only_the_last_part_completes_the_stream() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        let mut state = BillingState::default();
        let ops = (0..=u64::try_from(MAX_BILLING_OPS).unwrap() * 2)
            .map(registration)
            .collect();
        let update = follow(&mut state, ops, 10);
        sync.push(&update, &state).await;

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
    async fn a_failed_push_starts_a_new_stream_from_the_current_state() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        let mut state = BillingState::default();
        let first = follow(&mut state, vec![registration(1)], 10);
        sync.push(&first, &state).await;

        // The enclave rebooted, then the vsock dropped once.
        recorder.answer(Err(enclave::Error::Operation(
            enclave_types::Error::BillingOutOfOrder,
        )));
        recorder.answer(Err(enclave::Error::Timeout));
        let second = follow(&mut state, vec![registration(2)], 11);
        sync.push(&second, &state).await;

        let seqs: Vec<_> = recorder.pushes().iter().map(|push| push.seq).collect();
        assert_eq!(seqs, [0, 1, 0, 0]);
        let resync = recorder.pushes().pop().unwrap();
        assert_eq!(
            resync.ops.len(),
            2,
            "the new stream carries the whole state"
        );
        assert!(resync.backfill_done);

        let third = follow(&mut state, Vec::new(), 12);
        sync.push(&third, &state).await;
        assert_eq!(recorder.pushes().pop().unwrap().seq, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_answer_is_retried_without_a_new_stream() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        let mut state = BillingState::default();
        let first = follow(&mut state, vec![registration(1)], 10);
        sync.push(&first, &state).await;

        recorder.answer(Err(enclave::Error::Timeout));
        recorder.answer(Err(enclave::Error::Transport("reset".to_owned())));
        let second = follow(&mut state, vec![registration(2)], 11);
        sync.push(&second, &state).await;

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
        let mut state = BillingState::default();
        let update = follow(&mut state, Vec::new(), 10);
        sync.push(&update, &state).await;
        assert!(!sync.warned_capacity);

        recorder.answer(Ok(BillingStatus {
            registrations: 0,
            max_registrations: 1,
            ready: true,
        }));
        let update = follow(&mut state, Vec::new(), 11);
        sync.push(&update, &state).await;
        assert!(sync.warned_capacity);
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_reset_starts_a_new_stream() {
        let recorder = Arc::new(Recorder::default());
        let mut sync = pusher(&recorder);
        let mut state = BillingState::default();
        let first = follow(&mut state, vec![registration(1)], 10);
        sync.push(&first, &state).await;

        let mut state = BillingState::default();
        let mut reset = follow(&mut state, vec![registration(2)], 12);
        reset.reset = true;
        sync.push(&reset, &state).await;

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
}
