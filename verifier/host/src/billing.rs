//! Follows the WIP-107 Billing Contract and keeps the enclave's billing state current
//! (WIP-107 §4.8).
//!
//! The enclave holds the billing state. The pusher passes each follower update on as the next
//! update of a numbered stream, and retries an update whose answer it lost. When the enclave
//! loses the stream, e.g. after it restarted, or the follower meets a fork deeper than its window,
//! the host first clears the enclave's state so it stops serving, then follows the chain again from
//! the Billing Contract's deployment and rebuilds from a new stream.

use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use anyhow::Context as _;
use flamingo_verifier_billing_follower::{
    Backoff, BillingFollower, BillingUpdate, FollowerConfig, FollowerError, RpcUrl,
};
use flamingo_verifier_enclave_types::{
    self as enclave_types, BillingStatus, BillingUpdateRequest, MAX_BILLING_OPS,
};

use crate::{
    enclave::{self, EnclaveClient},
    metrics::{self as names, gauge_value},
};

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
}

/// Follows the Billing Contract and pushes its changes to the enclave until the follower fails.
///
/// Chain reads and pushes are retried without end, so this returns only when the follower cannot
/// start or stops: the endpoints serve another chain or no contract.
///
/// # Errors
/// When the follower cannot start or stops for another reason than a deep fork.
pub async fn run(config: BillingConfig, enclave: Arc<dyn EnclaveClient>) -> anyhow::Result<()> {
    let follower_config =
        FollowerConfig::new(config.chain_id, config.contract, config.deploy_block);
    // Restarts since a stream last caught up, which back off so an enclave that keeps rejecting
    // the state does not turn into back-to-back backfills.
    let mut restarts = Backoff::new(Duration::from_secs(1), Duration::from_secs(300));
    loop {
        let mut follower = connect(&config, follower_config.clone()).await?;
        let mut pusher = Pusher::new(Arc::clone(&enclave));
        let lost = loop {
            let update = match follower.next().await {
                Ok(update) => update,
                Err(FollowerError::DeepFork) => break StreamLost::DeepFork,
                Err(error) => return Err(error).context("the billing follower stopped"),
            };
            match pusher.push(&update).await {
                Ok(status) => {
                    if update.backfill_done && status.ready {
                        restarts.reset();
                    }
                }
                Err(error) => break StreamLost::Enclave(error),
            }
        };
        metrics::counter!(names::BILLING_RESTARTS, "cause" => lost.cause()).increment(1);
        // Drop any fork or partly applied state before the restart backoff, so the enclave does
        // not keep serving while we rebuild.
        if let Err(error) = invalidate(Arc::clone(&enclave)).await {
            tracing::warn!(
                error = ?error,
                dependency = "enclave",
                "could not clear the enclave's billing state after the stream was lost"
            );
        }
        let delay = restarts.next_delay();
        tracing::warn!(
            cause = lost.cause(),
            error = ?lost.error(),
            dependency = lost.dependency(),
            restarts = restarts.failures(),
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "the billing stream was lost; following the chain again from the deployment"
        );
        tokio::time::sleep(delay).await;
    }
}

/// Why the host follows the chain again from the deployment.
#[derive(Debug)]
enum StreamLost {
    /// The follower met a fork deeper than its window.
    DeepFork,
    /// The enclave refused an update, e.g. after it restarted.
    Enclave(enclave::Error),
}

impl StreamLost {
    const fn cause(&self) -> &'static str {
        match self {
            Self::DeepFork => "deep_fork",
            Self::Enclave(_) => "enclave",
        }
    }

    const fn error(&self) -> Option<&enclave::Error> {
        match self {
            Self::DeepFork => None,
            Self::Enclave(error) => Some(error),
        }
    }

    const fn dependency(&self) -> &'static str {
        match self {
            Self::DeepFork => "billing_rpc",
            Self::Enclave(_) => "enclave",
        }
    }
}

async fn connect(
    config: &BillingConfig,
    follower_config: FollowerConfig,
) -> anyhow::Result<BillingFollower> {
    let mut backoff = retry_backoff();
    loop {
        match BillingFollower::connect(config.rpc_url.clone(), follower_config.clone()).await {
            Ok(follower) => return Ok(follower),
            Err(FollowerError::Source(error)) => {
                let delay = backoff.next_delay();
                tracing::warn!(%error, dependency = "billing_rpc", failures = backoff.failures(), "billing follower cannot read the chain ID; retrying");
                tokio::time::sleep(delay).await;
            }
            Err(error) => return Err(error).context("the billing follower cannot start"),
        }
    }
}

/// Replaces the enclave's billing state with an empty stream that has not caught up, so it stops
/// serving until a rebuild does.
async fn invalidate(enclave: Arc<dyn EnclaveClient>) -> Result<BillingStatus, enclave::Error> {
    Pusher::new(enclave)
        .send(
            BillingUpdateRequest {
                seq: 0,
                ops: Vec::new(),
                backfill_done: false,
            },
            0,
        )
        .await
}

/// Passes one follower's updates to the enclave as one numbered stream.
pub struct Pusher {
    client: Arc<dyn EnclaveClient>,
    /// The `seq` of the next update; `0` starts the stream.
    next_seq: u64,
}

impl Pusher {
    /// A pusher whose first push starts a new stream.
    #[must_use]
    pub const fn new(client: Arc<dyn EnclaveClient>) -> Self {
        Self {
            client,
            next_seq: 0,
        }
    }

    /// Sends `update` to the enclave, retrying a lost answer until it is applied.
    ///
    /// # Errors
    /// When the enclave refuses the update, e.g. it restarted or rejected the state. The stream is
    /// then lost: only a new follower and pusher, from the deployment, can rebuild the state.
    pub async fn push(&mut self, update: &BillingUpdate) -> Result<BillingStatus, enclave::Error> {
        let mut parts = update.ops.chunks(MAX_BILLING_OPS).peekable();
        // An update without ops still goes out, so an enclave that lost the stream answers
        // `BillingOutOfOrder` within a block.
        let mut ops = parts.next().unwrap_or_default();
        loop {
            let request = BillingUpdateRequest {
                seq: self.next_seq,
                ops: ops.to_vec(),
                // An update split in parts is complete only after its last part.
                backfill_done: update.backfill_done && parts.peek().is_none(),
            };
            let status = self.send(request, update.head).await?;
            let Some(next) = parts.next() else {
                metrics::gauge!(names::BILLING_PUSHED_BLOCK).set(gauge_value(update.head));
                return Ok(status);
            };
            ops = next;
        }
    }

    /// Sends `request` as the next update of the stream.
    async fn send(
        &mut self,
        request: BillingUpdateRequest,
        head: u64,
    ) -> Result<BillingStatus, enclave::Error> {
        let mut backoff = retry_backoff();
        loop {
            match self.client.update_billing(request.clone()).await {
                Ok(status) => {
                    metrics::counter!(names::BILLING_PUSHES, "result" => "ok").increment(1);
                    record(status);
                    self.next_seq += 1;
                    return Ok(status);
                }
                // A lost answer is retried as is; the enclave applies a repeated `seq` once.
                Err(error @ (enclave::Error::Timeout | enclave::Error::Transport(_))) => {
                    metrics::counter!(names::BILLING_PUSHES, "result" => result_label(&error))
                        .increment(1);
                    let delay = backoff.next_delay();
                    let failures = backoff.failures();
                    if failures.is_power_of_two() {
                        tracing::warn!(
                            error = ?error,
                            dependency = "enclave",
                            failures,
                            head,
                            "billing push failed; retrying"
                        );
                    }
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    metrics::counter!(names::BILLING_PUSHES, "result" => result_label(&error))
                        .increment(1);
                    return Err(error);
                }
            }
        }
    }
}

fn record(status: BillingStatus) {
    metrics::gauge!(names::BILLING_ENCLAVE_REGISTRATIONS).set(gauge_value(status.registrations));
    metrics::gauge!(names::BILLING_ENCLAVE_MAX_REGISTRATIONS)
        .set(gauge_value(status.max_registrations));
    metrics::gauge!(names::BILLING_ENCLAVE_READY).set(if status.ready { 1.0 } else { 0.0 });
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

/// Backoff for chain reads and lost answers, from 200 ms to 5 s.
const fn retry_backoff() -> Backoff {
    Backoff::new(Duration::from_millis(200), Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Mutex, PoisonError},
    };

    use async_trait::async_trait;
    use flamingo_verifier_billing_state::{BillingOp, Registration};
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
            ops,
            head,
            backfill_done: true,
        }
    }

    fn pusher(recorder: &Arc<Recorder>) -> Pusher {
        Pusher::new(Arc::clone(recorder) as Arc<dyn EnclaveClient>)
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
        assert_eq!(
            recorder.pushes().len(),
            2,
            "a refused update is not retried"
        );
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
    async fn clearing_after_a_lost_stream_starts_an_empty_not_ready_stream() {
        let recorder = Arc::new(Recorder::default());
        recorder.answer(Err(enclave::Error::Timeout));
        recorder.answer(Ok(BillingStatus {
            registrations: 0,
            max_registrations: 1 << 22,
            ready: false,
        }));

        let status = invalidate(Arc::clone(&recorder) as Arc<dyn EnclaveClient>)
            .await
            .unwrap();
        assert!(!status.ready);

        let pushes = recorder.pushes();
        assert_eq!(pushes.len(), 2);
        assert!(
            pushes
                .iter()
                .all(|push| { push.seq == 0 && push.ops.is_empty() && !push.backfill_done })
        );
    }
}
