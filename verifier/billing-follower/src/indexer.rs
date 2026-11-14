//! Native billing updates from an event indexer's version-one snapshot/replay API.

mod api;
mod rps;

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolEvent as _,
};
use flamingo_verifier_billing_state::{BillingOp, Registration};
use futures_util::StreamExt as _;
use url::Url;
use world_id_primitives::{
    FieldElement,
    billing::{active_periods, is_period_active},
    rp::RpId,
};
use world_id_registries::world_id_billing::WorldIdBilling::{BilledRpUpdated, Registered};

use crate::{
    Backoff, BillingUpdate,
    follower::unix_now,
    metrics::{self as names, gauge_value},
};
use api::{Api, ApiError, BatchStream, Change, Event, Filter, Health, Scope, Status, TargetStatus};
use rps::{Projection, ProjectionError};

const PAGE_LIMIT: usize = 1000;

/// Trusted source configuration. Credentials are passed separately to [`IndexerFollower::new`].
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// The indexer's configured billing target.
    pub target: String,
    /// Expected chain ID, independently of the source's response.
    pub chain_id: u64,
    /// Expected block-zero hash.
    pub genesis_hash: B256,
    /// Expected Billing Contract address.
    pub contract: Address,
    /// The actual contract deployment block. Source coverage must begin no later.
    pub deploy_block: u64,
    /// Recent RP event history retained for retractions; deeper removals require a new stream.
    pub reorg_window: u64,
    /// Bound on retained RP history, including baselines. Registrations are never retained.
    pub max_rp_events: usize,
}

impl IndexerConfig {
    /// Uses a 256-block undo window and a 1,048,576-entry RP-history bound.
    #[must_use]
    pub fn new(
        target: String,
        chain_id: u64,
        genesis_hash: B256,
        contract: Address,
        deploy_block: u64,
    ) -> Self {
        Self {
            target,
            chain_id,
            genesis_hash,
            contract,
            deploy_block,
            reorg_window: 256,
            max_rp_events: 1_048_576,
        }
    }
}

/// A reason to invalidate the enclave's current stream before rebuilding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResetReason {
    /// The service replaced the target's generation.
    #[error("the indexer target generation changed")]
    Generation,
    /// Replay history or a snapshot expired.
    #[error("the indexer cursor requires resynchronization")]
    Cursor,
    /// Active-period filters changed.
    #[error("the active billing periods changed")]
    Period,
    /// The service cannot reconcile its canonical history.
    #[error("the indexer requires canonical recovery")]
    Recovery,
    /// The RP undo history cannot explain a retraction.
    #[error("billing RP undo history is unavailable")]
    History,
    /// The configured RP-history resource bound was reached.
    #[error("billing RP history reached its configured bound")]
    Capacity,
    /// A response violates the supported source protocol.
    #[error("the indexer response is inconsistent")]
    Protocol,
}

/// Configuration/source errors are surfaced without response bodies, URLs or credentials.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    /// The local configuration cannot be used.
    #[error("invalid indexer configuration: {0}")]
    Configuration(&'static str),
    /// A response names a different trusted source, or authentication failed.
    #[error("invalid billing source: {0}")]
    Source(&'static str),
    /// Discard this follower, invalidate the receiver with an incomplete seq-zero update,
    /// then use the host's restart backoff before constructing a new follower.
    #[error("billing stream reset required: {0}")]
    ResetRequired(ResetReason),
}

/// An optional indexer-backed implementation of the host's native billing-update contract.
///
/// Bootstrap streams registrations a page at a time; only RP history is retained. Call `next`
/// again only after the entire previous update was accepted by the native pusher. Lost answers
/// are the pusher's responsibility. After any pusher rejection, discard this instance and start
/// a new stream, just as for [`crate::BillingFollower`]. No HTTP consumer cursor is persisted.
///
/// Ordinary network outages retry with bounded requests and backoff, preserving an already
/// accepted enclave state. A reset-required error is terminal for this instance: do not append
/// its replacement snapshot to the old numbered stream. Active-period scope changes also reset
/// the stream, so their bootstrap cost must be considered when selecting this backend.
pub struct IndexerFollower {
    api: Api,
    config: IndexerConfig,
    phase: Phase,
    periods: Vec<u64>,
    scope: Scope,
    generation: Option<String>,
    source: Option<TargetStatus>,
    bootstrap_head: u64,
    projection: Projection,
    cursor: Option<String>,
    stream: Option<BatchStream>,
    draining: bool,
    last_sequence: Option<u64>,
    announced: bool,
    backoff: Backoff,
    clock: fn() -> u64,
}

impl IndexerFollower {
    /// Constructs the follower without IO. The first `next` validates source identity,
    /// contract-code verification metadata and complete billing-event scope.
    pub fn new(base: Url, token: String, config: IndexerConfig) -> Result<Self, IndexerError> {
        if config.target.is_empty()
            || config.target.len() > 64
            || !config
                .target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(IndexerError::Configuration("invalid target identifier"));
        }
        if config.reorg_window == 0 || config.max_rp_events == 0 {
            return Err(IndexerError::Configuration("zero RP history bound"));
        }
        let api = Api::new(base, token)
            .map_err(|_| IndexerError::Configuration("invalid API URL or token"))?;
        let projection = Projection::new(config.reorg_window, config.max_rp_events);
        Ok(Self {
            api,
            config,
            phase: Phase::Snapshot(None),
            periods: Vec::new(),
            scope: Scope {
                filters: Vec::new(),
            },
            generation: None,
            source: None,
            bootstrap_head: 0,
            projection,
            cursor: None,
            stream: None,
            draining: true,
            last_sequence: None,
            announced: false,
            backoff: Backoff::new(Duration::from_millis(200), Duration::from_secs(5)),
            clock: unix_now,
        })
    }

    /// Returns the next native update. Transient API/SSE failures retry without ending the host.
    ///
    /// # Errors
    /// A source/configuration error, or a terminal reset requirement. Receiver invalidation and
    /// recreation after those errors belong to the host, not this library's HTTP retry loop.
    pub async fn next(&mut self) -> Result<BillingUpdate, IndexerError> {
        loop {
            if let Phase::Failed(reason) = self.phase {
                return Err(IndexerError::ResetRequired(reason));
            }
            self.check_periods()?;
            match self.step().await {
                Ok(update) => {
                    self.backoff.reset();
                    if let Some(head) = self.source.as_ref().and_then(|s| s.observed_head.as_ref())
                    {
                        metrics::gauge!(names::HEAD_BLOCK).set(gauge_value(head.number));
                    }
                    metrics::gauge!(names::SYNCED_BLOCK).set(gauge_value(update.head));
                    metrics::gauge!(names::BILLED_RPS).set(gauge_value(
                        u64::try_from(self.projection.billed_len()).unwrap_or(u64::MAX),
                    ));
                    metrics::gauge!("billing_follower.indexer_rp_events").set(gauge_value(
                        u64::try_from(self.projection.len()).unwrap_or(u64::MAX),
                    ));
                    return Ok(update);
                }
                Err(StepError::Fatal(error)) => return Err(error),
                Err(StepError::Reset(reason)) => return Err(self.fail(reason)),
                Err(StepError::Api(ApiError::Unauthorized)) => {
                    return Err(IndexerError::Source("API authentication failed"));
                }
                Err(StepError::Api(ApiError::Resync)) => return Err(self.fail(ResetReason::Cursor)),
                Err(StepError::Api(ApiError::Protocol(reason))) => {
                    tracing::warn!(
                        dependency = "billing_indexer",
                        reason,
                        "invalid billing indexer response"
                    );
                    return Err(self.fail(ResetReason::Protocol));
                }
                Err(StepError::Api(error)) => {
                    self.stream = None;
                    self.draining = true;
                    metrics::counter!("billing_follower.indexer_errors", "class" => error_class(&error)).increment(1);
                    let delay = self.backoff.next_delay();
                    let failures = self.backoff.failures();
                    if failures == 1 || failures.is_power_of_two() && failures >= 8 {
                        tracing::warn!(
                            dependency = "billing_indexer",
                            class = error_class(&error),
                            failures,
                            retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                            "billing indexer read failed; retrying"
                        );
                    }
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn step(&mut self) -> Result<BillingUpdate, StepError> {
        match self.phase.clone() {
            Phase::Snapshot(cursor) => self.snapshot(cursor).await,
            Phase::Rps(after) => self.snapshot_rps(after).await,
            Phase::Live => self.live().await,
            Phase::Failed(reason) => Err(StepError::Reset(reason)),
        }
    }

    async fn snapshot(&mut self, cursor: Option<String>) -> Result<BillingUpdate, StepError> {
        let page = self.api.snapshot(&self.scope, cursor.as_deref()).await?;
        self.check_periods().map_err(StepError::Fatal)?;
        if page.events.len() > PAGE_LIMIT {
            return Err(StepError::Reset(ResetReason::Protocol));
        }
        validate_cursor(&page.resume_cursor)?;
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor != &page.resume_cursor)
        {
            return Err(StepError::Reset(ResetReason::Protocol));
        }
        let status = self.target(page.targets)?;
        self.validate_status(&status)?;
        if let Some(frozen) = &self.source {
            if frozen != &status {
                return Err(StepError::Reset(ResetReason::Protocol));
            }
        } else {
            self.bootstrap_head = status.observed_head.as_ref().map_or(0, |b| b.number);
            self.projection
                .advance(status.covered_through.as_ref().map_or(0, |b| b.number));
            self.generation = Some(status.generation.clone());
            self.source = Some(status.clone());
        }
        self.cursor = Some(page.resume_cursor);
        let events = page
            .events
            .iter()
            .filter(|event| event.state.canonical())
            .map(|event| self.decode(event))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ops = Vec::new();
        for event in events {
            match event {
                Decoded::Rp {
                    id,
                    block,
                    transaction,
                    index,
                    rp,
                    billed,
                } => {
                    self.projection
                        .add(rp, block, transaction, index, &id, billed)?;
                }
                Decoded::Registration {
                    nullifier,
                    registration,
                } => ops.push(BillingOp::AddRegistration {
                    nullifier,
                    registration,
                }),
            }
        }
        if let Some(next) = page.next_page {
            validate_cursor(&next)?;
            if cursor.as_ref() == Some(&next) {
                return Err(StepError::Reset(ResetReason::Protocol));
            }
            self.phase = Phase::Snapshot(Some(next));
        } else {
            self.projection.finish_snapshot();
            self.phase = Phase::Rps(None);
        }
        Ok(self.update(ops, false))
    }

    async fn snapshot_rps(&mut self, after: Option<u64>) -> Result<BillingUpdate, StepError> {
        let ops = self.projection.snapshot_after(after, PAGE_LIMIT);
        if let Some(BillingOp::SetBilledRp { rp_id, .. }) = ops.last() {
            self.phase = Phase::Rps(Some(rp_id.into_inner()));
            return Ok(self.update(ops, false));
        }
        // A frozen snapshot must not announce readiness after a known source recovery/reset.
        let current = self.target(self.api.status().await?)?;
        self.validate_status(&current)?;
        self.phase = Phase::Live;
        Ok(self.update(Vec::new(), false))
    }

    async fn live(&mut self) -> Result<BillingUpdate, StepError> {
        let cursor = self
            .cursor
            .as_ref()
            .ok_or(StepError::Reset(ResetReason::Protocol))?
            .clone();
        let batch = if self.draining {
            let batch = self.api.changes(&self.scope, &cursor).await?;
            self.draining = batch.has_more;
            batch
        } else {
            if self.stream.is_none() {
                self.stream = Some(self.api.stream(&self.scope, &cursor).await?);
            }
            self.stream
                .as_mut()
                .expect("stream was opened")
                .next()
                .await
                .ok_or(ApiError::Unavailable)??
        };
        self.check_periods().map_err(StepError::Fatal)?;
        if batch.records.len() > PAGE_LIMIT {
            return Err(StepError::Reset(ResetReason::Protocol));
        }
        let drained = !batch.has_more;
        validate_cursor(&batch.cursor)?;
        let mut sequence = self.last_sequence;
        // Validate the complete batch before changing the projection or exposing operations.
        for record in &batch.records {
            if sequence.is_some_and(|last| record.sequence <= last) {
                return Err(StepError::Reset(ResetReason::Protocol));
            }
            sequence = Some(record.sequence);
            if let Change::Progress { status } = &record.change {
                self.validate_status(status)?;
            }
        }
        let mut ops = Vec::new();
        for record in batch.records {
            match record.change {
                Change::Progress { status } => {
                    if let Some(block) = &status.covered_through {
                        self.projection.advance(block.number);
                    }
                    self.source = Some(*status);
                }
                Change::Event { previous, event } => {
                    let add = event.state.canonical() && !previous.is_some_and(Status::canonical);
                    let remove =
                        event.state == Status::Removed && previous.is_some_and(Status::canonical);
                    if previous.is_some_and(Status::canonical)
                        && !event.state.canonical()
                        && event.state != Status::Removed
                    {
                        return Err(StepError::Reset(ResetReason::Recovery));
                    }
                    if !add && !remove {
                        continue;
                    }
                    match self.decode(&event)? {
                        Decoded::Rp {
                            id,
                            block,
                            transaction,
                            index,
                            rp,
                            billed,
                        } => {
                            let op = if add {
                                self.projection
                                    .add(rp, block, transaction, index, &id, billed)?
                            } else {
                                self.projection.remove(
                                    rp,
                                    block,
                                    transaction,
                                    index,
                                    &id,
                                    billed,
                                )?
                            };
                            ops.extend(op);
                        }
                        Decoded::Registration {
                            nullifier,
                            registration,
                        } => ops.push(if add {
                            BillingOp::AddRegistration {
                                nullifier,
                                registration,
                            }
                        } else {
                            BillingOp::RemoveRegistration {
                                nullifier,
                                registration,
                            }
                        }),
                    }
                }
            }
        }
        // A frozen snapshot can have queued retractions. Apply the replay backlog before
        // opening the receiver's initial readiness latch, including the final batch's ops.
        self.announced |= drained && self.source.as_ref().is_some_and(|s| self.complete(s));
        self.cursor = Some(batch.cursor);
        self.last_sequence = sequence;
        Ok(self.update(ops, self.announced))
    }

    fn check_periods(&mut self) -> Result<(), IndexerError> {
        let now = (self.clock)();
        let active = active_periods(now)
            .map_err(|_| IndexerError::Configuration("clock is outside a billing period"))?;
        let mut periods = vec![active.current];
        periods.extend(active.next);
        if self.periods.is_empty() {
            self.scope = Scope {
                filters: vec![
                    Filter {
                        target: self.config.target.clone(),
                        topics: vec![Some(vec![BilledRpUpdated::SIGNATURE_HASH.to_string()])],
                    },
                    Filter {
                        target: self.config.target.clone(),
                        topics: vec![
                            Some(vec![Registered::SIGNATURE_HASH.to_string()]),
                            None,
                            Some(periods.iter().map(|p| format!("0x{p:064x}")).collect()),
                        ],
                    },
                ],
            };
            self.periods = periods;
        } else if self.periods != periods {
            return Err(self.fail(ResetReason::Period));
        }
        Ok(())
    }

    fn target(&self, mut targets: Vec<TargetStatus>) -> Result<TargetStatus, StepError> {
        targets.retain(|s| s.target == self.config.target);
        if targets.len() != 1 {
            return Err(StepError::Fatal(IndexerError::Source(
                "billing target missing or repeated",
            )));
        }
        Ok(targets.remove(0))
    }

    fn validate_status(&self, source: &TargetStatus) -> Result<(), StepError> {
        if source.target != self.config.target
            || source.chain_id != self.config.chain_id
            || source.genesis_hash.parse::<B256>().ok() != Some(self.config.genesis_hash)
            || source.address.parse::<Address>().ok() != Some(self.config.contract)
            || source.start_block > self.config.deploy_block
        {
            return Err(StepError::Fatal(IndexerError::Source(
                "configured chain, contract or deployment is not covered",
            )));
        }
        if source.generation.is_empty() || source.generation.len() > 256 {
            return Err(StepError::Reset(ResetReason::Protocol));
        }
        if self
            .generation
            .as_ref()
            .is_some_and(|g| g != &source.generation)
        {
            return Err(StepError::Reset(ResetReason::Generation));
        }
        if source.canonical == Health::RecoveryRequired {
            return Err(StepError::Reset(ResetReason::Recovery));
        }
        let Some(topics) = &source.topic_filter else {
            return Err(ApiError::Unavailable.into());
        };
        if topics.len() > 4
            || !topics.iter().skip(1).all(Option::is_none)
            || topics.first().is_some_and(|first| {
                first.as_ref().is_some_and(|values| {
                    ![BilledRpUpdated::SIGNATURE_HASH, Registered::SIGNATURE_HASH]
                        .iter()
                        .all(|expected| {
                            values
                                .iter()
                                .any(|value| value.parse::<B256>().ok() == Some(*expected))
                        })
                })
            })
        {
            return Err(StepError::Fatal(IndexerError::Source(
                "incomplete billing event filter",
            )));
        }
        let (Some(verified), Some(observed), Some(covered)) = (
            &source.contract_verified_at,
            &source.observed_head,
            &source.covered_through,
        ) else {
            return Err(ApiError::Unavailable.into());
        };
        if observed.number < self.config.deploy_block {
            return Err(StepError::Fatal(IndexerError::Source(
                "deployment is beyond the observed head",
            )));
        }
        if !same_block(verified, observed)
            || verified.hash.parse::<B256>().is_err()
            || covered.hash.parse::<B256>().is_err()
        {
            return Err(StepError::Reset(ResetReason::Protocol));
        }
        Ok(())
    }

    fn complete(&self, source: &TargetStatus) -> bool {
        source.caught_up
            && source.canonical == Health::Ready
            && source
                .covered_through
                .as_ref()
                .zip(source.observed_head.as_ref())
                .is_some_and(|(covered, observed)| {
                    same_block(covered, observed)
                        && covered.number >= self.bootstrap_head
                        && source
                            .startup_head
                            .as_ref()
                            .is_some_and(|start| covered.number >= start.number)
                })
    }

    fn decode(&self, event: &Event) -> Result<Decoded, StepError> {
        if event.target != self.config.target
            || event.chain_id != self.config.chain_id
            || event.address.parse::<Address>().ok() != Some(self.config.contract)
            || event.block.number < self.config.deploy_block
            || event.block.hash.parse::<B256>().is_err()
            || event.id.is_empty()
            || event.id.len() > 256
        {
            return Err(StepError::Reset(ResetReason::Protocol));
        }
        let topic = event
            .topics
            .first()
            .and_then(|value| value.parse::<B256>().ok())
            .ok_or(StepError::Reset(ResetReason::Protocol))?;
        if topic == BilledRpUpdated::SIGNATURE_HASH && event.topics.len() == 2 {
            let rp = uint64(&event.topics[1])?;
            let flag = uint64(&event.data)?;
            if flag > 1 {
                return Err(StepError::Reset(ResetReason::Protocol));
            }
            Ok(Decoded::Rp {
                id: event.id.clone(),
                block: event.block.number,
                transaction: event.transaction_index,
                index: event.log_index,
                rp,
                billed: flag == 1,
            })
        } else if topic == Registered::SIGNATURE_HASH
            && event.topics.len() == 4
            && event.data == "0x"
        {
            let registration = Registration {
                rp_id: RpId::new(uint64(&event.topics[1])?),
                period_start: uint64(&event.topics[2])?,
            };
            if !is_period_active(registration.period_start, (self.clock)()) {
                return Err(StepError::Reset(ResetReason::Protocol));
            }
            let nullifier = FieldElement::try_from(word(&event.topics[3])?)
                .map_err(|_| StepError::Reset(ResetReason::Protocol))?;
            Ok(Decoded::Registration {
                nullifier,
                registration,
            })
        } else {
            Err(StepError::Reset(ResetReason::Protocol))
        }
    }

    fn update(&self, ops: Vec<BillingOp>, backfill_done: bool) -> BillingUpdate {
        BillingUpdate {
            ops,
            head: self
                .source
                .as_ref()
                .and_then(|s| s.covered_through.as_ref())
                .map_or(0, |b| b.number),
            backfill_done,
        }
    }

    fn fail(&mut self, reason: ResetReason) -> IndexerError {
        self.stream = None;
        self.phase = Phase::Failed(reason);
        metrics::counter!("billing_follower.indexer_resets", "cause" => reset_class(reason))
            .increment(1);
        tracing::warn!(
            dependency = "billing_indexer",
            cause = reset_class(reason),
            "billing indexer stream requires receiver reset"
        );
        IndexerError::ResetRequired(reason)
    }
}

#[derive(Clone)]
enum Phase {
    Snapshot(Option<String>),
    Rps(Option<u64>),
    Live,
    Failed(ResetReason),
}

enum Decoded {
    Rp {
        id: String,
        block: u64,
        transaction: u64,
        index: u64,
        rp: u64,
        billed: bool,
    },
    Registration {
        nullifier: FieldElement,
        registration: Registration,
    },
}

enum StepError {
    Api(ApiError),
    Fatal(IndexerError),
    Reset(ResetReason),
}
impl From<ApiError> for StepError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}
impl From<ProjectionError> for StepError {
    fn from(error: ProjectionError) -> Self {
        Self::Reset(match error {
            ProjectionError::HistoryUnavailable => ResetReason::History,
            ProjectionError::InvalidEvent => ResetReason::Protocol,
            ProjectionError::Capacity => ResetReason::Capacity,
        })
    }
}

fn same_block(a: &api::Block, b: &api::Block) -> bool {
    a.number == b.number && a.hash.eq_ignore_ascii_case(&b.hash)
}
fn validate_cursor(cursor: &str) -> Result<(), StepError> {
    if cursor.is_empty() || cursor.len() > 2048 {
        Err(StepError::Reset(ResetReason::Protocol))
    } else {
        Ok(())
    }
}
fn word(value: &str) -> Result<U256, StepError> {
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(StepError::Reset(ResetReason::Protocol));
    }
    value
        .parse()
        .map_err(|_| StepError::Reset(ResetReason::Protocol))
}
fn uint64(value: &str) -> Result<u64, StepError> {
    word(value)?
        .try_into()
        .map_err(|_| StepError::Reset(ResetReason::Protocol))
}
fn error_class(error: &ApiError) -> &'static str {
    match error {
        ApiError::Timeout => "timeout",
        ApiError::Transport => "transport",
        ApiError::Unavailable => "unavailable",
        ApiError::Unauthorized => "unauthorized",
        ApiError::Resync => "resync",
        ApiError::Protocol(_) => "protocol",
    }
}
fn reset_class(reason: ResetReason) -> &'static str {
    match reason {
        ResetReason::Generation => "generation",
        ResetReason::Cursor => "cursor",
        ResetReason::Period => "period",
        ResetReason::Recovery => "recovery",
        ResetReason::History => "history",
        ResetReason::Capacity => "capacity",
        ResetReason::Protocol => "protocol",
    }
}

#[cfg(test)]
mod tests;
