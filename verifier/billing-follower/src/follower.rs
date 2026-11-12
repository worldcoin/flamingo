//! Follows the Billing Contract at the latest block and turns its logs into billing ops.

use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Address;
use flamingo_verifier_billing_state::{BillingOp, BillingState, BillingStateError, Registration};
use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use tokio::time::Instant;
use url::Url;
use world_id_primitives::{
    FieldElement,
    billing::{PERIOD_OVERLAP, billing_period, is_period_active, period_start},
};

use crate::{
    metrics::{self as names, gauge_value},
    rpc::RpcSource,
    schedule::{Backoff, PollSchedule},
    source::{BillingEvent, BlockRef, ChainLog, ChainSource, EventSet, SourceError},
};

/// Header reads in flight at once, e.g. for the window after backfill.
const HEADER_READS_IN_FLIGHT: usize = 16;

/// Follows the WIP-107 Billing Contract and emits the host's billing state (WIP-107 §4.8).
pub struct BillingFollower<S = RpcSource> {
    source: S,
    config: FollowerConfig,
    state: BillingState,
    phase: Phase,
    window: VecDeque<WindowBlock>,
    tip: Option<BlockRef>,
    next_block: u64,
    /// Applied ops not yet returned.
    outbox: Vec<BillingOp>,
    /// Rebuilding after a deep fork: updates are held back until a full snapshot is ready.
    rebuilding: bool,
    announced: bool,
    log_range: u64,
    schedule: PollSchedule,
    last_poll: Instant,
    backoff: Backoff,
    next_expiry: u64,
    clock: fn() -> u64,
}

impl BillingFollower<RpcSource> {
    /// Follows `config.contract` over the HTTP endpoint `url`; fails as [`Self::with_source`] does.
    pub async fn connect(url: Url, config: FollowerConfig) -> Result<Self, FollowerError> {
        let source = RpcSource::new(url, config.contract);
        Self::with_source(source, config).await
    }
}

impl<S: ChainSource> BillingFollower<S> {
    /// Follows `source`; fails on another chain, a missing contract or a deployment past the head.
    pub async fn with_source(source: S, config: FollowerConfig) -> Result<Self, FollowerError> {
        let actual = source.chain_id().await?;
        if actual != config.chain_id {
            return Err(FollowerError::WrongChain {
                expected: config.chain_id,
                actual,
            });
        }
        // A wrong address or deployment block would read as "nothing billed": fail closed.
        if !source.contract_deployed().await? {
            return Err(FollowerError::NoContract);
        }
        let head = source.latest().await?.number;
        if config.deploy_block > head {
            return Err(FollowerError::DeployBlockAhead {
                deploy_block: config.deploy_block,
                head,
            });
        }
        let schedule = PollSchedule::new(
            config.block_time,
            config.poll_interval,
            config.stalled_poll_interval,
        );
        Ok(Self {
            source,
            state: BillingState::with_limit(config.max_registrations),
            phase: Phase::Start,
            window: VecDeque::new(),
            tip: None,
            next_block: 0,
            outbox: Vec::new(),
            rebuilding: false,
            announced: false,
            log_range: config.max_log_range.max(1),
            schedule,
            last_poll: Instant::now(),
            backoff: Backoff::new(Duration::from_millis(200), Duration::from_secs(10)),
            next_expiry: 0,
            clock: unix_now,
            config,
        })
    }

    /// The follower's billing state, current up to the last returned update.
    #[must_use]
    pub const fn state(&self) -> &BillingState {
        &self.state
    }

    /// The next state change: per log page in backfill, then per new block; errs only on a bad op.
    pub async fn next(&mut self) -> Result<BillingUpdate, FollowerError> {
        loop {
            let step = match self.phase {
                Phase::Start => self.start().await,
                Phase::Backfill { .. } => self.backfill_step().await,
                Phase::Live => {
                    tokio::time::sleep_until(self.schedule.next_poll(self.last_poll)).await;
                    self.last_poll = Instant::now();
                    self.live_round().await
                }
            };
            match step {
                Ok(Some(update)) => {
                    self.backoff.reset();
                    return Ok(self.finish(update));
                }
                Ok(None) => self.backoff.reset(),
                Err(StepError::Source(error)) => self.source_failed(&error).await,
                // Live rounds already wait for the next poll; elsewhere wait one interval.
                Err(StepError::ChainMoved) => {
                    if !matches!(self.phase, Phase::Live) {
                        tokio::time::sleep(self.config.poll_interval).await;
                    }
                }
                Err(StepError::DeepFork) => self.reset(),
                Err(StepError::State(error)) => {
                    tracing::error!(%error, "billing state rejected an op");
                    return Err(error.into());
                }
            }
        }
    }

    /// Reads the head, finds where the active periods' registrations start, and plans the backfill.
    async fn start(&mut self) -> Result<Option<BillingUpdate>, StepError> {
        let head = self.source.latest().await?;
        let now = (self.clock)();
        let registrations_from = period_start(now)
            .unwrap_or_default()
            .saturating_sub(PERIOD_OVERLAP);
        let registered_from = self
            .first_block_at(self.config.deploy_block, head, registrations_from)
            .await?;
        let deep_end = head.number.saturating_sub(self.window_len());
        self.next_expiry = period_end(now);
        if self.config.deploy_block > deep_end {
            self.tip = match self.config.deploy_block.checked_sub(1) {
                Some(parent) => self.source.block(parent).await?,
                None => None,
            };
            self.anchor_window();
            self.next_block = self.config.deploy_block;
            self.phase = Phase::Live;
        } else {
            self.phase = Phase::Backfill {
                cursor: self.config.deploy_block,
                deep_end,
                registered_from,
                started: Instant::now(),
            };
        }
        Ok(None)
    }

    /// The first block in `from..=head` at or after `timestamp`, else the block after `head`.
    async fn first_block_at(
        &self,
        from: u64,
        head: BlockRef,
        timestamp: u64,
    ) -> Result<u64, StepError> {
        if head.timestamp < timestamp {
            return Ok(head.number + 1);
        }
        let (mut low, mut high) = (from.min(head.number), head.number);
        while low < high {
            let middle = low + (high - low) / 2;
            let block = self
                .source
                .block(middle)
                .await?
                .ok_or(StepError::ChainMoved)?;
            if block.timestamp >= timestamp {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        Ok(low)
    }

    /// Reads one page of logs below the reorganization window.
    async fn backfill_step(&mut self) -> Result<Option<BillingUpdate>, StepError> {
        let Phase::Backfill {
            cursor,
            deep_end,
            registered_from,
            started,
        } = self.phase
        else {
            return Ok(None);
        };
        if cursor > deep_end {
            self.tip = Some(
                self.source
                    .block(deep_end)
                    .await?
                    .ok_or(StepError::ChainMoved)?,
            );
            self.anchor_window();
            self.next_block = deep_end + 1;
            self.phase = Phase::Live;
            metrics::histogram!(names::BACKFILL_SECONDS).record(started.elapsed().as_secs_f64());
            return Ok(None);
        }
        let (events, end) = self.page(cursor, deep_end, registered_from);
        let logs = self.read_logs(cursor, end, events).await?;
        for log in &logs {
            if let Some((op, _)) = self.apply_event(log.event)? {
                self.outbox.push(op);
            }
        }
        self.phase = Phase::Backfill {
            cursor: end + 1,
            deep_end,
            registered_from,
            started,
        };
        if self.rebuilding {
            // The snapshot sent once live carries these.
            self.outbox.clear();
            return Ok(None);
        }
        Ok((!self.outbox.is_empty()).then(|| self.update(end)))
    }

    /// The events and inclusive end of the backfill page starting at `cursor`.
    fn page(&self, cursor: u64, deep_end: u64, registered_from: u64) -> (EventSet, u64) {
        let end = cursor.saturating_add(self.log_range - 1).min(deep_end);
        if cursor < registered_from {
            (EventSet::BilledRps, end.min(registered_from - 1))
        } else {
            (EventSet::All, end)
        }
    }

    /// Follows the chain to its latest block, undoing a reorganization first if there was one.
    async fn live_round(&mut self) -> Result<Option<BillingUpdate>, StepError> {
        let head = self.source.latest().await?;
        metrics::gauge!(names::HEAD_BLOCK).set(gauge_value(head.number));
        self.expire();

        if let Some(tip) = self.tip {
            if head.hash == tip.hash {
                return Ok(self.idle_update(tip.number));
            }
            if head.number <= tip.number {
                let ours = self
                    .window
                    .iter()
                    .find(|block| block.block.number == head.number)
                    .map(|block| block.block.hash);
                match ours {
                    // A shorter fork: everything from the head's height up is orphaned.
                    Some(hash) if hash != head.hash => self.unwind(head.number).await?,
                    // The head is our own ancestor: the source is behind.
                    Some(_) => return Ok(self.idle_update(tip.number)),
                    None => match self.source.block(tip.number).await? {
                        Some(block) if block.hash != tip.hash => self.unwind(tip.number).await?,
                        _ => return Ok(self.idle_update(tip.number)),
                    },
                }
            }
        }

        let to = head.number;
        if to < self.next_block {
            return Ok(self.idle_update(self.next_block.saturating_sub(1)));
        }
        // Far behind, e.g. after a long outage: catch up without headers to the window's start.
        if to - self.next_block >= self.window_len() {
            let from = self.next_block;
            let first = self
                .source
                .block(from)
                .await?
                .ok_or(StepError::ChainMoved)?;
            if let Some(tip) = self.tip
                && first.parent_hash != tip.hash
            {
                self.unwind(tip.number).await?;
                return Ok(self.idle_update(self.next_block.saturating_sub(1)));
            }
            self.catch_up(from, to - self.window_len()).await?;
        }

        let from = self.next_block;
        let source = &self.source;
        let mut headers = stream::iter(from..to)
            .map(|number| source.block(number))
            .buffered(HEADER_READS_IN_FLIGHT)
            .map(|block| block?.ok_or(StepError::ChainMoved))
            .try_collect::<Vec<_>>()
            .await?;
        headers.push(head);
        if let Some(tip) = self.tip
            && headers[0].parent_hash != tip.hash
        {
            self.unwind(tip.number).await?;
            return Ok(self.idle_update(self.next_block.saturating_sub(1)));
        }
        if headers
            .windows(2)
            .any(|pair| pair[1].parent_hash != pair[0].hash)
        {
            return Err(StepError::ChainMoved);
        }

        let logs = self.read_logs_paged(from, to).await?;
        let mut by_block: Vec<Vec<ChainLog>> = vec![Vec::new(); headers.len()];
        for log in logs {
            let offset = log
                .block_number
                .checked_sub(from)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|&offset| offset < headers.len())
                .ok_or_else(|| SourceError::Malformed {
                    method: "eth_getLogs",
                    reason: format!("a log of block {} outside {from}..={to}", log.block_number),
                })?;
            if log.block_hash != headers[offset].hash {
                return Err(StepError::ChainMoved);
            }
            by_block[offset].push(log);
        }

        for (block, logs) in headers.into_iter().zip(by_block) {
            let mut inverses = Vec::new();
            for log in logs {
                if let Some((op, inverse)) = self.apply_event(log.event)? {
                    self.outbox.push(op);
                    inverses.push(inverse);
                }
            }
            self.window.push_back(WindowBlock { block, inverses });
        }
        while self.window.len() > self.config.reorg_window.max(1) {
            self.window.pop_front();
        }
        self.tip = Some(head);
        self.next_block = to + 1;
        self.schedule.new_head(Instant::now());
        Ok(Some(self.update(to)))
    }

    /// Applies blocks `from..=to` without headers, then anchors the window at `to`.
    async fn catch_up(&mut self, from: u64, to: u64) -> Result<(), StepError> {
        let mut cursor = from;
        while cursor <= to {
            let end = cursor.saturating_add(self.log_range - 1).min(to);
            let logs = self.read_logs(cursor, end, EventSet::All).await?;
            for log in &logs {
                if let Some((op, _)) = self.apply_event(log.event)? {
                    self.outbox.push(op);
                }
            }
            cursor = end + 1;
            self.next_block = cursor;
        }
        self.tip = Some(self.source.block(to).await?.ok_or(StepError::ChainMoved)?);
        self.window.clear();
        self.anchor_window();
        Ok(())
    }

    /// Undoes blocks from `orphaned_from` up, then older ones until the newest is canonical.
    async fn unwind(&mut self, orphaned_from: u64) -> Result<(), StepError> {
        let mut depth = 0u64;
        loop {
            let Some(newest) = self.window.back() else {
                return Err(StepError::DeepFork);
            };
            if newest.block.number < orphaned_from {
                match self.source.block(newest.block.number).await? {
                    Some(block) if block.hash == newest.block.hash => break,
                    Some(_) => {}
                    // A block the source does not have is not proof of a fork: retry once it has.
                    None => return Err(StepError::ChainMoved),
                }
            }
            // Queued with its inverses applied, so a failed read leaves a state to continue from.
            let undone = self.window.pop_back().expect("checked above");
            for inverse in undone.inverses.into_iter().rev() {
                self.state.apply(inverse)?;
                self.outbox.push(inverse);
            }
            self.next_block = undone.block.number;
            self.tip = self.window.back().map(|block| block.block);
            depth += 1;
        }
        if depth > 0 {
            metrics::counter!(names::REORGS).increment(1);
            metrics::histogram!(names::REORG_DEPTH).record(gauge_value(depth));
            tracing::warn!(
                depth,
                fork_block = self.next_block,
                "billing follower undid a reorganization"
            );
        }
        Ok(())
    }

    /// Reads all logs of `from..=to` in pages; nothing is applied until all are read.
    async fn read_logs_paged(&mut self, from: u64, to: u64) -> Result<Vec<ChainLog>, StepError> {
        let mut logs = Vec::new();
        let mut cursor = from;
        while cursor <= to {
            let end = cursor.saturating_add(self.log_range - 1).min(to);
            logs.extend(self.read_logs(cursor, end, EventSet::All).await?);
            cursor = end + 1;
        }
        Ok(logs)
    }

    /// Reads logs, halving the page size after a failure and doubling it after a success.
    async fn read_logs(
        &mut self,
        from: u64,
        to: u64,
        events: EventSet,
    ) -> Result<Vec<ChainLog>, StepError> {
        match self.source.logs(from, to, events).await {
            Ok(logs) => {
                self.log_range = self
                    .log_range
                    .saturating_mul(2)
                    .min(self.config.max_log_range.max(1));
                Ok(logs)
            }
            Err(error) => {
                self.log_range = (self.log_range / 2).max(1);
                Err(error.into())
            }
        }
    }

    /// Applies one event and returns the op and its inverse; inactive registrations are skipped.
    fn apply_event(
        &mut self,
        event: BillingEvent,
    ) -> Result<Option<(BillingOp, BillingOp)>, StepError> {
        let op = match event {
            BillingEvent::BilledRpUpdated { rp_id, billed } => {
                BillingOp::SetBilledRp { rp_id, billed }
            }
            BillingEvent::Registered {
                rp_id,
                period_start,
                nullifier,
            } => {
                if !is_period_active(period_start, (self.clock)()) {
                    return Ok(None);
                }
                let Ok(nullifier) = FieldElement::try_from(nullifier) else {
                    metrics::counter!(names::INVALID_EVENTS).increment(1);
                    tracing::error!(%nullifier, "Registered nullifier outside the field");
                    return Ok(None);
                };
                BillingOp::AddRegistration {
                    nullifier,
                    registration: Registration {
                        rp_id,
                        period_start,
                    },
                }
            }
        };
        Ok(self.state.apply(op)?.map(|inverse| (op, inverse)))
    }

    /// Starts the window at the tip, so a reorganization of the tip itself can be undone.
    fn anchor_window(&mut self) {
        if let Some(block) = self.tip {
            self.window.push_back(WindowBlock {
                block,
                inverses: Vec::new(),
            });
        }
    }

    /// An update for a round that saw no new block: only queued ops, or the first live update.
    fn idle_update(&mut self, head: u64) -> Option<BillingUpdate> {
        (!self.outbox.is_empty() || !self.announced).then(|| self.update(head))
    }

    fn update(&mut self, head: u64) -> BillingUpdate {
        BillingUpdate {
            reset: false,
            ops: std::mem::take(&mut self.outbox),
            head,
            backfill_done: matches!(self.phase, Phase::Live),
        }
    }

    fn finish(&mut self, mut update: BillingUpdate) -> BillingUpdate {
        // The consumer keeps its old copy until this one replaces it in a single update.
        if std::mem::take(&mut self.rebuilding) {
            update.reset = true;
            update.ops = self.state.snapshot().collect();
        }
        self.announced |= update.backfill_done;
        metrics::gauge!(names::SYNCED_BLOCK).set(gauge_value(update.head));
        metrics::gauge!(names::REGISTRATIONS).set(gauge_value(
            u64::try_from(self.state.registration_count()).unwrap_or(u64::MAX),
        ));
        metrics::gauge!(names::BILLED_RPS).set(gauge_value(
            u64::try_from(self.state.billed_rp_count()).unwrap_or(u64::MAX),
        ));
        update
    }

    async fn source_failed(&mut self, error: &SourceError) {
        metrics::counter!(
            names::RPC_ERRORS,
            "method" => error.method(),
            "class" => error.class(),
        )
        .increment(1);
        let delay = self.backoff.next_delay();
        let failures = self.backoff.failures();
        // The first failure, then the 8th, 16th, 32nd, ..., so an outage does not flood the logs.
        if failures == 1 || failures.is_power_of_two() && failures >= 8 {
            tracing::warn!(
                %error,
                dependency = "billing_rpc",
                method = error.method(),
                class = error.class(),
                failures,
                retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                "billing chain read failed; retrying"
            );
        }
        tokio::time::sleep(delay).await;
    }

    /// Starts over from an empty state after a fork deeper than the window.
    fn reset(&mut self) {
        tracing::error!(
            reorg_window = self.config.reorg_window,
            "reorganization deeper than the billing follower's window; starting over"
        );
        metrics::counter!(names::RESETS).increment(1);
        self.state = BillingState::with_limit(self.config.max_registrations);
        self.window.clear();
        self.tip = None;
        self.outbox.clear();
        self.phase = Phase::Start;
        self.rebuilding = true;
        self.announced = false;
    }

    /// Drops ended periods' registrations without an op; consumers expire with their own clock.
    fn expire(&mut self) {
        let now = (self.clock)();
        if now >= self.next_expiry {
            self.state.expire(now);
            self.next_expiry = period_end(now);
        }
    }

    fn window_len(&self) -> u64 {
        u64::try_from(self.config.reorg_window.max(1)).unwrap_or(u64::MAX)
    }
}

/// What and how the follower follows.
#[derive(Debug, Clone)]
pub struct FollowerConfig {
    /// The chain hosting the Billing Contract. [`BillingFollower::with_source`] checks it.
    pub chain_id: u64,
    /// The Billing Contract's address. Used by [`BillingFollower::connect`].
    pub contract: Address,
    /// The block the Billing Contract was deployed in. `BilledRpUpdated` logs are read from here.
    pub deploy_block: u64,
    /// The largest `eth_getLogs` block range; halved after a failure, regrown after successes.
    pub max_log_range: u64,
    /// How many recent blocks a reorganization can undo; a deeper fork restarts the follower.
    pub reorg_window: usize,
    /// Bound on the registrations the follower holds.
    pub max_registrations: usize,
    /// The chain's block time.
    pub block_time: Duration,
    /// How often to poll while a new block is due.
    pub poll_interval: Duration,
    /// How often to poll once the chain is a whole block late.
    pub stalled_poll_interval: Duration,
}

impl FollowerConfig {
    /// World Chain defaults: 2 s blocks, 100 ms polls, 10,000-block log ranges, 256-block window.
    #[must_use]
    pub const fn new(chain_id: u64, contract: Address, deploy_block: u64) -> Self {
        Self {
            chain_id,
            contract,
            deploy_block,
            max_log_range: 10_000,
            reorg_window: 256,
            max_registrations: 1 << 22,
            block_time: Duration::from_secs(2),
            poll_interval: Duration::from_millis(100),
            stalled_poll_interval: Duration::from_secs(1),
        }
    }
}

/// A change to the billing state, to apply in order to a copy of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingUpdate {
    /// After a fork deeper than the window: replace the copy with `ops`, a full snapshot.
    pub reset: bool,
    /// The state changes, in chain order. Each changes the state.
    pub ops: Vec<BillingOp>,
    /// The block the state is current up to.
    pub head: u64,
    /// Whether the follower has caught up with the chain since it started or reset.
    pub backfill_done: bool,
}

/// Why the follower stopped. Failed chain reads are retried and never end it.
#[derive(Debug, thiserror::Error)]
pub enum FollowerError {
    /// The source serves another chain than the configured one.
    #[error("the source serves chain {actual}, not chain {expected}")]
    WrongChain {
        /// The configured chain.
        expected: u64,
        /// The source's chain.
        actual: u64,
    },
    /// No contract at the configured address; its empty logs would read as "nothing billed".
    #[error("no contract is deployed at the configured Billing Contract address")]
    NoContract,
    /// The configured deployment block is past the chain's head.
    #[error("the deployment block {deploy_block} is past the head {head}")]
    DeployBlockAhead {
        /// The configured deployment block.
        deploy_block: u64,
        /// The chain's head.
        head: u64,
    },
    /// Reading the chain ID, the head or the contract's code failed.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// The billing state rejected an op: it is full, or the logs registered a nullifier twice.
    #[error("the billing state rejected an op: {0}")]
    State(#[from] BillingStateError),
}

/// Why one step did not finish.
enum StepError {
    Source(SourceError),
    /// The source's view changed during the step; it is retried.
    ChainMoved,
    /// A reorganization reached past the window.
    DeepFork,
    State(BillingStateError),
}

impl From<SourceError> for StepError {
    fn from(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl From<BillingStateError> for StepError {
    fn from(error: BillingStateError) -> Self {
        Self::State(error)
    }
}

/// A recent block and the ops that undo what it applied, newest last.
struct WindowBlock {
    block: BlockRef,
    inverses: Vec<BillingOp>,
}

enum Phase {
    /// Nothing read yet.
    Start,
    /// Headerless log reads up to `deep_end`; below `registered_from` only `BilledRpUpdated`.
    Backfill {
        cursor: u64,
        deep_end: u64,
        registered_from: u64,
        started: Instant,
    },
    /// Following the chain block by block, with every block's header checked.
    Live,
}

/// The end of the billing period containing `now`, or `u64::MAX` if it cannot be computed.
fn period_end(now: u64) -> u64 {
    billing_period(now).map_or(u64::MAX, |(_, end)| end)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests;
