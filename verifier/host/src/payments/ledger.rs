//! The rules a channel nonce obeys: reserved once, admitted once.
//!
//! A lane is its last authorization and a deadline. Everything else the rules need follows from
//! those two fields: the next counter is `latest + 1`, and the units spent in an epoch are the
//! sum of the lanes' counters. [`PaymentLedger`] is the part that talks to a [`PaymentStore`]
//! and an [`EscrowReader`], so swapping either cannot change what a nonce means.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, B256, FixedBytes};
use flamingo_verifier_api_types::ChannelNonce;
use serde::{Deserialize, Serialize};

use super::escrow::{ChannelSettings, EscrowError, EscrowReader};
use super::store::{PaymentStore, StoreError};
use super::{PaymentConfig, eip712};

/// How long a reservation is held before its lane may be handed to someone else.
pub const RESERVATION_LIFETIME_SECS: u64 = 600;
/// How many lanes one channel may open in one epoch.
///
/// A lane is never reclaimed within an epoch, so without this an unbounded caller could grow a
/// host's memory by reserving and walking away.
pub const MAX_LANES_PER_EPOCH: usize = 10_000;

/// How many times a write may lose the race before the caller is told to retry.
const MAX_WRITE_ATTEMPTS: u32 = 5;
/// First backoff step. Doubles per attempt, with jitter, so replicas do not resynchronize.
const BASE_BACKOFF: Duration = Duration::from_millis(5);

/// An authorization the channel's spend key signed over one nonce.
///
/// Same shape and name as the EIP-712 struct and the escrow's `settle` entry: the channel and
/// epoch are implied by where it is stored, so only the lane, counter and signature travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAuthorization {
    /// Lane the counter belongs to.
    pub lane: u32,
    /// Counter authorized on that lane.
    pub counter: u64,
    /// `r || s || v` over the EIP-712 digest.
    pub signature: FixedBytes<65>,
}

impl PaymentAuthorization {
    /// The nonce this authorization was signed over.
    #[must_use]
    pub fn nonce(&self) -> ChannelNonce {
        ChannelNonce::new(self.lane, self.counter)
    }
}

/// What a reservation granted the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveOutcome {
    /// Lane the counter was reserved on.
    pub lane: u32,
    /// Counter reserved on that lane.
    pub counter: u64,
    /// Unix seconds after which the lane may be handed to another request.
    pub expires_by: u64,
    /// The authorization for `counter - 1` on this lane, or `None` at counter 1.
    pub previous: Option<PaymentAuthorization>,
}

/// A bearer authorization presented to spend one verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmitRequest {
    /// Channel the payment spends from.
    pub channel_id: B256,
    /// Epoch the nonce belongs to.
    pub epoch: u64,
    /// Lane and counter this payment spends.
    pub nonce: ChannelNonce,
    /// `r || s || v` over the EIP-712 digest.
    pub signature: FixedBytes<65>,
}

/// What a channel has spent in one epoch, and the signatures behind it.
///
/// Returned with a capacity refusal so the relying party can check the arithmetic rather than
/// take it on trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityProof {
    /// Epoch the counts belong to.
    pub epoch: u64,
    /// Verifications already served against this channel in that epoch.
    pub admitted_units: u64,
    /// Units the channel may spend in that epoch, as the escrow reports them.
    pub capacity: u64,
    /// The highest authorization on each lane, lowest lane first.
    pub authorizations: Vec<PaymentAuthorization>,
}

/// Why the ledger refused an operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The store could not answer, so nothing was read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The escrow could not be read, so this host cannot tell whether the spend is allowed.
    #[error(transparent)]
    Escrow(#[from] EscrowError),
    /// The escrow does not know this channel.
    #[error("channel is not in the fee escrow")]
    UnknownChannel,
    /// The channel settles to another verifier, so this one must not spend it.
    #[error("the channel settles to another collector")]
    WrongCollector,
    /// The epoch is neither the channel's current epoch nor the next one.
    #[error("epoch is not open for reservations")]
    InvalidEpoch,
    /// The channel has already spent its capacity for this epoch.
    #[error("channel capacity is exhausted for this epoch")]
    CapacityExhausted(Box<CapacityProof>),
    /// Every lane is taken and the epoch may not open another.
    #[error("too many reservations are outstanding for this epoch")]
    TooManyPending,
    /// No lane holds a live reservation for this counter.
    #[error("no reservation matches this lane and counter")]
    UnknownReservation,
    /// The reservation expired before the payment arrived.
    #[error("the reservation expired")]
    ReservationExpired,
    /// The signature does not recover the channel's spend key.
    #[error("the signature does not match the channel spend key")]
    InvalidSignature,
    /// The nonce has already been spent on a verification.
    #[error("the nonce has already been admitted")]
    AlreadyAdmitted,
}

/// One lane of a channel's nonce space.
///
/// Counters are dense from 1, so `latest` is both the last authorization and the count of units
/// this lane has spent. A lane is free when `pending_until` is unset or past.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Lane {
    latest: Option<PaymentAuthorization>,
    pending_until: Option<u64>,
}

impl Lane {
    /// The counter this lane hands out next.
    const fn next_counter(&self) -> u64 {
        match &self.latest {
            Some(latest) => latest.counter + 1,
            None => 1,
        }
    }

    /// Whether the lane may be handed to a new request.
    const fn is_free(&self, now: u64) -> bool {
        match self.pending_until {
            Some(until) => until < now,
            None => true,
        }
    }
}

/// One channel's state within one epoch.
///
/// A plain value: a persistent store round-trips it, and every rule below is a method on it that
/// takes the clock and the capacity as arguments rather than reaching for either.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochLedger {
    lanes: Vec<Lane>,
}

impl EpochLedger {
    /// Reserves the next counter on the first free lane, opening one if every lane is busy.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when capacity is spent or the epoch is at its lane ceiling.
    pub(crate) fn apply_reserve(
        &mut self,
        capacity: u64,
        epoch: u64,
        now: u64,
    ) -> Result<ReserveOutcome, LedgerError> {
        // What is spent plus what could still be spent. Handing out a counter past this would
        // promise a verification the escrow will not pay for.
        let outstanding = self.lanes.iter().filter(|lane| !lane.is_free(now)).count();
        let committed = self
            .admitted_units()
            .saturating_add(outstanding.try_into().unwrap_or(u64::MAX));

        if committed >= capacity {
            return Err(LedgerError::CapacityExhausted(Box::new(
                self.capacity_proof(epoch, capacity),
            )));
        }

        // Lowest free lane first, so lanes stay dense and the escrow settles the fewest of them.
        let index = match self.lanes.iter().position(|lane| lane.is_free(now)) {
            Some(index) => index,
            None => {
                if self.lanes.len() >= MAX_LANES_PER_EPOCH {
                    return Err(LedgerError::TooManyPending);
                }

                self.lanes.push(Lane::default());
                self.lanes.len() - 1
            }
        };

        let lane = u32::try_from(index).map_err(|_| LedgerError::TooManyPending)?;
        let expires_by = now.saturating_add(RESERVATION_LIFETIME_SECS);

        let Some(slot) = self.lanes.get_mut(index) else {
            return Err(LedgerError::TooManyPending);
        };

        slot.pending_until = Some(expires_by);

        Ok(ReserveOutcome {
            lane,
            counter: slot.next_counter(),
            expires_by,
            previous: slot.latest,
        })
    }

    /// Spends a payment on one verification.
    ///
    /// `signer` is the address recovered from the signature, computed by the caller so this
    /// stays free of both the clock and the curve.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when no live reservation matches, the nonce was already spent,
    /// the signature is not the channel's, or capacity is gone.
    pub(crate) fn apply_admit(
        &mut self,
        settings: &ChannelSettings,
        capacity: u64,
        request: &AdmitRequest,
        signer: Result<Address, eip712::SignatureError>,
        now: u64,
    ) -> Result<(), LedgerError> {
        let counter = request.nonce.counter();
        let index = usize::try_from(request.nonce.lane()).unwrap_or(usize::MAX);
        let lane = self
            .lanes
            .get(index)
            .ok_or(LedgerError::UnknownReservation)?;

        // A counter at or below the lane's latest was spent already. Checked before the deadline
        // so a replay reads as a replay rather than as an expiry: admission clears the deadline.
        if counter < lane.next_counter() {
            return Err(LedgerError::AlreadyAdmitted);
        }

        if counter != lane.next_counter() {
            return Err(LedgerError::UnknownReservation);
        }

        match lane.pending_until {
            None => return Err(LedgerError::UnknownReservation),
            Some(until) if until < now => return Err(LedgerError::ReservationExpired),
            Some(_) => {}
        }

        if signer.map_err(|_| LedgerError::InvalidSignature)? != settings.spend_key {
            return Err(LedgerError::InvalidSignature);
        }

        if self.admitted_units() >= capacity {
            return Err(LedgerError::CapacityExhausted(Box::new(
                self.capacity_proof(request.epoch, capacity),
            )));
        }

        let Some(lane) = self.lanes.get_mut(index) else {
            return Err(LedgerError::UnknownReservation);
        };

        lane.latest = Some(PaymentAuthorization {
            lane: request.nonce.lane(),
            counter,
            signature: request.signature,
        });
        lane.pending_until = None;

        Ok(())
    }

    /// Units spent in this epoch. Counters are dense, so each lane has spent its latest counter.
    fn admitted_units(&self) -> u64 {
        self.lanes
            .iter()
            .filter_map(|lane| lane.latest)
            .fold(0u64, |total, latest| total.saturating_add(latest.counter))
    }

    /// The evidence behind a capacity refusal.
    fn capacity_proof(&self, epoch: u64, capacity: u64) -> CapacityProof {
        CapacityProof {
            epoch,
            admitted_units: self.admitted_units(),
            capacity,
            authorizations: self.lanes.iter().filter_map(|lane| lane.latest).collect(),
        }
    }
}

/// Hands out channel nonces and spends the payments that come back.
///
/// Each operation reads the escrow, loads the epoch, takes a pure step, and writes the epoch back
/// conditionally. Every escrow or store failure refuses the request: this host does not spend a
/// channel it cannot check.
pub struct PaymentLedger {
    config: PaymentConfig,
    store: Arc<dyn PaymentStore>,
    escrow: Arc<dyn EscrowReader>,
}

impl PaymentLedger {
    /// Creates a ledger over `store` and `escrow`.
    #[must_use]
    pub const fn new(
        config: PaymentConfig,
        store: Arc<dyn PaymentStore>,
        escrow: Arc<dyn EscrowReader>,
    ) -> Self {
        Self {
            config,
            store,
            escrow,
        }
    }

    /// The configuration this ledger runs with.
    #[must_use]
    pub const fn config(&self) -> &PaymentConfig {
        &self.config
    }

    /// Whether both dependencies can serve traffic.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] naming whichever dependency is down.
    pub async fn ready(&self) -> Result<(), LedgerError> {
        if !self.store.ready().await {
            return Err(LedgerError::Store(StoreError::Unavailable(
                "the store reported itself unready".to_owned(),
            )));
        }

        self.escrow.ready().await?;

        Ok(())
    }

    /// Reserves the next counter on some lane of `channel_id`.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the channel is unknown or settles elsewhere, the epoch is not
    /// open, capacity is spent, the epoch is at its lane ceiling, or a dependency failed.
    pub async fn reserve(
        &self,
        channel_id: B256,
        epoch: u64,
        now: u64,
    ) -> Result<ReserveOutcome, LedgerError> {
        let settings = self.settings(channel_id).await?;

        // The next epoch is allowed so a caller near a boundary can reserve for the epoch its
        // request will land in. Anything else is a clock that disagrees with this host.
        let current = settings.epoch_at(now);
        if epoch != current && epoch != current + 1 {
            return Err(LedgerError::InvalidEpoch);
        }

        let capacity = self.escrow.capacity(channel_id, epoch).await?;

        self.mutate(channel_id, epoch, |ledger| {
            ledger.apply_reserve(capacity, epoch, now)
        })
        .await
    }

    /// Spends a payment on one verification.
    ///
    /// A nonce is admitted once. The result of the verification it paid for is not cached, so a
    /// caller that loses the response has to pay for another one; caching is out of scope here.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the channel is unknown or settles elsewhere, no live
    /// reservation backs the nonce, the nonce was already spent, the signature is not the
    /// channel's, capacity is gone, or a dependency failed.
    pub async fn admit(&self, request: &AdmitRequest, now: u64) -> Result<(), LedgerError> {
        let settings = self.settings(request.channel_id).await?;

        // Recovery is elliptic curve work on attacker-supplied bytes, kept out of the retry loop
        // so a burst of invalid signatures cannot multiply into store traffic.
        let signer = eip712::recover_signer(
            self.config.domain(),
            request.channel_id,
            request.epoch,
            request.nonce,
            &request.signature,
        );

        let capacity = self
            .escrow
            .capacity(request.channel_id, request.epoch)
            .await?;

        self.mutate(request.channel_id, request.epoch, |ledger| {
            ledger.apply_admit(&settings, capacity, request, signer, now)
        })
        .await
    }

    /// Reads a channel's settings and checks it settles to this host.
    async fn settings(&self, channel_id: B256) -> Result<ChannelSettings, LedgerError> {
        let settings = self
            .escrow
            .channel(channel_id)
            .await?
            .ok_or(LedgerError::UnknownChannel)?;

        // The first admission check: a channel funded for another verifier is not this one's to
        // spend, however good its signatures are.
        if settings.collector != self.config.collector() {
            return Err(LedgerError::WrongCollector);
        }

        Ok(settings)
    }

    /// Applies `apply` to one epoch and writes the result back, retrying a lost race.
    ///
    /// `apply` runs again from a fresh read on every attempt, so it must not carry state between
    /// calls. A refusal is returned without writing, which keeps a rejected request off the store.
    async fn mutate<T, F>(&self, channel_id: B256, epoch: u64, apply: F) -> Result<T, LedgerError>
    where
        F: Fn(&mut EpochLedger) -> Result<T, LedgerError>,
    {
        for attempt in 0..MAX_WRITE_ATTEMPTS {
            let (mut ledger, version) = self.store.load_epoch(channel_id, epoch).await?;
            let outcome = apply(&mut ledger)?;

            match self
                .store
                .store_epoch(channel_id, epoch, &ledger, version)
                .await
            {
                Ok(()) => return Ok(outcome),
                Err(StoreError::Conflict) => {
                    tracing::warn!(
                        attempt,
                        channel_id = %channel_id,
                        epoch,
                        dependency = "payments_store",
                        "epoch write lost a race, retrying"
                    );

                    tokio::time::sleep(backoff(attempt)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }

        // Sustained contention on one epoch is indistinguishable from an overloaded store, and
        // both want the same answer: come back later.
        Err(LedgerError::Store(StoreError::Unavailable(format!(
            "epoch write lost {MAX_WRITE_ATTEMPTS} races in a row"
        ))))
    }
}

/// Exponential backoff with full jitter, so replicas that collide do not collide again together.
fn backoff(attempt: u32) -> Duration {
    let ceiling = BASE_BACKOFF.saturating_mul(1u32 << attempt.min(6));

    ceiling.mul_f64(rand::random::<f64>())
}
