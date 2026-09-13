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
/// How far a reservation's `issued_at` may sit from this host's clock.
///
/// Tight enough that a captured signature is not a reusable ticket, loose enough for ordinary
/// clock skew between a relying party and this host.
pub const RESERVATION_CLOCK_SKEW_SECS: u64 = 60;
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

/// A signed request to hold a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveRequest {
    /// Channel the lane belongs to.
    pub channel_id: B256,
    /// Epoch the reservation belongs to.
    pub epoch: u64,
    /// Unix seconds the relying party signed at.
    pub issued_at: u64,
    /// `r || s || v` over the EIP-712 reservation digest.
    pub signature: FixedBytes<65>,
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
    /// When the earliest outstanding reservation frees its lane, if one is what is in the way.
    pub retry_after: Option<u64>,
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
    /// The channel settles to this host but on terms it does not accept.
    #[error("the channel's token or price is not accepted here")]
    ChannelTermsRejected,
    /// The reservation request was not signed by the channel's spend key.
    #[error("the reservation was not signed by the channel spend key")]
    InvalidReservation,
    /// The reservation request was issued too far from this host's clock.
    #[error("the reservation was issued too long ago")]
    StaleReservation,
    /// The channel has spent its capacity for this epoch. Waiting will not help.
    #[error("channel capacity is exhausted for this epoch")]
    CapacityExhausted(Box<CapacityProof>),
    /// Capacity is free but held by reservations that have not expired yet.
    #[error("channel capacity is held by outstanding reservations")]
    CapacityReserved(Box<CapacityProof>),
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
        // Spent is permanent; reserved is not. A caller told its own outstanding reservations
        // are in the way should come back, and one told the epoch is spent should not.
        let spent = self.admitted_units();
        if spent >= capacity {
            return Err(LedgerError::CapacityExhausted(Box::new(
                self.capacity_proof(epoch, capacity, None),
            )));
        }

        let outstanding = self.lanes.iter().filter(|lane| !lane.is_free(now)).count();
        let committed = spent.saturating_add(outstanding.try_into().unwrap_or(u64::MAX));

        if committed >= capacity {
            return Err(LedgerError::CapacityReserved(Box::new(
                self.capacity_proof(epoch, capacity, self.earliest_free(now)),
            )));
        }

        // Lowest free lane first, so lanes stay dense and the escrow settles the fewest of them.
        let free = self.lanes.iter().position(|lane| lane.is_free(now));

        let index = if let Some(index) = free {
            index
        } else {
            if self.lanes.len() >= MAX_LANES_PER_EPOCH {
                return Err(LedgerError::TooManyPending);
            }

            self.lanes.push(Lane::default());
            self.lanes.len() - 1
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
                self.capacity_proof(request.epoch, capacity, None),
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
    fn capacity_proof(&self, epoch: u64, capacity: u64, retry_after: Option<u64>) -> CapacityProof {
        CapacityProof {
            epoch,
            admitted_units: self.admitted_units(),
            capacity,
            retry_after,
            authorizations: self.lanes.iter().filter_map(|lane| lane.latest).collect(),
        }
    }

    /// When the earliest outstanding reservation gives its lane back.
    fn earliest_free(&self, now: u64) -> Option<u64> {
        self.lanes
            .iter()
            .filter(|lane| !lane.is_free(now))
            .filter_map(|lane| lane.pending_until)
            .min()
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
        request: &ReserveRequest,
        now: u64,
    ) -> Result<ReserveOutcome, LedgerError> {
        let channel_id = request.channel_id;
        let epoch = request.epoch;
        let settings = self.settings(channel_id).await?;

        // A reservation holds capacity for its lifetime, so anyone who could send one unsigned
        // could starve a channel it does not fund. Checked before any state is touched.
        let issued_at = request.issued_at;
        if now.abs_diff(issued_at) > RESERVATION_CLOCK_SKEW_SECS {
            return Err(LedgerError::StaleReservation);
        }

        let signer = eip712::recover_reservation_signer(
            self.config.domain(),
            channel_id,
            epoch,
            issued_at,
            &request.signature,
        )
        .map_err(|_| LedgerError::InvalidReservation)?;

        if signer != settings.spend_key {
            return Err(LedgerError::InvalidReservation);
        }

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

    /// Reads a channel's settings and checks this host accepts it.
    async fn settings(&self, channel_id: B256) -> Result<ChannelSettings, LedgerError> {
        let settings = self
            .escrow
            .channel(channel_id)
            .await?
            .ok_or(LedgerError::UnknownChannel)?;

        // A channel funded for another verifier is not this one's to spend, however good its
        // signatures are.
        if settings.collector != self.config.collector() {
            return Err(LedgerError::WrongCollector);
        }

        // Naming this host as collector does not set the terms. Whoever opened the channel chose
        // its token and price, and a channel priced at a wei would buy verifications for nothing.
        if settings.token != self.config.token()
            || settings.price_per_unit < self.config.min_price_per_unit()
        {
            return Err(LedgerError::ChannelTermsRejected);
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

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, FixedBytes, address};
    use flamingo_verifier_api_types::ChannelNonce;

    use super::{
        AdmitRequest, ChannelSettings, EpochLedger, LedgerError, MAX_LANES_PER_EPOCH,
        PaymentAuthorization, RESERVATION_LIFETIME_SECS,
    };
    use crate::payments::eip712::SignatureError;

    const SPEND_KEY: Address = address!("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF");
    const OTHER_KEY: Address = address!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    const EPOCH: u64 = 7;
    const NOW: u64 = 1_700_000_000;
    /// One second past the deadline a reservation taken at [`NOW`] carries.
    const LATER: u64 = NOW + RESERVATION_LIFETIME_SECS + 1;

    fn settings() -> ChannelSettings {
        ChannelSettings {
            spend_key: SPEND_KEY,
            collector: Address::ZERO,
            token: Address::ZERO,
            price_per_unit: alloy_primitives::U256::from(1_000u64),
            epoch_zero: 0,
            epoch_length: 3_600,
        }
    }

    /// A distinct signature per nonce, so a test cannot pass by comparing two identical blobs.
    fn signature(lane: u32, counter: u64) -> FixedBytes<65> {
        let mut bytes = [0u8; 65];
        bytes[..4].copy_from_slice(&lane.to_be_bytes());
        bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        bytes[64] = 27;

        FixedBytes(bytes)
    }

    fn admit_request(lane: u32, counter: u64) -> AdmitRequest {
        AdmitRequest {
            channel_id: alloy_primitives::B256::ZERO,
            epoch: EPOCH,
            nonce: ChannelNonce::new(lane, counter),
            signature: signature(lane, counter),
        }
    }

    /// Admits `(lane, counter)` with a signature that recovers to the channel's spend key.
    fn admit(
        ledger: &mut EpochLedger,
        capacity: u64,
        lane: u32,
        counter: u64,
        now: u64,
    ) -> Result<(), LedgerError> {
        ledger.apply_admit(
            &settings(),
            capacity,
            &admit_request(lane, counter),
            Ok(SPEND_KEY),
            now,
        )
    }

    #[test]
    fn a_first_reservation_takes_lane_zero_counter_one_with_nothing_to_settle() {
        let mut ledger = EpochLedger::default();

        let outcome = ledger
            .apply_reserve(10, EPOCH, NOW)
            .expect("the reservation should be granted");

        assert_eq!(outcome.lane, 0);
        assert_eq!(outcome.counter, 1);
        assert_eq!(outcome.expires_by, NOW + RESERVATION_LIFETIME_SECS);
        assert_eq!(outcome.previous, None);
    }

    /// A second caller arriving while the first is still out cannot share its lane, and a retry
    /// is just a second caller: the lane it abandons frees itself at its deadline.
    #[test]
    fn a_reservation_taken_while_another_is_live_opens_a_new_lane() {
        let mut ledger = EpochLedger::default();

        let first = ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        let second = ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        assert_eq!((first.lane, first.counter), (0, 1));
        assert_eq!((second.lane, second.counter), (1, 1));
    }

    /// Lowest free lane first, so lanes stay dense rather than growing with every retry.
    #[test]
    fn an_expired_lane_is_handed_out_again_with_the_same_counter() {
        let mut ledger = EpochLedger::default();

        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        let reissued = ledger.apply_reserve(10, EPOCH, LATER).expect("granted");

        assert_eq!(reissued.lane, 0, "the lowest expired lane goes first");
        assert_eq!(
            reissued.counter, 1,
            "nothing was admitted, so the counter stands"
        );
        assert_eq!(reissued.expires_by, LATER + RESERVATION_LIFETIME_SECS);
    }

    #[test]
    fn an_admitted_lane_is_reused_with_the_next_counter_and_carries_the_previous() {
        let mut ledger = EpochLedger::default();

        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        assert_eq!(admit(&mut ledger, 10, 0, 1, NOW), Ok(()));

        let next = ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        assert_eq!((next.lane, next.counter), (0, 2));
        assert_eq!(
            next.previous,
            Some(PaymentAuthorization {
                lane: 0,
                counter: 1,
                signature: signature(0, 1),
            })
        );
    }

    #[test]
    fn a_nonce_is_admitted_only_once() {
        let mut ledger = EpochLedger::default();
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        assert_eq!(admit(&mut ledger, 10, 0, 1, NOW), Ok(()));
        assert_eq!(
            admit(&mut ledger, 10, 0, 1, NOW),
            Err(LedgerError::AlreadyAdmitted)
        );
    }

    #[test]
    fn a_counter_that_is_not_the_lanes_next_is_refused() {
        let mut ledger = EpochLedger::default();
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        assert_eq!(
            admit(&mut ledger, 10, 0, 9, NOW),
            Err(LedgerError::UnknownReservation),
            "a counter beyond the next one names no reservation"
        );
        assert_eq!(
            admit(&mut ledger, 10, 4, 1, NOW),
            Err(LedgerError::UnknownReservation),
            "a lane that was never opened names no reservation"
        );
    }

    #[test]
    fn a_lane_with_no_live_reservation_is_refused() {
        let mut ledger = EpochLedger::default();
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        assert_eq!(
            admit(&mut ledger, 10, 0, 1, LATER),
            Err(LedgerError::ReservationExpired)
        );

        // Admission clears the deadline, so the lane holds nothing to spend afterwards.
        assert_eq!(admit(&mut ledger, 10, 0, 1, NOW), Ok(()));
        assert_eq!(
            admit(&mut ledger, 10, 0, 2, NOW),
            Err(LedgerError::UnknownReservation)
        );
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let mut ledger = EpochLedger::default();
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");

        assert_eq!(
            ledger.apply_admit(&settings(), 10, &admit_request(0, 1), Ok(OTHER_KEY), NOW),
            Err(LedgerError::InvalidSignature)
        );
        assert_eq!(
            ledger.apply_admit(
                &settings(),
                10,
                &admit_request(0, 1),
                Err(SignatureError::HighS),
                NOW
            ),
            Err(LedgerError::InvalidSignature)
        );
    }

    /// Units spent are the sum of the lanes' counters, so a second lane adds to the first.
    #[test]
    fn capacity_counts_every_lanes_counter() {
        let mut ledger = EpochLedger::default();

        // Both lanes at once, because an admitted lane frees immediately and would be reused.
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        assert_eq!(admit(&mut ledger, 10, 0, 1, NOW), Ok(()));
        assert_eq!(admit(&mut ledger, 10, 1, 1, NOW), Ok(()));

        // Lane 0 is free again, so it hands out its second counter.
        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        assert_eq!(admit(&mut ledger, 10, 0, 2, NOW), Ok(()));

        ledger.apply_reserve(10, EPOCH, NOW).expect("granted");
        let Err(LedgerError::CapacityExhausted(proof)) = admit(&mut ledger, 3, 0, 3, NOW) else {
            panic!("a fourth unit past a capacity of three should be refused");
        };

        assert_eq!(
            proof.admitted_units, 3,
            "two on lane zero plus one on lane one"
        );
        assert_eq!(proof.capacity, 3);
        assert_eq!(proof.epoch, EPOCH);
        assert_eq!(
            proof.authorizations.len(),
            2,
            "one per lane, the highest each"
        );
    }

    /// Held is not spent. A relying party whose own outstanding reservations are in the way
    /// should come back; one whose epoch is spent should not, and the two must not look alike.
    #[test]
    fn capacity_held_by_reservations_is_refused_as_retryable() {
        let mut ledger = EpochLedger::default();

        ledger.apply_reserve(2, EPOCH, NOW).expect("granted");
        assert_eq!(admit(&mut ledger, 2, 0, 1, NOW), Ok(()));
        let held = ledger.apply_reserve(2, EPOCH, NOW).expect("granted");

        let Err(LedgerError::CapacityReserved(proof)) = ledger.apply_reserve(2, EPOCH, NOW) else {
            panic!("one spent plus one held fills a capacity of two, but waiting frees it");
        };

        assert_eq!(proof.admitted_units, 1, "only one unit is actually spent");
        assert_eq!(proof.capacity, 2);
        assert_eq!(
            proof.retry_after,
            Some(held.expires_by),
            "the caller is told when the lane comes back rather than left to guess"
        );

        // Once the epoch really is spent, waiting stops helping and the answer changes.
        assert_eq!(admit(&mut ledger, 2, held.lane, held.counter, NOW), Ok(()));
        assert!(
            matches!(
                ledger.apply_reserve(2, EPOCH, NOW),
                Err(LedgerError::CapacityExhausted(_))
            ),
            "two spent units fill a capacity of two for good"
        );
    }

    #[test]
    fn an_epoch_stops_opening_lanes_at_its_ceiling() {
        let mut ledger = EpochLedger::default();

        for _ in 0..MAX_LANES_PER_EPOCH {
            ledger
                .apply_reserve(u64::MAX, EPOCH, NOW)
                .expect("lanes under the ceiling should be granted");
        }

        assert_eq!(
            ledger.apply_reserve(u64::MAX, EPOCH, NOW),
            Err(LedgerError::TooManyPending)
        );

        // Expired lanes are reusable, so they do not hold the epoch at its ceiling.
        assert!(ledger.apply_reserve(u64::MAX, EPOCH, LATER).is_ok());
    }
}
