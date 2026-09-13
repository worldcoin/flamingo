//! Test doubles shared across the host's integration tests.
//!
//! Compiled once per test binary, so a helper only one of them needs reads as dead in the rest.
#![allow(
    dead_code,
    reason = "each test binary uses its own subset of these helpers"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use alloy_primitives::{Address, B256, U256, address};
use async_trait::async_trait;
use flamingo_verifier_enclave_types::{KeyAttestation, MatchRequest, MatchResponse};
use flamingo_verifier_host::enclave::{self, EnclaveClient};
use flamingo_verifier_host::payments::escrow::{ChannelSettings, EscrowError, EscrowReader};
use flamingo_verifier_host::payments::{InMemoryStore, PaymentConfig, PaymentLedger, PaymentStore};
use flamingo_verifier_host::{AppState, Environment};

/// The address this host settles to, and the one a test channel must name.
pub const COLLECTOR: Address = address!("0x0000000000000000000000000000000000FeE5c0");
/// The only token this host accepts payment in.
pub const FEE_TOKEN: Address = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
/// The least this host sells a verification for. A cheaper channel is refused.
pub const MIN_PRICE_PER_UNIT: u64 = 1_000;

/// An [`EnclaveClient`] answering from fixed results.
///
/// Unconfigured operations panic, so a route asking for the wrong key fails loudly.
#[derive(Default)]
pub struct StubEnclaveClient {
    /// `None` is healthy, so only a test about readiness has to say anything.
    pub health: Option<Result<(), enclave::Error>>,
    pub encryption_key: Option<Result<KeyAttestation, enclave::Error>>,
    pub match_result: Option<Result<MatchResponse, enclave::Error>>,
    /// Asserted against the sealed body the route forwards, if set.
    pub expected_body: Option<Vec<u8>>,
}

#[async_trait]
impl EnclaveClient for StubEnclaveClient {
    async fn health(&self) -> Result<(), enclave::Error> {
        self.health.clone().unwrap_or(Ok(()))
    }

    async fn encryption_key_attestation(&self) -> Result<KeyAttestation, enclave::Error> {
        self.encryption_key
            .clone()
            .expect("route asked for the encryption key but the stub was not configured to answer")
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, enclave::Error> {
        if let Some(expected) = &self.expected_body {
            assert_eq!(&request.body, expected);
        }

        self.match_result
            .clone()
            .expect("route ran a match but the stub was not configured to answer")
    }
}

/// An [`EscrowReader`] answering from a map instead of a chain.
///
/// Stands in for the contract everywhere the register route used to stand in for it.
#[derive(Debug, Default)]
pub struct FakeEscrowReader {
    state: Mutex<EscrowState>,
}

#[derive(Debug, Default)]
struct EscrowState {
    channels: HashMap<B256, ChannelSettings>,
    capacities: HashMap<(B256, u64), u64>,
    failure: Option<EscrowError>,
}

impl FakeEscrowReader {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A reader that fails every call, for the tests about a node outage.
    #[must_use]
    pub fn unavailable() -> Self {
        let reader = Self::default();
        reader.state().failure = Some(EscrowError::Unavailable("node is down".to_owned()));

        reader
    }

    /// Adds a channel the escrow knows about.
    pub fn with_channel(self, channel_id: B256, settings: ChannelSettings) -> Self {
        self.state().channels.insert(channel_id, settings);

        self
    }

    /// Sets the units a channel may spend in one epoch.
    pub fn with_capacity(self, channel_id: B256, epoch: u64, capacity: u64) -> Self {
        self.state()
            .capacities
            .insert((channel_id, epoch), capacity);

        self
    }

    fn state(&self) -> std::sync::MutexGuard<'_, EscrowState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl EscrowReader for FakeEscrowReader {
    async fn channel(&self, channel_id: B256) -> Result<Option<ChannelSettings>, EscrowError> {
        let state = self.state();

        state
            .failure
            .clone()
            .map_or_else(|| Ok(state.channels.get(&channel_id).copied()), Err)
    }

    async fn capacity(&self, channel_id: B256, epoch: u64) -> Result<u64, EscrowError> {
        let state = self.state();

        state.failure.clone().map_or_else(
            || {
                Ok(state
                    .capacities
                    .get(&(channel_id, epoch))
                    .copied()
                    .unwrap_or(u64::MAX))
            },
            Err,
        )
    }

    async fn ready(&self) -> Result<(), EscrowError> {
        self.state().failure.clone().map_or(Ok(()), Err)
    }
}

/// Builds an [`AppState`] backed by `client`, an empty store and an escrow that knows nothing.
pub fn state_with(client: StubEnclaveClient) -> AppState {
    state_with_escrow(client, FakeEscrowReader::new())
}

/// Builds an [`AppState`] over `escrow`, which is how a test sets up its channels.
pub fn state_with_escrow(client: StubEnclaveClient, escrow: FakeEscrowReader) -> AppState {
    state_with_payments(client, ledger_with(payment_config(), Arc::new(escrow)))
}

/// Builds an [`AppState`] whose match route refuses an unpaid request.
pub fn state_requiring_payment(client: StubEnclaveClient, escrow: FakeEscrowReader) -> AppState {
    state_with_payments(
        client,
        ledger_with(payment_config_with(true), Arc::new(escrow)),
    )
}

/// Builds an [`AppState`] over a ledger a test has already assembled.
pub fn state_with_payments(client: StubEnclaveClient, payments: PaymentLedger) -> AppState {
    AppState::new(
        Environment::Development,
        Arc::new(client),
        Arc::new(payments),
    )
}

/// Builds a ledger over a fresh in-memory store and `escrow`.
pub fn ledger_with(config: PaymentConfig, escrow: Arc<dyn EscrowReader>) -> PaymentLedger {
    ledger_over(config, Arc::new(InMemoryStore::new()), escrow)
}

/// Builds a ledger over both dependencies, for the tests that drive their failures.
pub fn ledger_over(
    config: PaymentConfig,
    store: Arc<dyn PaymentStore>,
    escrow: Arc<dyn EscrowReader>,
) -> PaymentLedger {
    PaymentLedger::new(config, store, escrow)
}

/// The local defaults: World Chain Sepolia against an unset escrow address.
pub fn payment_config() -> PaymentConfig {
    payment_config_with(false)
}

/// The same defaults, with metering on or off.
pub fn payment_config_with(payment_required: bool) -> PaymentConfig {
    PaymentConfig::new(
        4801,
        Address::ZERO,
        COLLECTOR,
        FEE_TOKEN,
        U256::from(MIN_PRICE_PER_UNIT),
        payment_required,
    )
}
