//! An [`EscrowReader`] backed by JSON-RPC `eth_call`.
//!
//! The ABI is declared with `sol!`, so encoding and decoding are the same code the contract's
//! own tooling uses. The transport is the HTTP client this service already carries: pulling in
//! a provider stack would add a second rustls backend beside the one in use, which rustls
//! refuses to choose between at runtime.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolCall, sol};
use async_trait::async_trait;

use super::{ChannelSettings, EscrowError, EscrowReader};

sol! {
    /// Copied from the deployed fee escrow. Field order is part of the ABI.
    struct SolChannelSettings {
        uint64 rpId;
        address spendKey;
        address collector;
        address token;
        uint256 pricePerUnit;
        uint64 epochLength;
        uint64 epochZero;
        bytes32 salt;
    }

    /// Copied from the deployed fee escrow.
    struct SolEpochState {
        uint256 funded;
        uint64 settledUnits;
        bool closed;
    }

    function channelSettings(bytes32 channelId) external view returns (SolChannelSettings memory);
    function epochState(bytes32 channelId, uint64 epoch) external view returns (SolEpochState memory);
}

/// How the escrow reader talks to a node.
#[derive(Debug, Clone)]
pub struct EscrowConfig {
    /// JSON-RPC endpoint of an archive-free node on the escrow's chain.
    pub rpc_url: String,
    /// Address of the fee escrow contract.
    pub address: Address,
    /// Chain the escrow is deployed on. Checked by [`RpcEscrowReader::ready`].
    pub chain_id: u64,
    /// Deadline for one call, retry included.
    pub timeout: Duration,
    /// How long a capacity read stays good.
    pub capacity_ttl: Duration,
}

/// Reads the fee escrow over JSON-RPC, with a cache in front.
#[derive(Debug)]
pub struct RpcEscrowReader {
    config: EscrowConfig,
    http: reqwest::Client,
    cache: Mutex<Cache>,
}

#[derive(Debug, Default)]
struct Cache {
    /// Settings are immutable once the channel exists, so a hit never expires. The price rides
    /// along because capacity divides by it and it comes from the same call.
    channels: HashMap<B256, (ChannelSettings, U256)>,
    /// Absence and capacity both change with funding, so both carry a deadline.
    missing: HashMap<B256, Instant>,
    capacity: HashMap<(B256, u64), (u64, Instant)>,
}

impl RpcEscrowReader {
    /// Builds a reader for one escrow deployment.
    ///
    /// # Errors
    ///
    /// Returns [`EscrowError::Unavailable`] when the HTTP client cannot be built.
    pub fn new(config: EscrowConfig) -> Result<Self, EscrowError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| EscrowError::Unavailable(error.to_string()))?;

        Ok(Self {
            config,
            http,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Takes the cache lock, recovering it if a previous holder panicked.
    ///
    /// The critical sections are map operations that cannot panic partway, so refusing all
    /// payment traffic over a poisoned lock would be worse than carrying on.
    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends one `eth_call` and returns the returned bytes.
    ///
    /// Retried once, because a single dropped connection is common and a second failure is not
    /// worth queueing behind. A revert is not retried: it is the contract's answer, and asking
    /// again would only cost another round trip. The jitter keeps a fleet of hosts from retrying
    /// in step after a node blips.
    async fn call(&self, data: Vec<u8>) -> Result<Vec<u8>, CallFailure> {
        let mut last = CallFailure::Rpc(EscrowError::Unavailable("no attempt was made".to_owned()));

        for attempt in 0..=1u32 {
            if attempt > 0 {
                let jitter = Duration::from_millis(20).mul_f64(rand::random::<f64>());
                tokio::time::sleep(jitter).await;
            }

            match self
                .send("eth_call", call_params(self.config.address, &data))
                .await
            {
                Ok(result) => return decode_hex(&result).map_err(CallFailure::Rpc),
                Err(CallFailure::Reverted(data)) => return Err(CallFailure::Reverted(data)),
                Err(failure) => {
                    tracing::error!(
                        attempt,
                        retries = 1,
                        dependency = "fee_escrow_rpc",
                        failure = %failure,
                        "fee escrow call failed"
                    );

                    last = failure;
                }
            }
        }

        Err(last)
    }

    /// Sends one JSON-RPC request and returns the `result` field.
    async fn send(&self, method: &str, params: serde_json::Value) -> Result<String, CallFailure> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = self
            .http
            .post(&self.config.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    CallFailure::Rpc(EscrowError::Timeout)
                } else {
                    CallFailure::Rpc(EscrowError::Unavailable(error.to_string()))
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(CallFailure::Rpc(EscrowError::Unavailable(format!(
                "upstream status {}",
                status.as_u16()
            ))));
        }

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|error| CallFailure::Rpc(EscrowError::Unavailable(error.to_string())))?;

        // A revert is the contract answering, not the node failing. Telling the two apart is
        // what keeps a node outage from reading as an unknown channel. A rate limit, a quota
        // refusal and an internal node error all arrive here too, and none of them are answers.
        if let Some(error) = payload.get("error") {
            return Err(revert_data(error).map_or_else(
                || CallFailure::Rpc(EscrowError::Unavailable(format!("rpc error: {error}"))),
                CallFailure::Reverted,
            ));
        }

        payload
            .get("result")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                CallFailure::Rpc(EscrowError::Unavailable(
                    "rpc answer had no result".to_owned(),
                ))
            })
    }
}

/// Selector of the escrow's `ChannelNotFound(bytes32)` error, from `cast sig`.
///
/// The one revert that means "no such channel". Every other revert, and every failure that is
/// not a revert at all, leaves this host unable to tell, which is not the same answer.
const CHANNEL_NOT_FOUND: [u8; 4] = [0xf3, 0x83, 0xb1, 0x3e];

/// Why one `eth_call` did not produce bytes.
///
/// A revert and an outage look the same to a caller that only sees `Result`, and they must not:
/// one means the channel does not exist, the other means this host cannot tell. A rate limit is
/// an outage, and answering it as an absent channel would let a throttled node open the gate.
#[derive(Debug, thiserror::Error)]
enum CallFailure {
    /// The contract reverted, with whatever data it reverted with.
    #[error("the call reverted")]
    Reverted(Vec<u8>),
    /// The node could not answer.
    #[error(transparent)]
    Rpc(EscrowError),
}

impl CallFailure {
    /// Whether this is the escrow saying it does not know the channel.
    fn is_channel_not_found(&self) -> bool {
        match self {
            Self::Reverted(data) => data.starts_with(&CHANNEL_NOT_FOUND),
            Self::Rpc(_) => false,
        }
    }
}

/// Reads the revert data out of a JSON-RPC error object.
///
/// A node reports a revert as an error with the returned bytes in `data`. An error without them
/// is not a revert this host can read, so it is treated as an outage rather than as an answer.
fn revert_data(error: &serde_json::Value) -> Option<Vec<u8>> {
    let data = error
        .get("data")
        .and_then(|data| data.get("data").or(Some(data)))
        .and_then(serde_json::Value::as_str)?;

    decode_hex(data).ok()
}

#[async_trait]
impl EscrowReader for RpcEscrowReader {
    async fn channel(&self, channel_id: B256) -> Result<Option<ChannelSettings>, EscrowError> {
        // Each lookup releases the lock before branching: the call below is a network round
        // trip, and it must not run with the cache held.
        let cached = self.cache().channels.get(&channel_id).copied();
        if let Some((settings, _)) = cached {
            return Ok(Some(settings));
        }

        let seen = self.cache().missing.get(&channel_id).copied();
        if seen.is_some_and(|seen| seen.elapsed() < self.config.capacity_ttl) {
            return Ok(None);
        }

        let call = channelSettingsCall {
            channelId: channel_id,
        };

        // Only `ChannelNotFound` means the channel is absent. Any other revert, and every
        // transport or rate-limit failure, leaves this host unable to tell, which refuses.
        let returned = match self.call(call.abi_encode()).await {
            Ok(returned) => returned,
            Err(failure) if failure.is_channel_not_found() => {
                self.cache().missing.insert(channel_id, Instant::now());

                return Ok(None);
            }
            Err(CallFailure::Rpc(error)) => return Err(error),
            Err(CallFailure::Reverted(data)) => {
                return Err(EscrowError::Unavailable(format!(
                    "unexpected revert: 0x{}",
                    alloy_primitives::hex::encode(data)
                )));
            }
        };

        let decoded = channelSettingsCall::abi_decode_returns(&returned)
            .map_err(|error| EscrowError::Unavailable(format!("undecodable answer: {error}")))?;

        // The other way the contract says it does not know a channel: a zeroed record.
        if decoded.spendKey.is_zero() {
            self.cache().missing.insert(channel_id, Instant::now());

            return Ok(None);
        }

        let settings = ChannelSettings {
            spend_key: decoded.spendKey,
            collector: decoded.collector,
            token: decoded.token,
            price_per_unit: decoded.pricePerUnit,
            epoch_zero: decoded.epochZero,
            epoch_length: decoded.epochLength,
        };

        // Settings never change once the channel exists, so this entry never needs a deadline.
        self.cache()
            .channels
            .insert(channel_id, (settings, decoded.pricePerUnit));

        Ok(Some(settings))
    }

    async fn capacity(&self, channel_id: B256, epoch: u64) -> Result<u64, EscrowError> {
        let cached = self.cache().capacity.get(&(channel_id, epoch)).copied();
        if let Some((capacity, read_at)) = cached
            && read_at.elapsed() < self.config.capacity_ttl
        {
            return Ok(capacity);
        }

        // Warms the settings cache when it is cold, so the price below is one call, not two.
        // An unknown channel buys nothing, and its caller has already been refused.
        if self.channel(channel_id).await?.is_none() {
            return Ok(0);
        }

        let price = {
            let cache = self.cache();

            cache
                .channels
                .get(&channel_id)
                .map_or(U256::ZERO, |(_, price)| *price)
        };

        let call = epochStateCall {
            channelId: channel_id,
            epoch,
        };
        let returned = match self.call(call.abi_encode()).await {
            Ok(returned) => returned,
            // An epoch the contract will not talk about has nothing funded in it.
            Err(failure) if failure.is_channel_not_found() => return Ok(0),
            Err(CallFailure::Rpc(error)) => return Err(error),
            Err(CallFailure::Reverted(data)) => {
                return Err(EscrowError::Unavailable(format!(
                    "unexpected revert: 0x{}",
                    alloy_primitives::hex::encode(data)
                )));
            }
        };

        let decoded = epochStateCall::abi_decode_returns(&returned)
            .map_err(|error| EscrowError::Unavailable(format!("undecodable answer: {error}")))?;

        // A closed epoch buys nothing, whatever is still funded in it.
        let capacity = if decoded.closed || price.is_zero() {
            0
        } else {
            u64::try_from(decoded.funded / price).unwrap_or(u64::MAX)
        };

        self.cache()
            .capacity
            .insert((channel_id, epoch), (capacity, Instant::now()));

        Ok(capacity)
    }

    async fn ready(&self) -> Result<(), EscrowError> {
        let answer = self
            .send("eth_chainId", serde_json::json!([]))
            .await
            .map_err(|failure| match failure {
                CallFailure::Rpc(error) => error,
                CallFailure::Reverted(_) => {
                    EscrowError::Unavailable("eth_chainId reverted".to_owned())
                }
            })?;

        let digits = answer.strip_prefix("0x").unwrap_or(&answer);
        let actual = u64::from_str_radix(digits, 16)
            .map_err(|_| EscrowError::Unavailable(format!("undecodable chain id: {answer}")))?;

        if actual != self.config.chain_id {
            return Err(EscrowError::WrongChain {
                expected: self.config.chain_id,
                actual,
            });
        }

        // A real read, not just a reachable node: the channel id zero is not derivable, so the
        // contract must answer `ChannelNotFound`. Anything else means this host is pointed at
        // something that is not the escrow, or at a node that cannot reach it.
        let call = channelSettingsCall {
            channelId: B256::ZERO,
        };

        match self.call(call.abi_encode()).await {
            Err(failure) if failure.is_channel_not_found() => Ok(()),
            Ok(_) => Err(EscrowError::Unavailable(
                "the escrow answered for the zero channel id".to_owned(),
            )),
            Err(CallFailure::Rpc(error)) => Err(error),
            Err(CallFailure::Reverted(data)) => Err(EscrowError::Unavailable(format!(
                "unexpected revert: 0x{}",
                alloy_primitives::hex::encode(data)
            ))),
        }
    }
}

/// Builds the `eth_call` parameters for a read against `address`.
fn call_params(address: Address, data: &[u8]) -> serde_json::Value {
    serde_json::json!([
        { "to": address.to_string(), "data": format!("0x{}", alloy_primitives::hex::encode(data)) },
        "latest",
    ])
}

/// Decodes a `0x`-prefixed hex answer.
fn decode_hex(value: &str) -> Result<Vec<u8>, EscrowError> {
    let digits = value.strip_prefix("0x").unwrap_or(value);

    alloy_primitives::hex::decode(digits)
        .map_err(|error| EscrowError::Unavailable(format!("undecodable answer: {error}")))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address, b256};
    use alloy_sol_types::{SolCall, SolValue};

    use super::{SolChannelSettings, SolEpochState, channelSettingsCall, epochStateCall};

    const CHANNEL: alloy_primitives::B256 =
        b256!("0x2445d3989582ca28df4e2dc71b1e21dc0f752bbc6398d7461a71f676011eb4c5");

    /// The selector is what the node dispatches on, so a field-order slip would silently call
    /// something else. Cross-checked with `cast sig "channelSettings(bytes32)"`.
    #[test]
    fn the_call_selectors_match_the_contract() {
        assert_eq!(
            alloy_primitives::hex::encode(channelSettingsCall::SELECTOR),
            "8f81a65a"
        );
        assert_eq!(
            alloy_primitives::hex::encode(epochStateCall::SELECTOR),
            "67cb9744"
        );
    }

    #[test]
    fn channel_settings_round_trip_through_the_abi() {
        let settings = SolChannelSettings {
            rpId: 46,
            spendKey: address!("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"),
            collector: address!("0x0000000000000000000000000000000000FeE5c0"),
            token: address!("0xabababababababababababababababababababab"),
            pricePerUnit: U256::from(1_000u64),
            epochLength: 86_400,
            epochZero: 1_700_000_000,
            salt: CHANNEL,
        };

        let encoded = settings.abi_encode();
        let decoded = channelSettingsCall::abi_decode_returns(&encoded)
            .expect("the contract's own encoding should decode");

        assert_eq!(decoded.spendKey, settings.spendKey);
        assert_eq!(decoded.collector, settings.collector);
        assert_eq!(decoded.epochZero, settings.epochZero);
        assert_eq!(decoded.epochLength, settings.epochLength);
        assert_eq!(decoded.pricePerUnit, settings.pricePerUnit);
    }

    #[test]
    fn epoch_state_round_trips_through_the_abi() {
        let state = SolEpochState {
            funded: U256::from(10_000u64),
            settledUnits: 3,
            closed: false,
        };

        let decoded = epochStateCall::abi_decode_returns(&state.abi_encode())
            .expect("the contract's own encoding should decode");

        assert_eq!(decoded.funded, state.funded);
        assert_eq!(decoded.settledUnits, state.settledUnits);
        assert!(!decoded.closed);
    }
}
