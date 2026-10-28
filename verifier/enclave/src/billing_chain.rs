//! WIP-107 billing checks against the Billing Contract (WIP-107 §4.7, §4.8).
//!
//! The enclave dials the parent on vsock; the host forwards the bytes to the RPC provider. TLS
//! terminates here and verifies the configured URL's host, so the host relays only ciphertext.
//! The provider is trusted for chain state and the block's time.
//!
//! The check proves that the RP paid for the request's `billing_nullifier` in an active period.
//! It cannot prove the nullifier is the requester's: that needs the World ID's leaf index, which
//! the Verifier never sees. The Verifier signs the checked nullifier into the Flamingo Token, and
//! the Proof of Embedding Similarity (WIP-202 constraint 7) proves it belongs to the World ID it
//! proves for.

use std::time::Duration;

use tokio::sync::Semaphore;

use async_trait::async_trait;
use bytes::Bytes;
use flamingo_verifier_sealed_types::{BillingFailure, FailureReason};
use http_body_util::{BodyExt as _, Full, Limited};
use pontifex::http::HttpClient;
use serde_json::{Value, json};
use world_id_primitives::FieldElement;

/// WIP-107 §4.8: each chain read gets two seconds and no retry.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// All billing reads of one request share this budget, so a slow provider costs the Engine at
/// most this much of its deadline. Billed pipelines' last response slot must leave room for it.
pub const BILLING_BUDGET: Duration = Duration::from_secs(2);
/// WIP-107 `REGISTRATION_CONFIRMATIONS`: billing state is read this many blocks below the
/// provider's latest block, not at the latest block or at finality (WIP-107 §4.8).
const REGISTRATION_CONFIRMATIONS: u64 = 12;
/// Billing checks reading the chain at once; further ones are rejected, not queued, since any
/// sealed request can trigger reads (WIP-107 §4.8).
const MAX_CONCURRENT_READS: usize = 32;
/// Largest JSON-RPC response read; the replies used here are a few hundred bytes.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Selector of `registrationOf(uint256)`.
const REGISTRATION_OF: [u8; 4] = [0xa5, 0x63, 0xe2, 0x1b];
/// Selector of `getActivePeriods(uint64)`.
const GET_ACTIVE_PERIODS: [u8; 4] = [0x22, 0x68, 0x45, 0x3a];

/// Where the enclave reads billing state. Every value comes from the measured EIF environment,
/// never from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingChainConfig {
    /// HTTPS JSON-RPC endpoint; its host is the TLS server name.
    pub rpc_url: http::Uri,
    /// vsock port of the host's outbound proxy.
    pub proxy_port: u32,
    /// Chain the Billing Contract lives on; the provider must report it.
    pub chain_id: u64,
    /// The Billing Contract.
    pub billing_contract: [u8; 20],
}

/// The variables that enable billing reads; all or none must be set.
const ENV: [&str; 4] = [
    "BILLING_RPC_URL",
    "BILLING_RPC_PROXY_PORT",
    "BILLING_CHAIN_ID",
    "BILLING_CONTRACT",
];

impl BillingChainConfig {
    /// Reads the configuration from the environment; `None` when billing is not configured.
    ///
    /// # Errors
    /// Fails when only some variables are set or a value does not parse.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::parse(|name| std::env::var(name).ok())
    }

    fn parse(var: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let [Some(url), Some(port), Some(chain_id), Some(contract)] = ENV.map(&var) else {
            return if ENV.iter().any(|name| var(name).is_some()) {
                Err(ConfigError(
                    "set all of BILLING_RPC_URL, BILLING_RPC_PROXY_PORT, BILLING_CHAIN_ID and BILLING_CONTRACT, or none",
                ))
            } else {
                Ok(None)
            };
        };
        let rpc_url: http::Uri = url.parse().map_err(|_| ConfigError("BILLING_RPC_URL"))?;
        if rpc_url.scheme_str() != Some("https") || rpc_url.host().is_none() {
            return Err(ConfigError("BILLING_RPC_URL must be an https URL"));
        }
        Ok(Some(Self {
            rpc_url,
            proxy_port: port
                .parse()
                .map_err(|_| ConfigError("BILLING_RPC_PROXY_PORT"))?,
            chain_id: chain_id
                .parse()
                .map_err(|_| ConfigError("BILLING_CHAIN_ID"))?,
            billing_contract: contract
                .strip_prefix("0x")
                .and_then(|hex| hex::decode(hex).ok())
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(ConfigError(
                    "BILLING_CONTRACT must be a 0x-prefixed 20-byte address",
                ))?,
        }))
    }
}

/// An invalid billing configuration, naming the offending variable.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid billing configuration: {0}")]
pub struct ConfigError(&'static str);

/// Why a chain read failed.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The read took longer than [`READ_TIMEOUT`], or all of a request's reads longer than
    /// [`BILLING_BUDGET`].
    #[error("chain read timed out")]
    Timeout,
    /// [`MAX_CONCURRENT_READS`] checks are already reading the chain.
    #[error("too many concurrent chain reads")]
    Busy,
    /// The proxy, TLS or HTTP exchange failed.
    #[error("chain read transport failed: {0}")]
    Transport(String),
    /// The provider answered with a JSON-RPC error.
    #[error("chain read rejected: {0}")]
    Rpc(String),
    /// The provider's answer is not what the call returns.
    #[error("malformed chain response: {0}")]
    Malformed(&'static str),
}

/// What the Billing Contract records for a billing nullifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    /// The RP whose capacity it consumed.
    pub rp_id: u64,
    /// The billing period it was registered for.
    pub period_start: u64,
    /// Block time of the registration.
    pub registered_at: u64,
}

/// Billing state at one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The block's timestamp: the trusted time for the active-period check (WIP-107 §4.3).
    pub timestamp: u64,
    /// `getActivePeriods(timestamp)`: the current period and, within the overlap, the next one
    /// (otherwise `0`).
    pub active_periods: (u64, u64),
    /// `registrationOf(billing_nullifier)`; `None` if it is not registered.
    pub registration: Option<Registration>,
}

/// Billing state the enclave checks requests against.
#[async_trait]
pub trait BillingReader: Send + Sync {
    /// The chain and Billing Contract this reader serves.
    fn config(&self) -> &BillingChainConfig;

    /// The billing state of `billing_nullifier` at one block.
    async fn snapshot(&self, billing_nullifier: FieldElement) -> Result<Snapshot, ChainError>;
}

/// Checks the request's `billing_nullifier` before the Engine runs and returns the value to sign
/// into the Flamingo Token (WIP-107 §4.7).
///
/// An enclave without billing configuration bills no RP and signs `0`, whatever the request
/// carries. One with it bills every RP: `isBilledRp` is not in the Billing Contract yet. The
/// Verifier does not verify the RP's signature; capacity is consumed only by `register`.
///
/// # Errors
/// Returns the [`FailureReason`] the requester receives. A chain that cannot be read within
/// [`BILLING_BUDGET`] rejects the request (fail closed).
pub async fn check(
    reader: Option<&dyn BillingReader>,
    billing_nullifier: FieldElement,
    aud: FieldElement,
) -> Result<FieldElement, FailureReason> {
    let Some(reader) = reader else {
        return Ok(FieldElement::ZERO);
    };
    if billing_nullifier == FieldElement::ZERO {
        return Err(FailureReason::BillingRequired);
    }
    let unavailable = |error: &dyn std::fmt::Display| {
        tracing::warn!(%error, "billing state unavailable; rejecting the request");
        FailureReason::BillingUnavailable
    };
    let snapshot = tokio::time::timeout(BILLING_BUDGET, reader.snapshot(billing_nullifier))
        .await
        .map_err(|_| unavailable(&ChainError::Timeout))?
        .map_err(|error| unavailable(&error))?;
    check_snapshot(aud, &snapshot)?;
    Ok(billing_nullifier)
}

/// `registrationOf` must name `aud` and a period that is active at the snapshot's block.
fn check_snapshot(aud: FieldElement, snapshot: &Snapshot) -> Result<(), FailureReason> {
    let Some(registration) = snapshot
        .registration
        .filter(|registration| FieldElement::from(registration.rp_id) == aud)
    else {
        return Err(FailureReason::BillingRejected(
            BillingFailure::NotRegistered,
        ));
    };
    let (current, next) = snapshot.active_periods;
    if registration.period_start != current && (next == 0 || registration.period_start != next) {
        return Err(FailureReason::BillingRejected(
            BillingFailure::PeriodInactive,
        ));
    }
    Ok(())
}

/// Reads the Billing Contract through the host's outbound proxy.
pub struct BillingChain {
    client: HttpClient<Full<Bytes>>,
    config: BillingChainConfig,
    reads: Semaphore,
}

impl BillingChain {
    /// A client for `config`; it connects on first use.
    #[must_use]
    pub fn new(config: BillingChainConfig) -> Self {
        Self {
            client: pontifex::http::client(config.proxy_port),
            config,
            reads: Semaphore::new(MAX_CONCURRENT_READS),
        }
    }

    /// `eth_chainId` as the provider reports it.
    ///
    /// # Errors
    /// Fails when the read fails or the answer is not a quantity.
    pub async fn chain_id(&self) -> Result<u64, ChainError> {
        quantity(&self.call("eth_chainId", json!([])).await?)
    }

    /// `eth_call` of `calldata` on the Billing Contract at the block `block_hash` (EIP-1898).
    async fn eth_call(&self, calldata: &[u8], block_hash: &str) -> Result<Vec<u8>, ChainError> {
        let output = self
            .call(
                "eth_call",
                json!([
                    {
                        "to": format!("0x{}", hex::encode(self.config.billing_contract)),
                        "data": format!("0x{}", hex::encode(calldata)),
                    },
                    // A reorged-out block must not answer: the provider rejects a non-canonical hash.
                    { "blockHash": block_hash, "requireCanonical": true },
                ]),
            )
            .await?;
        output
            .as_str()
            .and_then(|data| data.strip_prefix("0x"))
            .and_then(|data| hex::decode(data).ok())
            .ok_or(ChainError::Malformed("eth_call output"))
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let request = http::Request::post(self.config.rpc_url.clone())
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|error| ChainError::Transport(error.to_string()))?;
            if !response.status().is_success() {
                return Err(ChainError::Transport(format!("HTTP {}", response.status())));
            }
            Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
                .map_err(|error| ChainError::Transport(error.to_string()))
        };
        let bytes = tokio::time::timeout(READ_TIMEOUT, exchange)
            .await
            .map_err(|_| ChainError::Timeout)??;
        let mut reply: Value =
            serde_json::from_slice(&bytes).map_err(|_| ChainError::Malformed("JSON-RPC reply"))?;
        if let Some(error) = reply.get("error") {
            return Err(ChainError::Rpc(error.to_string()));
        }
        reply
            .get_mut("result")
            .map(Value::take)
            .ok_or(ChainError::Malformed("JSON-RPC result"))
    }
}

#[async_trait]
impl BillingReader for BillingChain {
    fn config(&self) -> &BillingChainConfig {
        &self.config
    }

    async fn snapshot(&self, billing_nullifier: FieldElement) -> Result<Snapshot, ChainError> {
        let _permit = self.reads.try_acquire().map_err(|_| ChainError::Busy)?;
        let latest = quantity(&self.call("eth_blockNumber", json!([])).await?)?;
        let number = latest
            .checked_sub(REGISTRATION_CONFIRMATIONS)
            .ok_or(ChainError::Malformed("block number"))?;
        let block = self
            .call(
                "eth_getBlockByNumber",
                json!([format!("{number:#x}"), false]),
            )
            .await?;
        let hash = block
            .get("hash")
            .and_then(Value::as_str)
            .ok_or(ChainError::Malformed("block hash"))?;
        let timestamp = quantity(
            block
                .get("timestamp")
                .ok_or(ChainError::Malformed("block timestamp"))?,
        )?;
        // Both calls are pinned to that block, so the period and the registration agree with
        // its timestamp.
        let periods_call = calldata(GET_ACTIVE_PERIODS, word(timestamp));
        let registration_call = calldata(REGISTRATION_OF, billing_nullifier.to_be_bytes());
        let (periods, registration) = tokio::try_join!(
            self.eth_call(&periods_call, hash),
            self.eth_call(&registration_call, hash),
        )?;
        Ok(Snapshot {
            timestamp,
            active_periods: uint64_words::<2>(&periods)?.into(),
            registration: decode_registration(&registration)?,
        })
    }
}

/// ABI calldata of a one-argument call.
fn calldata(selector: [u8; 4], argument: [u8; 32]) -> [u8; 36] {
    let mut calldata = [0; 36];
    calldata[..4].copy_from_slice(&selector);
    calldata[4..].copy_from_slice(&argument);
    calldata
}

/// The ABI word of a `uint64`.
fn word(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Decodes `N` ABI words that each hold a `uint64`.
fn uint64_words<const N: usize>(output: &[u8]) -> Result<[u64; N], ChainError> {
    let malformed = || ChainError::Malformed("uint64 words");
    let (words, []) = output.as_chunks::<32>() else {
        return Err(malformed());
    };
    let words: &[[u8; 32]; N] = words.try_into().map_err(|_| malformed())?;
    let mut values = [0; N];
    for (value, word) in values.iter_mut().zip(words) {
        let (high, low) = word.split_at(24);
        if high.iter().any(|&byte| byte != 0) {
            return Err(malformed());
        }
        *value = u64::from_be_bytes(low.try_into().map_err(|_| malformed())?);
    }
    Ok(values)
}

/// Decodes `(uint64 rpId, uint64 periodStart, uint64 registeredAt)`; all zeros means unregistered.
fn decode_registration(output: &[u8]) -> Result<Option<Registration>, ChainError> {
    let [rp_id, period_start, registered_at] = uint64_words(output)?;
    // The contract stores a nonzero periodStart for every registration.
    Ok((period_start != 0).then_some(Registration {
        rp_id,
        period_start,
        registered_at,
    }))
}

/// A JSON-RPC quantity: a `0x`-prefixed hex number.
fn quantity(value: &Value) -> Result<u64, ChainError> {
    value
        .as_str()
        .and_then(|hex| hex.strip_prefix("0x"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .ok_or(ChainError::Malformed("quantity"))
}

#[cfg(test)]
mod tests {
    use sha3::{Digest as _, Keccak256};

    use super::*;

    #[test]
    fn selectors_match_the_contract() {
        for (signature, selector) in [
            ("registrationOf(uint256)", REGISTRATION_OF),
            ("getActivePeriods(uint64)", GET_ACTIVE_PERIODS),
        ] {
            assert_eq!(Keccak256::digest(signature)[..4], selector, "{signature}");
        }
    }

    #[test]
    fn decodes_registrations_and_rejects_other_outputs() {
        let output = [word(7), word(1_782_820_800), word(1_782_900_000)].concat();
        assert_eq!(
            decode_registration(&output).unwrap(),
            Some(Registration {
                rp_id: 7,
                period_start: 1_782_820_800,
                registered_at: 1_782_900_000,
            })
        );
        assert_eq!(decode_registration(&[0; 96]).unwrap(), None);

        // A value above uint64 is not what the contract returns.
        let mut wide = output.clone();
        wide[0] = 1;
        assert!(decode_registration(&wide).is_err());
        assert!(decode_registration(&output[..64]).is_err());
    }

    #[test]
    fn accepts_the_next_period_only_within_the_overlap() {
        const MAY: u64 = 1_777_636_800;
        const JUNE: u64 = 1_780_315_200;
        let aud = FieldElement::from(1u64);
        let snapshot = |active_periods, period_start| Snapshot {
            timestamp: 0,
            active_periods,
            registration: Some(Registration {
                rp_id: 1,
                period_start,
                registered_at: 0,
            }),
        };
        let inactive = Err(FailureReason::BillingRejected(
            BillingFailure::PeriodInactive,
        ));
        assert_eq!(check_snapshot(aud, &snapshot((MAY, 0), MAY)), Ok(()));
        assert_eq!(check_snapshot(aud, &snapshot((MAY, JUNE), JUNE)), Ok(()));
        assert_eq!(check_snapshot(aud, &snapshot((MAY, 0), JUNE)), inactive);
        // Outside the overlap the contract reports no next period as `0`, which no
        // registration's period matches.
        assert_eq!(check_snapshot(aud, &snapshot((MAY, 0), 0)), inactive);
        // A registration for another RP is not this RP's.
        assert_eq!(
            check_snapshot(FieldElement::from(2u64), &snapshot((MAY, 0), MAY)),
            Err(FailureReason::BillingRejected(
                BillingFailure::NotRegistered
            ))
        );
    }

    fn vars<'a>(set: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            set.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn configuration_is_all_or_nothing() {
        assert_eq!(BillingChainConfig::parse(vars(&[])), Ok(None));
        assert!(BillingChainConfig::parse(vars(&[("BILLING_CHAIN_ID", "480")])).is_err());

        let complete = [
            ("BILLING_RPC_URL", "https://rpc.example.org/v1"),
            ("BILLING_RPC_PROXY_PORT", "8001"),
            ("BILLING_CHAIN_ID", "480"),
            (
                "BILLING_CONTRACT",
                "0x00000000000000000000000000000000000000aa",
            ),
        ];
        let config = BillingChainConfig::parse(vars(&complete)).unwrap().unwrap();
        assert_eq!(config.chain_id, 480);
        assert_eq!(config.proxy_port, 8001);
        assert_eq!(config.billing_contract[19], 0xaa);

        let plaintext = [
            ("BILLING_RPC_URL", "http://rpc.example.org"),
            complete[1],
            complete[2],
            complete[3],
        ];
        assert!(BillingChainConfig::parse(vars(&plaintext)).is_err());
    }
}
