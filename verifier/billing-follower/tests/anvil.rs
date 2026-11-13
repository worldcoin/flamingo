//! The follower on anvil, with `BillingEventEmitter`'s events; run with `-- --ignored`.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::{Result, eyre};
use flamingo_verifier_billing_follower::{BillingFollower, BillingUpdate, FollowerConfig, RpcUrl};
use flamingo_verifier_billing_state::{BillingOp, Registration};
use world_id_primitives::{FieldElement, billing::period_start, rp::RpId};

sol!(
    #[sol(rpc)]
    BillingEventEmitter,
    "tests/fixtures/BillingEventEmitter.json"
);

const ANVIL_CHAIN_ID: u64 = 31_337;
const RP: u64 = 7;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after the epoch")
        .as_secs()
}

/// The billed RPs and registrations, built only from the follower's updates.
#[derive(Debug, Default, PartialEq, Eq)]
struct BillingState {
    billed_rps: HashSet<RpId>,
    registrations: HashMap<FieldElement, Registration>,
}

impl BillingState {
    fn apply(&mut self, op: BillingOp) {
        match op {
            BillingOp::SetBilledRp { rp_id, billed } if billed => {
                self.billed_rps.insert(rp_id);
            }
            BillingOp::SetBilledRp { rp_id, .. } => {
                self.billed_rps.remove(&rp_id);
            }
            BillingOp::AddRegistration {
                nullifier,
                registration,
            } => {
                self.registrations.insert(nullifier, registration);
            }
            BillingOp::RemoveRegistration { nullifier, .. } => {
                self.registrations.remove(&nullifier);
            }
        }
    }

    fn is_billed(&self, rp_id: RpId) -> bool {
        self.billed_rps.contains(&rp_id)
    }

    fn is_registered(&self, nullifier: FieldElement, rp_id: RpId) -> bool {
        self.registrations
            .get(&nullifier)
            .is_some_and(|registration| registration.rp_id == rp_id)
    }
}

/// A copy of the state built only from the follower's updates.
#[derive(Default)]
struct Mirror {
    state: BillingState,
    head: u64,
    backfill_done: bool,
}

impl Mirror {
    fn apply(&mut self, update: BillingUpdate) {
        for op in update.ops {
            self.state.apply(op);
        }
        self.head = update.head;
        self.backfill_done = update.backfill_done;
    }

    /// Applies updates until the copy is current up to `block`.
    async fn sync_to(&mut self, follower: &mut BillingFollower, block: u64) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !(self.backfill_done && self.head >= block) {
                self.apply(follower.next().await?);
            }
            Ok::<_, eyre::Report>(())
        })
        .await
        .map_err(|_| eyre!("the follower did not reach block {block}"))?
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the anvil binary"]
async fn follows_backfill_live_blocks_and_a_reorganization() -> Result<()> {
    let anvil = Anvil::new().try_spawn()?;
    let signer = PrivateKeySigner::from(anvil.keys()[0].clone());
    // Nonces come from the node, since `evm_revert` rewinds them.
    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(EthereumWallet::from(signer))
        .connect_http(anvil.endpoint_url());
    let emitter = BillingEventEmitter::deploy(&provider).await?;
    let deploy_block = provider.get_block_number().await?;
    let period = period_start(now())?;
    let rp = RpId::new(RP);
    let nullifier = |value: u64| FieldElement::from(value);

    let send = |call: alloy::rpc::types::TransactionRequest| {
        let provider = provider.clone();
        async move {
            let hash = *provider.send_transaction(call).await?.tx_hash();
            // Polled: `get_receipt` waits on new block numbers, which `evm_revert` reuses.
            let receipt = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(receipt) = provider.get_transaction_receipt(hash).await? {
                        return Ok::<_, eyre::Report>(receipt);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .map_err(|_| eyre!("no receipt for {hash}"))??;
            eyre::ensure!(receipt.status(), "the emitter call reverted");
            Ok::<_, eyre::Report>(receipt.block_number.unwrap_or_default())
        }
    };
    send(emitter.billedRpUpdated(RP, true).into_transaction_request()).await?;
    let backfilled = send(
        emitter
            .registered(RP, period, U256::from(1))
            .into_transaction_request(),
    )
    .await?;

    let config = FollowerConfig {
        reorg_window: 8,
        block_time: Duration::from_millis(500),
        poll_interval: Duration::from_millis(50),
        stalled_poll_interval: Duration::from_millis(200),
        ..FollowerConfig::new(ANVIL_CHAIN_ID, *emitter.address(), deploy_block)
    };
    let mut follower =
        BillingFollower::connect(RpcUrl(anvil.endpoint_url()), config.clone()).await?;
    let mut mirror = Mirror::default();
    mirror.sync_to(&mut follower, backfilled).await?;
    assert!(mirror.state.is_billed(rp));
    assert!(mirror.state.is_registered(nullifier(1), rp));

    let snapshot: U256 = provider.raw_request("evm_snapshot".into(), ()).await?;
    let orphaned = send(
        emitter
            .registered(RP, period, U256::from(2))
            .into_transaction_request(),
    )
    .await?;
    mirror.sync_to(&mut follower, orphaned).await?;
    assert!(mirror.state.is_registered(nullifier(2), rp));

    let reverted: bool = provider
        .raw_request("evm_revert".into(), (snapshot,))
        .await?;
    assert!(reverted);
    // Mine past the orphaned block, so the new fork is longer.
    let _: String = provider.raw_request("evm_mine".into(), ()).await?;
    let replacing = send(
        emitter
            .registered(RP, period, U256::from(3))
            .into_transaction_request(),
    )
    .await?;
    mirror.sync_to(&mut follower, replacing).await?;
    assert!(!mirror.state.is_registered(nullifier(2), rp));
    assert!(mirror.state.is_registered(nullifier(3), rp));
    assert!(mirror.state.is_registered(nullifier(1), rp));

    let mut fresh = BillingFollower::connect(RpcUrl(anvil.endpoint_url()), config).await?;
    let mut fresh_mirror = Mirror::default();
    fresh_mirror.sync_to(&mut fresh, replacing).await?;
    assert_eq!(fresh_mirror.state, mirror.state);

    Ok(())
}
