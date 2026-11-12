# flamingo-verifier-billing-follower

Follows the WIP-107 Billing Contract at the latest block and emits the billing state the Flamingo host supplies to the enclave (WIP-107 §4.8).

`BillingFollower::next` returns `BillingUpdate`s: the `BillingOp`s to apply to a copy of `flamingo_verifier_billing_state::BillingState`, the block the state is current up to, and whether the follower has caught up. The follower:

- backfills `BilledRpUpdated` logs from the Contract's deployment and `Registered` logs from the start of the earliest active billing period, with `eth_getLogs` ranges that shrink when a provider rejects them;
- polls on the chain's block schedule, checks each new block's parent hash, and answers a reorganization within its window with the ops that undo it; a deeper fork restarts it from an empty state, flagged as `reset`;
- retries failed reads with exponential backoff and jitter, over one JSON-RPC endpoint (failover belongs in front of it);
- reports `billing_follower.*` metrics through the `metrics` facade.

`ChainSource` abstracts the reads; `RpcSource` implements it over JSON-RPC.

The anvil test needs the `anvil` binary from Foundry: `cargo test -p flamingo-verifier-billing-follower --test anvil -- --ignored`. `tests/fixtures/BillingEventEmitter.json` is the compiled `BillingEventEmitter` of `tests/fixtures/BillingEventEmitter.sol`.
