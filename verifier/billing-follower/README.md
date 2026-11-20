# flamingo-verifier-billing-follower

Follows the WIP-107 Billing Contract at the latest block and emits the billing state the Flamingo host supplies to the enclave (WIP-107 §4.8).

`BillingFollower::next` returns `BillingUpdate`s: the `flamingo_verifier_billing_state::BillingOp`s to apply to a copy of the billing state, the block the state is current up to, and whether the follower has caught up. The follower:

- backfills `BilledRpUpdated` logs from the Contract's deployment and `Registered` logs from the start of the earliest active billing period, with `eth_getLogs` ranges that shrink when a provider rejects them;
- polls on the chain's block schedule, checks each new block's parent hash, and answers a reorganization within its window with the ops that undo it; a deeper fork stops it with `FollowerError::DeepFork`, so the consumer rebuilds its copy by following the chain again;
- keeps no registrations: the Billing Contract emits `Registered` once per nullifier, so the op undoing one is its removal;
- retries failed reads with exponential backoff and jitter, over one JSON-RPC endpoint (failover belongs in front of it);
- reports `billing_follower.*` metrics through the `metrics` facade.

`ChainSource` abstracts the reads; `RpcSource` implements it over JSON-RPC.

## Indexer backend

`IndexerFollower` is an opt-in library backend for an event indexer's API v1.
It emits the same native `BillingUpdate` and `BillingOp` types as `BillingFollower`;
it introduces no separate enclave protocol. The host CLI and existing RPC-backed
runner do not select this backend. A host integration must construct it explicitly
with `IndexerFollower::new(base_url, token, config)`.

Build `IndexerConfig` from independently trusted target, chain ID, genesis hash,
contract address and actual deployment block. The source must cover deployment,
both billing event signatures and unrestricted indexed fields, and report
hash-bound contract-code verification. The follower validates that metadata
before completing bootstrap. The indexer remains a trusted source of billing
history; matching identity and nonempty code do not independently prove log
completeness.

The follower reads a frozen, paginated HTTP snapshot, drains HTTP replay from its
resume cursor before first announcing completion, then follows SSE. This applies
queued retractions before the receiver becomes ready. After a transient transport failure it catches up
over HTTP before reopening SSE. Request, response-body, SSE-frame and idle limits
are bounded. `next()` handles transient source failures with backoff and keeps
already accepted receiver state; authentication and source-configuration errors
are returned to the caller.

Call `next()` again **only after the native `Pusher` has accepted the entire prior
update**, including all chunks. The follower advances its in-memory cursor when
returning an update; it has no separate acknowledgement or persisted consumer
cursor. A lost push reply must be retried by the pusher, without fetching another
update. After a pusher rejection, discard the follower and pusher and rebuild.

On `IndexerError::ResetRequired`, immediately use the host's existing invalidation
path: send an empty `seq = 0`, `backfill_done = false` update so the receiver stops
serving. Drop the old follower and pusher, then apply restart backoff before
constructing replacements. Never append a replacement snapshot to the old numbered
stream. Target-generation changes, expired cursors/snapshots, unrecoverable
retractions and changes to the active-period scope require this rebuild. Period
boundaries therefore incur a new bootstrap.

Registrations stream directly into updates; the follower keeps no registration
cache. It retains bounded RP history to restore prior flags after retractions.
`IndexerConfig::new` defaults to a 256-block undo window and 1,048,576 RP-history
entries, including baselines. That resource bound is distinct from a receiver's
registration limit. Exhausted history or capacity requires a reset, not silently
dropped changes.

For deployment, obtain an HTTPS base URL and token through the application's
secret-delivery mechanism, for example application-owned `BILLING_INDEXER_URL`
and `BILLING_INDEXER_TOKEN` environment variables. These names are not host CLI
settings. Keep tokens out of URLs, source files and logs; HTTP is intended only
for a trusted local transport. The receiver still owns trusted-time expiry,
capacity and request-time billing authorization.

The anvil test needs the `anvil` binary from Foundry: `cargo test -p flamingo-verifier-billing-follower --test anvil -- --ignored`. `tests/fixtures/BillingEventEmitter.json` is the compiled `BillingEventEmitter` of `tests/fixtures/BillingEventEmitter.sol`.
