# Architecture

The client encrypts images for an attested enclave. The HTTP host forwards the ciphertext over vsock. The enclave compares the faces and returns an encrypted result. Successful matches include a signed [WIP-201](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-201.md) Flamingo Token and an attestation of the signing key.

## Trust and attestation

The client verifies the Nitro attestation against the AWS root certificate, the configured PCR measurements, and an age limit. It checks that the encryption key matches the commitment in the attestation before using that key. The host neither decrypts images nor pins enclave measurements.

The enclave generates encryption and signing keys at boot. Keys stay in memory and change on restart. Both attestations must succeed before the enclave starts serving requests.

The enclave caches attestations and refreshes them every 10 minutes. Requests receive the last successful document while a refresh runs. If a refresh fails and the cached document is at least an hour old, the enclave exits.

## Flamingo Tokens

The enclave validates request bounds, expiry, pipeline, match strictness and optional AAT against the loaded release and its own time, and rejects replays. Its interim adapter interprets `pipeline_id`, positions in `compare`, `pipeline_inputs` and LightGuard entry metadata to select the Engine operation and image roles; the Engine processes the image contents. A token signs the enclave's time, `R(SHA-256(data))` of each compared entry, the RP's `aud` and `nonce`, `compare_sources`, `engine_config_hash` over the loaded `release_hash`, pipeline and match strictness, and `billing_nullifier = 0`, since the enclave bills no RP yet. It carries no score. Binding the Credential image to a Credential is the job of the downstream proof (WIP-202). The request and token formats come from [`world-id-flamingo`](https://github.com/worldcoin/world-id-protocol/tree/main/crates/flamingo).

The enclave's time is the `timestamp` of its latest Nitro attestation, advanced on its monotonic clock (WIP-201 §4.4.2). It attests its channel key again with the loaded `release_hash` as `user_data` when the provisioner loads the release.

The enclave runs each (`aud`, `nonce`) once per boot. It keeps up to 262,144 of them in memory; once full, it refuses requests and reports not ready until it reboots with a new channel key.

The current engine still returns similarity scores, so the enclave's [interim adapter](../verifier/enclave/src/pipeline.rs) maps pipelines to engine operations and strictness levels to thresholds. Every compared pair must clear the level's threshold.

## Billing state

The enclave checks WIP-107 billing against state its host supplies (WIP-107 §4.8). The host runs [`flamingo-verifier-billing-follower`](../verifier/billing-follower), which follows the Billing Contract at the latest block and undoes reorganizations, and passes each of its updates to the enclave's `/v1/billing` route as the next update of a numbered stream, at most 8,192 ops per update. The enclave applies a repeated update once, so the host retries an update whose answer it lost. When the enclave refuses an update, e.g. after it restarted, the host follows the chain again from the Billing Contract's deployment and starts a new stream, which replaces the enclave's state; the enclave serves again once the stream has caught up. Restarts back off from 1 s to 5 min, so an enclave that keeps rejecting the state does not cause back-to-back backfills.

An enclave bills when `FLAMINGO_BILLING_MAX_REGISTRATIONS` is set in the EIF's environment, so the switch and the bound are part of the measurement; an image without it bills nothing. The host is trusted for the billing state, so the enclave does not check which chain or contract it comes from; the host's follower fails on a wrong chain or a missing contract. An enclave that bills reports not ready until it has a caught-up state, and after it rejects an update, until a new stream catches up. Ended periods are dropped before an update applies, and an update that would pass the registration bound is rejected. The enclave keeps each registration as a 64-bit SipHash-2-4 digest of the nullifier and RP, keyed at boot from the hardware-seeded RNG, in one set per billing period. That takes about 18 bytes, so 4,194,304 registrations take about 72 MiB, and a new stream briefly needs room for a second copy. Neither the key nor any digest leaves the enclave, so a collision cannot be searched for; a blind one has a chance of about `n / 2^64`. The host's follower keeps the full registrations and rejects a nullifier registered twice. The host follows up to `BILLING_MAX_REGISTRATIONS`, with the same default, and warns when the enclave's bound is smaller. A stopped follower ends the host process. While the host cannot read the chain, the enclave keeps serving the state it has, as WIP-107 §4.8 allows; alert on `flamingo.billing.pushed_block` trailing the chain. Updates without ops still go out every block, so the host notices a restarted enclave within a block.

## Repository layout

All crates share the root [Cargo workspace](../Cargo.toml) and lockfile.

| Runtime crate | Purpose |
| --- | --- |
| [`host`](../verifier/host) | HTTP API and vsock relay. |
| [`enclave`](../verifier/enclave) | Face comparison, key attestation, and match signing. |
| [`client`](../verifier/client) | Attestation verification and encrypted HTTP requests. |
| [`e2e`](../verifier/e2e) | Runs a match against a host and enclave. |

| Contract crate | Purpose |
| --- | --- |
| [`api-types`](../verifier/api-types) | HTTP responses, errors, and payload limits. |
| [`enclave-types`](../verifier/enclave-types) | Host/enclave vsock messages. |
| [`sealed-types`](../verifier/sealed-types) | Plaintext CBOR requests and results carried inside encryption. |

[tabernaculum](https://github.com/worldcoin/tabernaculum) receives the external biometric worker with size and digest integrity checks and launches it under Minijail with its reviewed seccomp policy. The [sandbox client](../verifier/sandbox-client) validates, encodes and checks the worker's `biometric-engines-protocol` messages. The enclave owns request validation, the interim strictness policy, replay rejection and signing. Worker access uses one mutex with a timeout.

Nix uses the root workspace and lockfile to build the enclave. Public binaries, Docker images and EIFs exclude the biometric engine and models; the worker is provisioned at runtime. Shared dependency changes can affect its PCR measurements. The separate [DeepIdentifier migration](https://github.com/worldcoin/di-migration-tee) lives in its own repository.
