# Architecture

The client encrypts images for an attested enclave. The HTTP host forwards the ciphertext over vsock. The enclave compares the faces and returns an encrypted result. Successful matches include a signed [WIP-201](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-201.md) Flamingo Token and an attestation of the signing key.

## Trust and attestation

The client verifies the Nitro attestation against the AWS root certificate, the configured PCR measurements, and an age limit. It checks that the encryption key matches the commitment in the attestation before using that key. The host neither decrypts images nor pins enclave measurements.

The enclave generates encryption and signing keys at boot. Keys stay in memory and change on restart. Both attestations must succeed before the enclave starts serving requests.

The enclave caches attestations and refreshes them every 10 minutes. Requests receive the last successful document while a refresh runs. If a refresh fails and the cached document is at least an hour old, the enclave exits.

## Flamingo Tokens

The enclave validates request bounds, the release, pipeline, match strictness and optional AAT, and rejects replays. Its interim adapter interprets `pipeline`, positions in `compare` and LightGuard entry metadata to select the Engine operation and image roles; the Engine processes the image contents. A token signs `R(SHA-256(data))` of each compared entry, the RP's `aud` and `nonce`, and `engine_config_hash` over the `release_hash`, pipeline and match strictness. It carries no score. Binding the Credential image to a Credential is the job of the downstream proof (WIP-202). The request and token formats come from [`world-id-flamingo`](https://github.com/worldcoin/world-id-protocol/tree/main/crates/flamingo).

The enclave runs each (`aud`, `nonce`) once per boot. It keeps up to 262,144 of them in memory; once full, it refuses requests and reports not ready until it reboots with a new channel key.

The current engine still returns similarity scores, so the enclave's [interim adapter](../verifier/enclave/src/pipeline.rs) maps pipelines to engine operations and strictness levels to thresholds. Every compared pair must clear the level's threshold.

## Billing

For [WIP-107](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-107.md) billing, the enclave checks a request's billing nullifier against the Billing Contract before the Engine runs, and signs the checked nullifier into the token's `billing_nullifier` claim. The check shows that the RP paid for that nullifier in an active period. It cannot show that the nullifier is the requester's: that is the Proof of Embedding Similarity's job (WIP-202), which binds the signed nullifier to the World ID it proves for.

An enclave configured for billing bills every RP, since the Billing Contract has no `isBilledRp` yet:

1. `billing_nullifier` must be nonzero.
2. At the block `REGISTRATION_CONFIRMATIONS` (12) below the provider's latest, `registrationOf(billing_nullifier)` must return the request's `aud` and a `periodStart` that `getActivePeriods(block.timestamp)` reports as active. Both calls are pinned to that block's hash and require it to be canonical.
3. All reads of one request share a two-second budget, and at most 32 requests read at once. A provider that cannot be read in time rejects the request (`billing_unavailable`) and releases its nonce for a retry. Every other billing rejection consumes the nonce.

Billed pipelines' last response slot must leave the Engine its runtime plus that budget. An enclave without billing configuration signs `billing_nullifier = 0`, whatever the request carries. The Verifier does not verify the RP's signature: only `register` consumes capacity, and the RP checks its own `nonce`.

The enclave reads the Billing Contract through an approved JSON-RPC provider. Its HTTPS client dials the host on vsock, and the host's Pontifex proxy (`RPC_PROXY_PORT`, `RPC_UPSTREAM_HOST`) forwards the bytes to the provider and admits only the enclave's CID. TLS terminates in the enclave against the webpki roots, so the host relays only ciphertext. The provider is trusted for state and the block's time.

The image enables billing reads when its environment sets all of `BILLING_RPC_URL` (HTTPS, HTTP/2), `BILLING_RPC_PROXY_PORT`, `BILLING_CHAIN_ID` and `BILLING_CONTRACT`. The environment is part of the EIF and its PCRs, so the host cannot choose the chain, contract or provider. Don't put a secret API key in the URL, because the EIF is public. At boot, the enclave checks that the provider reports `BILLING_CHAIN_ID`: a different chain stops the boot, and an unreachable provider only logs a warning. Each read has a two-second timeout and no retries.

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
