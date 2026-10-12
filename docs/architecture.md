# Architecture

The client encrypts images for an attested enclave. The HTTP host forwards the ciphertext over vsock. The enclave compares the faces and returns an encrypted result. Successful matches include a signed [WIP-201](https://github.com/worldcoin/world-id-protocol/pull/979) Flamingo Token and an attestation of the signing key.

## Trust and attestation

The client verifies the Nitro attestation against the AWS root certificate, the configured PCR measurements, and an age limit. It checks that the encryption key matches the commitment in the attestation before using that key. The host neither decrypts images nor pins enclave measurements.

The enclave generates encryption and signing keys at boot. Keys stay in memory and change on restart. Both attestations must succeed before the enclave starts serving requests.

The enclave caches attestations and refreshes them every 10 minutes. Requests receive the last successful document while a refresh runs. If a refresh fails and the cached document is at least an hour old, the enclave exits.

## Flamingo Tokens

The enclave interprets none of the request: the `pipeline` fixes each compared entry's role by its position in `compare`. A token signs `R(SHA-256(data))` of each compared entry, the RP's `aud` and `nonce`, and `engine_config_hash` over the Engine bundle hash, pipeline and match strictness. It carries no score. Binding the Credential image to a Credential is the job of the downstream proof (WIP-202). See the [token format](../verifier/protocol/src/flamingo_token.rs).

The current engine still returns similarity scores, so the enclave's [interim adapter](../verifier/enclave/src/pipeline.rs) maps pipelines to engine operations and strictness levels to thresholds. Every compared pair must clear the level's threshold.

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
| [`protocol`](../verifier/protocol) | Flamingo Token claims, digest and encoding. |

The [sandbox client](../verifier/sandbox-client) launches the external biometric worker under Minijail and exchanges messages using `biometric-engines-protocol`. The [sandbox bundle](../verifier/sandbox-bundle) provisions the executable with size and digest integrity checks. The enclave owns request validation, the interim strictness policy and signing. Worker access uses one mutex with a timeout.

Nix uses the root workspace and lockfile to build the enclave. Public binaries, Docker images and EIFs exclude the biometric engine and models; the worker is provisioned at runtime. Shared dependency changes can affect its PCR measurements. The separate [DeepIdentifier migration](https://github.com/worldcoin/di-migration-tee) lives in its own repository.
