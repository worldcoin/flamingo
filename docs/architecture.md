# Architecture

The client encrypts images for an attested enclave. The HTTP host forwards the ciphertext over vsock. The enclave compares the faces and returns an encrypted result. Successful matches include a signed [WIP-201](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-201.md) Flamingo Token and an attestation of the signing key.

## Trust and attestation

The client verifies the Nitro attestation against the AWS root certificate, the configured PCR measurements, and an age limit. It checks that the encryption key matches the commitment in the attestation before using that key. The host neither decrypts images nor pins enclave measurements.

The enclave generates encryption and signing keys at boot. Keys stay in memory and change on restart. Both attestations must succeed before the enclave starts serving requests.

The enclave caches attestations and refreshes them every 10 minutes. Requests receive the last successful document while a refresh runs. If a refresh fails and the cached document is at least an hour old, the enclave exits.

## Flamingo Tokens

The enclave validates request bounds, the release, pipeline, match strictness and optional AAT, and rejects replays. Its interim adapter interprets `pipeline`, positions in `compare` and LightGuard entry metadata to select the Engine operation and image roles; the Engine processes the image contents. A token signs `R(SHA-256(data))` of each compared entry, the RP's `aud` and `nonce`, and `engine_config_hash` over the `release_hash`, pipeline and match strictness. It carries no score. Binding the Credential image to a Credential is the job of the downstream proof (WIP-202). The request and token formats come from [`world-id-flamingo`](https://github.com/worldcoin/world-id-protocol/tree/main/crates/flamingo).

The enclave runs each (`aud`, `nonce`) once per boot. It keeps up to 262,144 of them in memory; once full, it refuses requests and reports not ready until it reboots with a new channel key.

The sandboxed Engine interprets pipelines and match strictness and returns Pass or a bounded error code. The verifier forwards the original canonical Payload bytes and signs only Pass; scores and embeddings never cross this boundary. The prototype Engine defines `deepface_vanilla` (1), `graybadge_vanilla` (2), `deepface_lightguard` (3), and `graybadge_lightguard` (4), all with strictness ID `2`. Callers choose a pipeline explicitly; the Engine checks that its capture shape and frame metadata match that policy.

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
| [`engine-interface`](../verifier/engine-interface) | Versioned, bounded worker IPC around unchanged canonical Payload bytes. |

[tabernaculum](https://github.com/worldcoin/tabernaculum) receives the external biometric worker with size and digest integrity checks and launches it under Minijail with its reviewed seccomp policy. The [sandbox client](../verifier/sandbox-client) checks protocol readiness, frame bounds, response IDs and verdicts. The enclave owns release selection checks, AAT verification, replay rejection and signing. Worker access uses one cancellation-safe mutex with a timeout. The persistent worker lifecycle is unchanged; per-request reset remains an outstanding WIP-201 conformance requirement.

Nix uses the root workspace and lockfile to build the enclave. Public binaries, Docker images and EIFs exclude the biometric engine and models; the worker is provisioned at runtime. Shared dependency changes can affect its PCR measurements. The separate [DeepIdentifier migration](https://github.com/worldcoin/di-migration-tee) lives in its own repository.
