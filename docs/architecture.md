# Architecture

The client encrypts images for an attested enclave. The HTTP host forwards the ciphertext over vsock. The enclave compares the faces and returns an encrypted result. Successful matches include a signed statement and an attestation of the signing key.

## Trust and attestation

The client verifies the Nitro attestation against the AWS root certificate, the configured PCR measurements, and an age limit. It checks that the encryption key matches the commitment in the attestation before using that key. The host neither decrypts images nor pins enclave measurements.

The enclave generates encryption and signing keys at boot. Keys stay in memory and change on restart. Both attestations must succeed before the enclave starts serving requests.

The enclave caches attestations and refreshes them every 10 minutes. Requests receive the last successful document while a refresh runs. If a refresh fails and the cached document is at least an hour old, the enclave exits.

## Match statements

DeepFace compares each pair of images: Orb photo and selfie, Orb photo and challenge, and selfie and challenge. Every score must meet the caller's threshold, a number from 0 to 1.

The enclave checks that the Orb photo matches the `thumbnail.png` hash in the supplied `hashes.json`. It does not verify the Orb's signature or prove that the credential came from an Orb. The downstream proof must bind this commitment to an issuer-signed credential.

Version-2 BabyJubJub EdDSA statements bind the operation, live capture and challenge image. DeepFace additionally commits to raw `hashes.json` and reports the Orb/live score; GrayBadge has no credential commitment and reports the live/challenge score. Both operations accept vanilla or LightGuard captures. LightGuard commitments cover both frames and the matching-frame selection. The threshold and DeepFace’s other two scores remain enclave policy checks. See the [token format](../verifier/protocol/src/match_token.rs).

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
| [`protocol`](../verifier/protocol) | Signed match claims and token encoding. |

The [sandbox client](../verifier/sandbox-client) launches the external biometric worker under Minijail and exchanges messages using `biometric-engines-protocol`. The [sandbox bundle](../verifier/sandbox-bundle) provisions the executable with size and digest integrity checks. The enclave owns PCP verification, threshold policy and signing. Worker access uses one mutex with a timeout.

Nix uses the root workspace and lockfile to build the enclave. Public binaries, Docker images and EIFs exclude the biometric engine and models; the worker is provisioned at runtime. Shared dependency changes can affect its PCR measurements. The separate [DeepIdentifier migration](https://github.com/worldcoin/di-migration-tee) lives in its own repository.
