# Flamingo

A DeepFace-only verifier with an untrusted HTTP host, a public Nitro enclave broker,
and one separately sandboxed biometric worker. The broker decrypts requests and
signs results; the worker receives only three images and returns two comparison
scores. Broker keys, claims and thresholds never enter the worker.

The biometrics-owned executable must embed its models and configuration. It is
authenticated and sandboxed before broker keys or serving threads exist. There is
no placeholder, in-process fallback, worker restart or support for other proof types.

## Layout

| Path | Responsibility |
| --- | --- |
| `verifier/host` | HTTP relay, dependency deadlines, readiness and telemetry |
| `verifier/enclave` | Public broker: attestation, decryption, admission and signing |
| `verifier/worker-artifact` | Signed runtime verification and `worker-bundle` provisioner |
| `verifier/worker-process` | Production Minijail policy and worker lifecycle |
| `verifier/worker-{protocol,rpc}` | Bounded synchronous comparisons over inherited FD 3 |
| `verifier/{api-types,enclave-types,sealed-types,protocol,client,e2e}` | Wire contracts, client verification and integration harness |
| `verifier/worker` | Separate, repo-local inference prototype workspace; private dependencies |
| `di/{host,enclave}` | Unimplemented migration skeletons; exit nonzero |

The root Cargo workspace and lockfile contain only public dependencies. The local
worker prototype has its own lockfile; it is not part of public CI or image builds.

## Development

No model files or private-repository credentials are required for public checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features --
cargo test --locked --workspace --all-features --exclude flamingo-verifier-worker-process
```

Minijail tests require root on x86_64 Linux; [Rust CI](.github/workflows/rust-ci.yml)
builds and runs their isolated, deadline-bounded harness. Portable tests use explicit
test fixtures, never a deployable replacement for the biometric worker.

## Building and provisioning

Public Nix outputs require x86_64 Linux, but neither private code nor model access:

```sh
nix build --no-update-lock-file .#verifier-oci .#verifier-eif .#worker-bundle
```

The checked-in [bootstrap configuration](config/worker-bootstrap.json) intentionally
has no trusted publisher keys or selected resource budgets. An image can build in
this state, but cannot boot a serving verifier. Production release builds require
reviewed keys and qualified budgets committed in that measured configuration:

```sh
scripts/build-enclaves.sh --workload verifier target/eif
# target/eif/verifier-enclave.eif and target/eif/verifier-pcr.json
```

At boot, the parent host supplies a publisher-signed runtime bundle on vsock port
1001. The broker authenticates every file, launches the worker under Minijail, then
attests its boot keys and serves on port 1000. See [worker protocol and provisioning](docs/worker-protocol.md)
for the artifact format, signing commands and private prototype builds.

Replacing an accepted signed worker does not change the public EIF's PCRs. Clients
currently trust the publisher key set measured into the broker image, not an
individual worker digest. Key or budget changes do change the image measurement.

## HTTP contract

`POST /v1/enclave-assignment` returns the encryption-key attestation. The client
verifies AWS attestation, freshness and its configured PCR allow-list before sealing
inputs. Empty PCR policies and debug measurements are rejected by default.

`POST /v1/matches` accepts `{"ciphertext":"<base64>"}` and returns
`{"response_ciphertext":"<base64>"}`. The sealed response contains either a signed
match statement with its signing-key attestation or a rejection reason. HTTP 200
does not reveal whether a match succeeded. The RP must compare the statement's
`challenger_image_hash` with its issued challenge.

One match is admitted at a time; cancellation holds the slot until work ends.
Concurrent matches return 503. A request that cannot be opened returns 409, allowing
the client to reassign and reseal once; transport failures and overload are not
automatically retried. Unsupported LightGuard input is a sealed rejection, not a
panic. Fatal worker failures or deadlines terminate the enclave.

`/health` means the host process is alive; `/ready` checks broker availability and
observed worker liveness. Neither proves lazy model initialization or inference
correctness. [Operations](docs/worker-operations.md) documents nested deadlines,
production telemetry, proxy/probe configuration, rollout and rollback.

Actual worker correctness, resource sizing and Linux/Nitro qualification remain
release gates requiring the real executable and approved biometric fixtures.
See [release instructions](docs/release.md).
