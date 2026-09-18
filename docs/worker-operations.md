# External worker deployment

Build the bundled static worker in biometric-engines, including its approved models.
Flamingo no longer builds or downloads models. The protocol crate is temporarily a
pinned Git dependency in the private repository; private Git credentials remain
necessary until that crate is published. This is the only biometric-engines package
allowed in Flamingo's dependency graph.

## Package and build

```sh
sandbox-bundle manifest RELEASE_ID /path/to/biometric-engines-worker > worker-manifest.json
sandbox-bundle pack worker-manifest.json /path/to/biometric-engines-worker worker.bundle
scripts/build-enclaves.sh --workload verifier target/eif
```

The build output includes the EIF/PCRs and uploader runtime closure. Add `worker.bundle`
and `worker-release.json` to this carrier context, then build with
`scripts/Dockerfile.worker-carrier`. The executable and uploader stay outside the EIF.
The release record should include source commits, wire version, executable SHA-384,
bundle digest, paired host/carrier image digests and EIF/PCRs. Publish immutable images
and retain the previous release record for rollback. Artifact signing is not required.

## Runtime

The carrier's `run-worker-enclave.sh` launches one uniquely named enclave, retaining
the returned ID/CID. Its overall watchdog covers launch, connection, transfer and
initialization. It awaits both provisioning ACK and a Pontifex health response before
creating `/run/flamingo/ready`. Mount that directory into the host and set
`WORKER_READY_FILE` to the same path. On failure it stops the uploader, terminates
only its owned enclave and retries with backoff. The watchdog also cleans up an
enclave whose launch timed out before its JSON result was delivered.

On SIGTERM the carrier removes readiness, allows 35s for active requests, then cleans
up its enclave. Give the pod at least 60s termination grace. Host liveness stays local;
readiness checks the marker and enclave. Carrier startup/readiness probes check the
marker; its process supervises enclave failures without treating busy inference as dead.

The initial qualification configuration is two enclave CPUs and 4 GiB memory, with
4 GiB hugepages and matching node Nitro allocator reservations. The worker address-space
limit and executable budget are measured in `config/worker-bootstrap.json`; qualify
representative memory use rather than treating these defaults as proven minima.
Fixed CIDs require one replica per node. Use hostname anti-affinity and either spare
Nitro capacity for surge or controlled replacement (`maxSurge: 0`, `maxUnavailable: 1`).
PCR changes require clients to use the matching release record and reacquire assignment.

## Verification

```sh
cargo test -p flamingo-verifier-sandbox-bundle
cargo test -p flamingo-verifier-sandbox-client --test client
# Linux, root, using the static test binaries (see Rust CI):
sudo timeout --kill-after=5s 60s /path/to/process-test-binary
# Approved synthetic fixture, root-owned staged executable:
sudo /path/to/qualify-worker RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS FACE_FIXTURE
```

The fake worker exercises confinement, startup, crashes and cleanup using the real
upstream protocol. Client tests exercise frame bounds, incompatible readiness, response
correlation, scores, deadlines and biological failures. These establish lifecycle and
transport behavior, not biometric quality. Real qualification must run vanilla
DeepFace then GrayBadge, measure timing/memory and queued traffic, and exercise pod
restart, rollout and rollback. A public encrypted GrayBadge test depends on the API
migration; direct worker success alone does not establish that public integration.
