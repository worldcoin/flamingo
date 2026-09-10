# Worker contract

DeepFace only. The public broker handles attestation, encryption, admission,
thresholds and signing. One authenticated biometric executable handles images in
Minijail; its models and configuration must be embedded. Other proof types and
LightGuard are not implemented. There is no production placeholder or fallback.

## Comparisons and lifecycle

The worker starts with no arguments, an empty environment, null stdio, and a
connected Unix stream on FD 3. Each message is a four-byte big-endian length
followed by CBOR. A request contains three encoded images; the response contains
two finite raw cosine scores in [-1, 1], or `AnalysisFailed`.

- One synchronous request at a time. No handshake, ready message, protocol version,
  request IDs, pipelining, retries or reconnect.
- The first request has 120 seconds for lazy initialization and inference; later
  requests have 10 seconds. Idle time consumes neither budget.
- Limits: 8 MiB per encoded image, 24 MiB + 1024 bytes per request body, 1024 bytes
  per reply. The actual worker must additionally bound decoded images and allocations.
- Local input rejection and `AnalysisFailed` preserve the session. Missing models,
  backend faults, malformed replies, invalid scores, EOF during a request and
  deadlines are terminal. Clean EOF between requests permits worker exit.
- Keys, embeddings, claims, thresholds and signing operations never cross FD 3.

The broker authenticates and forks the worker during single-threaded bootstrap,
before generating keys. It frees the parent's Minijail configuration after fork;
the exclusive worker owner can then move to a blocking comparison thread.

One match is admitted before decrypting its ciphertext. Concurrent matches receive
`NotReady` / HTTP 503 without a queue. The owned admission permit survives caller
cancellation until blocking work finishes. Panics terminate the broker even if the
caller disconnected. Unsupported LightGuard input returns a sealed rejection;
nonfinite thresholds or thresholds outside [0, 1] are malformed because signed
match claims encode only nonnegative coefficients. Broker input-derived outcomes
stay out of logs and host-exported metrics as well as the cleartext response.

Readiness checks idle worker exits without sending IPC or reaping. While a match is
in flight, its hard deadline supplies the failure bound. A fatal failure requests
SIGKILL and immediately exits the broker, even if killing fails. Normal Drop also
requests SIGKILL. No restart, reaping loop or background supervisor exists. Guest
teardown owns final cleanup. The [source associated with the pinned AWS init][init-lifecycle]
waits only for its direct broker child, then requests a reboot without waiting for
remaining workers. Actual guest termination remains a Nitro release-qualification
check. Recovery starts a fresh enclave with fresh keys.

[init-lifecycle]: https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/3f79674465f816eeffe4482e1240b792ff75d2d9/init/init.c#L437-L441

## Authenticated runtime provisioning

`/etc/flamingo/worker-bootstrap.json` is copied from
[`config/worker-bootstrap.json`](../config/worker-bootstrap.json) into the measured
public image. It contains P-384 SEC1 public keys encoded as hex, plus explicit
bundle-size, address-space, thread and bootstrap-deadline budgets. Host environment
variables cannot override it. Empty keys/null budgets allow a public development
build but prevent serving; release scripts reject unconfigured policy. No test key
is installed as production trust.

The parent host sends one bundle to vsock port 1001. Its wire format is:

```text
u32 BE manifest length | exact JSON manifest bytes
u32 BE signature length | P-384 ECDSA/SHA-384 signature in ASN.1 DER
artifact bytes in manifest order | sender write-half EOF
```

The signature covers the exact JSON bytes, not reserialized JSON. The manifest has
`manifest_version: 1`, a bounded diagnostic `release_id`, and `artifacts` entries
with `logical_path`, `role`, lowercase hex `sha384`, and exact nonzero `size`.
Roles are `worker`, `loader`, and `library`; the latter two contain the approved
runtime closure. The only worker path is `bin/verifier-worker`; other files must be
under `lib/`, `lib64/`, or `nix/store/`. Paths are restricted relative components;
symlinks, devices, duplicate paths, file/directory conflicts, and external model or
configuration roles are not accepted. Preserve required absolute library paths by
staging their exact relative equivalents; do not copy the host's entire library tree.

The receiver bounds metadata before allocation, verifies the signature before
extracting, enforces the configured aggregate budget, and streams each file into a
fresh private root under `/worker-runtime` while checking its SHA-384. This real,
root-owned image directory stays on the executable root filesystem: the pinned
init [mounts `/tmp` with `noexec`][init-tmp], which also blocks execution through an
open file descriptor. Bootstrap rejects non-executable staging mounts rather than
relaxing mount policy. Partial files, hash mismatches,
trailing bytes and unexpected ELF architecture fail the boot. No supplied code runs
before verification and confinement. All accept/read/write/acknowledgement I/O
shares one absolute startup deadline, including slow-drip and stalled peers.

[init-tmp]: https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/3f79674465f816eeffe4482e1240b792ff75d2d9/init/init.c#L121-L123

The broker sends one zero acknowledgement byte and closes the provisioning socket
after authenticated launch and boot-key attestation. This is **not** a model
readiness handshake or proof of successful inference. Normal service uses vsock
port 1000. No transfer retry or worker substitution happens after a failed attempt.

The public EIF/PCRs do not change when only the signed worker changes. Client trust
currently accepts any valid bundle signed by the measured publisher key set; it
does not pin a worker digest or enforce a monotonic release counter. Changing
publisher keys or resource policy requires a new image/PCR rollout.

### Package and send

Build the public tool with `cargo build --locked --bin worker-bundle` or
`nix build --no-update-lock-file .#worker-bundle`. Stage the real worker and approved
runtime files under `ARTIFACT_ROOT`, then:

```sh
target/debug/worker-bundle manifest RELEASE_ID ARTIFACT_ROOT > manifest.json
openssl dgst -sha384 -sign publisher.pem -out manifest.sig manifest.json
target/debug/worker-bundle pack manifest.json manifest.sig ARTIFACT_ROOT worker.bundle
# On the parent Linux host after starting the enclave; timeout must be 1..900 seconds:
target/debug/worker-bundle send ENCLAVE_CID worker.bundle TIMEOUT_SECONDS
```

Keep the publisher signing key offline/private and out of Git, images and the
provisioner. Signing belongs to the approved publisher; the tool never creates or
requests a signing key. Do not edit or reformat `manifest.json` after signing.
Packaging verifies hashes and refuses to overwrite an existing output; it does not
establish publisher trust. The enclave performs that signature verification.

## Production sandbox

The public launcher embeds `worker-process/worker.policy`. Minijail installs it
before executing the worker's ELF loader, not through `LD_PRELOAD`. The same filter
applies to every thread. Missing namespace or whole-process seccomp termination
support fails closed on x86_64 Linux.

- A nonrecursive, read-only `nosuid,nodev` bind of the verified runtime becomes the
  worker's root/cwd in a private mount namespace. Host submounts are excluded.
  There is no `/proc`, `/sys`, `/dev`, writable cache or access to broker secrets.
- UID/GID 65532 are reserved for this worker. Supplementary groups and capabilities
  are dropped, and `no_new_privs` prevents privilege gains. FD 3 is the only surviving
  non-stdio descriptor; the executable descriptor closes on exec.
- Only pthread-style creation is allowed; sockets/vsock, forks, new namespaces,
  ptrace, process-memory access, device ioctls and pathname exec are forbidden.
  A seccomp violation kills all worker threads. Writable/executable mappings and
  file writes are denied.
- Limits are explicit address space and threads, 64 FDs, and zero core-dump,
  file-write and locked-memory allowances. `RLIMIT_AS` is not aggregate guest RAM;
  reserve memory for the broker, loaded artifacts/page cache and kernel as well.

The chroot/FD/capability combination supports the pinned Nitro initramfs layout;
chroot alone is not the sandbox. See the [Chromium sandboxing guide](https://www.chromium.org/chromium-os/developer-library/guides/development/sandboxing/)
for the layered-isolation approach. Never enable permissive policy logging, core
dumps or production-biometric syscall traces to make qualification pass.

## Tests and repo-local prototype

Public tests require no models or private source. Run portable suites as documented
in the [README](../README.md). [Rust CI](../.github/workflows/rust-ci.yml) separately
builds the Linux process test executable and runs it as root under an outer deadline.
Each broker case has its own PID namespace and timeout. The harness checks pre-main
confinement, privilege/FD/resource boundaries, forbidden syscalls, idle exits and
fatal shutdown using a test-only executable. A signed-runtime case also packages,
authenticates and launches that same fixture through the production artifact API.
The test executable and its publisher key never ship in the public image.

`verifier/worker` is a separate local workspace retaining the current detection and
embedding prototype, not the full biometrics DeepFace pipeline. It embeds YAML but
still opens `/models/{rgbnet,face_embedding_generator}.onnx`, so its runtime root is
for prototype qualification only and is **not** the production provisioning bundle.

```sh
CARGO_TARGET_DIR=target cargo test --locked --manifest-path verifier/worker/Cargo.toml
# Private Git access is required for the prototype; models are not needed for unit tests.
nix build --no-update-lock-file .#privatePackages.x86_64-linux.verifier-worker

# Also requires model access; this output is never included in the public image.
bash scripts/fetch-face-models.sh
nix build --no-update-lock-file .#privatePackages.x86_64-linux.verifier-worker-runtime
```

The ignored real-model RPC test additionally needs `WORKER_MODEL_DIR` and an approved
`WORKER_FACE_FIXTURE`:

```sh
CARGO_TARGET_DIR=target cargo test --locked --manifest-path verifier/worker/Cargo.toml --test model -- --ignored
```

For a real-runtime sandbox smoke test, build the `worker-process` `qualify-worker`
example and run it as root under
`timeout --kill-after=5s 150s unshare --fork --pid --mount-proc --kill-child --`, passing
`RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS FACE_FIXTURE`. It checks cold/warm
same-image scores and recoverable image rejection under the production policy.

Real model correctness, approved publisher trust, measured budgets and execution on
the pinned Linux/Nitro image remain release gates. Fixture success is not model
qualification. [Operations](worker-operations.md) covers deadlines, health semantics,
Datadog, canary rollout, rollback and the remaining kernel-diagnostics blind spot.
