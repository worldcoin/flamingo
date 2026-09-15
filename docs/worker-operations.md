# Worker operations

## Build and provision

Public builds require x86_64 Linux and Nix, without private Git/model credentials:

```sh
nix build --no-update-lock-file .#verifier-oci .#verifier-eif .#worker-bundle
```

The private adapter remains a separate workspace until its repository migration:

```sh
bash scripts/fetch-face-models.sh
nix build --no-update-lock-file .#privatePackages.x86_64-linux.verifier-worker-runtime
```

The private Nix build embeds both ONNX models and the YAML graphs in the worker.
Its runtime output contains five regular files: the worker, the ELF loader, and
three shared libraries. No model or configuration files are needed at runtime.
Only ELF runtime dependencies are packaged, rather than entire Nix packages.

Embedding currently uses `nix/worker-embedded-models.patch` against the pinned
private Face Engine dependency. Plain Cargo builds do not apply that patch and
are not equivalent to the embedded-model Nix build. Move this support upstream
before relying on plain Cargo for real-model tests.

Use the runtime output as `ARTIFACT_ROOT`. Then:

```sh
worker-bundle manifest RELEASE_ID ARTIFACT_ROOT > manifest.json
openssl dgst -sha384 -sign publisher.pem -out manifest.sig manifest.json
worker-bundle pack manifest.json manifest.sig ARTIFACT_ROOT worker.bundle
worker-bundle send ENCLAVE_CID worker.bundle IO_TIMEOUT_SECONDS
```

Use an approved publisher key, kept outside Git/images/the provisioner. Do not edit
the manifest after signing. Commit qualified budgets and public keys to the measured
bootstrap configuration before using `scripts/build-enclaves.sh`.

`IO_TIMEOUT_SECONDS` bounds each blocking read/write by the sender. The enclave
uses `provisioning_io_timeout_seconds` from its measured configuration for its
accepted socket. These are not whole-startup deadlines: a progressing transfer
can take longer, and connect/accept are outside the socket I/O timeouts.

Before deployment, configure a supervisor to bound the full bootstrap attempt,
terminate both the provisioner and enclave on timeout/failure, and retry only with
a fresh enclave. A timeout around the uploader alone is insufficient. The existing
carrier script only monitors whether the enclave is running; it does not yet
implement this startup watchdog or provisioning orchestration.

## Serving

`/health` checks host liveness; `/ready` checks enclave availability and observed
worker liveness. Neither proves model readiness. Concurrent matches return 503;
the enclave holds admission through blocking work even if the caller disconnects.
The host accepts up to 12 MiB per JSON match body. It buffers concurrent uploads
before enclave admission and does not impose an upload deadline.

The broker's cold/warm comparison budgets are 120s/10s, the host match deadline is
135s, and the client defaults to 150s. Control requests have a 2s host deadline.
Configure proxy upload timeouts and shutdown grace to accommodate the cold path
before rollout. Match failures are not automatically retried.

Configure host telemetry through telemetry-batteries. The default Axum layer
records HTTP routes, response statuses and request spans. Monitor `/ready`
failures, HTTP 5xx, latency and overload against the availability budget.
Worker and enclave failures use logs; host HTTP metrics provide the exported signal.
Transport errors alone cannot distinguish a worker crash, OOM or seccomp death; correlate with guest/kernel
diagnostics. Default spans include request paths, queries and user-agent values.
Pontifex DEBUG events contain wire payloads; Datadog's log-level filter does not
filter span events. Production telemetry must exclude those payload events.

## Qualification and rollout

Public CI runs portable checks, one root Linux sandbox harness and Nix evaluation;
it does not build or qualify the private model runtime. Before release:

- Build the public OCI/EIF and signed runtime; check reproducible measurements.
- Run the Linux signed-runtime sandbox test and the real adapter under the same policy.
- Measure cold/warm inference, memory and threads using approved fixtures.
- Verify Nitro provisioning, failed-launch handling, readiness and fatal guest teardown.
- Stall provisioning and verify that the supervisor times out, removes the old
  enclave and provisioner, and can start a fresh attempt.

The ignored `verifier/worker/tests/model.rs` test needs the patched embedded-model
dependency and `WORKER_FACE_FIXTURE`. The `worker-process` example `qualify-worker` takes
`RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS FACE_FIXTURE`; run it as root under
`timeout --kill-after=5s 150s unshare --fork --pid --mount-proc --kill-child --`.

Canary new images, bundles and resource limits. Keep the previous signed bundle
and image for rollback, with overlapping client PCR trust when measurements change.
Stop promotion on policy deaths, timeouts or unexpected 5xx. No permissive sandbox
or unsigned-worker fallback is supported.
