# Worker comparisons

Blocking RPC over inherited Unix socket FD 3: four-byte big-endian length, then
CBOR. One request (three encoded images) produces two scores or `AnalysisFailed`.
No handshake, ready message, version, pipelining, retries or reconnect.

- `compare(&mut self, ...)` completes before another request starts.
- The first request's deadline includes lazy initialization; idle time consumes nothing.
- Encoded images, CBOR and replies are bounded; the adapter must bound decoded pixels.
- Local input errors and `AnalysisFailed` preserve the connection. Transport errors,
  timeouts, malformed replies and invalid scores permanently close it.

## Process ownership

Linux-only `Worker::spawn(&File, SandboxConfig, WorkerClientConfig, on_fatal)` uses Minijail.
Launch from a single-threaded bootstrap before creating broker keys.
The worker gets null stdio, empty environment and FD 3 inside a new PID namespace.
Minijail remaps/closes descriptors. A short `execveat` path applies seccomp before
the executable's loader; upstream `run_fd_remap` instead uses `LD_PRELOAD`.

One worker lives for the broker's lifetime. A fatal comparison records the original
RPC failure, requests SIGKILL, then invokes the broker-supplied
`fn(WorkerClientError) -> !` handler. That handler must immediately exit the process
(for example, `std::process::exit(1)`), not panic, stop only a task, or wait for
runtime shutdown. Kill failures are reported but cannot prevent the fatal handler.
The enclave init must terminate the guest when the broker exits; recovery provisions
a fresh enclave and fresh keys. Verify this behavior on the pinned Nitro image.

Drop also requests SIGKILL for normal broker shutdown or unwinding. There is no
worker restart, wait/reap loop, cleanup deadline, or background supervisor. The
broker must not reap the worker elsewhere or keep running after dropping it.
Spawn success is not readiness; idle exits are detected on the next comparison.

The match handler now admits one request before opening its ciphertext, rejecting
concurrent requests with `NotReady` (host HTTP 503), without a queue. Decryption,
comparison and signing run in `spawn_blocking`; its owned permit survives caller
cancellation until all work finishes. A panic exits the broker even if the caller
has disconnected. Unsupported LightGuard input is a sealed `ImageAnalysisFailed`,
never a panic or fallback; thresholds outside [-1, 1], including NaN, are malformed.
Health remains responsive while busy; it is not an idle-capacity probe.

The in-process comparator is still the boot default. Wiring the sandboxed owner
requires respecting Minijail's non-Send ownership and launching before threads/keys.
Metrics `enclave_match.rejections{class=busy}` and `enclave_match.failures` distinguish
admission from task failures. Datadog export, worker readiness and public-image
reproducibility remain separate work; these counters currently have no exporter.
The legacy in-process comparator still has no hard deadline: a hung call holds the
slot indefinitely while health answers. Do not deploy this intermediate state as
worker readiness or sandboxed inference; complete the RPC deadline/fatal-exit wiring
first. Canary the final switch while watching admission rejections and HTTP 503s.

## Worker artifact and startup

`verifier/worker` owns the Face Engine implementation, embedded graph configs and
`verifier-worker` executable. It stays in this repo for now. The protocol/RPC/launcher
crates do not depend on it. The enclave temporarily uses a thin in-process adapter
to the same implementation; switching live broker requests to RPC is separate work.

- Entry point: no arguments, empty environment, connected Unix stream on FD 3.
  Invalid startup exits nonzero. EOF between frames exits successfully; a partial
  frame, timeout, backend error or panic exits nonzero. No handshake or restart.
- Models load once, after the first structurally valid request, even if its image
  bytes are undecodable. Missing/corrupt models are terminal, not `AnalysisFailed`.
  Both loading and first inference consume the first request's budget.
- Initial profile: 120 seconds for the first request, 10 seconds thereafter;
  8 MiB per encoded image, 24 MiB + 1024 bytes per CBOR body, 1024 bytes per reply.
  These are ceilings to qualify on Nitro, not measured latency guarantees.
- JPEG/PNG/WebP only; at most 4096 pixels per axis and 8,388,608 pixels total.
  Decode one image at a time. The decoder's 128 MiB allocation budget is best-effort;
  the explicit sandbox address-space limit remains the hard process bound.
- Malformed images and model-reported validation failures return `AnalysisFailed`.
  Unexpected graph/backend failures, missing outputs and invalid scores are terminal.
  Compute each embedding once and return two finite raw cosine scores in [-1, 1],
  clamping only endpoint floating-point roundoff within 1e-6.
  No embeddings, keys, PCP data, thresholds or signing operations cross this boundary.
- Configs still implement the prototype's largest-face detection and GhostFaceNet
  embeddings, **not** production quality/liveness/LightGuard checks.

The current artifact is a **runtime directory**, not a self-contained ELF:
`bin/verifier-worker`, `/models/{rgbnet,face_embedding_generator}.onnx`, and only the
executable's Nix runtime closure at its original `/nix/store` paths. The executable
opens models at fixed `/models` paths; no downloads, environment overrides or writable
cache are used. Model revisions/hashes remain pinned in `nix/face-models.nix`.
Treat the executable, configs, models and libraries as one immutable release unit.
Future signed provisioning must authenticate the whole bundle, not just the ELF.

Build on x86_64 Linux with Nix and private dependency access:

```sh
bash scripts/fetch-face-models.sh  # HUGGING_FACE_TOKEN needed only for uncached models
nix build --no-update-lock-file .#verifier-worker-runtime
```

Use the result's canonical directory as `SandboxConfig.root` and open its
`bin/verifier-worker` for `Worker::spawn`. Preserve root ownership, permissions and
absolute library paths when copying it. Never add the host store, devices or secrets.

Portable tests require no models. For an opt-in real-model RPC test, set
`WORKER_MODEL_DIR` and `WORKER_FACE_FIXTURE` to local model and approved test-face paths:

```sh
cargo test --locked -p flamingo-verifier-worker --test model -- --ignored
```

For the actual runtime/policy smoke test, build
`cargo build --locked -p flamingo-verifier-worker-process --example qualify-worker`.
Run the example as root in an isolated Linux test environment, under
`timeout --kill-after=5s 150s unshare --fork --pid --mount-proc --kill-child`, passing
`RUNTIME_ROOT ADDRESS_SPACE_BYTES MAX_THREADS FACE_FIXTURE`. Budgets are deliberately
explicit. It checks cold/warm same-image scores and recoverable rejection under the
production policy. Use only synthetic/approved fixtures, never production biometrics.
Passing this smoke test does not replace resource, syscall and pinned-Nitro qualification.

## Production sandbox

`worker-process/worker.policy` is embedded in the public launcher, not supplied by
the worker. The same policy applies to the loader and every inference thread.
The launcher requires x86_64 Linux with PID/mount/network/IPC/cgroup namespaces and seccomp
`KILL_PROCESS` support (Linux 4.14+); missing features fail closed, without fallback.

- A non-recursive, read-only `nosuid,nodev` bind of `SandboxConfig.root` becomes the
  worker's root/cwd via `chroot`, inside a private-propagation mount namespace.
  Host submounts are excluded, and no directory FDs survive to reach the old root.
  No `/proc`, `/sys`, `/dev`, writable scratch space or broker secrets are provided.
- UID/GID 65532 are reserved exclusively for this worker. Supplementary groups and
  all capabilities are dropped; `no_new_privs` prevents privilege gains at exec.
- Only pthread-style `clone` is allowed. `clone3` returns ENOSYS for libc fallback;
  forks, new namespaces, sockets (including vsock), ptrace, process-memory syscalls,
  device ioctls and pathname exec are forbidden. A violation kills **all** threads.
- Memory mappings cannot be simultaneously writable/executable. Files open read-only.
  Limits cannot be raised: explicit address-space and thread budgets, 64 FDs, and
  zero core-dump, file-write and locked-memory allowances. RPC deadlines bound stuck
  requests; there is no cumulative CPU-time limit that would kill a healthy old worker.

The boot configuration must supply an authenticated, immutable executable and a
dedicated root-owned runtime tree containing only its approved loader, shared-library
closure, config and models. Keep the entire tree and its ancestors trusted/immutable
through launch; never point it at the broker root, host `/lib`, or all of `/nix/store`.
The launcher rejects `/`, non-directories and group/world-writable or non-root-owned
roots; this is not an untrusted archive extractor or manifest verifier.

There are intentionally no default memory/thread budgets: measure the packaged model
and reserve enclave RAM for the broker, page cache and kernel. `RLIMIT_AS` bounds
virtual mappings, not aggregate guest memory; `RLIMIT_NPROC` counts the reserved UID's
threads. Trace cold loading and warm inference under this policy on the pinned Nitro
image before rollout, including malformed images, exhaustion and forbidden syscalls.
The worker now has a local runtime bundle, but broker RPC integration and model/Nitro
qualification remain outstanding. Do not treat fixture success as qualification.
Policy/resource deaths currently surface as fatal RPC transport/timeout metrics;
kernel audit diagnostics are still needed to distinguish the underlying cause.
Roll out the public image, runtime closure and budgets together; rollback requires
a fresh enclave, never disabling the sandbox or restarting its worker in place.

### Chromium guide cross-check

The [Chromium sandboxing guide](https://www.chromium.org/chromium-os/developer-library/guides/development/sandboxing/)
informs the UID/capability drop, namespaces, private mounts, argument-filtered seccomp
and error-path testing. Deliberate platform differences:

- Apply seccomp **before** exec, including loader syscalls. The guide's preload
  shortcut would execute the supplied loader before installing its filter.
- The pinned Nitro CLI v1.2.3 init predates AWS's [root-switch fix](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/commit/203242d54e4f).
  Its chrooted initramfs layout cannot support our previous `pivot_root` setup.
  Use chroot plus FD/capability/syscall restrictions, not chroot alone; the Linux
  harness also exercises a broker launched from this legacy root layout.
- Landlock requires [Linux 5.13+](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#kernel-support),
  so the pinned 4.14 kernel uses the minimal filesystem view instead. The Rust
  Minijail binding lacks a UTS namespace setter; hostname reads/changes are denied
  by seccomp. Add UTS isolation before granting any such syscalls.
- Any audit/strace policy discovery must use synthetic data in an isolated debug
  environment. Never enable Minijail's permissive `-L` mode or core dumps on a
  production biometric worker. C/C++ CFI and target-userland syscall coverage must
  be checked when packaging the real worker, not inferred from the public fixture.

Tests: portable RPC tests run with Cargo. Build the Linux process integration
executable with `cargo test -p flamingo-verifier-worker-process --all-features --no-run`,
then run it as root under `timeout --kill-after=5s 60s` (as in Rust CI).
It uses no libtest threads. Each broker test runs under `unshare` (util-linux) in
its own PID namespace with a ten-second timeout; broker exit removes descendants.
Only the normal-drop test waits for the child, to verify that SIGKILL was issued.
The root harness uses `ldd` only on its own trusted test executable to stage a minimal
runtime. It checks pre-main confinement, library/data reads, privileges, forbidden
syscalls (including from a secondary thread), memory/FD/thread exhaustion and fatal
broker shutdown. No permissive test-policy override exists.
