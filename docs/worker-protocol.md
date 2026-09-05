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

Async integration must retain ownership and single-request admission through the
blocking operation, even if its caller cancels. Minijail's Rust owner is not Send.
Datadog export, readiness wiring and public-image reproducibility remain separate work.

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
The real private worker is not yet packaged/integrated; production Face Engine and
Pontifex are unchanged. Do not treat fixture success as model/Nitro qualification.
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
