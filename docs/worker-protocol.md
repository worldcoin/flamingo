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

Linux-only `Worker::spawn(&File, &Path, WorkerClientConfig, on_fatal)` uses Minijail.
Launch from a single-threaded bootstrap before creating broker keys.
The worker gets null stdio, empty environment and FD 3 inside a new PID namespace.
Minijail remaps/closes descriptors. A short `fexecve` path applies seccomp before
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

The policy is trusted build input. The test policy is deliberately permissive:
filesystem isolation, privilege/resource limits, private packaging and provisioning
remain subsequent work. Production Face Engine and Pontifex are unchanged.

Async integration must retain ownership and single-request admission through the
blocking operation, even if its caller cancels. Minijail's Rust owner is not Send.
Datadog export, readiness wiring and public-image reproducibility remain separate work.

Tests: portable RPC tests run with Cargo. Build the Linux process integration
executable with `cargo test -p flamingo-verifier-worker-process --all-features --no-run`,
then run it as root under `timeout --kill-after=5s 60s` (as in Rust CI).
It uses no libtest threads. Each broker test runs under `unshare` (util-linux) in
its own PID namespace with a ten-second timeout; broker exit removes descendants.
Only the normal-drop test waits for the child, to verify that SIGKILL was issued.
