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

Linux-only `Worker::spawn(&File, &Path, WorkerClientConfig)` uses Minijail.
Launch from a single-threaded bootstrap before creating broker keys.
The worker gets null stdio, empty environment and FD 3 inside a new PID namespace.
Minijail remaps/closes descriptors. A short `fexecve` path applies seccomp before
the executable's loader; upstream `run_fd_remap` instead uses `LD_PRELOAD`.

The owner compares synchronously and shuts down explicitly or on Drop.
Fatal RPC failures also shut down the namespace. SIGKILL stops a stuck PID 1 and
its descendants; a fixed two-second reap deadline reports kernel cleanup delays.
There is no supervisor thread, idle-exit polling or background reaper.
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
It uses no libtest threads.
