# Worker comparisons

Blocking RPC over an inherited Unix socket (FD 3): four-byte big-endian length,
then CBOR. One `CompareRequest` (three encoded images) produces one `WorkerResult`
(two scores or `AnalysisFailed`). No handshake, ready message, version, request IDs,
pipelining, retries or reconnect.

- `WorkerClient::new` takes a connected socket. `compare(&mut self, ...)` completes
  before another request starts; the server runs an inline `FnMut` comparator.
- `first_request_timeout` covers the first comparison, including lazy initialization.
  Later calls use `request_timeout`. Idle time consumes neither budget.
- Both sides bound lengths before allocation, encoded images and CBOR decoding.
  Replies are at most 1 KiB; scores use std `RangeInclusive<f32>`.
  The model adapter must bound decoded pixels.
- Partial I/O never resets a deadline. Local input errors and `AnalysisFailed`
  preserve the connection. Timeout, broken transport, malformed replies and invalid
  scores permanently invalidate it. Model faults/panics must make the worker exit.

## Process ownership

`WorkerProcess::spawn` launches an absolute executable with empty environment,
null stdio and FD 3. Call before serving threads or generating broker keys.
The owner exposes blocking `compare`, `try_wait`, `wait` and `shutdown`.
`wait` observes termination without requesting it and may wait indefinitely.

An independent thread supervises the child. Fatal comparisons, exit or owner drop
trigger bounded grace, kill and reap. Fatal `compare` calls also await cleanup.
A stuck comparator cannot interrupt itself; the broker must kill the process.
Forced termination and reap failures remain errors, including background reaping
that outlives its deadline. Only the direct child is supervised.

Linux FD sanitization requires readable `/proc/self/fd` and supports Nitro 4.14.
macOS is for development. This is not yet a sandbox; worker output is discarded.

## Integration

Launch success is not model readiness. A hung initializer without startup traffic
is detected by the first comparison. Production readiness must reflect known failures.
Async brokers must admit only one blocking operation off executor threads and reject
excess work; caller cancellation must retain admission and ownership until completion.

Metrics use `worker_rpc.*` and `worker_process.*`, including first-comparison latency.
Datadog export, cross-process traces, readiness/alerts, Minijail, private packaging,
provisioning and reproducible-image verification remain separate work.
Deploy and roll back broker/worker as a tested pair. Pontifex/production paths are unchanged.

Test: `cargo test --locked -p flamingo-verifier-worker-protocol -p flamingo-verifier-worker-rpc -p flamingo-verifier-worker-process --all-features`.
