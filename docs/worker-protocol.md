# Worker RPC v1

`worker-protocol` defines CBOR payloads; `worker-rpc` provides a Hyper client and
reusable Axum server. The private worker supplies an initialized, synchronous
comparison callback. Three encoded images go in; two scores or `AnalysisFailed`
come out. Embeddings and broker keys never cross the socket.

- HTTP/2 over one inherited Unix socket (intended FD 3); no listener, retries or reconnect.
  `GET /v1/ready` checks version/capacity; `POST /v1/compare` uses `application/cbor`.
- Capacity is the smaller broker/worker limit. Admission rejects immediately.
  HTTP/2 handles framing, multiplexing and response correlation.
- Bodies, encoded images and deadlines are bounded independently on both sides.
  Replies are at most 1 KiB; headers 4 KiB; frames 16 KiB; flow-control windows and
  per-stream send buffers 65,535 bytes. CBOR rejects unknown/trailing/malformed data.
- Local input errors, HTTP 429 and `AnalysisFailed` are nonfatal. Unexpected status
  (including every 5xx), invalid scores, malformed replies, EOF and hard timeouts
  permanently invalidate the session. Score bounds use std `RangeInclusive<f32>`.
- Caller cancellation retains its admission slot, validation and original deadline.
  The server holds its compute permit inside inference, including after stream resets.
- `WorkerSession::connect` returns an owner and clonable client. Only the owner
  shuts down the session; dropping it also closes all clients. Await `shutdown()`
  for supervisor errors. Worker-side socket-close errors remain explicit.
- `serve_worker` waits a bounded time for actual inference during cleanup.
  `ShutdownTimeout` requires killing the worker process; blocking inference cannot
  be forcibly cancelled by Tokio.
- `is_available`/`wait_unavailable` expose broker readiness, not liveness.
  `/v1/ready` is startup capability discovery, not an ongoing model-health probe.
- Metrics use `worker_rpc.*`; spans redact images and inherit local trace context.
  Production integration must export them to Datadog, propagate traces across IPC,
  wire readiness, and add user-impact alerts.

## Process lifecycle

`worker-process` launches an absolute executable with FD 3, empty environment and
null stdio. Call `WorkerProcess::spawn` before serving threads or broker-key creation,
then `connect` inside Tokio. The startup budget begins at launch; OS spawn is synchronous.

One supervisor thread owns the child independently of Tokio. Fatal RPC errors, exit,
startup expiry or owner drop close IPC; cleanup waits a bounded grace period, then
kills and reaps. Forced termination is an error. `ReapTimeout` is fatal: background
reaping continues where possible, but the enclosing process must not keep serving.
Await `shutdown()` for cleanup results; `wait()` observes termination without stopping it.

Linux requires readable `/proc/self/fd`; enumeration failures abort launch. This
supports the pinned Nitro 4.14 kernel. macOS enumeration is for development. Only the direct worker is
supervised; this is not process-tree confinement. Worker stdio is deliberately discarded
to avoid exposing images/secrets; diagnostics use RPC errors, PID and exit status.
Lifecycle metrics use `worker_process.*`; Datadog export remains production integration work.

Minijail, decoded-image limits, signed provisioning, private worker packaging, production
integration and public-image reproducibility verification remain separate work.
Replace broker and worker together for v1. No production path changes yet.

`cargo test --locked -p flamingo-verifier-worker-protocol -p flamingo-verifier-worker-rpc`

`cargo test --locked -p flamingo-verifier-worker-process --all-features`

The `test-worker` feature builds the subprocess fixture; Linux workspace CI enables it.
