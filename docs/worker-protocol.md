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

Process launch/kill, Minijail, decoded-image limits, signed provisioning, reproducible
build verification and progressive production rollout remain separate work.
No production path changes in this PR; replace broker and worker together for v1.

`cargo test --locked -p flamingo-verifier-worker-protocol -p flamingo-verifier-worker-rpc`
