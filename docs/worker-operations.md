# Worker operations

DeepFace only. One authenticated worker per enclave, no queue, restart or in-process
fallback. Real-model correctness, cold/warm resource sizing and Nitro qualification
remain release gates; fixtures do not replace the biometrics binary.

## Health and deadlines

| Check | Meaning |
| --- | --- |
| Host `/health` | HTTP process is alive; does not check dependencies. |
| Host `/ready` | Enclave answers within 2 seconds with fresh cached boot attestations and no observed worker exit. Failure is HTTP 503. |
| Startup | Artifact authentication, sandbox launch and boot-key attestation completed. No model handshake or inference warmup. |

Busy does not make readiness fail. Admission rejects concurrent matches with
`NotReady` / HTTP 503; cancellation keeps the slot until the blocking work ends.
Idle worker exits are checked by readiness. Fatal worker RPC failures kill the worker
best-effort and exit the enclave, making subsequent readiness fail. Spawn/readiness
success does **not** prove the model can perform inference.

NSM startup and refresh operations have a 5s deadline. Ordinary refresh failures may
use the last good attestation for at most one hour; after that readiness fails.
An NSM timeout/panic exits the enclave instead of leaving a blocked ioctl alive.

Budgets are nested: worker cold **120s**, warm **10s**; host match **135s**;
client request default/maximum **150s**; client connect **5s**. Controls remain **2s**.
Client configuration may tighten but cannot disable these bounds. There are no
automatic match retries; a caller can reassign and reseal once after a stale-key
response. Do not automatically retry transport errors or overload.

The compatible broker transport admits at most 32 connections and one allocated
match body, validates frame lengths before allocation, and bounds frame reads to
5s / complete connections to 130s. Busy uploads are drained in bounded space before
`NotReady`; malformed/slow or excess connections are closed. HTTP request limits
cover three 8 MiB images plus bounded metadata/sealing/base64 overhead. The client
caps every response it reads at 64 KiB, including chunked error bodies.
The host also admits just one match before reading JSON, with a 5s upload deadline;
local overload returns 503 without polling another large body. Controls bypass this
gate. Cancelling the HTTP request releases the host slot, not the enclave's active
blocking-work slot.

Before rollout, set the deployment's ingress/LB idle deadline to at least **145s**
and its drain grace to at least **150s**. Verify every proxy/CDN hop supports this
budget; otherwise bypass that hop or do not launch this profile. Probe `/ready`
every 5s with a 3s probe timeout; use `/health` only for liveness. Keep an independent
HTTP readiness monitor: process death must not leave a last-seen gauge green.

## Datadog

Staging/production host startup requires this explicit configuration:

```sh
APP_ENV=production
TELEMETRY_PRESET=datadog
TELEMETRY_SERVICE_NAME=flamingo-verifier-host
TELEMETRY_METRICS_BACKEND=statsd
TELEMETRY_STATSD_HOST=127.0.0.1
TELEMETRY_STATSD_PORT=8125
TELEMETRY_DATADOG_ENDPOINT=http://127.0.0.1:8126
TELEMETRY_LOG_LEVEL=warn
```

Use the local Agent's IP if it is not loopback; StatsD hostnames are rejected in
production to avoid unbounded startup DNS. Attach `service`, `env`, `version` and
instance/container identity through Agent configuration. Do not set a metric prefix
unless the queries below are updated. `RUST_LOG`, when set, takes precedence and
must also be `warn` or `error` outside development.

The host exports:

- `verifier.enclave.calls`: count, tagged with fixed `operation` (`health`,
  `assignment`, `match`) and `result` (`success`, `transport`, `request_timeout`,
  `not_ready`, `nsm_unavailable`, `attestation_failed`, `request_not_opened`, `internal`).
- `verifier.enclave.call_seconds`: DogStatsD distribution with the same tags.
- `verifier.enclave.ready`: 0/1 gauge emitted on each readiness check.
- `verifier.match.rejections`: host-side admission/body failures, with `class=busy`
  or `class=upload_timeout`; these are not enclave failures.

`success` means the enclave answered, **not** a successful biometric match.
`match/not_ready` measures rejected admission, including startup unavailability;
it does not disclose a model outcome. No plaintext, ciphertext, scores, image sizes,
caller labels or model decisions are exported. Existing enclave-local worker
counters are not forwarded to the untrusted host.

Create a dashboard with readiness by instance, match/assignment request rates,
dependency error rate, rejected admission, and match p50/p95/p99. Useful queries:

```text
min:verifier.enclave.ready{service:flamingo-verifier-host} by {host}
sum:verifier.enclave.calls{operation:match,result:not_ready}.as_count()
sum:verifier.match.rejections{class:busy}.as_count()
p95:verifier.enclave.call_seconds{operation:match,result:success}
sum:verifier.enclave.calls{operation:match,!result:success,!result:request_not_opened}.as_count()
```

Scope every monitor to environment/service and the active deployment. Alert on
readiness 0 for one minute, missing readiness samples for one minute, any sustained
transport/timeouts, and admission failures consuming the availability error budget.
Use failed operational matches / all matches as the SLO error ratio; exclude only
`request_not_opened`, a caller reassignment response; include host `busy` rejections
in both offered demand and operational failures. Calibrate latency and
short/long-window burn thresholds with the real binary before promotion. Configure
distribution percentiles in Datadog. APM `http.request` / `enclave.call` spans and
failure logs carry trace context and HTTP status without raw URL/query/header data.

Release builds compile out DEBUG/TRACE events because upstream Pontifex logs wire
payloads there and Datadog's log filter alone does not filter span events. Cargo
feature unification applies that release ceiling across linked workspace crates;
INFO spans remain available. Never run a debug build with production inputs.

Telemetry is explicitly best-effort: the bounded StatsD queue holds at most 5,000
events, sends immediately without waiting for an acknowledgement, and can drop
events when full or when the Agent is down. Trace export has bounded queues and
30s deadlines. Telemetry loss does not make inference unavailable; monitor Agent
health and missing data externally. No telemetry traffic enters the sandbox.

## Release and rollback

Before production: run public tests plus root Linux sandbox tests; build the exact
release image; run real-binary qualification under the shipped policy on Nitro;
record artifact digest, trusted signing key, image digest/PCRs, cold/warm latency,
peak memory and threads. Model-less checks alone cannot approve a release.

Retain the previous image, authenticated worker artifact and compatible PCR policy.
Add new PCRs before routing traffic, launch one isolated canary, then increase
traffic gradually only while readiness, failures, latency and memory remain within
the measured envelope. Do not increase memory/thread limits broadly without a
canary. Stop promotion and remove canary traffic on any policy death, timeout,
unexpected 5xx or missing telemetry. Drain then restore the previous image/artifact;
remove new PCR trust after rollback. No downgrade to an unsigned worker or permissive
policy, and no worker-level restart toggle.

Blind spot: RPC transport failure cannot distinguish seccomp, OOM, process exit or
kernel failure. Correlate the redacted enclave fatal class with Nitro lifecycle and
host kernel/audit diagnostics; do not turn on payload logging. Deployment/Agent
configuration and monitors live outside this repo and must be applied and verified
by the deployment owner before launch.
