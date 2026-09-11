# Worker contract

The public broker owns attestation, decryption, thresholds and signing. The private
worker receives three encoded images and returns two scores or `AnalysisFailed`.
Keys, claims and embeddings never cross the process boundary.

## IPC and lifecycle

The worker inherits a connected Unix stream on FD 3, an empty environment and null
stdio. Frames are a four-byte big-endian length followed by CBOR:

- Request: `credential_image`, `live_image`, `challenge_image` byte strings.
- Response: `Compared { live_similarity, challenge_similarity }` or `AnalysisFailed`.
- Limits: 8 MiB per image, 24 MiB + 1024 bytes per request, 1024 bytes per response.
- Scores must be finite and in [-1, 1]. The broker applies the client's [0, 1] threshold.

There is one synchronous request at a time, without handshake, IDs, retries or
reconnect. The broker enforces a 120-second first comparison and 10-second later
comparisons, including partial I/O. The worker bounds frames and decoded images;
it relies on the broker to kill stuck I/O or inference.

Local input errors and `AnalysisFailed` preserve the session. EOF during a request,
malformed replies, invalid scores, crashes and timeouts kill the worker and exit
the enclave. Idle exits are detected by readiness probes. Recovery requires a fresh
enclave. A successful spawn or probe does not prove lazy model initialization.

## Signed runtime

The measured `config/worker-bootstrap.json` supplies publisher keys and resource
budgets. Empty keys or zero budgets prevent startup and release builds.
The parent host sends one bundle to vsock port 1001:

```text
u32 BE manifest length | exact JSON manifest bytes
u32 BE signature length | P-384 ECDSA/SHA-384 signature in DER
artifact bytes in manifest order | sender write-half EOF
```

The signature covers the exact JSON bytes. A version-1 manifest contains a
diagnostic `release_id` and an `artifacts` list of `logical_path`, `role`,
`sha384` and `size`. The worker is `bin/verifier-worker`; models and configuration
use `models/` and `config/`; libraries/loaders use `lib/`, `lib64/` or `nix/store/`.
Files must be regular, with safe relative paths and no duplicates or parent/file
conflicts. Model weights may be separate signed files; the local adapter embeds YAML.

The broker verifies the signature and streams hash-checked files into a fresh root
under `/worker-runtime`. Metadata, total bytes and all provisioning I/O are bounded.
It launches through Minijail before starting Tokio threads or generating broker keys.
After launch and key attestation it acknowledges with one zero byte and closes the
socket. Normal requests use port 1000. The acknowledgement is not model warmup.

Clients accept any runtime signed by the measured publisher keys; there is no
worker-digest pin or anti-rollback counter. Key/budget changes require new PCR trust.

## Sandbox

The measured policy is `verifier/worker-process/worker.policy`. It applies before
the supplied ELF loader executes. Minijail supplies a private read-only root,
PID/network/IPC namespaces, UID/GID 65532, no capabilities, no inherited secrets,
and explicit address-space/thread/FD limits. Forbidden syscalls kill all threads.
There is no writable cache or access to broker files, sockets, devices or processes.
Guest teardown owns final cleanup; the broker does not restart workers.

See [operations](worker-operations.md) for build commands and qualification.
