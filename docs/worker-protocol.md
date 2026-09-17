# External worker boundary

Flamingo pins `biometric-engines-protocol` to biometric-engines commit
`60de92b37c2e6dbcb4ad8f543d72fd6024506c96` (wire version 1). It launches the
separately built static x86_64 Linux worker with `--bundled`, connected Unix
stream FD 3 and no inherited environment. Executable FD 4 is closed on exec.
Minijail applies its namespaces, read-only root, UID, resource and syscall policy
before the executable starts. The worker owns models and inference; the broker
owns attestation, PCP, encryption, result policy and signing.

Readiness and requests use upstream's protobuf codec and four-byte big-endian
length frames. Readiness must arrive after model initialization within 120s.
The broker caps readiness at 64 bytes and replies at 16 KiB before allocation.
Each exchange has one 10s deadline, including partial reads/writes. IDs, operation
types and every cosine score (finite and within [-1, 1]) are validated.
DeepFace and GrayBadge are supported internally; embedding generation is a follow-up.
Biological failures retain upstream structured details and keep IPC usable.
Internal engine failures, malformed replies, crashes and timeouts terminate the
enclave. A new worker requires a fresh enclave boot; there is no fallback.

The current public match adapter still consumes two credential comparison scores;
the public API/claim migration owns exposing and authenticating three-way DeepFace
and GrayBadge. `Worker::evaluate` already returns all three DeepFace scores or the
GrayBadge score, without dummy credential inputs. It does not apply thresholds.

## Provisioning format

Format 3 is unsigned: a four-byte big-endian JSON length, the JSON manifest, then
exactly `size` executable bytes and write-half EOF. The manifest has only
`manifest_version`, `release_id`, `sha384` and `size`. Metadata is capped at 64 KiB;
`config/worker-bootstrap.json` supplies the measured executable and sandbox budgets.
The receiver streams into a fresh root, checks the digest and ELF architecture,
and retains only a read-only executable FD. Failure removes the partial root.
Older signed/multi-file formats are rejected. No publisher keys or signatures exist.

The parent deployment is trusted to select the executable. The digest checks
transfer integrity; it does not authenticate a publisher. Minijail confines the
worker but does not guarantee truthful inference. PCRs measure the broker image,
not the sideloaded executable. Release records must pin the worker digest separately.
The broker records that digest operationally without logging biometric inputs/results.

Provisioning ACK means initialized worker and attested broker keys. The carrier
separately probes the serving broker before publishing readiness. Fixed provisioning
socket timeouts bound individual I/O; a carrier watchdog bounds the whole bootstrap.

## Admission and cancellation

The host admits at most four uploads before body extraction. Accepted requests queue
for up to five seconds for serialized inference; excess admission gets retryable
`not_ready`. The enclave separately bounds four retained requests. Decryption and
PCP checks happen before taking the inference mutex. The mutex and admission permit
remain owned by the blocking exchange even if its async caller disconnects. Host
match timeout remains 30s. Idle worker health is checked without waiting on busy IPC.

The JSON/base64 route budget derives from the ciphertext limit. Each image is capped
at 8 MiB by the broker, below upstream's ceiling. The carrier readiness marker closes
admission during startup/shutdown; active relays get a 35s drain before enclave teardown.
