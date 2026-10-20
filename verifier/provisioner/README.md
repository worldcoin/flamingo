# Flamingo enclave provisioner

This binary runs outside Nitro and owns one enclave lifecycle. Kubernetes owns restart and backoff.
It uses `tabernaculum_provisioner::provision` with an executable path, CID and I/O timeout; the
API host no longer loads or periodically resends the release manifest.

Startup, under one `BOOTSTRAP_TIMEOUT_SECONDS` deadline:

1. Read this boot's compact JWS manifest from `RELEASE_MANIFEST_PATH`.
2. Download the pinned worker archive from S3, verify its SHA-256, extract its single executable,
   and require a static x86_64 ELF. The existing one-directory/one-file archive format is unchanged.
3. Launch the EIF and sideload the executable through Tabernaculum bootstrap port 1001.
4. After worker acknowledgement, load the manifest through `/v1/release` on `ENCLAVE_PORT`.
5. Check `/v1/health` and Nitro running state, then write `BUNDLE_READY_FILE`.
6. Monitor Nitro state. On failure, timeout, SIGTERM or SIGINT, clear readiness and stop only the
   enclave owned by this process. A new process loads the manifest again for its new enclave.

Worker acknowledgement can precede the Pontifex listener. Transient transport failures retry
with 250-ms delays and 2-second request deadlines inside the shared bootstrap deadline. A rejected
manifest fails startup immediately. Health `NotReady` retries without reloading an accepted
manifest. The enclave retains its existing manifest validation and immutable-per-boot release.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `BUNDLE_ARTIFACT_URI` | required | S3 archive URI. |
| `BUNDLE_ARTIFACT_SHA256` | required | Expected archive SHA-256, separate from the executable's `engine_hash`. |
| `RELEASE_MANIFEST_PATH` | required | Mounted compact JWS manifest for this worker. |
| `BUNDLE_EXECUTABLE` | `biometric-engines-worker` | Executable filename inside the archive. |
| `EIF_PATH` | `/home/enclave.eif` | EIF built with the matching Tabernaculum revision. |
| `ENCLAVE_CID` | `16` | Enclave CID, greater than 3. |
| `ENCLAVE_PORT` | `1000` | Pontifex application port. |
| `ENCLAVE_CPU_COUNT` | `2` | Nitro CPU allocation. |
| `ENCLAVE_MEMORY_SIZE` | `6144` | Nitro memory allocation, MiB. |
| `ENCLAVE_DEBUG_MODE` | `false` | Launch with debug measurements only when explicitly requested. |
| `BUNDLE_READY_FILE` | `/run/tabernaculum/ready` | Existing Kubernetes readiness marker. |
| `BOOTSTRAP_TIMEOUT_SECONDS` | `300` | Total acquisition, worker initialization and release-loading budget. |
| `PROVISIONING_IO_TIMEOUT_SECONDS` | `120` | Worker-transfer connection retry/per-I/O budget, 1–900 seconds. |
| `POLL_SECONDS` | `2` | Nitro running-state polling interval after startup. |

The runtime image includes Nitro CLI, AWS CLI and archive/ELF tools. It contains no worker, model,
release JWS or EIF. Deployment adds the paired EIF and mounts the manifest. Server releases record
the provisioner image digest alongside the EIF checksum in `release.json`.

Both the provisioner and enclave pin Tabernaculum commit
`288613703669c92978e8ecbe3a3b30c571f56361` (worldcoin/tabernaculum#8), using bootstrap format 4.
Update both together. The deployment follow-up must consume `provisioner_image`, move the manifest
mount and `RELEASE_MANIFEST_PATH` to the enclave-launcher container, and retain the existing ready
file probes. No deployment is performed by this source change.
