# Host-side worker carrier

`flamingo-carrier` runs in the Kubernetes sidecar, **not inside the enclave**.
The deployment repository owns its container image, AWS identity, resource values
and exact source/worker pins. This crate owns the lifecycle and ships alongside
the same revision's `sandbox-bundle` tool and measured EIF.

```text
private S3 archive → SHA256 + archive/ELF checks → sandbox-bundle pack
  → non-debug Nitro boot → vsock provisioning ACK → worker health → ready
```

The AWS CLI uses the pod's normal credential chain. Credentials and S3 access
stay on the host. The enclave receives only the unsigned bundle and independently
checks its manifest/integrity before starting the worker under Minijail. An archive
SHA256 pin is not a publisher signature or a PCR measurement of the worker.

## Review order

1. `src/main.rs`: one bootstrap attempt; readiness and shutdown.
2. `src/artifact.rs`: S3 download, archive SHA256, one-file extraction and static ELF checks.
3. `src/enclave.rs`: measured launch, provisioning, health and owned-only cleanup.
4. `src/process.rs`: deadlines and process-group cancellation (including descendants).
5. `src/config.rs`: environment/release/URI binding and resource settings.

Required environment: `WORKER_ENVIRONMENT`, `WORKER_RELEASE_ID`,
`WORKER_ARTIFACT_URI`, `WORKER_ARTIFACT_SHA256`. Defaults: CID 16, 2 CPUs,
4096 MiB, 300-second overall bootstrap, 120-second provisioning I/O deadline,
2-second health polling, `/run/flamingo/ready` marker. Paths and budgets are
configurable in `Config::from_env`.

Each container owns one uniquely named enclave. Failure or SIGTERM clears readiness,
kills active subprocess groups and terminates only that enclave. There is no inner
restart loop: Kubernetes owns restart/backoff. Fixed CID replicas need separate
hosts; allow at least 60 seconds termination grace. SIGKILL/host failure cannot run
cleanup and may require operator reconciliation of the host's Nitro inventory.

## Validation

`cargo test --locked -p flamingo-verifier-carrier` runs unit tests plus Linux
lifecycle tests (bash, jq, tar and sha256sum required). The lifecycle tests mock
AWS/Nitro/RPC commands, but use real archives, hashes, child processes and signals.
They do not prove AWS permissions, Nitro boot or a real inference result; those
must be tested in the selected dev deployment using its trusted build PCRs.

`scripts/build-enclaves.sh` exports the EIF, PCRs and the combined Nix runtime
closure for `flamingo-carrier` and `sandbox-bundle`. Neither private worker bytes
nor models are build inputs or baked into the carrier image.
