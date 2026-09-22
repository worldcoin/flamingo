# Enclave provisioner

`flamingo-enclave-provisioner` runs in the host-side Kubernetes container, not
inside the enclave. Source owns its lifecycle and shared sandbox-bundle library;
the deployment repository owns Docker packaging, resource settings and exact pins.

## Flow

1. `artifact::fetch`: download the pinned S3 release, check archive SHA256,
   extract its single executable and verify the static x86-64 ELF contract.
2. `enclave.launch`: boot the measured EIF using Nitro CLI.
3. `bundle.provision`: stream the manifest and executable directly over vsock,
   then wait for the enclave to acknowledge sandbox/model initialization.
4. `enclave.wait_ready`: check the serving health RPC and non-debug Nitro state.
5. Mark the pod ready, then `enclave.monitor` checks health until shutdown/failure.
6. Clear readiness and stop the owned enclave. Kubernetes owns restart/backoff.

Read `src/main.rs` first, then `artifact.rs` and `enclave.rs`. The shared
transport lives in `verifier/sandbox-bundle/src/host.rs`. Its standalone CLI
remains available for manual testing but is no longer a runtime dependency here.

## Bundle boundary

The S3 archive is the existing producer format, not the vsock bundle format.
The external bucket, release and executable names still contain
`biometric-engines-worker`; those published identifiers are unchanged.

The provisioner constructs a version-3 JSON manifest in memory and streams its
4-byte big-endian length, JSON and raw executable bytes. No intermediate manifest
or bundle file is created. The receiver and wire format are unchanged.
The archive SHA256 and executable SHA384 provide integrity, not a publisher
signature or a PCR measurement of the externally supplied sandbox bundle.

The enclave accepts one parent-host connection on port 1001. Initialization ACK
is followed by the health RPC on port 1000. Only pre-transfer connection refusal
is retried; a failed/partial transfer requires a fresh enclave.

## Configuration and dependencies

Required: `BUNDLE_ENVIRONMENT`, `BUNDLE_RELEASE_ID`, `BUNDLE_ARTIFACT_URI`,
`BUNDLE_ARTIFACT_SHA256`. These replace the draft's `WORKER_*` settings;
the source and deploy revisions must be updated together.
Defaults: CID16, 2 CPUs, 4096 MiB, 300-second overall bootstrap, 120-second
socket-operation timeout, 2-second health polling, `/run/flamingo/ready`.
The marker path is configurable with `BUNDLE_READY_FILE`.

AWS CLI, tar/gzip, readelf and Nitro CLI remain installed dependencies.
S3 uses the pod's standard credential chain; credentials stay outside the enclave.
The image contains the EIF and provisioner Nix closure, never private bundle/model bytes.

## Failure handling and tests

Async vsock is cancellation-safe: dropping initialization closes its socket.
External commands retain process-group cancellation. Initialization errors report
a fixed stage plus I/O kind/errno, never bundle contents or arbitrary command output.
Both readiness clearing and enclave termination are attempted during cleanup.
SIGKILL/host failure cannot execute cleanup and may need Nitro inventory reconciliation.
Use separate hosts for fixed-CID replicas and at least 60 seconds termination grace.

Run `cargo test --locked -p flamingo-verifier-enclave-provisioner -p flamingo-verifier-sandbox-bundle`.
Linux bootstrap tests mock AWS/Nitro but use real archives, hashes and signals.
Shared-library tests verify wire compatibility, ACK semantics, timeouts, cancellation
and safe diagnostics with in-process streams. They do not establish live Nitro/S3
or attested-match success for this revision; those require separate dev qualification.
