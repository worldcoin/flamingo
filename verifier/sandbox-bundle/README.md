# Sandbox bundle

This crate owns the bundle manifest, receiver and host-side protocol APIs.
The deployment-specific provisioner lives in worldcoin/flamingo-deploy.

`host::Bundle::prepare` hashes a local executable and builds its manifest.
`Bundle::provision` streams the manifest and executable over vsock and waits
for the enclave's initialization acknowledgement. `host::health` checks the
normal serving RPC. Neither API knows about S3 buckets or Kubernetes readiness.

The standalone `sandbox-bundle` CLI uses these same APIs for manual testing.
The wire format remains a 4-byte big-endian manifest length, version-3 JSON,
then raw executable bytes. No intermediate packed file is needed by the API.

Callers must bound the complete bootstrap with a timeout. Only connection
refusal before transfer is retried; a partial upload requires a fresh enclave.
Dropping the provisioning future closes its owned socket. Integrity hashes
are not publisher signatures or PCR measurements of the external bundle.

Run `cargo test --locked -p flamingo-verifier-sandbox-bundle` for protocol,
wire-compatibility, acknowledgement, timeout and cancellation tests.
