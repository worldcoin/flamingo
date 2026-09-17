# External worker qualification — 2026-09-17

The pinned prototype is biometric-engines commit
`60de92b37c2e6dbcb4ad8f543d72fd6024506c96` (PR #677). Its bundled static executable
uses wire protocol version 1. There are no additional source patches. Worker artifact
signing is intentionally absent; the deployment release record pins SHA-384 digests.
Minijail confines execution but does not authenticate the artifact's publisher.

Verified on x86_64 Linux with the production Minijail policy:

- Process/confinement tests, including startup failures, resource limits, forbidden
  syscalls, crashes, deadline failures and broker teardown.
- Real worker: all three vanilla DeepFace similarities, GrayBadge, invalid-image
  failure and a successful subsequent request. An approved synthetic portrait was
  reused across roles; this establishes integration, not biometric accuracy.
- Measured Nitro enclave, 2 CPUs / 4 GiB, no debug mode: unsigned artifact transfer,
  eager initialization, serving health, attested assignment, encrypted request and
  response, signed result and input binding checks.
- Approximately 5.0s from carrier launch to serving readiness, 1.0s for the first
  encrypted request, and 1.2 / 1.8 / 2.5s for three concurrent encrypted requests.
- Carrier shutdown removes readiness and terminates its owned enclave. After an
  externally terminated enclave, the carrier bootstrapped a replacement with fresh
  keys and passed another encrypted request (about 12s recovery). Four fake carrier
  tests cover shutdown, disappeared enclaves, uploader watchdog cleanup and serving
  health after provisioning acknowledgement.
- One repeated-start run saw transient connection resets before a successful retry.
  Subsequent connection traces and restart qualification succeeded; the reset phase
  was not captured. The carrier safely removed each failed boot before retrying.

Portable workspace tests, bounded protocol client tests, formatting and Clippy passed.
The EIF and uploader were built using Nix. Kubernetes manifests were rendered against
common-app 2.44.0; its small-deployment strategy override requires `strategy.force`.
Dev nodes advertise 4 GiB hugepages each. Cluster rollout/restart/rollback and peak
memory remain deployment qualification gates; these host results do not prove them.

Agent 1 owns the new public operation/claim contract. The current public adapter retains
its existing two-score interface; direct worker GrayBadge and three-score success do
not establish public GrayBadge support or authenticate the additional score.

The sole remaining private biometric dependency is the pinned protocol crate. Removing
private Git credentials depends on its publication; engine/model dependencies and
Hugging Face credentials have been removed from the Flamingo build.
