# Releasing an enclave

Each workload releases on its own tag: `verifier/vX.Y.Z`, `di/vX.Y.Z`. The tag is handled by
[`.github/workflows/release-enclaves.yml`](../.github/workflows/release-enclaves.yml).

## Cutting a release

Verifier releases require reviewed publisher public keys and measured resource budgets in
`config/worker-bootstrap.json`. The checked-in empty/zero configuration deliberately cannot
boot a verifier. `scripts/build-enclaves.sh` rejects it before release builds; no test key or
guessed budget is substituted. Commit the approved configuration before tagging.
Configured releases also run `worker-bundle validate-config`, using the broker's exact
Rust parser, curve-key validation and resource bounds before building artifacts.

1. **Bump the version.** Edit `workspace.package.version` in the root `Cargo.toml`, then refresh
   the root lockfile:
   ```
   cargo update --workspace
   ```
2. **Tag and push:**
   ```
   git tag verifier/v0.2.0 <sha-on-main>
   git push origin verifier/v0.2.0
   ```
3. **Wait for the build.** The enclave build takes about 90 minutes when cold.
4. **Review the draft**, check the PCR table, publish. The draft is the last human step: the
   release is created unpublished, so nothing is live until someone publishes it.

> The `release` GitHub environment carries no protection rules today, so `approve-publish`
> passes straight through and images are pushed as soon as the enclave build succeeds.
> To require a human before anything is published, add required reviewers to that environment —
> a settings change, no workflow edit.

To exercise the pipeline without a tag, dispatch it:

```
gh workflow run release-enclaves.yml -f workload=di -f ref=main -f version=0.1.0 -f dry_run=true
```

A dry run builds, verifies and publishes nothing.

## How the measurement is produced

Nix builds both artifacts from the same root filesystem. `dockerTools.buildLayeredImage`
produces the OCI image, while `aws-nitro-util` produces the EIF using pinned AWS kernel,
init, and NSM blobs. Both are content-addressed Nix outputs.

PCR0 covers the kernel, the cmdline and both ramdisks; PCR1 the kernel and boot ramdisk;
PCR2 the application ramdisk. The EIF metadata section — which carries a wall-clock
`BuildTime` — is *not* measured, so the timestamp does not reach a PCR.

## Building and measuring locally

Needs x86_64-linux with Nix. Both public enclave images build without private Git credentials,
Hugging Face access, model bytes, or a worker executable. The verifier image contains only
the broker, public runtime dependencies, and its measured bootstrap configuration.

```
scripts/build-enclaves.sh --workload verifier target/eif
jq . target/eif/verifier-pcr.json
```

For a development build with the unconfigured, fail-closed bootstrap file:

```
nix build --no-update-lock-file .#verifier-oci .#verifier-eif
```

The public `worker-bundle` tool packages signed runtime artifacts and provisions them over
vsock on Linux. Build it with `nix build --no-update-lock-file .#worker-bundle`; no model or
private-repository access is needed to build the tool.

The repo-local inference prototype lives in its own Cargo workspace at `verifier/worker`.
Only its explicit builds require `worldcoin/biometric-engines` access:

```
CARGO_TARGET_DIR=target cargo test --locked --manifest-path verifier/worker/Cargo.toml
nix build --no-update-lock-file .#privatePackages.x86_64-linux.verifier-worker
```

`privatePackages.x86_64-linux.verifier-worker-runtime` additionally requires model access;
it is a prototype qualification root, never part of a public image. All private outputs are
outside `packages`, so generic public flake checks do not fetch them.
The production handoff is a signed worker/runtime bundle
with separate authenticated models and optional configuration files. See [worker protocol](worker-protocol.md).

## Rotating a measurement in production

`verifier/client/src/config.rs` accepts an attestation matching **any one** entry of
`allowed_pcr_configs` in full, so several enclave versions can be trusted at once. Use that
overlap:

1. Publish the new release. Add its PCR0 to the client allow-list **alongside** the old one.
2. Wait for clients to pick up the new allow-list. Until they have, deploying the new enclave
   alone would break every client still pinning only the old measurement.
3. Deploy the new enclave and point the host at its CID/port. The untrusted host relays
   attestations; clients enforce the PCR allow-list.
4. Retire the old measurement from the allow-list once nothing is verifying against it.

Registry rows carry the `pcr0` they were attested under, so a withdrawn image can be revoked in
bulk. That path is not built yet: nothing sets `KeyStatus::Revoked`, the IAM policy grants no
`UpdateItem`, and a bulk revoke needs a GSI on `pcr0`.

## Verifying a published release

```
gh release download verifier/v0.2.0 -R worldcoin/flamingo-verifier
gh attestation verify manifest.json --repo worldcoin/flamingo-verifier \
   --signer-workflow worldcoin/verifier/.github/workflows/release-enclaves.yml
```

The attestation binds the assets to the workflow and commit that produced them. Then reproduce
the measurements from source and compare against `manifest.json`.

## Notes

- Both EIFs pin AWS Nitro CLI v1.5.0's init binary in `nix/enclave-images.nix`, which switches
  the mount root before launching the broker. Init changes require a Linux confinement test
  and actual Nitro boot/shutdown validation. Record the new EIF measurements and use the
  allow-list overlap above; retain the previous EIF and measurements for rollback.
- `di/host` and `di/enclave` are skeletons that exit with a failure code. A `di/v*` tag exercises
  the release pipeline; it does not ship a working service.
- Publisher keys and resource limits are measured public inputs. Rotating them changes the EIF
  measurement and follows the same client allow-list overlap above. A worker rollout must also
  retain the previous signed bundle for rollback; neither version may add unsupported proof flows.
- A successful public build is not real-worker qualification. Before release, measure the actual
  signed binary's cold/warm latency, memory and thread requirements, then validate production
  Minijail confinement and fatal enclave shutdown on Linux/Nitro. No model-dependent check is
  replaced with a placeholder or marked passed without the artifact.
