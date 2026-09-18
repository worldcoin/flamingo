# Releasing an enclave

The enclave releases on a `verifier/vX.Y.Z` tag. The tag is handled by
[`.github/workflows/release-enclaves.yml`](../.github/workflows/release-enclaves.yml).

## Cutting a release

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
gh workflow run release-enclaves.yml -f workload=verifier -f ref=main -f version=0.1.0 -f dry_run=true
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

Needs x86_64-linux with Nix and Git credentials that can read
`worldcoin/biometric-engines`, plus a `HUGGING_FACE_TOKEN` for the private models. Expect
~90 minutes cold.

```
scripts/build-enclaves.sh --workload verifier target/eif
jq . target/eif/flamingo-verifier-pcr.json
```

## Rotating a measurement in production

`verifier/client/src/config.rs` accepts an attestation matching **any one** entry of
`allowed_pcr_configs` in full, so several enclave versions can be trusted at once. Use that
overlap:

1. Publish the new release. Add its PCR0 to the client allow-list **alongside** the old one.
2. Wait for clients to pick up the new allow-list. Until they have, deploying the new enclave
   alone would break every client still pinning only the old measurement.
3. Deploy the new enclave. The host pins one PCR0 — its own local sidecar's — so it moves with
   the deployment; the overlap exists for clients, not for the host.
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

- The EIF is published publicly, and the verifier enclave links private face-engine code. Confirm
  with the `biometric-engines` owners before the first `verifier/v*` tag.
