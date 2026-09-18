# Enclave releases

The [release workflow](../.github/workflows/release-enclaves.yml) runs on `verifier/vX.Y.Z` tags. It builds the OCI image and EIF, records PCR measurements, and creates a draft GitHub release.

## Publish a release

1. Update `workspace.package.version` and the versioned local dependencies in `Cargo.toml`, then run `cargo update --workspace`.
2. Tag the reviewed commit on `main` and push the tag:

   ```bash
   git tag verifier/vX.Y.Z <sha-on-main>
   git push origin verifier/vX.Y.Z
   ```

3. Wait for the build; a cold build takes about 90 minutes.
4. Check the draft's artifacts and PCR measurements, then publish it.

The workflow pushes the OCI image before creating the draft release. Approval before that push depends on the GitHub `release` environment's protection rules.

The EIF contains private face-engine code. Confirm its distribution with the `biometric-engines` owners before publishing it publicly.

To build without publishing:

```bash
gh workflow run release-enclaves.yml \
  -f workload=verifier -f ref=main -f version=0.4.0 -f dry_run=true
```

## Measurements

Nix builds the OCI image and EIF from the same root filesystem. `aws-nitro-util` creates the EIF with pinned AWS kernel, init, and Nitro Secure Module files.

| Measurement | Covers |
| --- | --- |
| PCR0 | Kernel, command line, and both ramdisks. |
| PCR1 | Kernel and boot ramdisk. |
| PCR2 | Application ramdisk. |

The EIF metadata's `BuildTime` is not measured. See [development](development.md#build-images) to rebuild an image and inspect its measurements.

## Rotate a measurement

1. Publish the new release and add its PCR0 alongside the old one in the clients' `allowed_pcr_configs`.
2. Wait for clients to receive the updated configuration.
3. Deploy the new enclave. Clients accept either image during the rollout; the host does not pin PCRs.
4. Remove the old measurement after clients no longer need to verify it.

## Verify a release

Replace `vX.Y.Z` with the release tag:

```bash
gh release download verifier/vX.Y.Z --repo worldcoin/flamingo
gh attestation verify manifest.json --repo worldcoin/flamingo \
  --signer-workflow worldcoin/flamingo/.github/workflows/release-enclaves.yml
```

Check the downloaded artifacts' hashes against `manifest.json`. Rebuild the source commit named in the manifest and compare PCR measurements.
