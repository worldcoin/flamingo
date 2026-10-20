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

Public EIFs and OCI images exclude the biometric engine and models; the worker is provisioned separately at runtime.

To build without publishing:

```bash
gh workflow run release-enclaves.yml \
  -f workload=verifier --ref main -f version=0.4.0 -f dry_run=true
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

## Server releases

[Release server](../.github/workflows/release-server.yml) publishes the API, provisioner
base, and enclave images to GHCR, plus the EIF, PCRs, and `release.json` under
`server/v<version>`. The workflow runs from `main` and uses the `release` environment.

```sh
gh workflow run release-server.yml --repo worldcoin/flamingo --ref main \
  -f version=1.0.0-rc.1
```

Client crate versions are independent. `release.json` contains the API,
`provisioner_image`, and enclave image digests, EIF checksum, and PCRs from the same
source commit. The provisioner image contains the Flamingo bootstrap binary and its
Nitro/S3 tooling; deployment adds the paired EIF at `/home/enclave.eif`.

The [Docker build workflow](../.github/workflows/build-docker.yml) checks both API and
provisioner images on pull requests without publishing. Its `verifier` workload
continues to select only the API image; `verifier-provisioner` selects the provisioner.

Deployment must consume `provisioner_image` by digest from the verified server
release, replacing the generic Tabernaculum provisioner base. The provisioner also
needs the provider's compact JWS mounted at `RELEASE_MANIFEST_PATH`; it sends the
worker first, then loads the manifest and checks enclave health before writing the
readiness file. This requires a deployment update: mounting the JWS only in the API
container does not initialize the release.

Keep the provisioner and EIF paired. This source uses Tabernaculum bundle schema 4,
which is incompatible with the schema 3 provisioner/receiver in Tabernaculum v0.1.0.
The deployment still supplies the worker archive and checksum separately; the
worker and provider manifest are not embedded in the public images.
