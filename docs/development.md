# Development

## Setup and checks

Use the Rust toolchain in [`rust-toolchain.toml`](../rust-toolchain.toml). Git credentials must allow access to the private `worldcoin/biometric-engines` dependency. The Nix development shell supplies Rust, Clang, pkg-config, jq, and Linux sandbox dependencies:

```bash
nix develop
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
cargo deny --all-features check
```

Install `cargo-deny` separately. Minijail process tests live in [tabernaculum](https://github.com/worldcoin/tabernaculum).

## Build images

Build on x86_64 Linux with Nix, jq, and curl. Nitro hardware is only needed to run the enclave. Git must have access to `biometric-engines`; set `HUGGING_FACE_TOKEN` to fetch private models that are not already in the Nix store.

```bash
scripts/build-enclaves.sh --workload verifier
jq . target/eif/verifier-pcr.json
```

The script builds a reproducible OCI image and writes `target/eif/verifier-enclave.eif` and `target/eif/verifier-pcr.json`. Both images use the same root filesystem. Expect about 90 minutes for a cold build.

To build and inspect only the OCI image after fetching the models:

```bash
nix build --no-update-lock-file .#verifier-oci
skopeo inspect \
  "oci:$(readlink -f result):$(nix eval --raw --no-update-lock-file .#packages.x86_64-linux.verifier-enclave.version)"
```

Install `skopeo` separately. The [Docker workflow](../.github/workflows/build-docker.yml) builds host images; Nix builds enclave images. See [releases](release.md) for publishing and measurement changes.

## Prepare a Nitro host

Use an Amazon Linux 2023 EC2 instance that supports Nitro Enclaves, with enclaves enabled at launch. Restrict inbound SSH to your IP. Install the runtime:

```bash
sudo dnf install -y docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker
```

Set the enclave's CPU and memory reservation in `/etc/nitro_enclaves/allocator.yaml`, then restart the allocator service. Reconnect after changing group membership and check the runtime:

```bash
nitro-cli --version
nitro-cli describe-enclaves
docker version
```

## Run the host and a match

Use the Rust provisioner in [flamingo-deploy](https://github.com/worldcoin/flamingo-deploy)
to launch the EIF, sideload its worker, load the matching WIP-201 manifest, and check enclave
health before publishing readiness. The provisioner receives `RELEASE_MANIFEST_PATH`; the API
host can start independently. Use a normal enclave, since the client rejects debug measurements.
Set `ENCLAVE_CID` to the provisioned enclave's CID; its vsock port is `1000`.

Flamingo pins Tabernaculum `v0.2.0` (bootstrap format 4). The deploy-owned provisioner
must use the matching release. Rebuild the EIF and deploy it with the matching provisioner;
the Tabernaculum v0.1.0 provisioner image uses the incompatible format 3.

The host reads every setting from an environment variable and an equivalent CLI flag, with a flag overriding its variable:

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--app-env` | `APP_ENV` | `development` | `production`, `staging`, or `development`. |
| `--enclave-cid` | `ENCLAVE_CID` | required | Nitro enclave CID. |
| `--enclave-port` | `ENCLAVE_PORT` | required | Enclave Pontifex port. |
| `--engine-provider-metadata` | `ENGINE_PROVIDER_METADATA` | unset | Complete public WIP-201 provider JSON; unset disables discovery. |
| `--port` | `PORT` | `8000` | API listen port. |
| `--ws-idle-timeout-secs` | `WS_IDLE_TIMEOUT_SECS` | `30` | Idle deadline for each WebSocket session phase. |
| `--ws-max-connections` | `WS_MAX_CONNECTIONS` | `100` | Concurrent WebSocket sessions per host process. |

`PORT`, `WS_IDLE_TIMEOUT_SECS`, and `WS_MAX_CONNECTIONS` reject zero. The API host publishes configured provider metadata but does not provision enclave manifests. The enclave accepts only a manifest whose `engine_hash` matches the SHA-256 of its worker executable and reports not ready until the provisioner has loaded it.

```bash
RUST_LOG=info ENCLAVE_CID=16 ENCLAVE_PORT=1000 \
  cargo run --locked --bin flamingo-verifier-host
```

In another shell:

```bash
curl --fail http://localhost:8000/health
curl --fail http://localhost:8000/ready
```

The enclave binary, `verifier-enclave`, requires the Nitro Secure Module and its hardware RNG. Run it through the EIF.

Create `client.json` using the [client configuration](api.md#client-configuration), pinning PCR0–2 from the verified server release. Obtain the selected engine release's `world-id-engine.json` from the signing workflow and independently enroll its provider JWK as `trusted-provider-dev.jwk.json`. Check that public key against the trusted KMS/provider identity; accepting a key merely because it accompanies a manifest does not establish trust. Then supply the reviewed release hash and the three images:

```bash
VERIFIER_CONFIG=./client.json \
PROVIDER_METADATA=./signed/world-id-engine.json \
PROVIDER_KEY=./trusted-provider-dev.jwk.json \
EXPECTED_RELEASE_HASH="<reviewed-64-character-release-hash>" \
  cargo run --locked --bin flamingo-verifier-e2e -- credential.png live.png challenge.png
```

For cluster testing, an authorized `kubectl -n flamingo-verifier port-forward deployment/flamingo-verifier 8000:8000` exposes the internal API locally. Set `host_url` to `http://127.0.0.1:8000`; the client still verifies Nitro attestation and encrypts the biometric request. This tests the enclave path, not the external attested-proxy/gateway admission layer, whose authenticated handshake needs a separate client test.

The harness verifies the selected active manifest under the independently trusted provider key, requires that exact release to be offered by the host, and rejects measurement bypass. It opens one WebSocket session, verifies the Nitro assignment against the configured PCR0–2, seals the DeepFace request to the attested channel key, and verifies the returned Flamingo Token, signing-key attestation and claims. Match strictness defaults to `2`; an override must be declared by the selected manifest.

For a known rejection fixture, set `EXPECTED_OUTCOME=reject` and an exact serialized `EXPECTED_FAILURE`, for example `EXPECTED_FAILURE='"biometric_rejected"'`. Only that sealed rejection counts as success; transport, attestation, signature, internal and timeout failures fail the run. The default outcome is a successful signed match. Also verify that substituting an untrusted provider key, another release hash or incorrect PCRs fails before a successful match. No debug report or biometric data is printed.

`MATCH_OPERATION=gray_badge` runs the credential-free operation instead and takes only `<live-image> <challenge-image>`. `LIGHT_GUARD_UNILLUMINATED_IMAGE` adds the second frame and `LIGHT_GUARD_MATCHING_FRAME` selects `illuminated` (default) or `unilluminated`.
