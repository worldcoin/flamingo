# Development

## Setup and checks

Use the Rust toolchain in [`rust-toolchain.toml`](../rust-toolchain.toml). Git credentials must allow access to the private `worldcoin/biometric-engines` dependency. The Nix development shell supplies Rust, Clang, pkg-config, jq, and Linux sandbox dependencies:

```bash
nix develop
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features --exclude flamingo-verifier-worker-process
cargo deny --all-features check
```

Install `cargo-deny` separately. Minijail process tests need x86_64 Linux and root privileges; [Rust CI](../.github/workflows/rust-ci.yml) shows how to build and run that test binary separately.

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

Start the EIF with `nitro-cli run-enclave`, using the CPU and memory allocation for your instance. Use a normal enclave by default. For Nitro `--debug-mode`, explicitly enable the [development-only debug measurement option](api.md#client-configuration) and pin its zero PCRs. Set `ENCLAVE_CID` to the running enclave's CID; its vsock port is `1000`.

```bash
RUST_LOG=info ENCLAVE_CID=16 ENCLAVE_PORT=1000 \
  cargo run --locked --bin flamingo-verifier-host
```

The host listens on port `8000` by default; `PORT` overrides it. In another shell:

```bash
curl --fail http://localhost:8000/health
curl --fail http://localhost:8000/ready
```

The enclave binary, `verifier-enclave`, requires the Nitro Secure Module and its hardware RNG. Run it through the EIF.

Create `client.json` using the [client configuration](api.md#client-configuration), then supply the three images:

```bash
VERIFIER_CONFIG=./client.json cargo run --locked --bin flamingo-verifier-e2e -- \
  credential.png live.png challenge.png
```

The harness fetches an assignment, submits an encrypted DeepFace request, and verifies the result. It defaults to a `0.9` threshold; `MATCH_THRESHOLD` overrides it. It creates `hashes.json` from the supplied credential image for this test. Real callers must supply the credential's original `hashes.json`.
