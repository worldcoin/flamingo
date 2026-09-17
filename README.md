# Flamingo

TODO: This Readme contains a lot of AI slob and needs to be fully reworked once we move out of prototyping phase.

Rust workspaces for the Flamingo Verifier host and secure enclave.

## Structure

Two workloads over the same host/enclave shape — the `Verifier` verifier and the
`DeepIdentifier` migration. Each owns a top-level directory; what both would duplicate
lives in `shared/`. Crate names compose from the path: `verifier/host` is `flamingo-verifier-host`.

```text
verifier/
├── Cargo.toml             # Host-side workspace  -> Cargo.lock
├── shared/
│   └── attested-channel/  # Client↔enclave channel and the attestation it rests on; destined for pontifex
├── verifier/
│   ├── host/              # Axum HTTP API — the untrusted side of the boundary
│   ├── enclave/           # Nitro enclave workload — the trusted side. Own workspace -> own Cargo.lock
│   ├── enclave-types/     # Host↔enclave vsock contract: health, errors, key attestation, the match exchange
│   ├── api-types/         # Unpublished wrapper for shared HTTP types
│   ├── protocol/          # Unpublished wrapper for shared signed claims
│   ├── sealed-types/      # Unpublished wrapper for shared sealed payloads
│   ├── client/            # Published client, HTTP API, signed protocol and sealed payload types
│   └── e2e/               # End-to-end harness driving host and enclave together
└── di/                    # Skeleton — dirs and crates only, no behaviour yet
    ├── host/
    └── enclave/           # Own workspace -> own Cargo.lock
```

One crate per boundary, in the graphs that boundary reaches. Nothing is shared between
`verifier/` and `di/`, because a shared crate means a `flamingo-verifier` edit rotates `di`'s PCR0.

`di-host` and `di-enclave` log and exit non-zero — a skeleton that idled would read as healthy. See
[Spec: DeepIdentifier Migration TEE Setup v1](https://app.notion.com/p/worldcoin/Spec-DeepIdentifier-Migration-TEE-Setup-v1-3c08614bdf8c8014b7ddf50f3cac4e4b)
for what goes in them.

### Rust client

`flamingo-verifier-client` is the only published crate. Consumers use its `api_types`,
`protocol` and `sealed_types` modules alongside `FlamingoVerifierClient`:

```rust
use flamingo_verifier_client::{FlamingoVerifierClient, Config};
use flamingo_verifier_client::protocol::match_token::MatchClaims;
use flamingo_verifier_client::sealed_types::MatchInputs;
```

The host and enclave depend on unpublished `api-types`, `protocol` and `sealed-types`
crates. These crates use `#[path]` modules to compile the same source files shipped inside
`client/src`; neither depends on the client. Keep shared implementations in that directory
so the published client package is self-contained. There is no source copying or build-time
code generation.

The internal crates and client compile separate Rust types from the shared source. Use one
family consistently within a process; the host/enclave boundary uses serialized messages.
External dependency versions are shared through the workspace manifests.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --
cargo test --workspace --all-features
cargo deny --all-features check
```

```bash
# Run the host on http://localhost:8000
# ENCLAVE_CID and ENCLAVE_PORT are required; the process panics without them. The host pins no
# measurements of its own -- it is the untrusted side, and it is the client that pins PCR0.
RUST_LOG=info ENCLAVE_CID=16 ENCLAVE_PORT=1000 cargo run --bin flamingo-verifier-host
curl http://localhost:8000/health

# Run the secure enclave placeholder
RUST_LOG=info cargo run --bin flamingo-verifier-enclave
```

## Building images

Each workload has a host image, a reproducible OCI enclave image, and an AWS Nitro EIF.
Nix builds the OCI image and converts its root filesystem directly with aws-nitro-util.
`build-docker.yml` only builds and publishes hosts.

```bash
# Reproducible OCI image -> deterministic EIF + PCRs.
# Needs Linux x86_64; Nitro hardware is only needed to run.
scripts/build-enclaves.sh --workload verifier   # -> target/eif/verifier-enclave.eif, verifier-pcr.json
scripts/build-enclaves.sh --workload di         # -> target/eif/di-enclave.eif, di-pcr.json

# Build or inspect only the reproducible OCI boundary.
nix build .#di-oci
skopeo inspect \
  "oci:$(readlink -f result):$(nix eval --raw .#packages.x86_64-linux.di-enclave.version)"

```

`GIT_HUB_TOKEN` and `HUGGING_FACE_TOKEN` are both `verifier`-only. The whole Cargo workspace
is resolved from the root lockfile; `di` itself has no private dependencies or models.

`di-enclave` exits non-zero on start, so its EIF builds and measures but will not stay
running, until the boot sequence lands.

## Enclave assignment

`POST /v1/enclave-assignment` returns the enclave's encryption-key attestation and nothing
else:

```json
{ "attestation": "<base64 COSE_Sign1>" }
```

The enclave's identity (`module_id`) and expiry (the leaf certificate's `notAfter`) are read
from the document *after* verifying it, never from fields the untrusted host could set.

Documents are served from an in-enclave cache. After boot starts background refresh, a task
re-attests every 10 minutes (`MAX_CACHED_AGE`); requests always receive the last successful
document immediately, including past `MAX_CACHED_AGE` if a refresh is in flight or has failed.
Attest errors do not block serving until the document is older than `MAX_SERVABLE_AGE` (1 hour),
at which point the refresh task exits and the enclave process exits. The cache is boot-scoped,
so a restart takes it along and there is nothing for the host to invalidate.

`flamingo-verifier-client` verifies the document — the COSE signature, the certificate chain up to the
pinned AWS Nitro root, and the expected measurements. It is configured by a JSON file, in the
shape `world-id-protocol` uses for an authenticator:

```json
{
  "host_url": "http://localhost:8000",
  "allowed_pcr_configs": [
    [{ "index": 0, "value": "<PCR0 hex from flamingo-verifier-pcrs.json>" }]
  ],
  "max_attestation_age_millis": 3600000,
  "allow_debug_measurements": false
}
```

Only `host_url` and `allowed_pcr_configs` are required; the rest have defaults. A
configuration that pins no measurements is rejected — with nothing pinned, verification only
proves a document came from *some* enclave. A `--debug-mode` enclave reports all-zero PCRs and
its memory is readable from the parent instance, so it is rejected unless
`allow_debug_measurements` is set.

`flamingo-verifier-e2e` reads that file from `VERIFIER_CONFIG` and fetches its encryption key
through the host, exercising the assignment route and the client together:

```bash
VERIFIER_CONFIG=./client.json cargo run --bin flamingo-verifier-e2e -- <credential> <live> <challenge>
```

## Matches

`POST /v1/matches` accepts and returns raw encrypted bytes with
`Content-Type: application/octet-stream`. There is no JSON/base64 match envelope.
The plaintext remains CBOR, with exactly one `deep_face` or `gray_badge` operation.
DeepFace requires all three Orb/live/challenge similarities to meet a normalized `[0, 1]`
threshold. Both operations have explicit vanilla/LightGuard capture variants. GrayBadge
currently returns encrypted `unsupported_operation` pending its signed-token contract;
LightGuard returns encrypted `unsupported_capture`.

A `200` response contains a padded encrypted success or failure. Successful DeepFace
statements retain the legacy token format: live and challenge image hashes, a hash of the
credential claims, and the credential/live score. The threshold and other two scores are
not included in the signed token. The client returns parsed, verified claims alongside the
token and signing-key attestation. Infrastructure
errors retain the JSON error envelope; `409 reassign_required` requires fresh assignment and
resealing, with at most one retry. `415` rejects the old JSON transport and `413` enforces the
binary body limit.

## Nitro-enabled development host

Use an Amazon Linux 2023 EC2 instance type that supports Nitro Enclaves and launch it with
Nitro Enclaves enabled. Limit inbound SSH access to your current public IP.

On the instance, install the development tools and Nitro Enclaves runtime:

```bash
sudo dnf install -y \
  git wget jq tmux tree unzip tar gzip \
  gcc gcc-c++ make cmake clang pkgconf-pkg-config openssl-devel \
  bubblewrap docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker
```

These commands follow the [AWS Nitro Enclaves setup for Amazon Linux 2023](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).

The allocator defaults to 2 vCPUs and 512 MiB. Adjust
`/etc/nitro_enclaves/allocator.yaml` before starting the service when the enclave needs more.
Log out and reconnect after changing group membership, then verify the host:

```bash
nitro-cli --version
nitro-cli describe-enclaves
docker version
```

Install Rust and the components these workspaces use:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
for ws in . verifier/enclave di/enclave; do cargo test --manifest-path "$ws/Cargo.toml" --all; done
```

For private repository access, install and authenticate the GitHub CLI using its
[official RPM instructions](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#dnf4).

Optionally install Codex for development on the remote host:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
exec "$SHELL" -l
codex login --device-auth
codex doctor
```

To use the Codex desktop app, add a concrete host alias to your local `~/.ssh/config`, confirm
`ssh <alias>` works, then select the host and repository path under **Settings > Connections**.
See the [Codex remote connection guide](https://learn.chatgpt.com/docs/remote-connections#connect-to-an-ssh-host).
