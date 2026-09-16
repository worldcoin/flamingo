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
│   ├── api-types/         # Client↔host HTTP contract; stops at the host, so no enclave links it
│   ├── enclave-types/     # Host↔enclave vsock contract: health, errors, key attestation, the match exchange
│   ├── sealed-types/      # Sealed client↔enclave match payload; the host relays it, so the host does not link this
│   ├── protocol/          # The signed match statement a held match produces. Will likely move to `world-id-protocol`.
│   ├── client/            # Attestation-verifying client
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

### Three workspaces, three lockfiles

Each enclave is its own cargo workspace. One lockfile for the whole repository meant a
`flamingo-verifier-host` dependency bump re-resolved the enclave graph and moved PCR0, which clients
pin. Now an EIF's inputs are its own `Cargo.toml`, the `Cargo.lock` beside it, and the path
crates they name.

`attested-channel`, `flamingo-verifier-protocol`, `flamingo-verifier-sealed-types` and
`flamingo-verifier-enclave-types` are in both an enclave
graph and the host-side one. They are members of the root workspace but inherit nothing from it
— not `[workspace.dependencies]`, not `[workspace.package]` — so the root manifest cannot reach
an enclave graph either. Treat them as standalone crates: write the version, and the `edition`,
in their own manifest. `flamingo-verifier-api-types` is host-side only and inherits normally.

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

`POST /v1/matches` compares a credential image against a live frame and the RP's challenge
frame. The host relays but cannot read anything it carries:

```json
{ "ciphertext": "<base64 enc || ciphertext>" }
```

`ciphertext` is the match inputs sealed to the enclave's attested encryption key — all three
frames and `hashes.json`. The requester downloads the challenge frame from the RP and seals it
along with the rest, so the host has nothing to look up and no plaintext field it could be
steered by.

Nothing in the payload proves the challenge frame is the one the RP issued. The enclave commits to
whatever it compared, as `challenger_image_hash`, and the RP rejects a statement whose hash is not
the one it retained — that comparison is the entire binding.

The sealed payload also carries an optional `light_guard_image`, a second liveness frame. Omitting
it selects vanilla mode, the flow described here. Sending one selects LightGuard — challenge-response
spoof detection — which **is not implemented**: the enclave panics on such a request today.

```json
{ "response_ciphertext": "<base64 nonce || ciphertext>" }
```

The sealed response carries either a `COSE_Sign1` match statement or the reason no statement was
issued. A statement travels with the signing key's attestation sealed beside it, since that
document is the only thing saying which enclave signed it. A rejection carries no document.
Only the requester can open any of it — a second channel to the same enclave key cannot.

The signing key's attestation is a separate document from the encryption key's on purpose: it
outlives the exchange and is carried into the `Verifier` proof, while the encryption key's is
transport setup discarded with the channel.

The host learns only that the enclave answered. Once a request has been opened there is a sealed
channel to reply on, so everything the enclave discovers from that point — a malformed payload, an
unusable `hashes.json`, an image refused on quality grounds, a below-threshold score, an unusable
challenge frame — travels inside `response_ciphertext`. None of it reaches the status code.

| Status | Meaning |
| --- | --- |
| `200` | The enclave answered; the sealed payload holds the outcome |
| `409` `reassign_required` | The request did not open, so there was no channel to reply on; re-assign and re-seal, once |
| `413` `request_too_large` | The body exceeded the route's ceiling; nothing was forwarded |
| `400` `invalid_request` | The body was not the expected JSON, or `ciphertext` was not base64 |
| `500` `internal_error` | Enclave fault |

`409` is the only *opened*-request failure with a status of its own, because with no channel open
there is nothing to seal a reply into. Everything else the host might want — how often matches fail,
how often a requester sends an unusable frame — has to come from enclave-side metrics rather than
from status codes. A challenge frame the requester could not download never reaches this service at
all, so do not look for it here.

### The body ceiling

All three frames arrive inside one sealed payload, so the request body is the only thing bounding
what the host buffers and what the enclave is then asked to allocate — the vsock framing takes the
host's word for a length. `MAX_BODY_BYTES` in `verifier/host/src/routes/matches.rs` sets it to
12 MiB, budgeting ~7 MiB of images plus the ~1.37x that CBOR framing, HPKE overhead and base64 add.

It hangs off the match route alone. Assignment sends no body and the health routes are `GET`s, so
allowing multi-megabyte requests there would widen the service's ingress for nothing. Over-limit
bodies come back as `413 request_too_large` in the usual envelope rather than as a bare status.

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
