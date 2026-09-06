#!/bin/bash
set -euo pipefail

# Build a workload's enclave EIF and emit its PCR measurements.
#
# Nix constructs a reproducible OCI image and converts its root filesystem directly into
# an EIF with aws-nitro-util and AWS's EIF builder.
#
# Needs x86_64-linux. Nitro hardware is only needed to run.
#
# Usage: scripts/build-enclaves.sh [--workload <name>] [output-dir]
#        (workload defaults to verifier, output-dir to target/eif)
#
# Outputs in <output-dir>:
#   <workload>-enclave.eif   the enclave image
#   <workload>-pcr.json      PCR measurements extracted from the EIF
#
# Env: HUGGING_FACE_TOKEN (verifier only, and only when a model is not in the store
#      yet — read access to the model repositories).

# Workload names map to the package names exported by flake.nix below.
WORKLOADS=("verifier" "di")

usage() {
  printf '%s\n' \
    "Usage: scripts/build-enclaves.sh [--workload <name>] [output-dir]" \
    "" \
    "Build a workload's enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --workload <name>  Which enclave to build: ${WORKLOADS[*]} (default verifier)." \
    "  -h, --help         Show this help."
}

workload="verifier"
out_dir="target/eif"
output_dir_provided=false
while (( $# > 0 )); do
  case "$1" in
    --workload)
      if (( $# < 2 )); then
        echo "[ERROR] --workload needs a value." >&2
        exit 2
      fi
      workload="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[ERROR] Unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [[ "$output_dir_provided" == "true" ]]; then
        echo "[ERROR] Only one output directory may be provided." >&2
        exit 2
      fi
      out_dir="$1"
      output_dir_provided=true
      ;;
  esac
  shift
done

case "$workload" in
  verifier) package="flamingo-verifier" ;;
  di) package="di" ;;
  *) echo "[ERROR] Unknown workload: $workload (expected one of: ${WORKLOADS[*]})" >&2; exit 2 ;;
esac

command -v nix >/dev/null || {
  echo "[ERROR] nix not found. The OCI image and EIF are built by flake.nix." >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# Fetch the models outside Nix and add them to the store under the fixed-output hash
# flake.nix declares, which leaves the fetch in the build already satisfied. The token
# is used here and nowhere else, so it never reaches a derivation or the store.
#
# --no-update-lock-file on the flake calls below: an input added to flake.nix without a
# matching `nix flake update` would otherwise be resolved to whatever upstream serves right
# now, and the lock silently rewritten. The PCRs must follow the committed lock or nothing.
if [[ "$workload" == "verifier" ]]; then
  echo "Fetching face models..."
  models_json="$(nix eval --json --no-update-lock-file .#faceModels)"

  for file in $(jq -r 'keys[]' <<<"$models_json"); do
    store_path="$(jq -r --arg f "$file" '.[$f].storePath' <<<"$models_json")"
    if nix path-info "$store_path" >/dev/null 2>&1; then
      echo "  $file: already in the store"
      continue
    fi

    if [[ -z "${HUGGING_FACE_TOKEN:-}" ]]; then
      echo "[ERROR] $file is not in the store and HUGGING_FACE_TOKEN is unset." >&2
      echo "        The token is only needed to fetch a model that is missing; rebuilding" >&2
      echo "        a commit whose models are already in the store needs neither." >&2
      exit 1
    fi

    url="$(jq -r --arg f "$file" '.[$f].url' <<<"$models_json")"
    expected="$(jq -r --arg f "$file" '.[$f].hash' <<<"$models_json")"
    echo "  $file: downloading"
    # --fail so an HTML error page never gets hashed as if it were a model. The token goes
    # to huggingface.co only; curl does not follow it across the redirect to the CDN, which
    # carries its own signature. It arrives through --config so it never appears in argv,
    # where anyone running `ps` on the build host could read it.
    printf 'header = "Authorization: Bearer %s"\n' "$HUGGING_FACE_TOKEN" |
      curl --proto '=https' --tlsv1.2 -sSfL \
        --retry 3 --retry-all-errors --connect-timeout 10 --max-time 600 \
        --config - \
        -o "$work_dir/$file" "$url"

    observed="$(nix hash file --type sha256 --base16 "$work_dir/$file")"
    if [[ "$observed" != "$expected" ]]; then
      echo "[ERROR] checksum mismatch for $file: expected $expected, got $observed" >&2
      exit 1
    fi

    added="$(nix-store --add-fixed sha256 "$work_dir/$file")"
    if [[ "$added" != "$store_path" ]]; then
      echo "[ERROR] $file landed at $added, but the build expects $store_path" >&2
      exit 1
    fi
  done
fi

echo "Building reproducible $workload OCI image..."
if ! oci_store=$(nix build ".#${package}-oci" --no-update-lock-file --no-link --print-out-paths); then
  echo >&2
  echo "[ERROR] OCI image build failed; the error above says why. A 'platform" >&2
  echo "        mismatch' for x86_64-linux means this host needs a remote builder." >&2
  exit 1
fi

echo "Building $workload EIF..."
if ! eif_store=$(nix build ".#${package}-eif" --no-update-lock-file --no-link --print-out-paths); then
  echo >&2
  echo "[ERROR] EIF build failed; the error above says why." >&2
  exit 1
fi

install -m 0644 "$eif_store/image.eif" "$out_dir/$workload-enclave.eif"
install -m 0644 "$eif_store/pcr.json" "$out_dir/$workload-pcr.json"

echo "Validating measurements..."
# Registering a missing or malformed PCR with a client would weaken verification.
for pcr in PCR0 PCR1 PCR2; do
  value="$(jq -r --arg k "$pcr" '.[$k] // ""' "$out_dir/$workload-pcr.json")"
  if [[ ! "$value" =~ ^[0-9a-f]{96}$ ]]; then
    echo "[ERROR] $workload-pcr.json holds no usable $pcr (got '$value')." >&2
    echo "        eif_build's output format may have changed; do not register these." >&2
    exit 1
  fi
done

echo
echo "OCI image:    $oci_store"
echo "EIF:          $out_dir/$workload-enclave.eif"
echo "Measurements: $out_dir/$workload-pcr.json"
jq . "$out_dir/$workload-pcr.json"
