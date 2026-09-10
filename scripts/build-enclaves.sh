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
# Verifier releases require reviewed publisher keys and worker resource budgets in
# config/worker-bootstrap.json. Public Nix builds may use the unconfigured, fail-closed file.

# A new workload is an entry here plus a `<name>-eif` output in flake.nix.
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

if [[ ! " ${WORKLOADS[*]} " == *" $workload "* ]]; then
  echo "[ERROR] Unknown workload: $workload (expected one of: ${WORKLOADS[*]})" >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ "$workload" == "verifier" ]]; then
  if [[ "$(wc -c < config/worker-bootstrap.json)" -gt 65536 ]] || ! jq -e '
    (.publisher_keys | type == "array" and length > 0) and
    all(.max_bundle_bytes, .address_space_bytes, .max_threads, .bootstrap_timeout_seconds;
      . != null)
  ' config/worker-bootstrap.json >/dev/null; then
    echo "[ERROR] Configure reviewed publisher keys and qualified worker budgets in config/worker-bootstrap.json before a verifier release build." >&2
    echo "        For an unconfigured, fail-closed development image use nix build .#verifier-eif directly." >&2
    exit 1
  fi
fi

command -v nix >/dev/null || {
  echo "[ERROR] nix not found. The OCI image and EIF are built by flake.nix." >&2
  exit 1
}

if [[ "$workload" == "verifier" ]]; then
  # Use the exact broker parser, curve validation and integer bounds, not a shell approximation.
  nix run --no-update-lock-file .#worker-bundle -- validate-config config/worker-bootstrap.json
fi

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

# --no-update-lock-file on the flake calls below: an input added to flake.nix without a
# matching `nix flake update` would otherwise be resolved to whatever upstream serves right
# now, and the lock silently rewritten. The PCRs must follow the committed lock or nothing.
echo "Building reproducible $workload OCI image..."
if ! oci_store=$(nix build ".#${workload}-oci" --no-update-lock-file --no-link --print-out-paths); then
  echo >&2
  echo "[ERROR] OCI image build failed; the error above says why. A 'platform" >&2
  echo "        mismatch' for x86_64-linux means this host needs a remote builder." >&2
  exit 1
fi

echo "Building $workload EIF..."
if ! eif_store=$(nix build ".#${workload}-eif" --no-update-lock-file --no-link --print-out-paths); then
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
