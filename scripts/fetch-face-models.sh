#!/bin/bash
set -euo pipefail

# Prime Nix's fixed-output store without exposing the Hugging Face token to a derivation.
cd "$(git rev-parse --show-toplevel)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
models_json="$(nix eval --json --no-update-lock-file .#faceModels)"

for file in $(jq -r 'keys[]' <<<"$models_json"); do
  store_path="$(jq -r --arg f "$file" '.[$f].storePath' <<<"$models_json")"
  if nix path-info "$store_path" >/dev/null 2>&1; then
    continue
  fi
  if [[ ! "${HUGGING_FACE_TOKEN:-}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "[ERROR] $file is missing; set a valid HUGGING_FACE_TOKEN with model read access." >&2
    exit 1
  fi

  url="$(jq -r --arg f "$file" '.[$f].url' <<<"$models_json")"
  expected="$(jq -r --arg f "$file" '.[$f].hash' <<<"$models_json")"
  # HTTPS-only redirects; curl does not forward authorization to the model CDN.
  # Config via stdin keeps the token out of argv, and validation prevents config injection.
  printf 'header = "Authorization: Bearer %s"\n' "$HUGGING_FACE_TOKEN" |
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -sSfL \
      --retry 3 --retry-all-errors --retry-max-time 600 --connect-timeout 10 --max-time 600 \
      --config - -o "$work_dir/$file" "$url"

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
