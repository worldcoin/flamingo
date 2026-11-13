#!/bin/bash
set -euo pipefail

# Fails unless each world-id-* version in the main Cargo.toml equals the pinned rev's, as
# e2e/Cargo.lock records it; otherwise [patch.crates-io] does not apply and the types split.

cd "$(dirname "$0")"
status=0
while read -r name version; do
    pinned="$(grep -A2 "^name = \"$name\"$" Cargo.lock | grep -B1 '^source = "git+' | sed -n 's/^version = "\(.*\)"$/\1/p')"
    if [[ "$pinned" != "$version" ]]; then
        echo "$name: main workspace has $version, the pinned rev has ${pinned:-none}" >&2
        status=1
    fi
done < <(sed -nE 's/^(world-id-[a-z-]+) = (\{ *version = )?"([^"]+)".*/\1 \3/p' ../Cargo.toml)
exit "$status"
