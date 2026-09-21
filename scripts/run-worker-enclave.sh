#!/bin/bash
# One owned enclave, with a watchdog spanning launch, upload and initialization.
set -euo pipefail
: "${EIF_PATH:=/home/enclave.eif}"
: "${WORKER_BUNDLE:=/home/worker.bundle}"
: "${WORKER_TOOL:=/home/sandbox-bundle}"
: "${WORKER_READY_FILE:=/run/flamingo/ready}"
: "${ENCLAVE_CPU_COUNT:=2}"
: "${ENCLAVE_MEMORY_SIZE:=4096}"
: "${BOOTSTRAP_TIMEOUT_SECONDS:=180}"
: "${PROVISIONING_IO_TIMEOUT_SECONDS:=120}"
: "${POLL_SECONDS:=2}"
: "${RETRY_SECONDS:=5}"

for number in "$BOOTSTRAP_TIMEOUT_SECONDS" "$PROVISIONING_IO_TIMEOUT_SECONDS" "$POLL_SECONDS" "$RETRY_SECONDS"; do
    [[ "$number" =~ ^[0-9]+$ ]] || exit 2
done
(( BOOTSTRAP_TIMEOUT_SECONDS > 0 && POLL_SECONDS > 0 && RETRY_SECONDS > 0 )) || exit 2
mkdir -p "$(dirname "$WORKER_READY_FILE")"
state=$(mktemp -d)
enclave_id=""
enclave_name=""
startup_pid=""

cleanup() {
    rm -f "$WORKER_READY_FILE"
    if [[ -n "$startup_pid" ]]; then
        kill -TERM "$startup_pid" 2>/dev/null || true
        wait "$startup_pid" 2>/dev/null || true
        startup_pid=""
    fi
    # A timed-out launch may have created the enclave before returning its JSON.
    # Recover only our unique name, never the first/another enclave on this host.
    if [[ -z "$enclave_id" && -n "$enclave_name" ]]; then
        enclave_id=$(nitro-cli describe-enclaves | jq -r --arg name "$enclave_name" '.[] | select(.EnclaveName == $name) | .EnclaveID')
    fi
    if [[ -n "$enclave_id" ]]; then
        if ! timeout --kill-after=5s 15s nitro-cli terminate-enclave --enclave-id "$enclave_id"; then
            # A crashed or externally terminated enclave may already be gone.
            # Confirm absence before retrying; a real cleanup failure must stop the carrier.
            local remaining present
            remaining=$(nitro-cli describe-enclaves) || return 1
            present=$(jq -er --arg id "$enclave_id" 'any(.[]; .EnclaveID == $id) | tostring' <<< "$remaining") || return 1
            [[ "$present" == false ]] || return 1
        fi
        enclave_id=""
    fi
}
shutdown() {
    trap '' TERM INT
    rm -f "$WORKER_READY_FILE"
    cleanup
    rm -rf "$state"
    exit 0
}
trap shutdown TERM INT
trap 'cleanup; rm -rf "$state"' EXIT

export EIF_PATH WORKER_BUNDLE WORKER_TOOL ENCLAVE_CPU_COUNT ENCLAVE_MEMORY_SIZE
export PROVISIONING_IO_TIMEOUT_SECONDS
attempt=0
while true; do
    rm -f "$WORKER_READY_FILE"
    attempt=$((attempt + 1))
    enclave_name="flamingo-${HOSTNAME:-host}-$$-$attempt"
    export enclave_name
    # timeout manages the entire process group so no uploader survives failure/retry.
    # shellcheck disable=SC2016 # Expanded inside the supervised child.
    timeout --signal=TERM --kill-after=5s "${BOOTSTRAP_TIMEOUT_SECONDS}s" bash -c '
        set -euo pipefail
        args=(--eif-path "$EIF_PATH" --cpu-count "$ENCLAVE_CPU_COUNT" --memory "$ENCLAVE_MEMORY_SIZE" --enclave-name "$enclave_name")
        if [[ -n "${ENCLAVE_CID:-}" ]]; then args+=(--enclave-cid "$ENCLAVE_CID"); fi
        nitro-cli run-enclave "${args[@]}" > "$1/launch.json"
        cid=$(jq -er .EnclaveCID "$1/launch.json")
        jq -er .EnclaveID "$1/launch.json" > "$1/enclave-id"
        "$WORKER_TOOL" send "$cid" "$WORKER_BUNDLE" "$PROVISIONING_IO_TIMEOUT_SECONDS"
        # Provisioning ACK proves initialized worker/key setup, not a bound serving socket.
        until "$WORKER_TOOL" health "$cid"; do sleep 0.2; done
    ' _ "$state" &
    startup_pid=$!
    if wait "$startup_pid"; then
        startup_pid=""
        enclave_id=$(cat "$state/enclave-id")
        enclave_cid=$(jq -er .EnclaveCID "$state/launch.json")
        touch "$WORKER_READY_FILE"
        echo "worker enclave ready: $enclave_id"
        while nitro-cli describe-enclaves | jq -e --arg id "$enclave_id" 'any(.[]; .EnclaveID == $id and .State == "RUNNING")' >/dev/null; do
            "$WORKER_TOOL" health "$enclave_cid" || break
            sleep "$POLL_SECONDS" & wait $! || true
        done
    else
        startup_pid=""
        echo "worker enclave bootstrap failed" >&2
    fi
    cleanup
    rm -f "$state/enclave-id" "$state/launch.json"
    sleep "$RETRY_SECONDS" & wait $! || true
done
