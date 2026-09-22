#!/bin/bash
# Linux contract tests. AWS/Nitro/Rust RPCs are mocked; tar, checksums and watchdogs are real.
set -euo pipefail
: "${CARRIER_BIN:?set CARRIER_BIN to the compiled flamingo-carrier}"
suite=$(mktemp -d)
carrier_pid=""
cleanup() {
    if [[ -n "$carrier_pid" ]]; then
        kill -TERM "$carrier_pid" 2>/dev/null || true
        wait "$carrier_pid" 2>/dev/null || true
    fi
    rm -rf -- "$suite"
}
trap cleanup EXIT
assert_not() { if "$@"; then echo "FAIL: unexpected success: $*"; exit 1; fi; }
mkdir -p "$suite/bin" "$suite/archive/release"
printf 'fixture worker\n' > "$suite/archive/release/biometric-engines-worker"
tar -czf "$suite/good.tar.gz" -C "$suite/archive" release
touch "$suite/enclave.eif"

cat > "$suite/bin/aws" <<'MOCK'
#!/bin/bash
set -euo pipefail
echo download >> "$CASE_DIR/events"
[[ "$SCENARIO" != download_fail ]] || exit 1
cp "$ARCHIVE" "$4"
MOCK
cat > "$suite/bin/readelf" <<'MOCK'
#!/bin/bash
case "$1" in
    -h) echo 'Machine: Advanced Micro Devices X86-64' ;;
    -l) if [[ "$SCENARIO" == dynamic ]]; then echo INTERP; else echo DYNAMIC; fi ;;
    -d) if [[ "$SCENARIO" == shared_library ]]; then echo '(NEEDED) libm.so'; fi ;;
esac
exit 0
MOCK
cat > "$suite/bin/nitro-cli" <<'MOCK'
#!/bin/bash
set -euo pipefail
case "$1" in
    run-enclave)
        echo launch >> "$CASE_DIR/events"
        [[ " $* " != *' --debug-mode '* ]]
        flags=NONE
        [[ "$SCENARIO" != debug ]] || flags=DEBUG_MODE
        name=""
        while (( $# > 0 )); do
            if [[ "$1" == --enclave-name ]]; then name=$2; break; fi
            shift
        done
        jq -n --arg name "$name" --arg flags "$flags" \
            '{EnclaveID:"owned",EnclaveName:$name,EnclaveCID:16,State:"RUNNING",Flags:$flags}' > "$CASE_DIR/owned"
        if [[ "$SCENARIO" == launch_timeout || "$SCENARIO" == signal_launch ]]; then sleep 30; fi
        cat "$CASE_DIR/owned"
        ;;
    describe-enclaves)
        if [[ -f "$CASE_DIR/owned" ]]; then
            jq -s '. + [{EnclaveID:"unrelated",EnclaveName:"another-owner",State:"RUNNING",Flags:"NONE"}]' "$CASE_DIR/owned"
        else
            echo '[{"EnclaveID":"unrelated","EnclaveName":"another-owner","State":"RUNNING","Flags":"NONE"}]'
        fi
        ;;
    terminate-enclave)
        [[ "$2" == --enclave-id && "$3" == owned ]] || exit 99
        echo terminate-owned >> "$CASE_DIR/events"
        [[ "$SCENARIO" != cleanup_fail ]] || exit 1
        rm -f "$CASE_DIR/owned"
        ;;
    *) exit 1 ;;
esac
MOCK
cat > "$suite/bin/sandbox-bundle" <<'MOCK'
#!/bin/bash
set -euo pipefail
case "$1" in
    manifest) echo '{}' ;;
    pack) cp "$3" "$4" ;;
    send)
        echo send >> "$CASE_DIR/events"
        [[ "$SCENARIO" != ack_fail ]] || exit 1
        if [[ "$SCENARIO" == send_timeout || "$SCENARIO" == signal_send ]]; then
            echo $$ > "$CASE_DIR/uploader-pid"
            trap '' TERM
            sleep 30
        fi
        ;;
    health)
        [[ "$SCENARIO" != health_timeout ]] || exit 1
        count=0
        [[ ! -f "$CASE_DIR/health-count" ]] || read -r count < "$CASE_DIR/health-count"
        count=$((count + 1))
        echo "$count" > "$CASE_DIR/health-count"
        if [[ "$SCENARIO" == health_fail || "$SCENARIO" == cleanup_fail ]]; then
            (( count < 3 )) || exit 1
        fi
        ;;
    *) exit 1 ;;
esac
MOCK
chmod +x "$suite/bin/"*
export PATH="$suite/bin:$PATH"
export EIF_PATH="$suite/enclave.eif" WORKER_TOOL="$suite/bin/sandbox-bundle"
export WORKER_ENVIRONMENT=dev WORKER_RELEASE_ID=biometric-engines-worker-v0.1.0-test
export WORKER_ARTIFACT_URI=s3://biometric-engines-worker-dev-eu-central-1/worker/v0.1.0-test/biometric-engines-worker-v0.1.0-test-x86_64-unknown-linux-gnu.tar.gz
export BOOTSTRAP_TIMEOUT_SECONDS=2 POLL_SECONDS=1

run_case() {
    export SCENARIO=$1 CASE_DIR="$suite/$1" ARCHIVE="${2:-$suite/good.tar.gz}"
    mkdir -p "$CASE_DIR"
    export WORKER_READY_FILE="$CASE_DIR/ready"
    WORKER_ARTIFACT_SHA256=$(sha256sum "$ARCHIVE" | cut -d ' ' -f 1)
    export WORKER_ARTIFACT_SHA256
    if [[ "$SCENARIO" == checksum ]]; then WORKER_ARTIFACT_SHA256=$(printf '%064d' 1); fi
    if [[ "$SCENARIO" == invalid_pin ]]; then WORKER_ARTIFACT_SHA256=placeholder; touch "$WORKER_READY_FILE"; fi
    if [[ "$SCENARIO" == wrong_bucket ]]; then WORKER_ENVIRONMENT=stage; fi
    "$CARRIER_BIN" > "$CASE_DIR/output" 2>&1 &
    carrier_pid=$!
}
finish_failure() {
    if wait "$carrier_pid"; then echo "FAIL: $SCENARIO unexpectedly succeeded"; exit 1; fi
    carrier_pid=""
    [[ ! -e "$WORKER_READY_FILE" ]] || { echo "FAIL: $SCENARIO left readiness"; exit 1; }
    if [[ "$SCENARIO" != cleanup_fail ]]; then [[ ! -e "$CASE_DIR/owned" ]]; fi
    echo "PASS: $SCENARIO"
}

run_case happy
for ((i=0; i<100; i++)); do
    [[ ! -f "$WORKER_READY_FILE" ]] || break
    sleep 0.05
done
[[ -f "$WORKER_READY_FILE" ]]
kill -TERM "$carrier_pid"
wait "$carrier_pid"
carrier_pid=""
[[ ! -e "$WORKER_READY_FILE" && ! -e "$CASE_DIR/owned" ]]
[[ $(grep -c '^launch$' "$CASE_DIR/events") == 1 ]]
grep -q '^terminate-owned$' "$CASE_DIR/events"
echo 'PASS: successful provisioning, live readiness, SIGTERM and owned-only cleanup'

for scenario in invalid_pin wrong_bucket download_fail checksum dynamic shared_library; do
    run_case "$scenario"
    finish_failure
    assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null
    WORKER_ENVIRONMENT=dev
done
for scenario in ack_fail launch_timeout send_timeout health_timeout debug health_fail cleanup_fail; do
    run_case "$scenario"
    finish_failure
    [[ $(grep -c '^launch$' "$CASE_DIR/events") == 1 ]]
    grep -q '^terminate-owned$' "$CASE_DIR/events"
    if [[ "$scenario" == send_timeout ]]; then
        read -r uploader_pid < "$CASE_DIR/uploader-pid"
        # A killed grandchild can briefly remain a zombie until init reaps it.
        uploader_state=""
        if [[ -r "/proc/$uploader_pid/stat" ]]; then
            read -r _ _ uploader_state _ < "/proc/$uploader_pid/stat" || true
        fi
        [[ -z "$uploader_state" || "$uploader_state" == Z* ]]
    fi
done

for scenario in signal_launch signal_send; do
    run_case "$scenario"
    event=launch
    [[ "$scenario" != signal_send ]] || event=send
    for ((i=0; i<100; i++)); do
        if grep -q "^$event$" "$CASE_DIR/events" 2>/dev/null; then break; fi
        sleep 0.01
    done
    grep -q "^$event$" "$CASE_DIR/events"
    kill -TERM "$carrier_pid"
    wait "$carrier_pid"
    carrier_pid=""
    [[ ! -e "$WORKER_READY_FILE" && ! -e "$CASE_DIR/owned" ]]
    grep -q '^terminate-owned$' "$CASE_DIR/events"
    echo "PASS: $scenario"
done

mkdir -p "$suite/bad/release"
ln -s /etc/passwd "$suite/bad/release/biometric-engines-worker"
tar -czf "$suite/link.tar.gz" -C "$suite/bad" release
run_case symlink "$suite/link.tar.gz"
finish_failure
assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null

tar -czf "$suite/duplicate.tar.gz" -C "$suite/archive" release/biometric-engines-worker release/biometric-engines-worker
run_case duplicate "$suite/duplicate.tar.gz"
finish_failure
assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null

printf 'unexpected library\n' > "$suite/archive/release/library.so"
tar -czf "$suite/extra.tar.gz" -C "$suite/archive" release
run_case extra_file "$suite/extra.tar.gz"
finish_failure
assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null
echo 'All carrier contract tests passed.'
