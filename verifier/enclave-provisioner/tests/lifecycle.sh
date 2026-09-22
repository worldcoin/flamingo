#!/bin/bash
# Linux bootstrap/cleanup tests. AWS and Nitro are mocked.
# Direct bundle transfer and cancellation are tested in sandbox-bundle.
set -euo pipefail
: "${PROVISIONER_BIN:?set PROVISIONER_BIN to the compiled flamingo-enclave-provisioner}"
suite=$(mktemp -d)
provisioner_pid=""
cleanup() {
    if [[ -n "$provisioner_pid" ]]; then
        kill -TERM "$provisioner_pid" 2>/dev/null || true
        wait "$provisioner_pid" 2>/dev/null || true
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
        echo launch >> "$CASE_DIR/events"
        if [[ "$SCENARIO" == launch_fail || "$SCENARIO" == cleanup_fail ]]; then exit 1; fi
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
chmod +x "$suite/bin/"*
export PATH="$suite/bin:$PATH"
export EIF_PATH="$suite/enclave.eif"
export BUNDLE_ENVIRONMENT=dev BUNDLE_RELEASE_ID=biometric-engines-worker-v0.1.0-test
export BUNDLE_ARTIFACT_URI=s3://biometric-engines-worker-dev-eu-central-1/worker/v0.1.0-test/biometric-engines-worker-v0.1.0-test-x86_64-unknown-linux-gnu.tar.gz
export BOOTSTRAP_TIMEOUT_SECONDS=2 POLL_SECONDS=1

run_case() {
    export SCENARIO=$1 CASE_DIR="$suite/$1" ARCHIVE="${2:-$suite/good.tar.gz}"
    mkdir -p "$CASE_DIR"
    export BUNDLE_READY_FILE="$CASE_DIR/ready"
    BUNDLE_ARTIFACT_SHA256=$(sha256sum "$ARCHIVE" | cut -d ' ' -f 1)
    export BUNDLE_ARTIFACT_SHA256
    if [[ "$SCENARIO" == checksum ]]; then BUNDLE_ARTIFACT_SHA256=$(printf '%064d' 1); fi
    if [[ "$SCENARIO" == invalid_pin ]]; then BUNDLE_ARTIFACT_SHA256=placeholder; touch "$BUNDLE_READY_FILE"; fi
    if [[ "$SCENARIO" == wrong_bucket ]]; then BUNDLE_ENVIRONMENT=stage; fi
    "$PROVISIONER_BIN" > "$CASE_DIR/output" 2>&1 &
    provisioner_pid=$!
}
finish_failure() {
    if wait "$provisioner_pid"; then echo "FAIL: $SCENARIO unexpectedly succeeded"; exit 1; fi
    provisioner_pid=""
    [[ ! -e "$BUNDLE_READY_FILE" ]] || { echo "FAIL: $SCENARIO left readiness"; exit 1; }
    if [[ "$SCENARIO" != cleanup_fail ]]; then [[ ! -e "$CASE_DIR/owned" ]]; fi
    echo "PASS: $SCENARIO"
}

for scenario in invalid_pin wrong_bucket download_fail checksum dynamic shared_library; do
    run_case "$scenario"
    finish_failure
    assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null
    BUNDLE_ENVIRONMENT=dev
done
for scenario in launch_fail launch_timeout cleanup_fail; do
    run_case "$scenario"
    finish_failure
    [[ $(grep -c '^launch$' "$CASE_DIR/events") == 1 ]]
    grep -q '^terminate-owned$' "$CASE_DIR/events"
done

run_case signal_launch
for ((i=0; i<100; i++)); do
    if grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null; then break; fi
    sleep 0.01
done
grep -q '^launch$' "$CASE_DIR/events"
kill -TERM "$provisioner_pid"
wait "$provisioner_pid"
provisioner_pid=""
[[ ! -e "$BUNDLE_READY_FILE" && ! -e "$CASE_DIR/owned" ]]
grep -q '^terminate-owned$' "$CASE_DIR/events"
echo 'PASS: SIGTERM during launch cleans up only the owned enclave'

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
echo 'All provisioner contract tests passed.'
