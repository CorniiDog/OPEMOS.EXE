#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
HARNESS="$SCRIPT_DIR/run.sh"
BASE_IMAGE="${STEAMOS_HEADLESS_VM_BASE:-$SCRIPT_DIR/../../builder/appliance/fedora-builder-x86_64.qcow2}"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/steamos-vm-lifecycle.XXXXXX")"

cleanup()
{
    rm -rf -- "$ROOT"
}
trap cleanup EXIT INT TERM

wait_for_phase()
{
    local state="$1"
    local phase="$2"
    local pid="$3"
    local deadline=$((SECONDS + 300))
    while [[ ! -f "$state/test-phase" ]]; do
        kill -0 "$pid" 2>/dev/null || { wait "$pid" || true; return 1; }
        (( SECONDS < deadline )) || return 1
        sleep 1
    done
    [[ "$(cat "$state/test-phase")" == "$phase" ]]
}

assert_cleanup()
{
    local state="$1"
    ! find "$state/work" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit | grep -q .
    node -e '
const fs = require("fs");
const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (value.schemaVersion !== 1 || value.status !== "failed") process.exit(1);
' "$state/results/latest.json"
}

for phase in seed qemu result; do
    state="$ROOT/$phase"
    mkdir -m 0700 -- "$state"
    STEAMOS_HEADLESS_VM_STATE_ROOT="$state" \
    STEAMOS_HEADLESS_VM_BASE="$BASE_IMAGE" \
    STEAMOS_HEADLESS_VM_LIFECYCLE_TEST=1 \
    STEAMOS_HEADLESS_VM_TEST_PHASE="$phase" \
        bash "$HARNESS" >"$state/stdout" 2>"$state/stderr" &
    pid="$!"
    wait_for_phase "$state" "$phase" "$pid"
    kill -TERM "$pid"
    if wait "$pid"; then
        printf 'Lifecycle phase %s unexpectedly succeeded after SIGTERM.\n' "$phase" >&2
        exit 1
    fi
    assert_cleanup "$state"
done

state="$ROOT/runtime-replacement"
redirected="$ROOT/redirected-runtime"
mkdir -m 0700 -- "$state" "$redirected"
printf 'preserve\n' > "$redirected/sentinel"
STEAMOS_HEADLESS_VM_STATE_ROOT="$state" \
STEAMOS_HEADLESS_VM_BASE="$BASE_IMAGE" \
STEAMOS_HEADLESS_VM_LIFECYCLE_TEST=1 \
STEAMOS_HEADLESS_VM_TEST_PHASE=seed \
    bash "$HARNESS" >"$state/stdout" 2>"$state/stderr" &
pid="$!"
wait_for_phase "$state" seed "$pid"
runtime="$(find "$state/work" -mindepth 1 -maxdepth 1 -type d -name 'run.*' -print -quit)"
[[ -n "$runtime" ]]
mv -- "$runtime" "$runtime.original"
ln -s -- "$redirected" "$runtime"
printf 'continue\n' > "$state/test-continue"
if wait "$pid"; then
    printf 'Replaced runtime unexpectedly passed validation.\n' >&2
    exit 1
fi
grep -q 'detected replaced runtime/result state' "$state/stderr"
[[ "$(cat "$redirected/sentinel")" == preserve ]]

state="$ROOT/timeout-recovery"
mkdir -m 0700 -- "$state"
if STEAMOS_HEADLESS_VM_STATE_ROOT="$state" \
    STEAMOS_HEADLESS_VM_BASE="$BASE_IMAGE" \
    STEAMOS_HEADLESS_VM_TIMEOUT_SECONDS=30 \
        bash "$HARNESS" >"$state/timeout.stdout" 2>"$state/timeout.stderr"; then
    printf 'Forced-timeout VM run unexpectedly succeeded.\n' >&2
    exit 1
fi
node -e '
const fs = require("fs");
const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (value.status !== "failed" || !value.reason.includes("timed out")) process.exit(1);
' "$state/results/latest.json"
! find "$state/work" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit | grep -q .
STEAMOS_HEADLESS_VM_STATE_ROOT="$state" \
STEAMOS_HEADLESS_VM_BASE="$BASE_IMAGE" \
    bash "$HARNESS" >"$state/recovery.stdout" 2>"$state/recovery.stderr"
node -e '
const fs = require("fs");
const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (value.status !== "passed") process.exit(1);
' "$state/results/latest.json"
! find "$state/work" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit | grep -q .

printf 'Headless VM lifecycle SIGTERM, replacement, timeout, and recovery checks passed.\n'
