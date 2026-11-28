#!/usr/bin/env bash
# Load test in one command (see ../docs/load-test.md). Builds dvtee and
# dvtee-load, then runs:
#   1. in-process micro benchmarks (BLS signing, watermark fsync) on WORK_DIR;
#   2. the realistic duty mix for each key count in SIZES;
#   3. a stress ramp: STRESS_KEYS keys, ATTESTERS of them attesting per slot,
#      stopping at the first level that fails the budget.
# Results go to WORK_DIR/results-<time>/ (summary.jsonl, the tables, and a
# probe-*.csv of disk sync stalls per run).
#
# Run it from a directory on the disk the signer's data dir will use. In an
# SNP guest, run it inside the guest: the signer serves as --platform tee
# (no attestation is requested, so no TEE call is made).
#
# Environment (defaults in brackets):
#   BUILD        release | debug                     [release]
#   SIZES        realistic key counts                [100 1000 3200 6400]
#   EPOCHS       measured epochs per realistic run   [2]
#   STRESS_KEYS  keys for the stress ramp            [6400]
#   ATTESTERS    stress levels, attesters per slot   [800 1600 3200 6400]
#   STRESS_EPOCHS measured epochs per stress level   [2]
#   SLOT_MS      simulated slot length in ms         [3000]
#   BUDGET_MS    latency budget in ms                [1000]
#   WORK_DIR     keystores, data dirs, results       [load-test-work]
#   EXTRA        more flags for every run, e.g. "--conns 512", "--http2",
#                "--plain-http" or "--data-parent /dev/shm"
#
# With the defaults it takes 45 to 60 minutes.
set -euo pipefail

cd "$(dirname "$0")/.."
BUILD=${BUILD:-release}
SIZES=${SIZES:-"100 1000 3200 6400"}
EPOCHS=${EPOCHS:-2}
STRESS_KEYS=${STRESS_KEYS:-6400}
ATTESTERS=${ATTESTERS:-"800 1600 3200 6400"}
STRESS_EPOCHS=${STRESS_EPOCHS:-2}
SLOT_MS=${SLOT_MS:-3000}
BUDGET_MS=${BUDGET_MS:-1000}
WORK_DIR=${WORK_DIR:-load-test-work}
EXTRA=${EXTRA:-}

if [ "$BUILD" = release ]; then
  cargo build --release --locked --features load-test
  BIN=target/release
else
  cargo build --locked --features load-test
  BIN=target/debug
fi

OUT="$WORK_DIR/results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
{
  echo "# dvtee load test, $(date -u +%FT%TZ), profile $BUILD"
  echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs), $(nproc) threads"
  echo "kernel: $(uname -r)"
  echo "work dir: $(df -hT "$WORK_DIR" | tail -1)"
} | tee "$OUT/machine.txt"

common=(--work-dir "$WORK_DIR" --slot-ms "$SLOT_MS" --budget-ms "$BUDGET_MS"
  --json-out "$OUT/summary.jsonl" --label "$BUILD")
# shellcheck disable=SC2206
common+=($EXTRA)

"$BIN/dvtee-load" micro --dir "$WORK_DIR" | tee "$OUT/micro.md"

# Disk sync stalls, logged per second next to each run.
probe_start() {
  "$BIN/dvtee-load" probe --dir "$WORK_DIR" --secs 100000 >"$OUT/probe-$1.csv" &
  PROBE=$!
}
probe_stop() {
  kill "$PROBE" 2>/dev/null || true
  wait "$PROBE" 2>/dev/null || true
}
trap probe_stop EXIT

for n in $SIZES; do
  probe_start "keys-$n"
  "$BIN/dvtee-load" run --keys "$n" --epochs "$EPOCHS" "${common[@]}" |
    tee -a "$OUT/realistic.md"
  probe_stop
done

for k in $ATTESTERS; do
  probe_start "stress-$k"
  pass=1
  "$BIN/dvtee-load" run --keys "$STRESS_KEYS" --attesters-per-slot "$k" \
    --epochs "$STRESS_EPOCHS" "${common[@]}" | tee -a "$OUT/stress.md" |
    grep 'verdict: PASS' >/dev/null || pass=0
  probe_stop
  if [ "$pass" = 0 ]; then
    echo "stress: $k attesters/slot failed; stopping the ramp"
    break
  fi
done

echo "results in $OUT"
