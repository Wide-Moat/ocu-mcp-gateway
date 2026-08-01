#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# perf_gate.sh - the k6 perf-regression gate harness for the gateway-LOCAL /mcp
# handshake (wave-2 perf increment 1). It:
#   1. mints ONE boot-set fixture set (boot-set.json + service-credential.token +
#      provisioning-policy.json) via scripts/mint_boot_set.py and captures the
#      printed plaintext bearer.
#   2. for each binary (BASE, HEAD), boots gatewayd on 127.0.0.1:PORT with those
#      three fixtures + an -audit-sink and NO -control-url (so tools/call fails
#      closed and only the gateway-LOCAL handshake is on the measured path),
#      polls `-health-check` until ready, runs the k6 scenario writing a summary,
#      then SIGTERMs the daemon.
#   3. INTERLEAVES the runs ABAB (base, head, base, head) so both binaries see the
#      same machine weather; hands the 2 base + 2 head summaries to
#      scripts/perf_compare.py, which decides the verdict (0 ok / 1 regression /
#      2 broken rig). The gate's exit code is the comparer's.
#
# Usage:
#   scripts/perf_gate.sh <base-binary> <head-binary>
# For a self-baseline (prove the harness end-to-end) pass the same binary twice;
# in CI base is the merge-base build and head is the PR build.

set -euo pipefail

BASE_BIN="${1:?usage: perf_gate.sh <base-binary> <head-binary>}"
HEAD_BIN="${2:?usage: perf_gate.sh <base-binary> <head-binary>}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K6_SCRIPT="${REPO_ROOT}/test/perf/mcp_handshake.js"
MINT="${REPO_ROOT}/scripts/mint_boot_set.py"
COMPARE="${REPO_ROOT}/scripts/perf_compare.py"

# Deployment scope for the fixtures; the gateway's -deployment MUST equal it.
DEPLOYMENT="perf-ci"
# Two loopback ports, one per binary, so a lingering socket from one never
# collides with the other's boot.
BASE_PORT="${PERF_BASE_PORT:-18080}"
HEAD_PORT="${PERF_HEAD_PORT:-18081}"

for f in "$K6_SCRIPT" "$MINT" "$COMPARE"; do
  [ -f "$f" ] || { echo "perf_gate: missing required file: $f" >&2; exit 2; }
done
command -v k6 >/dev/null 2>&1 || { echo "perf_gate: k6 not on PATH (install the pinned tarball first)" >&2; exit 2; }
[ -x "$BASE_BIN" ] || { echo "perf_gate: base binary not executable: $BASE_BIN" >&2; exit 2; }
[ -x "$HEAD_BIN" ] || { echo "perf_gate: head binary not executable: $HEAD_BIN" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/perf-gate.XXXXXX")"
FIX_DIR="${WORK}/fixtures"
mkdir -p "$FIX_DIR"

# Track daemon PIDs so the cleanup trap always tears them down, even on an early
# failure - a leaked gatewayd would hold a port and poison a re-run.
DAEMON_PIDS=()

cleanup() {
  local pid
  for pid in "${DAEMON_PIDS[@]:-}"; do
    [ -n "${pid:-}" ] || continue
    kill -TERM "$pid" 2>/dev/null || true
  done
  # Give a moment for a clean SIGTERM unwind, then hard-kill any survivor.
  sleep 1
  for pid in "${DAEMON_PIDS[@]:-}"; do
    [ -n "${pid:-}" ] || continue
    kill -KILL "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# (1) Mint the fixtures ONCE and capture the printed bearer (last stdout line).
echo "perf_gate: minting boot-set fixtures (deployment=${DEPLOYMENT})" >&2
MINT_OUT="$(python3 "$MINT" --deployment "$DEPLOYMENT" --out-dir "$FIX_DIR")"
BEARER="$(printf '%s\n' "$MINT_OUT" | tail -n 1)"
case "$BEARER" in
  sk-ocu-*) : ;;
  *) echo "perf_gate: mint did not print an sk-ocu- bearer (got: ${BEARER})" >&2; exit 2 ;;
esac

BOOT_SET="${FIX_DIR}/boot-set.json"
SVC_CRED="${FIX_DIR}/service-credential.token"
PROV_POLICY="${FIX_DIR}/provisioning-policy.json"
for f in "$BOOT_SET" "$SVC_CRED" "$PROV_POLICY"; do
  [ -f "$f" ] || { echo "perf_gate: mint did not produce ${f}" >&2; exit 2; }
done

# boot_and_run boots one binary, waits for readiness, runs one k6 round, SIGTERMs
# the daemon, and leaves the summary at $3. It NEVER sets -control-url, so
# tools/call fails closed and only the gateway-local handshake is measured.
#   $1 = binary path, $2 = port, $3 = summary output path, $4 = round label.
boot_and_run() {
  local bin="$1" port="$2" summary="$3" label="$4"
  local addr="127.0.0.1:${port}"
  local audit_sink="${WORK}/audit-${label}.ndjson"
  local log="${WORK}/gatewayd-${label}.log"

  echo "perf_gate: [${label}] booting ${bin} on ${addr}" >&2
  "$bin" \
    -listen "$addr" \
    -deployment "$DEPLOYMENT" \
    -boot-set "$BOOT_SET" \
    -service-credential-file "$SVC_CRED" \
    -provisioning-policy "$PROV_POLICY" \
    -audit-sink "$audit_sink" \
    >"$log" 2>&1 &
  local pid=$!
  DAEMON_PIDS+=("$pid")

  # Poll -health-check (a client that dials /healthz on the same address) until
  # ready. A dead daemon (the boot flags rejected) exits, so the process-alive
  # check turns a boot failure into a fast, distinct broken-rig exit.
  # The loop body only needs a bounded retry count, not the index value; `_`
  # marks the loop var unused for shellcheck (SC2034).
  local ready="" _
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "perf_gate: [${label}] daemon exited during boot; log:" >&2
      cat "$log" >&2 || true
      exit 2
    fi
    if "$bin" -health-check -listen "$addr" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.2
  done
  if [ -z "$ready" ]; then
    echo "perf_gate: [${label}] daemon never became ready; log:" >&2
    cat "$log" >&2 || true
    exit 2
  fi

  echo "perf_gate: [${label}] ready; running k6" >&2
  # A functional check failure (abortOnFail) makes k6 exit non-zero; that is a
  # broken measured pipeline, so surface it as a broken rig, not a false pass.
  if ! GATEWAY_URL="http://${addr}" GATEWAY_BEARER="$BEARER" SUMMARY_PATH="$summary" \
       k6 run "$K6_SCRIPT" >"${WORK}/k6-${label}.log" 2>&1; then
    echo "perf_gate: [${label}] k6 run failed (functional check or setup guard); log:" >&2
    cat "${WORK}/k6-${label}.log" >&2 || true
    exit 2
  fi
  [ -f "$summary" ] || { echo "perf_gate: [${label}] k6 produced no summary at ${summary}" >&2; exit 2; }

  # SIGTERM the daemon and wait for a clean unwind before the next round reuses
  # the machine.
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# (2)+(3) ABAB interleave so both binaries share the same machine weather.
BASE_1="${WORK}/base-1.summary.json"
HEAD_1="${WORK}/head-1.summary.json"
BASE_2="${WORK}/base-2.summary.json"
HEAD_2="${WORK}/head-2.summary.json"

boot_and_run "$BASE_BIN" "$BASE_PORT" "$BASE_1" "base-1"
boot_and_run "$HEAD_BIN" "$HEAD_PORT" "$HEAD_1" "head-1"
boot_and_run "$BASE_BIN" "$BASE_PORT" "$BASE_2" "base-2"
boot_and_run "$HEAD_BIN" "$HEAD_PORT" "$HEAD_2" "head-2"

echo "perf_gate: comparing (min-of-rounds p95, base 2 rounds vs head 2 rounds)" >&2
python3 "$COMPARE" \
  --base "$BASE_1" "$BASE_2" \
  --head "$HEAD_1" "$HEAD_2"
