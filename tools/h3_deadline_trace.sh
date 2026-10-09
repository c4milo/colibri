#!/usr/bin/env bash
# Trace validation of spec/tla/h3_deadlines against colibri (design §8 step 20d). The simulator's
# h3 deadline trace run acts out a seed's plan with an honest client and a server `Endpoint` over
# QUIC, and logs after each action the variables of the model that map one to one onto colibri
# and its client, and whether each of colibri's clocks runs. TLC then checks every seed's log is
# a behavior of the model, each clock running as decision 110's rules say
# (spec/tla/h3_deadlines/H3DeadlinesTrace.tla).
#
# It writes `sim --h3-deadline-trace-write`'s modules into a scratch directory beside copies of
# the two model files, and runs `zig build tla` over their configurations. It needs Java, as
# `zig build tla` does, and it is not part of `zig build test`.
#
#   tools/h3_deadline_trace.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly model="${repository_root}/spec/tla/h3_deadlines"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

cd "${repository_root}"
command -v java >/dev/null 2>&1 || { echo "h3_deadline_trace.sh: java is not installed" >&2; exit 1; }
zig build sim -- --h3-deadline-trace-write "${scratch}"
cp "${model}/H3Deadlines.tla" "${model}/H3DeadlinesTrace.tla" "${scratch}/"
report="${scratch}/report.txt"
status=0
zig build tla -- "${scratch}"/H3DeadlineTraceSeed*.cfg >"${report}" 2>&1 || status=$?
followed="$(grep -c "violated, as expected" "${report}" || true)"
total="$(ls "${scratch}"/H3DeadlineTraceSeed*.cfg | wc -l | tr -d ' ')"
if [ "${status}" -ne 0 ]; then
  grep -E "error: \[tla\]" "${report}" >&2 || tail -20 "${report}" >&2
  echo "h3_deadline_trace.sh: ${followed} of ${total} traces are behaviors of the model" >&2
  exit 1
fi
echo "h3_deadline_trace.sh: ${followed} of ${total} traces are behaviors of the model"
