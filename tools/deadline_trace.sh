#!/usr/bin/env bash
# Trace validation of spec/tla/server_deadlines against colibri
# (https://github.com/c4milo/colibri/issues/86). The simulator's deadline trace run acts out a
# seed's plan with colibri's h2 client and a `server.Connection`, and logs the model's state and
# three of colibri's clocks after each action; TLC then checks every seed's log is a behavior of
# the model, each clock running as decision 110's rules say
# (spec/tla/server_deadlines/ServerDeadlinesTrace.tla).
#
# It writes `sim --deadline-trace-write`'s modules into a scratch directory beside copies of the
# two model files, and runs `zig build tla` over their configurations. It needs Java, as
# `zig build tla` does, and it is not part of `zig build test`.
#
#   tools/deadline_trace.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly model="${repository_root}/spec/tla/server_deadlines"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

cd "${repository_root}"
command -v java >/dev/null 2>&1 || { echo "deadline_trace.sh: java is not installed" >&2; exit 1; }
zig build sim -- --deadline-trace-write "${scratch}"
cp "${model}/ServerDeadlines.tla" "${model}/ServerDeadlinesTrace.tla" "${scratch}/"
report="${scratch}/report.txt"
status=0
zig build tla -- "${scratch}"/DeadlineTraceSeed*.cfg >"${report}" 2>&1 || status=$?
followed="$(grep -c "violated, as expected" "${report}" || true)"
total="$(ls "${scratch}"/DeadlineTraceSeed*.cfg | wc -l | tr -d ' ')"
if [ "${status}" -ne 0 ]; then
  grep -E "error: \[tla\]" "${report}" >&2 || tail -20 "${report}" >&2
  echo "deadline_trace.sh: ${followed} of ${total} traces are behaviors of the model" >&2
  exit 1
fi
echo "deadline_trace.sh: ${followed} of ${total} traces are behaviors of the model"
